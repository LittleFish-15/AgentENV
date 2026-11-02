"""Stable-image root lifecycle and miss dispatcher; no SDK calls as root.

Kernel arenas are registered from the ordinary SDK service's readonly FDs.
Mounts are private; an ordinary inherited-FD broker serves actual lower reads.
"""
from dataclasses import asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import stat
import struct
import threading
import time
import uuid

from . import contract, host_pmem, host_pmem_lease, host_pmem_mount, host_dax_worker, region_provenance, stored
from .demand_control import proof_mac
from .demand_source import DirectSource
from .demand_views import unit_pid
from .demand_wire import LOAD_BYTES, DEVICE_BYTES
from .host_dax_demand import require
from .io import atomic_json


class StableRoot:
    def __init__(self, config, manifest, coordinator, image_key, receipt_key):
        require(os.getuid()==os.geteuid()==0,'Stable root supervisor requires root')
        self.config,self.manifest,self.coordinator=config,manifest,coordinator
        self.image_key,self.receipt_key=image_key,receipt_key
        require(os.uname().release==config['kernelRelease']
                and Path('/sys/module/obmm/srcversion').read_text().strip()==config['moduleSrcversion'],
                'Exact candidate kernel/module required')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==config['bootId'],
                'Root config belongs to another boot; preserve old state')
        require(Path('/sys/module/obmm/parameters/pmem_ro_enable').read_text().strip() in ('Y','1'),
                'Pmem frontend not enabled')
        self.writer=config['node']==config['ownerNode']
        if self.writer:
            require(Path('/sys/module/obmm/parameters/pmem_demand_write_enable').read_text().strip() in ('Y','1'),
                    'Controlled arena writes require separately approved module gate')
        self.namespace=host_pmem_mount.private_namespace()  # Before starting ANY threads.
        self.work=Path(config['stateRoot'])
        require(self.work.is_relative_to(Path('/home/jwk/root')) and self.work.parent.resolve()==self.work.parent,
                'Root artifacts must remain under /home/jwk/root')
        self.work.mkdir(mode=0o700,exist_ok=False);(self.work/'mount').mkdir(mode=0o700)
        engine,_=unit_pid(config.get('engineUnit','ubse.service'),config.get('engineUid',985))
        self.engine=region_provenance.attest_engine(engine)
        self.control_fd=host_pmem.open_control();self.control=host_pmem.SparseControl(self.control_fd)
        self.volume_uuid=str(uuid.uuid5(uuid.UUID(config['run']),config['node']))
        self.record={'run':config['run'],'node':config['node'],'phase':'PREPARED','volumeUuid':self.volume_uuid,
                     'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                     'pools':{},'units':{},'fatal':None,'controlPinned':True}
        self.lock=threading.RLock();self.fdsets={};self.worker=None;self.mount=None;self.status=None
        self.admin_lock=threading.Lock()
        self.stop_event=threading.Event();self.miss_thread=None;self.consumers=[];self.save()
        self.socket_ready=threading.Event()

    def save(self):
        with self.lock:
            try:atomic_json(self.work/'root.json',self.record)
            except BaseException:
                self.record['fatal']='Root journal durability uncertain; preserve all resources'
                raise
    def retain_consumer(self,consumer):self.consumers.append(consumer)
    def proof(self,kind,**fields):
        body={'kind':kind,'run':self.config['run'],'node':self.config['node'],**fields}
        return {'body':body,'mac':proof_mac(self.receipt_key,body)}

    def sdk_call(self,method,descriptor=None):
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(30);stream.connect(self.config['sdkSocket'])
            pid,uid,_=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            expected,ticks=unit_pid(self.config['sdkUnit'],self.config['uid'])
            require(pid==expected and uid==self.config['uid'] and host_pmem_lease.process_ticks(pid)==ticks,
                    'SDK service identity changed')
            host_dax_worker.send(stream,{'run':self.config['run'],'method':method,'descriptor':descriptor})
            response=contract.receive_json(stream);require(response.get('ok') is True,response.get('reason','SDK RPC failed'))
            result=response['result']
            if method=='attach':return result,host_pmem_lease.receive_segments(stream,result['lengths'])
            return result

    def attach_pool(self,descriptor):
        body={k:v for k,v in descriptor.items() if k!='signature'};pool=descriptor['poolUuid']
        require(hmac.compare_digest(descriptor['signature'],proof_mac(self.image_key,body))
                and body.get('kind')=='stable-arena-v1' and body['run']==self.config['run']
                and body['ownerNode']==self.config['ownerNode'] and body['bytes']==self.config['poolBytes'],
                'Untrusted arena publication')
        with self.lock:
            require(not self.record['fatal'] and not self.stop_event.is_set(),'Root no longer admits arena attachment')
            if pool in self.record['pools']:
                r=self.record['pools'][pool]
                require(r['descriptor']==descriptor and r['phase']=='READY','Unknown arena attach; preserve')
                return {'state':'READY','originFingerprint':r['originFingerprint']}
            r={'descriptor':descriptor,'phase':'SDK_FD_INTENT','segments':[]};self.record['pools'][pool]=r;self.save()
            result,segments=self.sdk_call('attach',descriptor);self.fdsets[pool]=segments
            require(result['descriptor']==descriptor and sum(s.bytes for s in segments)==descriptor['bytes'],
                    'SDK segment coverage differs')
            offset=0
            for i,segment in enumerate(segments):
                local=str(uuid.uuid5(uuid.UUID(pool),str(i)))
                row={'uuid':local,'offset':offset,'bytes':segment.bytes,'rdev':os.fstat(segment.fd).st_rdev,
                     'phase':'REGISTER_INTENT'}
                r['segments'].append(row);self.save()
                self.control.create_pool(local,segment,writer=self.writer)
                row['phase']='READY';offset+=segment.bytes;self.save()
            origins=[{'rdev':row['rdev'],'offset':0,'bytes':row['bytes'],'logicalOffset':row['offset']}
                     for row in r['segments']]
            r['origin']=region_provenance.collect(os.getpid(),host_pmem_lease.process_ticks(os.getpid()),
                                                origins,descriptor['objectName'])
            topology=sorted([{'exportNodeId':row['origin']['exportNodeId'],
                'exportMemId':row['origin']['exportMemId'],'regionOffset':span['offset'],
                'logicalOffset':span['logicalOffset'],'bytes':span['bytes']}
                for row in r['origin'] for span in row['ranges']],key=lambda value:value['logicalOffset'])
            cursor=0
            for span in topology:
                require(span['logicalOffset']==cursor,'Origin mapping has a hole/overlap');cursor+=span['bytes']
            require(cursor==descriptor['bytes'],'Origin mapping incomplete')
            r['originFingerprint']=hashlib.sha256(contract.canonical(topology)).hexdigest()
            r['phase']='READY';self.save();return {'state':'READY','originFingerprint':r['originFingerprint']}

    def slot(self,pool,offset):
        r=self.record['pools'][pool];require(r['phase']=='READY','Arena not ready')
        for row in r['segments']:
            if row['offset']<=offset<row['offset']+row['bytes']:
                require(offset+LOAD_BYTES<=row['offset']+row['bytes'],'Slot crosses SDK segment')
                return row['uuid'],offset-row['offset']
        raise ValueError('Slot outside arena')

    def fill(self,pool,offset,index):
        require(self.writer and type(index)is int and 0<=index<len(self.manifest.chunks),'Not an owner unit')
        with self.lock:
            require(not self.record['fatal'] and not self.stop_event.is_set(),'Root no longer admits filling')
            chunk=self.manifest.chunks[index];local,at=self.slot(pool,offset)
            record=self.record['units'].setdefault(str(index),{'phase':'FILL_INTENT','pool':pool,'slot':offset})
            require(record['phase']=='FILL_INTENT' and record['pool']==pool and record['slot']==offset,
                    'Fill may already have happened; query, never rewrite')
            require(not record.get('attempted'),'Unknown fill result preserved')
            record['attempted']=True;self.save()
            source=DirectSource(self.config['sourceImage'],self.manifest.file_bytes)
            try:data=source.read(chunk.offset,chunk.length)
            finally:source.close()
            self.control.fill_slot(local,at,data,chunk.sha256)
            receipt=self.control.query_slot(local,at)
            require(receipt['state']=='ready' and receipt['sha256']==chunk.sha256 and receipt['bytes']==chunk.length,
                    'Owner fill not confirmed')
            record['phase']='FILLED';self.save();return {'state':'FILLED'}

    def miss_loop(self):
        try:
            while not self.stop_event.is_set():
                miss=self.control.claim_miss(self.volume_uuid)
                if miss is None:self.stop_event.wait(0.02);continue
                index=miss['logicalOffset']//LOAD_BYTES;operation=uuid.uuid4().hex
                with self.lock:
                    self.record['activeMiss']={'index':index,'operation':operation,'phase':'ACQUIRE_INTENT'};self.save()
                result=self.coordinator.acquire(operation,self.manifest.sha256,index,time.monotonic()+30)
                body={k:v for k,v in result.items() if k!='signature'};chunk=self.manifest.chunks[index]
                require(hmac.compare_digest(result['signature'],proof_mac(self.image_key,body))
                        and body.get('kind')=='stable-unit-v1'
                        and body['run']==self.config['run'] and body['manifestSha256']==self.manifest.sha256
                        and (body['index'],body['offset'],body['bytes'],body['sha256'])==
                        (index,chunk.offset,chunk.length,chunk.sha256),'Unit publication differs')
                origin=self.attach_pool(body['pool'])
                require(origin['originFingerprint']==body['originFingerprint'],
                        'Peer import does not match the owner export-region mapping')
                with self.lock:
                    local,at=self.slot(body['pool']['poolUuid'],body['slotOffset'])
                    if not self.writer:self.control.accept_slot(local,at,chunk.length,chunk.sha256)
                    self.record['activeMiss']['phase']='BIND_INTENT';self.save()
                    self.control.bind_slot(self.volume_uuid,chunk.offset,local,at,chunk.sha256)
                    self.record['units'][str(index)]={'phase':'BOUND','pool':body['pool']['poolUuid'],
                        'slot':body['slotOffset'],'sha256':chunk.sha256}
                    self.record.pop('activeMiss',None);self.save()
        except Exception as error:
            with self.lock:
                self.record['fatal']=str(error)
                try:self.save()
                except Exception:pass
            try:
                if 'miss' in locals() and miss:self.control.fail_miss(self.volume_uuid,miss['logicalOffset'],miss['bytes'])
            except Exception:pass  # Unknown SDK/root work remains retained, not retried.
            try:self.coordinator.call('halt',uuid.uuid4().hex)
            except Exception:pass

    def start(self):
        sdk=self.sdk_call('status')
        require(sdk['state']=='READY' and sdk['node']==self.config['node'] and not sdk['finalized'],
                'Local SDK service is not ready')
        receipt=self.proof('stable-root-ready',writerEnabled=self.writer,manifestSha256=self.manifest.sha256,
                           logicalBytes=DEVICE_BYTES,controlPinned=True,bootId=self.config['bootId'],
                           rootPid=os.getpid(),rootStartTicks=host_pmem_lease.process_ticks(os.getpid()),
                           moduleSrcversion=self.config['moduleSrcversion'])
        self.coordinator.call('ready',uuid.uuid4().hex,{'receipt':receipt})
        deadline=time.monotonic()+300
        while True:
            status=self.coordinator.call('status',uuid.uuid4().hex)
            if set(status['readyNodes'])==set(self.config['nodes']):break
            require(time.monotonic()<deadline,'Peer root not ready; no UB allocations')
            time.sleep(0.2)
        require(self.sdk_call('initialize')['state']=='INITIALIZED','SDK initialization not confirmed')
        with self.lock:
            self.record['phase']='CREATE_INTENT';self.save()
            self.control.create_sparse(self.volume_uuid,self.manifest.file_bytes)
            self.status=self.control.query(self.volume_uuid)
            self.record['volume']=asdict(self.status);self.record['phase']='DEVICE_READY';self.save()
        self.miss_thread=threading.Thread(target=self.miss_loop,daemon=True);self.miss_thread.start()
        self.mount=host_pmem_mount.ReadonlyMount(self.namespace,self.status,self.work/'mount',
                    lambda value:self.mount_record(value))
        try:
            self.mount.mount()
            with self.lock:self.record['phase']='mounted_pending_file_verification';self.save()
            stable={'imageSha256':self.manifest.layer_digest,'imageBytes':self.manifest.file_bytes,
                    'manifestSha256':'sha256:'+self.manifest.sha256}
            self.worker=host_dax_worker.Worker(self,self.config['files'],self.config['uid'],self.config['gid'],
                self.config['brokerSocket'],lambda r:self.worker_record(r),stable=stable,
                child_package=self.config['ordinaryPackagePath'])
            ready=self.worker.start()
            require(not self.record['fatal'] and self.miss_thread.is_alive(), 'Miss service failed during startup')
            require(self.coordinator.call('status',uuid.uuid4().hex)['state']=='SERVING',
                    'Peer/global startup failed; do not publish runtime index')
            published=self.sdk_call('publish-index',ready['index'])
            require(published['indexPath']==self.config['indexPath'],'SDK index destination differs')
            with self.lock:self.record['phase']='SERVING';self.save()
            return {'state':'SERVING',**published}
        except Exception as error:
            with self.lock:self.record.update(phase='STOPPED_PRESERVE',fatal=str(error));self.save()
            raise

    def mount_record(self,value):
        with self.lock:self.record['mount']=value;self.save()
    def worker_record(self,value):
        with self.lock:self.record['worker']=value;self.save()

    def drain(self, reconcile=False):
        require(self.coordinator.call('status',uuid.uuid4().hex)['state']=='CLOSED','Close global admission first')
        with self.lock:
            if self.record['phase']=='DRAINED':
                receipt=self.record['drainReceipt']
                self.coordinator.call('node-drained',uuid.uuid4().hex,{'receipt':receipt})
                return {'state':'DRAINED','receipt':receipt}
            require((not self.record['fatal'] and self.record['phase']=='SERVING') or reconcile,
                    'Uncertain root state needs explicit abort inspection')
            require('journal durability' not in (self.record['fatal'] or '').lower(),
                    'Journal uncertainty requires operator inspection; preserve')
            self.record['phase']='DRAINING';self.save()
            if self.worker is not None and not self.worker.retired:
                if reconcile and self.worker.process is not None and self.worker.process.poll() is not None:
                    # Known Popen child exited; this only closes OUR parent FDs.
                    # Kernel mount/device/pool checks below remain mandatory.
                    self.worker.close_fds();self.worker.retired=True
                    self.worker.mark('exited_reconciled',exitCode=self.worker.process.returncode)
                else:
                    try:self.worker.retire()
                    except Exception:
                        if self.worker.record['state']=='busy_preserve_mount':
                            self.record['phase']='SERVING';self.save()
                        raise
        self.stop_event.set()
        if self.miss_thread is not None:self.miss_thread.join(35)
        require(self.miss_thread is None or not self.miss_thread.is_alive(),'Miss still active; retain resources')
        require(reconcile or not self.record.get('activeMiss'),'Miss outcome uncertain; explicit abort required')
        with self.lock:
            if self.mount is not None and self.mount.state['phase']!='new':self.mount.unmount()
            else:require(host_pmem_mount.mounted_at(self.work/'mount') is None,'Unexpected mount; preserve')
            self.record['phase']='DESTROY_INTENT';self.save()
            try:observed=self.control.query(self.volume_uuid)
            except OSError as error:
                import errno
                if not reconcile or error.errno!=errno.ENOENT:raise
            else:self.control.destroy(observed)
            self.record['phase']='DEVICE_ABSENT';self.save()
            for pool,r in self.record['pools'].items():
                require(r['phase']=='READY' or reconcile,'Uncertain pool registration')
                for segment in r['segments']:
                    if segment['phase']=='ABSENT':continue
                    require(segment['phase']=='READY' or reconcile,'Uncertain local arena')
                    segment['phase']='DESTROY_INTENT';self.save()
                    try:self.control.query_slot(segment['uuid'],0)
                    except OSError as error:
                        import errno
                        if not reconcile or error.errno!=errno.ENOENT:raise
                    else:self.control.destroy_pool(segment['uuid'])
                    segment['phase']='ABSENT';self.save()
                for segment in self.fdsets.get(pool,[]):os.close(segment.fd)
                self.fdsets[pool]=[];r['phase']='ABSENT';self.save()
            sdk=self.sdk_call('status')
            require(sdk['state']=='READY' and sdk['run']==self.config['run'],'SDK state uncertain; preserve anchors')
            if not self.writer:
                result=self.sdk_call('release-imports');require(result['finalizeAcknowledged'],'Importer not finalized')
            receipt=self.proof('stable-root-drained',localDeviceAbsent=True,localPoolsAbsent=True,
                pools=sorted(sdk['pools']),reconciled=reconcile,
                sdkDisposition='owner_anchor_retained' if self.writer else 'importer_finalized')
            self.record['drainReceipt']=receipt;self.record['phase']='DRAINED';self.save()
        self.coordinator.call('node-drained',uuid.uuid4().hex,{'receipt':receipt})
        return {'state':'DRAINED','receipt':receipt}

    def serve(self):
        path=Path(self.config['rootSocket']);require(not path.exists(),'Existing root socket preserved')
        require(path.parent.resolve()==path.parent and path.parent.stat().st_uid==0
                and not path.parent.stat().st_mode&0o022,'Protected root socket parent required')
        listener=socket.socket(socket.AF_UNIX);listener.bind(str(path));os.chown(path,0,self.config['gid']);os.chmod(path,0o660);listener.listen(16)
        self.socket_ready.set()
        def handle(stream):
            with stream:
                try:
                    stream.settimeout(330)
                    pid,uid,_=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    request=contract.receive_json(stream);require(request['run']==self.config['run'],'Wrong root run')
                    method=request['method'];params=request.get('params',{})
                    if method in ('arena-attach','arena-fill'):
                        expected,ticks=unit_pid(self.config['sdkUnit'],self.config['uid'])
                        require(self.writer and uid==self.config['uid'] and pid==expected
                                and host_pmem_lease.process_ticks(pid)==ticks,'Unexpected SDK owner peer')
                        result=(self.attach_pool(params['descriptor']) if method=='arena-attach'
                                else self.fill(params['poolUuid'],params['slotOffset'],params['unit']))
                    else:
                        require(uid==0,'Root admin required')
                        if method=='status':result={'phase':self.record['phase'],'fatal':self.record['fatal'],
                            'volumeUuid':self.volume_uuid,'pools':len(self.record['pools']),
                            'units':len(self.record['units']),'controlPinned':self.record['controlPinned'],
                            'activeMiss':self.record.get('activeMiss'),'drainReceipt':self.record.get('drainReceipt')}
                        elif method=='drain':
                            with self.admin_lock:result=self.drain()
                        elif method=='abort':
                            with self.admin_lock:result=self.drain(reconcile=True)
                        elif method=='release-control':
                            receipt=params['receipt'];body=receipt['body']
                            require(hmac.compare_digest(receipt['mac'],proof_mac(self.image_key,body))
                                    and body['kind']=='stable-global-released' and body['run']==self.config['run']
                                    and body['globalObjectsReleased'] and body['ownerFinalizationAcknowledged']
                                    ,'Global release not confirmed')
                            with self.admin_lock,self.lock:
                                require(self.record['phase'] in ('DRAINED','RELEASED'),'Local release not confirmed')
                                if self.control_fd is not None:os.close(self.control_fd);self.control_fd=None
                                self.record.update(phase='RELEASED',controlPinned=False);self.save()
                                result={'state':'RELEASED'}
                        else:raise ValueError('Unknown root method')
                    contract.send_json(stream,{'ok':True,'result':result})
                except Exception as error:
                    try:contract.send_json(stream,{'ok':False,'reason':str(error)})
                    except OSError:pass
        while True:
            stream,_=listener.accept();threading.Thread(target=handle,args=(stream,),daemon=True).start()
