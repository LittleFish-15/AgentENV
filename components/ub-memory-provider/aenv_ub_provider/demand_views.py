"""Concrete root chunk supervisor and ordinary chunk-broker client.

The supervisor only accepts its configured node-agent system unit. It creates
typed per-chunk host_pmem_rootfs helpers, never executes client commands.
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
import subprocess
import sys
import threading
import time

from . import contract, host_pmem, host_pmem_cli, host_pmem_lease, host_pmem_rootfs, stored
from .demand_control import proof_mac
from .host_dax_demand import require
from .io import atomic_json
from . import region_provenance

BOOTSTRAP="import sys,runpy;p=sys.argv.pop(1);sys.path.insert(0,p);sys.argv[0]='host_pmem_rootfs';runpy.run_module('aenv_ub_provider.host_pmem_rootfs',run_name='__main__')"


def process_ticks(pid):return host_pmem_lease.process_ticks(pid)


def unit_pid(name,uid):
    require(isinstance(name,str) and name.endswith('.service') and '/' not in name,'Invalid approved unit')
    result=subprocess.run(['systemctl','show',name,'--property=ActiveState,MainPID,Job'],capture_output=True,text=True,timeout=15,check=True)
    value=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    require(value['ActiveState']=='active' and value.get('Job','') in ('','0'),'Approved unit is not stably active')
    pid=int(value['MainPID']);require(pid>0,'No approved unit PID')
    status=(Path('/proc')/str(pid)/'status').read_text()
    observed=next(line.split()[1:] for line in status.splitlines() if line.startswith('Uid:'))
    require(observed==[str(uid)]*4,'Approved SDK/node unit credentials differ')
    return pid,process_ticks(pid)


class RootSupervisor:
    def __init__(self,config,manifests,image_key,receipt_key):
        require(os.getuid()==os.geteuid()==0,'Root supervisor requires root')
        self.config,self.manifests,self.image_key,self.receipt_key=config,manifests,image_key,receipt_key
        self.root=Path(config['root'])
        require(self.root.is_absolute() and self.root.parent.resolve(strict=True)==self.root.parent
                and not self.root.exists() and not self.root.is_symlink(),'Existing/redirected root state preserved')
        parent=self.root.parent.stat()
        require(parent.st_uid==0 and not parent.st_mode&0o022,'Protected root state parent required')
        self.records={};self.processes={};self.lock=threading.RLock()
        require(Path('/sys/module/obmm/srcversion').read_text().strip()==config['moduleSrcversion']
                and os.uname().release==config['kernelRelease'],'Configured kernel/candidate differs')
        require(Path('/sys/module/obmm/parameters/pmem_ro_enable').read_text().strip() in ('Y','1'),
                'Readonly pmem frontend is not enabled; no demand admission')
        engine_pid,_=unit_pid(config.get('engineUnit','ubse.service'),config.get('engineUid',985))
        self.engine=region_provenance.attest_engine(engine_pid)
        # Pin the exact registered frontend for this supervisor's lifetime.
        # Opening the control device creates no UB object or local volume.
        self.control=host_pmem.open_control()
        try:self.root.mkdir(mode=0o700,exist_ok=False)
        except BaseException:
            os.close(self.control);raise

    def readiness(self):
        info=os.fstat(self.control)
        require(stat.S_ISCHR(info.st_mode),'Root control reference no longer valid')
        body={'version':1,'kind':'demand-root-ready','run':self.config['run'],
              'node':self.config['node'],'rootControlPinned':True,
              'kernelRelease':os.uname().release,'moduleSrcversion':self.config['moduleSrcversion'],
              'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
        return {'body':body,'mac':proof_mac(self.receipt_key,body)}

    def _save(self):atomic_json(self.root/'supervisor.json',{'run':self.config['run'],'records':self.records,
                                                         'controlPinned':self.control is not None})

    def release_control(self,receipt):
        body=receipt['body']
        require(hmac.compare_digest(receipt['mac'],proof_mac(self.image_key,body))
                and body.get('version')==1 and body.get('kind')=='demand-global-released'
                and body.get('run')==self.config['run'] and body.get('ownerNode')==self.config['ownerNode']
                and body.get('globalObjectsReleased') is True and body.get('ownerFinalizationAcknowledged') is True,
                'Global release/finalization receipt is missing or differs')
        with self.lock:
            require(all(record['phase']=='RELEASED' for record in self.records.values()),
                    'Local root views remain live or uncertain')
            if self.control is not None:
                os.close(self.control);self.control=None;self._save()
        return {'state':'ROOT_CONTROL_RELEASED','run':self.config['run'],'node':self.config['node']}

    def authorize(self,stream):
        pid,uid,_=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        expected,ticks=unit_pid(self.config['agentUnit'],self.config['uid'])
        require(pid==expected and uid==self.config['uid'] and process_ticks(pid)==ticks,'Unexpected local agent peer')

    def _verify_publication(self,pub):
        unsigned={k:v for k,v in pub.items() if k!='ownerSignature'}
        require(hmac.compare_digest(pub['ownerSignature'],proof_mac(self.image_key,unsigned)),'Owner publication signature differs')
        require(pub['run']==self.config['run'] and pub['ownerNode']==self.config['ownerNode'],'Owner/run differs')
        manifest=self.manifests[pub['manifestSha256']];chunk=manifest.chunks[pub['chunkIndex']]
        require(pub['chunkSha256']==chunk.sha256 and pub['payloadBytes']==chunk.length
                and pub['source']=='obmm-host-fsdax' and pub['immutable'] is True,'Chunk publication differs')
        require(pub['image']['bytes']==self.config['imageBytes'],'Image exceeds approved fixed size')
        require(len(pub['generation'])==32 and all(c in '0123456789abcdef' for c in pub['generation']), 'Invalid generation')
        return chunk

    def prepare(self,params):
        pub=params['publication'];chunk=self._verify_publication(pub);generation=pub['generation']
        with self.lock:
            if generation in self.records:
                record=self.records[generation]
                require(record['publication']==pub,'Generation reused for another publication')
                if record['phase']=='READY':return record['ready']
                raise RuntimeError('Existing root attempt must be queried/reconciled, not recreated')
            require(len(self.records)<self.config['maxViews'],'Root view capacity exhausted')
            local=params['source'];contract.validate_spec(local)
            require(all(local[k]==pub['image'][k] for k in ('objectId','generation','sha256','bytes')),
                    'Local SDK source identity differs')
            source_path=Path(local['socket'])
            require(source_path.resolve(strict=True)==source_path
                    and source_path.is_relative_to(Path(self.config['sdkRoot'])),'Unexpected local SDK socket')
            source_info=source_path.stat()
            require(stat.S_ISSOCK(source_info.st_mode) and source_info.st_uid==self.config['uid'],'SDK socket ownership differs')
            sdk_pid,sdk_ticks=unit_pid(self.config['sdkUnit'],self.config['uid'])
            work=self.root/generation;work.mkdir(mode=0o700)
            broker=Path(params['brokerSocket'])
            require(broker.is_relative_to(Path(self.config['brokerRoot'])) and broker.parent.resolve(strict=True)==broker.parent,
                    'Unexpected chunk broker location')
            chunk_replica=stored.Replica(str(broker),pub['objectName'],generation,'sha256:'+chunk.sha256,
                chunk.length,((chunk.length+4096+stored.ALIGN-1)//stored.ALIGN)*stored.ALIGN)
            publication={'version':1,'ownerId':generation,'mode':'pmem','readers':self.config['nodes'],
                         'replicas':[pub['imageReplica']]}
            cfg={'version':1,'workDir':str(work/'view'),'source':local,'ownerUid':self.config['uid'],
                'ownerPid':sdk_pid,'ownerStartTicks':sdk_ticks,'publication':publication,
                'releaseReceipt':str(work/'release.json'),'kernelRelease':self.config['kernelRelease'],
                'moduleSrcversion':self.config['moduleSrcversion'],
                'files':[{'name':'payload.bin','replica':asdict(chunk_replica)}],
                'brokerSocket':str(broker),'brokerGid':self.config['gid'],'runtimeIndex':str(work/'index.json'),
                'payloadResponses':self.config.get('payloadResponses',4)}
            pin=host_pmem_rootfs.plan(cfg)['configSha256'];path=work/'config.json';atomic_json(path,cfg)
            record={'phase':'LAUNCH_INTENT','publication':pub,'configSha256':pin,'config':cfg}
            self.records[generation]=record;self._save()
            log=(work/'helper.log').open('xb')
            try:
                package=str(Path(__file__).resolve().parents[1])
                proc=subprocess.Popen([sys.executable,'-I','-B','-c',BOOTSTRAP,package,'serve','--config',str(path),
                    '--expected-config-sha256',pin,'--approval','CREATE_READONLY_ROOTFS_HOST_PMEM'],
                    stdin=subprocess.DEVNULL,stdout=log,stderr=log,close_fds=True)
            finally:log.close()
            self.processes[generation]=proc
            record.update(phase='STARTED',pid=proc.pid,startTicks=process_ticks(proc.pid));self._save()
        deadline=time.monotonic()+300
        while time.monotonic()<deadline:
            if proc.poll() is not None:raise RuntimeError('Root helper exited; preserve exact journal for reconciliation')
            journal=work/'view/host-pmem-session.json'
            if journal.exists():
                data=json.loads(journal.read_text())
                if data['phase']=='rootfs_broker_ready':
                    origins=region_provenance.collect(proc.pid,record['startTicks'],data['volume']['segments'],pub['objectName'])
                    status=host_pmem_cli.request_action(cfg,pin,'status')
                    require(status['state']=='rootfs_broker_ready','Root helper state changed')
                    ready={'state':'VIEW_READY','run':self.config['run'],'node':self.config['node'],
                        'objectName':pub['objectName'],'generation':generation,'replica':asdict(chunk_replica),
                        'configSha256':pin,'helperPid':proc.pid,'helperStartTicks':record['startTicks'],
                        'volume':status['volume'],'files':data['rootfsBroker']['fileEvidence'],
                        'origin':origins,'engine':self.engine}
                    with self.lock:record.update(phase='READY',ready=ready);self._save()
                    return ready
                if data['phase'] in ('stopped_preserve_resources','retirement_stopped_preserve_resources') or 'rootfsFailure' in data:
                    raise RuntimeError('Root view startup failed; resources preserved')
            time.sleep(0.05)
        raise TimeoutError('Root view readiness unknown; query same generation, never create a replacement')

    def retire(self,pub):
        generation=pub['generation'];self._verify_publication(pub)
        with self.lock:
            record=self.records[generation]
            require(record['publication']==pub,'Wrong root publication')
            if record['phase']=='RELEASED':return record['receipt']
            require(record['phase']=='READY','Root startup/retirement outcome unknown; explicit reconciliation required')
            proc=self.processes[generation]
            require(proc.poll() is None and process_ticks(proc.pid)==record['startTicks'],'Root helper identity changed')
            record['phase']='RETIRE_INTENT';self._save()
        result=host_pmem_cli.request_action(record['config'],record['configSha256'],'retire')
        require(result['state'] in ('local_resources_released','released'),'Root view did not retire')
        require(proc.wait(timeout=15)==0,'Root helper exit not confirmed')
        body={'version':1,'run':self.config['run'],'node':self.config['node'],'objectName':pub['objectName'],
              'generation':generation,'localVolumeAbsent':True,'workerExited':True}
        receipt={'body':body,'mac':proof_mac(self.receipt_key,body)}
        with self.lock:record.update(phase='RELEASED',receipt=receipt);self._save()
        return receipt

    def dispatch(self,request):
        require(request.get('run')==self.config['run'],'Wrong root scope')
        if request['method']=='readiness':return self.readiness()
        if request['method']=='release-control':return self.release_control(request['params']['receipt'])
        if request['method']=='prepare':return self.prepare(request['params'])
        if request['method']=='retire':return self.retire(request['params']['publication'])
        if request['method']=='status':
            generation=request['params'].get('generation')
            with self.lock:
                return self.records.get(generation,{'phase':'NONE'}) if generation else {
                    'run':self.config['run'],'state':'SERVING' if self.control is not None else 'ROOT_CONTROL_RELEASED'}
        raise ValueError('Unsupported root operation')

    def serve(self,path):
        path=Path(path);require(not path.exists() and not path.is_symlink(),'Existing root socket preserved')
        parent=path.parent
        if not parent.exists():
            above=parent.parent.stat()
            require(parent.parent.resolve(strict=True)==parent.parent and above.st_uid==0
                    and not above.st_mode&0o022,'Unsafe root socket parent')
            parent.mkdir(mode=0o750);os.chown(parent,0,self.config['gid'])
        info=parent.lstat()
        require(parent.resolve(strict=True)==parent and info.st_uid==0 and stat.S_ISDIR(info.st_mode)
                and not info.st_mode&0o022,'Root socket directory is not protected')
        server=socket.socket(socket.AF_UNIX);server.bind(str(path));os.chown(path,0,self.config['gid']);os.chmod(path,0o660);server.listen(16)
        def connection(stream):
            with stream:
                try:
                    stream.settimeout(330);self.authorize(stream);result=self.dispatch(contract.receive_json(stream))
                    reply={'ok':True,'result':result}
                except Exception as error:reply={'ok':False,'reason':str(error)}
                try:contract.send_json(stream,reply)
                except OSError:pass
        while True:
            stream,_=server.accept();threading.Thread(target=connection,args=(stream,),daemon=True).start()


class RootClient:
    def __init__(self,path,run):self.path,self.run=path,run
    def call(self,method,params):
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(330);stream.connect(self.path)
            _,uid,_=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(uid==0,'Unexpected root supervisor peer')
            contract.send_json(stream,{'run':self.run,'method':method,'params':params})
            result=contract.receive_json(stream)
            require(result.get('ok') is True,result.get('reason','Root operation failed'))
            return result['result']


class ChunkBrokerView:
    def __init__(self,ready,uid):
        require(ready['state']=='VIEW_READY' and ready['files']
                and all(f['activeDax'] and f['readonlyMount'] for f in ready['files']),'No verified root DAX evidence')
        self.ready=ready;self.replica=stored.Replica(**ready['replica']).validate();self.lock=threading.Lock()
        stream=socket.socket(socket.AF_UNIX);self.stream=stream;self.healthy=True
        try:
            stream.settimeout(300);stream.connect(self.replica.brokerSocket)
            _,peer_uid,_=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(peer_uid==uid,'Unexpected ordinary chunk broker UID')
            r=self.replica
            packet=stored.MAGIC+struct.pack('>H',37)+r.objectName.encode()+bytes.fromhex(r.generation)
            packet+=struct.pack('>QQ',r.fileBytes,r.mappingBytes)+bytes.fromhex(r.layerDigest[7:])
            stream.sendall(packet);self._response(0)
        except BaseException:stream.close();raise
    def _response(self,count):
        magic,status,actual=stored.RESPONSE.unpack(stored.recv_exact(self.stream,stored.RESPONSE.size))
        require(magic==stored.MAGIC and status==0 and actual==count,'Chunk broker response differs')
    def read(self,offset,count):
        require(type(offset) is int and type(count) is int and 0<=offset<=self.replica.fileBytes
                and 0<count<=min(stored.CHUNK,self.replica.fileBytes-offset),'Invalid bounded chunk read')
        with self.lock:
            require(self.healthy,'Chunk session failed; no implicit reconnect')
            try:
                self.stream.sendall(struct.pack('>QI',offset,count));self._response(count)
                return stored.recv_exact(self.stream,count)
            except BaseException:self.healthy=False;raise
    def close(self):self.stream.close()
