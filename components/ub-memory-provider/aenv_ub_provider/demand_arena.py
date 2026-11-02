"""Production SDK arena ownership and authenticated global unit directory.

An arena is a mutable-unpublished / immutable-published slot container, NOT a
whole immutable image. Never run RawImages.verify_mapping on an arena. SDK
operations remain in this ordinary-user process; root owns controlled writes.
"""
import array
import hashlib
import hmac
import os
from pathlib import Path
import socket
import struct
import threading
import types
import uuid

from . import contract, raw, host_dax_worker
from .demand_control import proof_mac
from .demand_views import RootClient, unit_pid
from .demand_wire import LOAD_BYTES, DEVICE_BYTES
from .host_dax_demand import require
from .io import atomic_json


class ArenaSdk:
    def __init__(self, config, key):
        self.config,self.key=config,key
        self.root=Path(config['stateRoot']);self.root.mkdir(mode=0o700,exist_ok=False)
        require(os.getuid()==os.geteuid()==config['uid']!=0,'SDK must run as its ordinary owner')
        require(hashlib.sha256(Path(config['adapter']).read_bytes()).hexdigest()==config['adapterSha256'],
                'SDK adapter differs')
        self.records={};self.live={};self.backend=None;self.init_attempt=False
        self.finalize_attempt=False;self.finalized=False;self.lock=threading.RLock()
        self.poisoned=False
        self.socket_ready=threading.Event()
        self.persist()

    def persist(self):
        try:
            atomic_json(self.root/'sdk.json',{'run':self.config['run'],'node':self.config['node'],
                'initializeAttempted':self.init_attempt,'finalizeAttempted':self.finalize_attempt,
                'finalizeAcknowledged':self.finalized,'pools':self.records,
                'physicalIncrementBytes':None,'physicalHardQuota':False})
        except BaseException:self.poisoned=True;raise

    def initialize(self):
        require(not self.poisoned and not self.finalize_attempt and not self.finalized,'SDK uncertain or closing')
        if self.backend is not None:return
        require(not self.init_attempt,'Unknown initialization; preserve, no retry')
        self.init_attempt=True;self.persist()
        backend=raw.NativeRawBackend(self.config['adapter'],self.config['coverageLimitBytes'])
        backend.configure_region(self.config['region']);backend.initialize();self.backend=backend

    def verify(self, descriptor):
        body={k:v for k,v in descriptor.items() if k!='signature'}
        require(hmac.compare_digest(descriptor['signature'],proof_mac(self.key,body))
                and body.get('kind')=='stable-arena-v1'
                and body['run']==self.config['run'] and body['ownerNode']==self.config['ownerNode']
                and body['bytes']==self.config['poolBytes'],'Arena publication differs')
        require(str(uuid.UUID(body['poolUuid']))==body['poolUuid'],'Invalid arena UUID')
        require(body['objectName']=='aenv_'+uuid.UUID(body['poolUuid']).hex,'Arena object name differs')
        return body

    def create(self, pool_uuid):
        require(self.config['node']==self.config['ownerNode'],'Only owner allocates')
        body={'kind':'stable-arena-v1','run':self.config['run'],'ownerNode':self.config['ownerNode'],'poolUuid':pool_uuid,
              'objectName':'aenv_'+uuid.UUID(pool_uuid).hex,'bytes':self.config['poolBytes']}
        descriptor={**body,'signature':proof_mac(self.key,body)}
        self.attach(descriptor,allocate=True)
        return descriptor

    def attach(self, descriptor, *, allocate=False):
        body=self.verify(descriptor);pool=body['poolUuid']
        with self.lock:
            require(not self.poisoned,'SDK journal uncertain; no new operations')
            if pool in self.records:
                r=self.records[pool]
                require(r['descriptor']==descriptor and r['phase']=='READY','Existing SDK outcome unresolved')
                return self.describe(pool)
            require(allocate == (self.config['node']==self.config['ownerNode']),
                    'Owner must allocate; importer must only map existing publication')
            require(sum(r['descriptor']['bytes'] for r in self.records.values())+body['bytes']
                    <=self.config['logicalBudgetBytes'],'Arena logical budget exhausted')
            r={'descriptor':descriptor,'phase':'INITIALIZE','allocationOwner':allocate};self.records[pool]=r;self.persist()
            self.initialize()
            api=types.SimpleNamespace(objectName=body['objectName'],mappingBytes=body['bytes'])
            if allocate:
                r['phase']='ALLOCATE_INTENT';self.persist();self.backend.allocate(api)
                r['phase']='ALLOCATED';self.persist()
            r['phase']='MAP_INTENT';self.persist()
            mapping=self.backend.map(api,False)  # No ordinary writable mapping, even for the owner.
            self.live[pool]={'mapping':mapping,'fds':[],'api':api}
            r.update(phase='MAPPED',coverageBytes=mapping.backing_coverage);self.persist()
            segments=self.backend.open_segments(mapping,body['bytes'])
            self.live[pool]['fds']=segments
            require(all(n%LOAD_BYTES==0 for _,n in segments),'Arena segments not slot aligned')
            r.update(phase='READY',lengths=[n for _,n in segments]);self.persist()
            return self.describe(pool)

    def describe(self, pool):
        require(not self.poisoned,'SDK journal uncertain; cannot hand off FDs')
        r=self.records[pool];require(r['phase']=='READY','Arena is not a confirmed readonly SDK anchor')
        return {'descriptor':r['descriptor'],'lengths':r['lengths'],'coverageBytes':r['coverageBytes'],
                'physicalIncrementBytes':None}

    def release_imports(self):
        require(self.config['node']!=self.config['ownerNode'],'Owner anchors require global finish')
        with self.lock:
            require(not self.poisoned,'SDK journal uncertain; retain imports')
            for pool,r in self.records.items():
                if r['phase']=='UNMAPPED':continue
                require(r['phase']=='READY','Uncertain import cannot be retired automatically')
                r['phase']='UNMAP_INTENT';self.persist();live=self.live[pool]
                for fd,_ in live['fds']:os.close(fd)
                live['fds']=[];live['mapping'].close()
                r['phase']='UNMAPPED';self.persist()
            return self.finalize()

    def finish_owner(self):
        require(self.config['node']==self.config['ownerNode'],'Not allocation owner')
        with self.lock:
            require(not self.poisoned,'SDK journal uncertain; retain owner objects')
            for pool,r in self.records.items():
                if r['phase']=='FREED':continue
                require(r['phase']=='READY','Unknown delete/unmap cannot be repeated')
                live=self.live[pool];r['phase']='UNMAP_INTENT';self.persist()
                for fd,_ in live['fds']:os.close(fd)
                live['fds']=[];live['mapping'].close()
                r['phase']='DELETE_INTENT';self.persist();self.backend.deallocate(live['api'])
                r['phase']='FREED';self.persist()
            return self.finalize()

    def finalize(self):
        if self.finalized:return {'finalizeAcknowledged':True}
        require(not self.poisoned and (not self.init_attempt or self.backend is not None),
                'Initialization/journal outcome uncertain; do not invent finalization')
        require(not self.finalize_attempt,'Unknown finalize; preserve')
        self.finalize_attempt=True;self.persist()
        if self.backend is not None:self.backend.finalize()
        self.finalized=True;self.persist();return {'finalizeAcknowledged':True}

    def serve(self):
        path=Path(self.config['sdkSocket']);require(not path.exists(),'Existing SDK socket preserved')
        require(path.parent.resolve()==path.parent and path.parent.stat().st_uid==os.geteuid()
                and not path.parent.stat().st_mode&0o077,'SDK socket needs private owned parent')
        listener=socket.socket(socket.AF_UNIX);listener.bind(str(path));os.chmod(path,0o600);listener.listen(8)
        self.socket_ready.set()
        def handle(stream):
            with stream:
                try:
                    stream.settimeout(30)
                    pid,uid,_=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    expected,_=unit_pid(self.config['rootUnit'],0)
                    require(uid==0 and pid==expected,'Only configured root service may borrow arena FDs')
                    request=host_dax_worker.receive(stream)
                    require(request['run']==self.config['run'],'Wrong arena run')
                    if request['method']=='status':
                        contract.send_json(stream,{'ok':True,'result':{'state':'PRESERVE' if self.poisoned else 'READY','node':self.config['node'],
                            'run':self.config['run'],'finalized':self.finalized,'SDKInitialized':self.backend is not None,
                            'pools':{pool:r['phase'] for pool,r in self.records.items()}}})
                    elif request['method']=='initialize':
                        with self.lock:self.initialize()
                        contract.send_json(stream,{'ok':True,'result':{'state':'INITIALIZED'}})
                    elif request['method']=='attach':
                        descriptor=request['descriptor']
                        if self.config['node']==self.config['ownerNode']:
                            self.verify(descriptor);result=self.describe(descriptor['poolUuid'])
                            require(result['descriptor']==descriptor,'Owner arena identity differs')
                        else:result=self.attach(descriptor)
                        contract.send_json(stream,{'ok':True,'result':result})
                        fds=[fd for fd,_ in self.live[descriptor['poolUuid']]['fds']]
                        stream.sendmsg([b'F'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))])
                    elif request['method']=='release-imports':
                        contract.send_json(stream,{'ok':True,'result':self.release_imports()})
                    elif request['method']=='publish-index':
                        index=request['descriptor']
                        require(index['version']==3 and index['mode']=='host-dax-stable-demand'
                                and index['state']=='metadata_ready','Stable index required')
                        from .demand_wire import Layer
                        rows=[Layer(**row).validate() for row in index['replicas']]
                        require(rows and all(row.generation==self.config['run'] and row.stablePmem is not None
                                             for row in rows),'Index epoch differs')
                        target=Path(self.config['indexPath'])
                        require(target.parent.resolve()==target.parent and target.parent.stat().st_uid==os.geteuid()
                                and not target.parent.stat().st_mode&0o077 and not target.exists(),
                                'New private ordinary-user index required')
                        atomic_json(target,index)
                        contract.send_json(stream,{'ok':True,'result':{'indexPath':str(target)}})
                    else:raise ValueError('Unsupported SDK operation')
                except Exception as error:
                    try:contract.send_json(stream,{'ok':False,'reason':str(error)})
                    except OSError:pass
        while True:
            stream,_=listener.accept();threading.Thread(target=handle,args=(stream,),daemon=True).start()


class ArenaDirectory:
    """One immutable image, append-only slot assignment; no per-unit SDK deletion."""
    def __init__(self, config, manifest, sdk, key, receipt_keys):
        self.config,self.manifest,self.sdk,self.key,self.receipt_keys=config,manifest,sdk,key,receipt_keys
        self.root=Path(config['stateRoot'])/'directory';self.root.mkdir(mode=0o700,exist_ok=False)
        self.lock=threading.RLock();self.pools=[];self.units={};self.operations={};self.ready={};self.drained={}
        self.closed=False;self.released=None;self.poisoned=False
        self.owner=RootClient(config['rootSocket'],config['run']);self.save()

    def save(self):
        try:
            atomic_json(self.root/'directory.json',{'run':self.config['run'],'pools':self.pools,'units':self.units,
                'operations':self.operations,'ready':self.ready,'drained':self.drained,
                'closed':self.closed,'released':self.released,'physicalIncrementBytes':None})
        except BaseException:self.poisoned=True;self.closed=True;raise

    def acquire(self,node,operation,index):
        key=node+':'+operation
        with self.lock:
            require(not self.poisoned,'Directory journal uncertain; preserve all objects')
            if key in self.operations:
                require(self.operations[key]['index']==index,'Operation reused for different unit')
                return dict(self.operations[key])
            require(not self.closed and not self.drained and set(self.ready)==set(self.config['nodes']),
                    'Both roots must be ready; no new allocations after closing/draining')
            require(type(index)is int and 0<=index<len(self.manifest.chunks),'Invalid image unit')
            op={'state':'PENDING','index':index};self.operations[key]=op;self.save()
            try:
                unit=self.units.get(str(index))
                if unit is None:
                    chunk=self.manifest.chunks[index]
                    if not self.pools or self.pools[-1]['used']==self.config['poolBytes']//LOAD_BYTES:
                        pool={'poolUuid':str(uuid.uuid4()),'phase':'CREATE_INTENT','used':0};self.pools.append(pool);self.save()
                        pool['descriptor']=self.sdk.create(pool['poolUuid']);pool['phase']='ROOT_INTENT';self.save()
                        origin=self.owner.call('arena-attach',{'descriptor':pool['descriptor']})
                        require(isinstance(origin.get('originFingerprint'),str) and len(origin['originFingerprint'])==64,
                                'Owner origin mapping evidence missing')
                        pool['originFingerprint']=origin['originFingerprint']
                        pool['phase']='READY';self.save()
                    pool=self.pools[-1];require(pool['phase']=='READY','Unknown arena creation preserved')
                    slot=pool['used']*LOAD_BYTES;pool['used']+=1
                    unit={'index':index,'offset':chunk.offset,'bytes':chunk.length,'sha256':chunk.sha256,
                          'pool':pool['descriptor'],'originFingerprint':pool['originFingerprint'],
                          'slotOffset':slot,'phase':'FILL_INTENT','nodes':[]}
                    self.units[str(index)]=unit;self.save()
                    self.owner.call('arena-fill',{'poolUuid':pool['poolUuid'],'slotOffset':slot,'unit':index})
                    unit['phase']='READY';self.save()
                require(unit['phase']=='READY','Uncertain unit must not be refilled')
                if node not in unit['nodes']:unit['nodes'].append(node)
                body={k:v for k,v in unit.items() if k not in ('phase','nodes')}
                body.update(kind='stable-unit-v1',run=self.config['run'],manifestSha256=self.manifest.sha256)
                op.update(state='READY',result={**body,'signature':proof_mac(self.key,body)})
                self.save();return dict(op)
            except Exception as error:
                self.closed=True;op.update(state='UNCERTAIN',reason=str(error));self.save();raise

    def dispatch(self,node,request):
        require(node in self.config['nodes'] and request['run']==self.config['run'],'Wrong control identity')
        operation=request['operation'];require(isinstance(operation,str) and len(operation)==32
                    and all(c in '0123456789abcdef' for c in operation),'Invalid operation ID')
        method=request['method'];params=request.get('params',{})
        if method=='acquire':
            require(params['manifest']==self.manifest.sha256,'Wrong image manifest')
            return self.acquire(node,operation,params['chunk'])
        with self.lock:
            if method=='query':return dict(self.operations[node+':'+operation])
            if method in ('ready','node-drained'):
                proof=params['receipt'];body=proof['body']
                require(hmac.compare_digest(proof['mac'],proof_mac(self.receipt_keys[node],body))
                        and body['run']==self.config['run'] and body['node']==node
                        and body['kind']==('stable-root-ready' if method=='ready' else 'stable-root-drained'),
                        'Root receipt differs')
                if method=='ready':
                    require(not self.closed and not self.drained,'Admission already closed')
                    require(body['writerEnabled']==(node==self.config['ownerNode']),'Root pool role differs')
                    require(body['manifestSha256']==self.manifest.sha256 and body['logicalBytes']==DEVICE_BYTES,
                            'Root image/geometry differs')
                    if node in self.ready:require(self.ready[node]==proof,'Root identity changed in live epoch')
                    self.ready[node]=proof
                else:
                    require(self.closed and body['localDeviceAbsent'] and body['localPoolsAbsent']
                            and body['sdkDisposition']==('owner_anchor_retained' if node==self.config['ownerNode']
                                                        else 'importer_finalized'),'Incomplete drain receipt')
                    expected=({p['poolUuid'] for p in self.pools} if node==self.config['ownerNode']
                              else {u['pool']['poolUuid'] for u in self.units.values() if node in u['nodes']})
                    require(expected==set(body['pools']),'Drain receipt does not cover expected arenas')
                    if node in self.drained:require(self.drained[node]==proof,'Changed drain receipt')
                    self.drained[node]=proof
                self.save();return {'state':'READY' if method=='ready' else 'DRAINED'}
            if method=='status':
                return {'state':'CLOSED' if self.closed else 'SERVING','readyNodes':sorted(self.ready),
                        'requiredNodes':self.config['nodes'],'units':len(self.units),'pools':len(self.pools),
                        'drainedNodes':sorted(self.drained),'globalReleaseReceipt':self.released,
                        'logicalPoolBytes':len(self.pools)*self.config['poolBytes'],'physicalIncrementBytes':None}
            if method=='halt':
                self.closed=True;self.save();return {'state':'CLOSED'}
            require(node==self.config['ownerNode'],'Owner-only control')
            if method=='close-admission':self.closed=True;self.save();return {'state':'CLOSED'}
            if method=='finish':
                require(not self.poisoned,'Directory journal uncertain; do not release')
                require(self.closed and set(self.drained)==set(self.config['nodes']), 'Both nodes must drain before global release')
                # With both explicit local retirements confirmed, failed data
                # publication does not prevent releasing a confirmed allocation.
                # SDK allocation/map uncertainty still does: describe refuses it.
                for pool in self.pools:
                    known=self.sdk.describe(pool['poolUuid']) if self.released is None else None
                    if known is not None:
                        require(known['descriptor']['poolUuid']==pool['poolUuid'],'Pool release identity differs')
                if self.released is None:
                    self.sdk.finish_owner()
                    body={'kind':'stable-global-released','run':self.config['run'],'globalObjectsReleased':True,
                          'ownerFinalizationAcknowledged':True}
                    self.released={'body':body,'mac':proof_mac(self.key,body)};self.save()
                return {'state':'RELEASED','receipt':self.released}
            raise ValueError('Unsupported stable control method')
