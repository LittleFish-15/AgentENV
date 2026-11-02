"""Production arena lifecycle/directory tests with explicit SDK/root doubles.
No native allocation, DAX mapping, physical-sharing or savings acceptance.
"""
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import types
import unittest
import uuid
from unittest import mock

from aenv_ub_provider import demand_arena as a
from aenv_ub_provider.host_dax_demand import Manifest,canonical

KEY=b'k'*32


class ArenaSdkTests(unittest.TestCase):
    def make(self,directory,node='a',allocate_error=False):
        root=Path(directory);library=root/'adapter';library.write_bytes(b'test adapter')
        events=[]
        class Mapping:
            backing_coverage=128*1024**2
            def close(self):events.append('unmap')
            def read(self,*args):raise AssertionError('full arena read is forbidden')
        class Backend:
            def configure_region(self,r):events.append('configure')
            def initialize(self):events.append('initialize')
            def allocate(self,r):
                events.append('allocate')
                if allocate_error:raise OSError('unknown allocate response')
            def map(self,r,writable):
                if writable:raise AssertionError('ordinary writable mapping forbidden')
                events.append('map_readonly');return Mapping()
            def open_segments(self,m,n):events.append('open_fds');return [(9876,n)]
            def deallocate(self,r):events.append('delete')
            def finalize(self):events.append('finalize')
        config={'node':node,'ownerNode':'a','run':'a'*32,'uid':1204,'stateRoot':str(root/'sdk'),
                'adapter':str(library),'adapterSha256':hashlib.sha256(b'test adapter').hexdigest(),
                'poolBytes':128*1024**2,'logicalBudgetBytes':256*1024**2,
                'coverageLimitBytes':512*1024**2,'region':'default'}
        proxy=types.SimpleNamespace(getuid=lambda:1204,geteuid=lambda:1204,close=lambda fd:events.append('close_fd'))
        patches=[mock.patch.object(a,'os',proxy),mock.patch.object(a.raw,'NativeRawBackend',return_value=Backend())]
        for p in patches:p.start();self.addCleanup(p.stop)
        return a.ArenaSdk(config,KEY),events

    def test_owner_allocates_once_and_never_reads_entire_pool(self):
        with tempfile.TemporaryDirectory() as d:
            sdk,events=self.make(d);pool=str(uuid.uuid4())
            pub=sdk.create(pool);self.assertEqual(sdk.create(pool),pub)
            self.assertEqual(events.count('allocate'),1)
            self.assertEqual(events.count('map_readonly'),1)
            sdk.finish_owner();sdk.finish_owner()
            self.assertEqual(events.count('delete'),1)
            self.assertEqual(events.count('finalize'),1)

    def test_unknown_allocation_is_not_retried(self):
        with tempfile.TemporaryDirectory() as d:
            sdk,events=self.make(d,allocate_error=True);pool=str(uuid.uuid4())
            with self.assertRaises(OSError):sdk.create(pool)
            with self.assertRaises(ValueError):sdk.create(pool)
            self.assertEqual(events.count('allocate'),1)
            self.assertNotIn('delete',events)

    def test_importer_never_allocates_and_waits_for_explicit_retirement(self):
        with tempfile.TemporaryDirectory() as d:
            sdk,events=self.make(d,node='b');pool=str(uuid.uuid4())
            body={'kind':'stable-arena-v1','run':'a'*32,'ownerNode':'a','poolUuid':pool,'objectName':'aenv_'+uuid.UUID(pool).hex,'bytes':128*1024**2}
            pub={**body,'signature':a.proof_mac(KEY,body)}
            sdk.attach(pub);sdk.attach(pub)
            self.assertNotIn('allocate',events);self.assertNotIn('unmap',events)
            sdk.release_imports();sdk.release_imports()
            self.assertEqual(events.count('unmap'),1);self.assertEqual(events.count('finalize'),1)


class DirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.calls=[];self.deleted=0
        document={'version':1,'layerDigest':'sha256:'+'a'*64,'fileBytes':3*a.LOAD_BYTES,
                  'chunkBytes':a.LOAD_BYTES,'chunks':[{'index':i,'offset':i*a.LOAD_BYTES,'length':a.LOAD_BYTES,
                  'sha256':str(i+1)*64} for i in range(3)]}
        self.manifest=Manifest(document,hashlib.sha256(canonical(document)).hexdigest())
        config={'stateRoot':self.temp.name,'run':'a'*32,'nodes':['a','b'],'node':'a','ownerNode':'a',
                'poolBytes':128*1024**2,'rootSocket':'unused'}
        outer=self
        class Sdk:
            def create(self,pool):outer.calls.append(('allocate',pool));return {'poolUuid':pool,'bytes':128*1024**2}
            def describe(self,pool):return {'descriptor':{'poolUuid':pool}}
            def finish_owner(self):outer.deleted+=1
        class Root:
            def call(self,m,p):outer.calls.append((m,p));return {'state':'ok','originFingerprint':'f'*64}
        patch=mock.patch.object(a,'RootClient',return_value=Root());patch.start();self.addCleanup(patch.stop)
        self.directory=a.ArenaDirectory(config,self.manifest,Sdk(),KEY,{'a':KEY,'b':KEY})

    def request(self,node,method,params=None,operation=None):
        return self.directory.dispatch(node,{'run':'a'*32,'method':method,'params':params or {},
                                             'operation':operation or uuid.uuid4().hex})

    def ready(self,node):
        body={'run':'a'*32,'node':node,'kind':'stable-root-ready','writerEnabled':node=='a',
              'manifestSha256':self.manifest.sha256,'logicalBytes':a.DEVICE_BYTES}
        self.request(node,'ready',{'receipt':{'body':body,'mac':a.proof_mac(KEY,body)}})

    def test_both_ready_gate_and_same_unit_cross_node_reuse(self):
        self.ready('a')
        with self.assertRaises(ValueError):self.directory.acquire('a',uuid.uuid4().hex,0)
        self.assertEqual(self.calls,[]);self.ready('b')
        results=[]
        threads=[threading.Thread(target=lambda n=n:results.append(self.directory.acquire(n,uuid.uuid4().hex,0))) for n in ('a','b')]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(len(results),2)
        self.assertEqual(results[0]['result'],results[1]['result'])
        self.directory.acquire('b',uuid.uuid4().hex,1)
        self.assertEqual(sum(c[0]=='allocate' for c in self.calls),1)
        self.assertEqual(sum(c[0]=='arena-fill' for c in self.calls),2)

    def test_global_release_needs_both_complete_pool_receipts(self):
        self.ready('a');self.ready('b');result=self.directory.acquire('b',uuid.uuid4().hex,0)
        pool=result['result']['pool']['poolUuid']
        with self.assertRaises(ValueError):self.request('a','finish')
        self.request('a','close-admission')
        for node in ('a','b'):
            body={'kind':'stable-root-drained','run':'a'*32,'node':node,'localDeviceAbsent':True,
                  'localPoolsAbsent':True,'pools':[pool],
                  'sdkDisposition':'owner_anchor_retained' if node=='a' else 'importer_finalized'}
            self.request(node,'node-drained',{'receipt':{'body':body,'mac':a.proof_mac(KEY,body)}})
            if node=='a':
                with self.assertRaises(ValueError):self.request('a','finish')
        self.request('a','finish');self.request('a','finish');self.assertEqual(self.deleted,1)

    def test_fill_failure_closes_admission_without_retrying_sdk(self):
        self.ready('a');self.ready('b')
        self.directory.owner.call=mock.Mock(side_effect=OSError('lost root reply'))
        operation=uuid.uuid4().hex
        with self.assertRaises(OSError):self.directory.acquire('a',operation,0)
        self.assertEqual(self.request('a','query',operation=operation)['state'],'UNCERTAIN')
        with self.assertRaises(ValueError):self.directory.acquire('b',uuid.uuid4().hex,1)
        self.assertEqual(sum(c[0]=='allocate' for c in self.calls),1);self.assertEqual(self.deleted,0)


class RootDirectoryIntegration(unittest.TestCase):
    def test_root_retirement_order_and_ack_retry(self):
        from aenv_ub_provider.demand_stable import StableRoot
        with tempfile.TemporaryDirectory() as d:
            events=[];root=StableRoot.__new__(StableRoot)
            root.config={'run':'a'*32,'node':'b'};root.receipt_key=KEY;root.writer=False
            root.work=Path(d);root.lock=threading.RLock();root.stop_event=threading.Event();root.miss_thread=None
            root.volume_uuid='volume';root.fdsets={'pool':[]}
            root.record={'phase':'SERVING','fatal':None,'pools':{'pool':{'phase':'READY',
                'segments':[{'uuid':'segment','phase':'READY'}]}},'units':{}}
            root.worker=mock.Mock(retired=False,record={'state':'serving'})
            root.worker.retire.side_effect=lambda:events.append('broker_exit')
            root.mount=mock.Mock();root.mount.state={'phase':'mounted'}
            root.mount.unmount.side_effect=lambda:events.append('unmount')
            root.control=mock.Mock();root.control.destroy.side_effect=lambda v:events.append('device_destroy')
            root.control.destroy_pool.side_effect=lambda p:events.append('pool_destroy')
            def sdk(method):
                if method=='status':return {'state':'READY','run':'a'*32,'pools':{'pool':'READY'}}
                events.append('sdk_unmap_finalize');return {'finalizeAcknowledged':True}
            root.sdk_call=sdk
            def coordinator(method,*args):
                if method=='status':return {'state':'CLOSED'}
                events.append('drained_ack');return {'state':'DRAINED'}
            root.coordinator=mock.Mock();root.coordinator.call.side_effect=coordinator
            root.drain();root.drain()
            self.assertEqual(events,['broker_exit','unmount','device_destroy','pool_destroy',
                                     'sdk_unmap_finalize','drained_ack','drained_ack'])

    def test_busy_broker_keeps_volume_and_sdk_alive(self):
        from aenv_ub_provider.demand_stable import StableRoot
        with tempfile.TemporaryDirectory() as d:
            root=StableRoot.__new__(StableRoot);root.work=Path(d);root.lock=threading.RLock()
            root.record={'phase':'SERVING','fatal':None};root.worker=mock.Mock(retired=False)
            root.worker.record={'state':'busy_preserve_mount'}
            root.worker.retire.side_effect=RuntimeError('readers remain')
            root.coordinator=mock.Mock();root.coordinator.call.return_value={'state':'CLOSED'}
            root.control=mock.Mock();root.sdk_call=mock.Mock()
            with self.assertRaises(RuntimeError):root.drain()
            self.assertEqual(root.record['phase'],'SERVING')
            root.control.destroy.assert_not_called();root.sdk_call.assert_not_called()

    def test_production_miss_loops_share_pool_and_only_load_requested_units(self):
        from collections import deque
        import time
        from aenv_ub_provider import demand_stable as s, host_pmem
        data=b'A'*a.LOAD_BYTES+b'B'*a.LOAD_BYTES+b'C'*a.LOAD_BYTES
        doc={'version':1,'layerDigest':'sha256:'+hashlib.sha256(data).hexdigest(),'fileBytes':len(data),
             'chunkBytes':a.LOAD_BYTES,'chunks':[{'index':i,'offset':i*a.LOAD_BYTES,'length':a.LOAD_BYTES,
              'sha256':hashlib.sha256(data[i*a.LOAD_BYTES:(i+1)*a.LOAD_BYTES]).hexdigest()} for i in range(3)]}
        manifest=Manifest(doc,hashlib.sha256(canonical(doc)).hexdigest())
        shared={};allocations=[];reads=[];fds=[];owner=[]
        class Source:
            def __init__(self,*args):pass
            def read(self,offset,count):reads.append((offset,count));return data[offset:offset+count]
            def close(self):pass
        class Sdk:
            def create(self,pool):
                allocations.append(pool)
                body={'kind':'stable-arena-v1','run':'a'*32,'ownerNode':'a','poolUuid':pool,'objectName':'aenv_'+uuid.UUID(pool).hex,'bytes':128*1024**2}
                return {**body,'signature':a.proof_mac(KEY,body)}
        class OwnerRpc:
            def call(self,method,params):
                if method=='arena-attach':return owner[0].attach_pool(params['descriptor'])
                return owner[0].fill(params['poolUuid'],params['slotOffset'],params['unit'])
        class Control:
            def __init__(self):self.pending=deque([0]);self.bound={}
            def claim_miss(self,volume):
                return {'logicalOffset':self.pending.popleft()*a.LOAD_BYTES,'bytes':a.LOAD_BYTES} if self.pending else None
            def create_pool(self,uid,segment,writer):pass
            def fill_slot(self,uid,offset,payload,digest):
                assert hashlib.sha256(payload).hexdigest()==digest
                assert (uid,offset) not in shared
                shared[(uid,offset)]=payload
            def query_slot(self,uid,offset):
                payload=shared[(uid,offset)]
                return {'state':'ready','bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
            def accept_slot(self,uid,offset,size,digest):
                payload=shared[(uid,offset)];assert len(payload)==size and hashlib.sha256(payload).hexdigest()==digest
            def bind_slot(self,volume,logical,uid,offset,digest):
                assert hashlib.sha256(shared[(uid,offset)]).hexdigest()==digest
                self.bound[logical]=(uid,offset)
            def fail_miss(self,*args):pass
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(a,'RootClient',return_value=OwnerRpc()), \
             mock.patch.object(s,'DirectSource',Source), \
             mock.patch.object(s,'os',types.SimpleNamespace(getpid=os.getpid,fstat=lambda fd:types.SimpleNamespace(st_rdev=1))), \
             mock.patch.object(s.region_provenance,'collect',side_effect=lambda pid,ticks,segments,name:
                 [{'origin':{'exportNodeId':'test-double','exportMemId':int(hashlib.sha256(name.encode()).hexdigest()[:8],16)},
                   'ranges':segments}]), \
             mock.patch.object(s.host_pmem_lease,'process_ticks',return_value='1'):
            config={'stateRoot':directory,'run':'a'*32,'nodes':['a','b'],'ownerNode':'a',
                    'poolBytes':128*1024**2,'rootSocket':'unused'}
            directory_state=a.ArenaDirectory(config,manifest,Sdk(),KEY,{'a':KEY,'b':KEY})
            roots=[]
            for node in ('a','b'):
                root=s.StableRoot.__new__(s.StableRoot)
                root.config={**config,'node':node,'sourceImage':'test-double'};root.manifest=manifest
                root.writer=node=='a';root.image_key=KEY;root.receipt_key=KEY;root.volume_uuid=str(uuid.uuid4())
                root.work=Path(directory)/node;root.work.mkdir()
                root.record={'phase':'SERVING','fatal':None,'pools':{},'units':{}}
                root.lock=threading.RLock();root.stop_event=threading.Event();root.fdsets={};root.control=Control()
                class Client:
                    def __init__(self,node):self.node=node
                    def acquire(self,operation,m,index,deadline):return directory_state.acquire(self.node,operation,index)['result']
                    def call(self,method,operation,params=None):return directory_state.dispatch(self.node,
                        {'run':'a'*32,'method':method,'operation':operation,'params':params or {}})
                root.coordinator=Client(node)
                def sdk_call(method,descriptor,root=root):
                    path=root.work/'fake-region';path.touch(exist_ok=True)
                    fd=os.open(path,os.O_RDONLY);fds.append(fd)
                    return {'descriptor':descriptor},[host_pmem.Segment(fd,0,descriptor['bytes'])]
                root.sdk_call=sdk_call;roots.append(root)
                receipt=root.proof('stable-root-ready',writerEnabled=root.writer,manifestSha256=manifest.sha256,logicalBytes=a.DEVICE_BYTES)
                root.coordinator.call('ready',uuid.uuid4().hex,{'receipt':receipt})
            owner.append(roots[0])
            threads=[threading.Thread(target=r.miss_loop) for r in roots]
            try:
                for thread in threads:thread.start()
                deadline=time.monotonic()+5
                while not all(0 in r.control.bound for r in roots) and time.monotonic()<deadline:time.sleep(.01)
                self.assertTrue(all(0 in r.control.bound for r in roots),[r.record for r in roots])
                roots[1].control.pending.append(1)
                while a.LOAD_BYTES not in roots[1].control.bound and time.monotonic()<deadline:time.sleep(.01)
                self.assertIn(a.LOAD_BYTES,roots[1].control.bound)
                self.assertEqual(len(allocations),1)
                self.assertEqual(reads,[(0,a.LOAD_BYTES),(a.LOAD_BYTES,a.LOAD_BYTES)])
                self.assertEqual(roots[0].control.bound[0],roots[1].control.bound[0])
                self.assertTrue(all(r.record['fatal'] is None for r in roots))
            finally:
                for r in roots:r.stop_event.set()
                for thread in threads:thread.join(3);self.assertFalse(thread.is_alive())
                for fd in fds:os.close(fd)


if __name__=='__main__':unittest.main()
