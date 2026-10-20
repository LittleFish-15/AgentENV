"""Control/translation tests only; no claim of target Linux physical validation."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import types
import unittest
import uuid
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
C=module('controlled_tested','cow_controlled_once.py')
R=module('controlled_reader_tested','cow_ram_readonly.py')
P=module('controlled_prepare_tested','cow_marker_prepare.py')
def need(ok,message):
    if not ok:raise RuntimeError(message)


class Mapping(unittest.TestCase):
    def fixture(self):
        # Two GPA regions separated by a hole; different, noncontiguous HVAs.
        binding={'guest_regions':[{'guest_phys_addr':0x80000000,'size':8*1024**2,'base_host_virt_addr':0x100000000},
                                  {'guest_phys_addr':0x90000000,'size':8*1024**2,'base_host_virt_addr':0x200000000}],
                 'maps':[{'start':0x100000000,'end':0x100800000},{'start':0x200000000,'end':0x200800000}]}
        target={'guest_page_bytes':4096,'gpas':[0x80000000+i*4096 for i in range(2048)]+[0x90000000+i*4096 for i in range(2048)]}
        return binding,target

    def test_gpa_holes_and_host_translation_not_guest_virtual_address(self):
        binding,target=self.fixture();ranges=R.marker_ranges(binding,target,4096)
        self.assertEqual(ranges[0],[{'start':0x100000000,'end':0x100400000}])
        self.assertEqual(ranges[2],[{'start':0x200000000,'end':0x200400000}])

    def test_out_of_ram_alias_alignment_and_budget_fail_closed(self):
        for change in ('hole','alias','unaligned','length','page','clipped'):
            b,t=self.fixture()
            if change=='hole':t['gpas'][0]=0x88000000
            if change=='alias':t['gpas'][0]=t['gpas'][1]
            if change=='unaligned':t['gpas'][0]+=1
            if change=='length':t['gpas'].pop()
            if change=='page':t['guest_page_bytes']=65536
            if change=='clipped':b['maps'][0]['start']+=4096
            with self.subTest(change=change),self.assertRaises(RuntimeError):R.marker_ranges(b,t,4096)

    def test_overlapping_authoritative_regions_rejected(self):
        b,t=self.fixture();b['guest_regions'].append(dict(b['guest_regions'][0]))
        with self.assertRaisesRegex(RuntimeError,'exactly one'):R.marker_ranges(b,t,4096)


class Protocol(unittest.TestCase):
    def test_root_peer_and_phase_guards_precede_collection(self):
        scope={'run_id':'a'*32};endpoint={'path':'/home/jwk/agent/r/cow-control-'+'a'*16+'.sock',
                                       'identity':[1,2],'pid':22,'ticks':'t'}
        class FakePath:
            def __init__(self,value):self.value=str(value);self.name=self.value.rsplit('/',1)[-1]
            @property
            def parent(self):return FakePath(self.value.rsplit('/',1)[0])
            def __truediv__(self,other):return FakePath(self.value+'/'+other)
            def __eq__(self,other):return isinstance(other,FakePath) and self.value==other.value
            def __str__(self):return self.value
            def resolve(self,**kw):return self
            def lstat(self):return types.SimpleNamespace(st_mode=0o140600,st_uid=1204,st_dev=1,st_ino=2)
        class Client:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def settimeout(self,*a):pass
            def connect(self,*a):pass
            def getsockopt(self,*a):return struct.pack('3i',22,1204,1205)
        for bad in ('peer','phase','none'):
            calls=[];sent=[]
            messages=iter([{'run_id':'a'*32,'phase':('wrong' if bad=='phase' else p),'marker_targets':{}}
                           for p in C.PHASES]+[{'ack':'a'*32}])
            env={'Path':FakePath,'ROOT':FakePath('/home/jwk/agent'),'require':need,'json':json,'re':re,
                 'hashlib':hashlib,'stat':__import__('stat'),'struct':struct,
                 'os':types.SimpleNamespace(geteuid=lambda:0,uname=lambda:types.SimpleNamespace(nodename='server1')),
                 'socket':types.SimpleNamespace(AF_UNIX=1,SOCK_STREAM=1,SOL_SOCKET=1,SO_PEERCRED=1,socket=lambda *a:Client()),
                 'identity':lambda pid:(1,'bad' if bad=='peer' else 't'),
                 'wire_send':lambda client,value:sent.append(value),'wire_receive':lambda client:next(messages),
                 'collect_scope':lambda current:calls.append(current) or {'status':'fixture'}}
            exec(C.ROOT_DRIVER,env)
            with contextlib.redirect_stdout(io.StringIO()) as output:env['controlled_reader'](scope,endpoint)
            if bad!='none':self.assertEqual(calls,[]);self.assertIn('STOPPED_CONTROLLED_ROOT_READER',output.getvalue())
            else:self.assertEqual(len(calls),4);self.assertEqual(sent[-1],{'finished':'a'*32})

    def test_frame_roundtrip_short_reads_and_disconnect(self):
        output=bytearray();client=types.SimpleNamespace(sendall=output.extend)
        C.wire_send(client,{'phase':'baseline'})
        def recv(n):
            value=bytes(output[:min(n,3)]);del output[:min(n,3)];return value
        self.assertEqual(C.wire_receive(types.SimpleNamespace(recv=recv)),{'phase':'baseline'})
        with self.assertRaisesRegex(RuntimeError,'disconnected'):C.wire_receive(types.SimpleNamespace(recv=lambda _:b''))

    def test_oversized_frame_rejected_before_body_read(self):
        data=iter([struct.pack('!I',4*1024**2+1)])
        with self.assertRaisesRegex(RuntimeError,'size'):C.wire_receive(types.SimpleNamespace(recv=lambda n:next(data)))

    def test_pins_and_inline_root_syntax(self):
        self.assertEqual(hashlib.sha256((HERE/'cow_ram_readonly.py').read_bytes()).hexdigest(),C.COLLECTOR_SHA)
        self.assertEqual(hashlib.sha256((HERE/'cow_marker_prepare.py').read_bytes()).hexdigest(),C.PREPARE_SHA)
        ast.parse((HERE/'cow_ram_readonly.py').read_text()+C.WIRE_SOURCE+C.ROOT_DRIVER+'\ncontrolled_reader({}, {})\n')
        self.assertNotIn('subprocess',C.ROOT_DRIVER);self.assertNotIn('exec(',C.ROOT_DRIVER)

    def test_repeat_identity_requires_one_stable_identity_in_each_window(self):
        def result(values):return {'samples':[{'marker_segments':[{'guests':[{'sandbox_id':'a','pagemap':{'identity_hash':v},'segment_gpa_sha256':'g'}]}]} for v in values]}
        self.assertTrue(C.repeat_identity(result(['x']*3),result(['x']*3),'a')['stable_pfn_and_gpa_identity_between_windows'])
        self.assertFalse(C.repeat_identity(result(['x']*3),result(['x','y','y']),'a')['stable_pfn_and_gpa_identity_between_windows'])

    def test_wrong_scope_and_missing_root_samples_not_success(self):
        with patch.object(C,'H',types.SimpleNamespace(need=need)):
            with self.assertRaisesRegex(RuntimeError,'scope'):C.assess_measurement({'scope':{'other':1}},'baseline',{})
            with self.assertRaisesRegex(RuntimeError,'Incomplete'):C.assess_measurement({'scope':{}},'baseline',{})


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.root=HERE.parent/('.controlled-test-'+uuid.uuid4().hex[:8]);self.root.mkdir(mode=0o755)
        self.work=self.root/'work';self.work.mkdir();self.alive={};self.calls=[];self.count=0
        self.fail_measure=False;self.fail_capture=False;self.fail_restore=0;self.foreign=False
        self.report={'run_id':'a'*32,'snapshot_id':'measurement-template','catalog_sha256':'c'*64,
                     'restore_calls':0,'restore_outcome_uncertain':False,'known_sandboxes':[],
                     'cleanup_attempted':[],'released_sandboxes':[],'snapshot_capture_calls':0,
                     'snapshot_outcome_uncertain':False,'measurements':{}}
        self.prepare={'run_id':'b'*32,'restored_marker_status':{'server_pid':157,'arena_guest_virtual_address':4096}}
        self.H=types.SimpleNamespace(need=need,save=lambda p,o:p.write_text(json.dumps(o)),ID=re.compile(r'[\w-]+'))
        self.reader=types.SimpleNamespace(find_firecrackers=lambda pid:[] if not self.count else [11,12],identity=lambda pid:(1,'ticks'))
        self.prep=types.SimpleNamespace(inventory_empty=lambda api:None,restore=self.restore)
        self.api_obj=types.SimpleNamespace(call=self.api,key='fixture',identity=(5,'ticks'))

    def tearDown(self):
        assert self.root.resolve().parent==HERE.parent.resolve();shutil.rmtree(self.root)

    def restore(self,api,snapshot,run,role):
        self.count+=1
        self.assertLess(sum(self.alive.values()),2)
        if self.count==self.fail_restore:raise TimeoutError('unknown restore')
        self.assertEqual(snapshot,'written-template' if self.count==3 else 'measurement-template')
        sid='guest-'+str(self.count);self.alive[sid]=True;return sid

    def api(self,method,path,data=None,timeout=20):
        self.calls.append((method,path))
        if path.endswith('/snapshots'):
            if self.fail_capture:raise TimeoutError('unknown capture')
            return 201,{'snapshotID':'written-template'}
        sid=path.rsplit('/',1)[1]
        if method=='DELETE':self.alive[sid]=False;return 204,None
        if not self.alive.get(sid):return 404,None
        return 200,{'metadata':{'cow_marker_run':'foreign' if self.foreign else 'a'*32}}

    def run_fixture(self):
        def measure(experiment,*args):
            if self.fail_measure:raise RuntimeError('reader disconnected')
            experiment.report['root_reader_finished']=True
        with patch.object(C,'H',self.H),patch.object(C,'P',self.prep),patch.object(C,'R',self.reader), \
             patch.object(C,'BASE',self.root),patch.object(C,'PENDING',self.root/'pending.json'), \
             patch.object(C.Experiment,'measure',measure),patch.object(C.Experiment,'check',return_value={}), \
             patch.object(Path,'read_text',lambda p,*a,**kw:'boot' if str(p).endswith('boot_id') else p.open(*a,**kw).read()), \
             contextlib.redirect_stdout(io.StringIO()):
            C.Experiment(self.api_obj,self.work,self.report,self.prepare).run('source')

    def test_four_restores_one_capture_own_cleanup_and_base_preserved(self):
        self.run_fixture()
        self.assertEqual(self.count,4);self.assertEqual(len(self.report['released_sandboxes']),4)
        self.assertEqual(self.report['snapshot_capture_calls'],1)
        self.assertTrue(self.report['generation_and_base_content_verified'])
        self.assertNotIn(('DELETE','/sandboxes/measurement-template'),self.calls)
        self.assertFalse((self.work/'config/aenv/credentials').exists())

    def test_measurement_disconnect_releases_pair_without_capture(self):
        self.fail_measure=True
        with self.assertRaisesRegex(RuntimeError,'disconnected'):self.run_fixture()
        self.assertEqual(self.count,2);self.assertEqual(len(self.report['released_sandboxes']),2)
        self.assertEqual(self.report['snapshot_capture_calls'],0)

    def test_unknown_capture_retains_uncertainty_no_retry(self):
        self.fail_capture=True
        with self.assertRaises(TimeoutError):self.run_fixture()
        self.assertTrue(self.report['snapshot_outcome_uncertain']);self.assertEqual(self.count,2)
        self.assertEqual(len(self.report['released_sandboxes']),2)

    def test_unknown_second_restore_cleans_only_known_first(self):
        self.fail_restore=2
        with self.assertRaises(TimeoutError):self.run_fixture()
        self.assertTrue(self.report['restore_outcome_uncertain'])
        self.assertEqual(self.report['released_sandboxes'],['guest-1']);self.assertEqual(self.count,2)

    def test_foreign_metadata_blocks_delete_and_further_restores(self):
        self.foreign=True
        with self.assertRaisesRegex(RuntimeError,'not released'):self.run_fixture()
        self.assertFalse(any(m=='DELETE' for m,p in self.calls));self.assertEqual(self.count,2)
        self.assertFalse(self.report['released_sandboxes'])

    def test_four_phase_controller_sequence_and_measurement_return(self):
        pair=['guest-a','guest-b'];scope={'run_id':'a'*32,'sandbox_ids':pair};messages=[];operations=[];checks=[];sent=[]
        for phase in C.PHASES:
            expected=[4*1024**2]*4
            if phase!='baseline':expected[0]=0
            if phase=='b_disjoint':expected[1]=0
            segments=[{'segment':i,'stable':True,'physical':{'all_selected_guest_ram':{'shared_unique_bytes':n},
                       'categories':{k:{'unique_bytes':0} for k in ('zero','ksm','compound_or_huge','unclassified_nonanon')}},
                       'guests':[{'sandbox_id':sid,'pagemap':{'identity_hash':'same'},'segment_gpa_sha256':'same'} for sid in pair]}
                      for i,n in enumerate(expected)]
            sample={'started_unix':1,'finished_unix':2,'marker_segments':segments,'guests':[],
                    'stored_layer_cache':[],'rootfs':[],'pagemap_stable_during_flags':True,
                    'physical_page_observation':{'all_selected_guest_ram':{}},'memory_device_cache':{}}
            report={'scope':scope,'status':'SCOPED_RAM_PAGE_AND_CACHE_OBSERVATIONS_COMPLETED','samples':[sample]*3}
            messages.append({'phase':phase,'report':report,'sha256':hashlib.sha256(json.dumps(report,sort_keys=True).encode()).hexdigest()})
        messages=iter([{'hello':'a'*32}]+messages+[{'finished':'a'*32}])
        class Stream:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def settimeout(self,*a):pass
            def bind(self,path):Path(path).touch()
            def listen(self,*a):pass
            def accept(self):return self,None
            def getsockopt(self,*a):return struct.pack('3i',99,0,0)
        fake_socket=types.SimpleNamespace(socket=lambda *a:Stream(),AF_UNIX=1,SOCK_STREAM=1,SOL_SOCKET=1,SO_PEERCRED=1)
        self.H.safe=lambda p:p
        def checked(experiment,sid,label,tags,file_tag):
            checks.append((sid,label,tags,file_tag))
            return {'guest_page_bytes':4096,'guest_page_mapping':{'guest_physical_addresses':[4096*(i+1) for i in range(4096)]}}
        (self.root/'r').mkdir()
        with patch.object(C,'ROOT',self.root),patch.object(C,'H',self.H),patch.object(C,'R',self.reader), \
             patch.object(C,'PENDING',self.root/'pending.json'),patch.object(C,'socket',fake_socket), \
             patch.object(C,'wire_receive',lambda client:next(messages)),patch.object(C,'wire_send',lambda c,m:sent.append(m)), \
             patch.object(C.os,'chmod'),patch.object(C.Experiment,'check',checked), \
             patch.object(C.Experiment,'guest',lambda e,sid,op,label:operations.append((sid,op))), \
             contextlib.redirect_stdout(io.StringIO()):
            e=C.Experiment(self.api_obj,self.work,self.report,self.prepare);e.measure('source\n',scope,pair)
        self.assertEqual(operations,[('guest-a','ram_a'),('guest-a','rootfs_a')]*2+[('guest-b','ram_b'),('guest-b','rootfs_b')])
        self.assertEqual(len(checks),16)
        self.assertTrue(self.report['root_reader_finished'])
        self.assertEqual(sent[-1],{'ack':'a'*32})
        self.assertTrue(all(v['guest_gpa_layout_stable_before_after'] for v in self.report['measurements'].values()))
        self.assertIsNone(self.report['measurements']['baseline']['samples'][0]['rootfs_lower']['stored_bytes'])


if __name__=='__main__':unittest.main(verbosity=2)
