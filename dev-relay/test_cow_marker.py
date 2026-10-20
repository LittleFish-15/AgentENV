"""Marker protocol/lifecycle tests; Guest snapshot and GPA behavior require target execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import types
import unittest
import uuid
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
G=module('marker_guest_tested','cow_marker_guest.py')
P=module('marker_prepare_tested','cow_marker_prepare.py')


class MarkerLogic(unittest.TestCase):
    def test_nonzero_patterns_and_host_guest_hash_contract(self):
        seed='a'*32
        block=G.pattern(seed,'ram-base',0)
        self.assertEqual(len(block),65536);self.assertNotEqual(block,b'\0'*65536)
        self.assertNotEqual(block,G.pattern(seed,'ram-base',1))
        self.assertEqual(G.expected_hash(seed,'ram-base',0,65536),P.expected_hash(seed,'ram-base',0,65536))

    def test_first_repeat_and_disjoint_writes_change_only_selected_segments(self):
        marker=object.__new__(G.Marker);marker.seed='a'*32;marker.arena=bytearray(G.ARENA_BYTES);marker.tags=['ram-base']*4
        for i in range(4):marker.fill_ram(i,'ram-base')
        def hashes():return [hashlib.sha256(marker.arena[i*G.SEGMENT_BYTES:(i+1)*G.SEGMENT_BYTES]).hexdigest() for i in range(4)]
        base=hashes();marker.fill_ram(0,'ram-a');first=hashes()
        self.assertNotEqual(first[0],base[0]);self.assertEqual(first[1:],base[1:])
        marker.fill_ram(0,'ram-a');self.assertEqual(hashes(),first)
        marker.fill_ram(1,'ram-b');other=hashes()
        self.assertEqual(other[0],first[0]);self.assertNotEqual(other[1],first[1]);self.assertEqual(other[2:],base[2:])
        with self.assertRaisesRegex(RuntimeError,'Unknown'):marker.operation('arbitrary-command')

    def test_frame_limit_and_early_disconnect_stop(self):
        with self.assertRaisesRegex(RuntimeError,'limit'):
            G.receive(types.SimpleNamespace(recv=lambda n:b'x'*(n)),16)
        with self.assertRaisesRegex(RuntimeError,'early'):
            G.receive(types.SimpleNamespace(recv=lambda n:b''),16)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.root=HERE.parent/('.marker-test-'+uuid.uuid4().hex[:8]);self.root.mkdir(mode=0o755)
        self.work=self.root/'work';self.work.mkdir()
        self.count=0;self.alive={};self.calls=[];self.bad_restore_hash=False;self.no_gpas=False;self.foreign=False;self.capture_timeout=False
        self.report={'run_id':'a'*32,'source_snapshot_id':'original-template','measurement_snapshot_id':None,
                     'restore_calls':0,'restore_outcome_uncertain':False,'known_sandboxes':[],
                     'cleanup_attempted':[],'released_sandboxes':[],'snapshot_capture_calls':0,
                     'snapshot_outcome_uncertain':False,'marker_survived_snapshot_restore':False}
        self.hashes=[G.expected_hash('a'*32,'ram-base',i*G.SEGMENT_BYTES,G.SEGMENT_BYTES) for i in range(4)]
        def need(ok,why):
            if not ok:raise RuntimeError(why)
        self.H=types.SimpleNamespace(need=need,save=lambda p,obj:p.write_text(json.dumps(obj)),read=lambda p:p.read_bytes(),
            checked_process=self.child,ID=re.compile(r'[A-Za-z0-9_-]+'),error_summary=lambda b,k:b)

    def tearDown(self):
        assert self.root.resolve().parent==HERE.parent.resolve();shutil.rmtree(self.root)

    def state(self):
        return {'version':1,'seed':'a'*32,'server_pid':123,'guest_uid':0,
            'arena_bytes':G.ARENA_BYTES,'segment_bytes':G.SEGMENT_BYTES,'rootfs_file_bytes':G.FILE_BYTES,
            'guest_page_bytes':4096,'arena_guest_virtual_address':4096,
            'ram_tags':['ram-base']*4,'ram_hashes':self.hashes.copy(),'rootfs_tag':'rootfs-base',
            'rootfs_hash':G.expected_hash('a'*32,'rootfs-base',0,G.FILE_BYTES),'content_verified':True,
            'guest_page_mapping':{'available':not self.no_gpas,'present_pages':4096,
                'masked_pages':4096 if self.no_gpas else 0,'swapped_pages':0,
                'guest_physical_addresses':None if self.no_gpas else [0x80000000+i*4096 for i in range(4096)]}}

    def child(self,cmd,env,log,timeout):
        if '-c' in cmd:log.write_bytes(b'COW_MARKER_PROCESS_STARTED');return
        state=self.state()
        if self.count==2 and self.bad_restore_hash:state['ram_hashes'][0]='bad'
        log.write_text('BEGIN_COW_MARKER_STATUS\n'+json.dumps({'ok':True,'status':state})+'\nEND_COW_MARKER_STATUS\n')

    def restore(self,api,snapshot,run,role):
        self.assertFalse(any(self.alive.values()),'Guests must be sequential, not concurrent')
        self.count+=1
        self.assertEqual(snapshot,'original-template' if self.count==1 else 'measurement-template')
        sid='guest-'+str(self.count);self.alive[sid]=True;return sid

    def api(self,method,path,data=None,timeout=20):
        self.calls.append((method,path))
        if path.endswith('/snapshots'):
            if self.capture_timeout:raise TimeoutError('fixture timeout')
            return 201,{'snapshotID':'measurement-template'}
        sid=path.rsplit('/',1)[1]
        if method=='DELETE':self.alive[sid]=False;return 204,None
        if not self.alive.get(sid):return 404,None
        return 200,{'metadata':{'cow_marker_run':'foreign' if self.foreign else 'a'*32}}

    def run_fixture(self):
        with patch.object(P,'H',self.H),patch.object(P,'BASE',self.root),patch.object(P,'PENDING',self.root/'pending.json'), \
             patch.object(P,'inventory_empty'),patch.object(P,'restore',side_effect=self.restore), \
             contextlib.redirect_stdout(io.StringIO()):
            P.lifecycle(types.SimpleNamespace(call=self.api,key='e2b_fixture'),b'guest source',self.work,self.report)

    def test_derivative_snapshot_verified_without_restarting_marker_and_both_released(self):
        self.run_fixture()
        self.assertEqual(self.count,2);self.assertEqual(self.report['released_sandboxes'],['guest-1','guest-2'])
        self.assertEqual(self.report['measurement_snapshot_id'],'measurement-template')
        self.assertTrue(self.report['marker_survived_snapshot_restore']);self.assertTrue(self.report['guest_gpa_layout_equal'])
        self.assertEqual(sum(p.endswith('/snapshots') for m,p in self.calls),1)
        self.assertNotIn(('DELETE','/sandboxes/original-template'),self.calls)
        self.assertFalse((self.work/'config/aenv/credentials').exists())
        self.assertNotIn('guest_physical_addresses',self.report['restored_marker_status']['guest_page_mapping'])

    def test_unavailable_guest_page_metadata_stops_before_capture_and_releases_parent(self):
        self.no_gpas=True
        with self.assertRaisesRegex(RuntimeError,'metadata unavailable'):self.run_fixture()
        self.assertEqual(self.count,1);self.assertEqual(self.report['released_sandboxes'],['guest-1'])
        self.assertEqual(self.report['snapshot_capture_calls'],0)
        self.assertFalse(self.report['parent_marker_status']['guest_page_mapping']['available'])

    def test_restore_content_mismatch_retains_snapshot_and_releases_verifier(self):
        self.bad_restore_hash=True
        with self.assertRaisesRegex(RuntimeError,'content differs'):self.run_fixture()
        self.assertEqual(len(self.report['released_sandboxes']),2)
        self.assertFalse(self.report['marker_survived_snapshot_restore'])
        self.assertEqual(self.report['measurement_snapshot_id'],'measurement-template')

    def test_unknown_capture_has_no_retry_and_only_known_parent_cleanup(self):
        self.capture_timeout=True
        with self.assertRaises(TimeoutError):self.run_fixture()
        self.assertTrue(self.report['snapshot_outcome_uncertain']);self.assertIsNone(self.report['measurement_snapshot_id'])
        self.assertEqual(self.count,1);self.assertEqual(self.report['released_sandboxes'],['guest-1'])

    def test_foreign_ownership_prevents_delete_and_second_restore(self):
        self.foreign=True
        with self.assertRaisesRegex(RuntimeError,'not released'):self.run_fixture()
        self.assertEqual(self.count,1);self.assertFalse(any(m=='DELETE' for m,p in self.calls))
        self.assertFalse(self.report['released_sandboxes'])


if __name__=='__main__':unittest.main(verbosity=2)
