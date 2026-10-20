"""Synthetic control/arithmetic tests; target PFN/mincore validation remains pending."""
import ast
import hashlib
import contextlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import shutil
import struct
import types
import unittest
import uuid
from unittest.mock import patch
from unittest.mock import MagicMock

HERE=Path(__file__).resolve().parent
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
R=module('ram_reader','cow_ram_readonly.py');L=module('ram_launcher','cow_ram_pair.py')


class Arithmetic(unittest.TestCase):
    def test_whole_process_rss_uses_status_and_pss_uses_rollup(self):
        def opened(path,*a,**kw):
            return io.StringIO('VmRSS:\t1000 kB\n' if path.name=='status' else 'Rss: 1100 kB\nPss: 800 kB\n')
        with patch.object(R,'identity',return_value=(1,'ticks')),patch.object(Path,'open',opened):
            result=R.whole_process_metrics(10,'ticks')
        self.assertTrue(result['available'])
        self.assertEqual(result['rss_bytes'],1000*1024)
        self.assertEqual(result['pss_bytes'],800*1024)
        self.assertEqual(result['rss_minus_pss_bytes'],200*1024)
        self.assertEqual(result['smaps_rollup_rss_bytes'],1100*1024)

    def test_whole_process_permission_error_preserves_unknown(self):
        with patch.object(R,'identity',return_value=(1,'ticks')),patch.object(Path,'open',side_effect=PermissionError):
            result=R.whole_process_metrics(10,'ticks')
        self.assertFalse(result['available']);self.assertNotIn('rss_bytes',result)

    def test_process_summary_keeps_scope_and_uses_same_sample_deltas(self):
        scope={'snapshot_id':'template','sandbox_ids':['a','b']}
        samples=[]
        for pairs in (((100,70),(110,80)),((120,100),(115,95))):
            samples.append({'guests':[{'sandbox_id':sid,'whole_process':{'available':True,
                'rss_bytes':rss,'pss_bytes':pss,'rss_minus_pss_bytes':rss-pss}}
                for sid,(rss,pss) in zip(scope['sandbox_ids'],pairs)]})
        rows=R.process_comparison(scope,samples)
        self.assertEqual(rows[0]['template_min_shared_bytes'],40)
        self.assertEqual(rows[0]['template_max_shared_bytes'],60)
        self.assertEqual(rows[0]['sandbox_min_rss_minus_pss_bytes'],20)
        self.assertEqual(rows[0]['sandbox_max_rss_minus_pss_bytes'],30)
        self.assertEqual(rows[0]['sandbox_min_rss_bytes'],100)
        self.assertEqual(rows[0]['valid_samples'],2)
        self.assertEqual(rows[0]['scope'],'whole_firecracker_process')

    def test_missing_process_metrics_are_na_not_zero(self):
        rows=R.process_comparison({'snapshot_id':'t','sandbox_ids':['a','b']},
                                 [{'guests':[{'sandbox_id':'a','whole_process':{'available':False}}]}])
        self.assertEqual(rows[0]['valid_samples'],0)
        self.assertIsNone(rows[0]['sandbox_min_rss_bytes'])
        self.assertIsNone(rows[0]['template_min_shared_bytes'])

    def test_region_query_is_fixed_get_and_checks_socket_peer_before_request(self):
        for peer,status in ((101,200),(999,200),(101,404)):
            client=MagicMock();client.getsockopt.return_value=struct.pack('3i',peer,1204,1205)
            connection=MagicMock();response=connection.getresponse.return_value
            response.status=status;response.read.return_value=b'[]'
            with patch.object(Path,'resolve',lambda path,**kw:path), \
                 patch.object(Path,'stat',return_value=types.SimpleNamespace(st_mode=0o140600,st_uid=1204)), \
                 patch.object(R.socket,'socket',return_value=client), \
                 patch.object(R.socket,'AF_UNIX',1,create=True), \
                 patch.object(R.socket,'SO_PEERCRED',17,create=True), \
                 patch.object(R.http.client,'HTTPConnection',return_value=connection):
                if peer==101 and status==200:self.assertEqual(R.guest_regions(Path('/fixture'),101),[])
                else:
                    with self.assertRaises(RuntimeError):R.guest_regions(Path('/fixture'),101)
            if peer==101:connection.request.assert_called_once_with('GET','/vm/guest-memory-regions')
            else:connection.request.assert_not_called()
            client.close.assert_called_once()

    def test_api_guest_ranges_include_anonymous_discard_segments(self):
        raw='1000-2000 rw-p 0000 00:06 1 /dev/ublkb7\nRss: 4 kB\n2000-4000 rw-p 0000 00:00 0\nRss: 4 kB\n4000-5000 rw-p 3000 00:06 1 /dev/ublkb7\nRss: 4 kB\n'
        with self.assertRaises(R.BindingError) as old:R.parse_guest_smaps(raw,'/dev/ublkb7',16384)
        self.assertEqual(old.exception.diagnostics['device_named_vma_bytes'],8192)
        with patch.object(R.os,'sysconf',return_value=4096,create=True):
            result=R.parse_guest_smaps(raw,'/dev/ublkb7',16384,[{'base_host_virt_addr':4096,'size':16384,'offset':0}])
        self.assertEqual(sum(x['end']-x['start'] for x in result),16384)
        self.assertEqual(result[1]['mapping_kind'],'anonymous_inside_guest_region')

    def test_api_range_clips_merged_anonymous_vma_without_claiming_full_smaps(self):
        raw='0000-3000 rw-p 0000 00:00 0\nRss: 12 kB\n3000-5000 rw-p 2000 00:06 1 /dev/ublkb7\nRss: 8 kB\n'
        with patch.object(R.os,'sysconf',return_value=4096,create=True):
            result=R.parse_guest_smaps(raw,'/dev/ublkb7',16384,[{'base_host_virt_addr':4096,'size':16384,'offset':0}])
        self.assertEqual(result[0]['start'],4096)
        self.assertTrue(result[0]['smaps_metrics_omitted_due_to_clipping'])
        self.assertEqual(result[0]['bytes'],{})

    def test_authoritative_range_still_rejects_holes_and_wrong_backing_offsets(self):
        region=[{'base_host_virt_addr':4096,'size':8192,'offset':0}]
        with patch.object(R.os,'sysconf',return_value=4096,create=True):
            with self.assertRaises(R.BindingError):
                R.parse_guest_smaps('1000-2000 rw-p 0000 00:00 0\n','/dev/ublkb7',8192,region)
            with self.assertRaisesRegex(RuntimeError,'offset differs'):
                R.parse_guest_smaps('1000-3000 rw-p 1000 00:06 1 /dev/ublkb7\n','/dev/ublkb7',8192,region)

    def test_two_consumer_union_shared_and_avoided_bytes(self):
        r=R.sharing([{1,2,3},{2,3,4}],{x:0 for x in (1,2,3,4)},4096,[{1,2,3},{2,3,4}])['all_selected_guest_ram']
        self.assertEqual(r['unique_bytes'],4*4096)
        self.assertEqual(r['shared_unique_bytes'],2*4096)
        self.assertEqual(r['shared_participating_bytes'],4*4096)
        self.assertEqual(r['avoided_duplicate_bytes'],2*4096)
        self.assertAlmostEqual(r['sharing_participation_ratio'],2/3)
        self.assertAlmostEqual(r['duplicate_avoidance_ratio'],1/3)

    def test_zero_ksm_and_compound_are_not_snapshot_file_claim(self):
        flags={1:0,2:1<<24,3:1<<21,4:1<<15,5:1<<12}
        r=R.sharing([set(flags),set(flags)],flags,4096,[set(flags),set(flags)])
        self.assertEqual(r['snapshot_file_shared_bytes_excluding_special_pages'],4096)
        self.assertFalse(r['compound_attribution_complete'])
        self.assertEqual(r['categories']['ordinary_anon']['shared_unique_bytes'],4096)

    def test_nonanonymous_without_file_pagemap_flag_is_unclassified(self):
        r=R.sharing([{1},{1}],{1:0},4096,[{1},set()])
        self.assertEqual(r['snapshot_file_shared_bytes_excluding_special_pages'],0)
        self.assertEqual(r['categories']['unclassified_nonanon']['shared_unique_bytes'],4096)

    def test_memory_binding_requires_logged_file_backend(self):
        body={'mem_backend':{'backend_type':'File','backend_path':'/dev/ublkb7'}}
        line='The API server received a Put request on "/snapshot/load" with body '+json.dumps(json.dumps(body))+'.'
        self.assertEqual(R.memory_backend(line),'/dev/ublkb7')
        with self.assertRaises(RuntimeError):R.memory_backend(line+'\n'+line)
        with self.assertRaises(RuntimeError):R.memory_backend(line.replace('File','Uffd'))

    def test_vma_selection_tracks_file_private_cow_and_checks_coverage(self):
        raw='1000-3000 rw-p 0000 00:06 1 /dev/ublkb7\nRss: 8 kB\nAnonymous: 4 kB\n3000-4000 rw-p 0000 00:00 0\nRss: 4 kB\n'
        maps=R.parse_guest_smaps(raw,'/dev/ublkb7',8192)
        self.assertEqual(len(maps),1);self.assertEqual(maps[0]['bytes']['Anonymous'],4096)
        with self.assertRaises(RuntimeError):R.parse_guest_smaps(raw,'/dev/ublkb7',12288)
        with self.assertRaises(RuntimeError):R.parse_guest_smaps(raw.replace('rw-p','rw-s'),'/dev/ublkb7',8192)

    def test_hidden_pfn_zero_is_not_shared_zero_page(self):
        with patch.object(R.os,'open',return_value=5),patch.object(R.os,'close'), \
             patch.object(R.os,'pread',return_value=struct.pack('=Q',1<<63),create=True):
            with self.assertRaisesRegex(RuntimeError,'hidden'):
                R.pagemap(100,[{'start':4096,'end':8192}],4096)

    def test_inline_source_has_no_system_mutation_or_guest_memory_read(self):
        source=(HERE/'cow_ram_readonly.py').read_text()
        ast.parse(source)
        for forbidden in ('O_WRONLY','O_RDWR','setcap','setfacl','systemctl restart','process_vm_readv','/mem\"','drop_caches'):
            self.assertNotIn(forbidden,source)
        self.assertIn("'show',UNIT",source)
        text=L.root_command(source,{'main_pid':1})
        ast.parse(text.split('\n',1)[1].rsplit('\n',1)[0])

    def test_rootfs_metadata_failure_preserves_valid_ram_observations(self):
        ids=['11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222']
        record={'id':ids[0],'committed':{'memory_layers':[{'digest':'sha256:'+'a'*64}],
                                       'rootfs_layers':[{'Managed':{'digest':'sha256:'+'b'*64}}]}}
        raw=json.dumps(record).encode()
        scope={'main_pid':50,'main_start_ticks':'123','boot_id':'boot','snapshot_id':ids[0],
               'catalog_sha256':hashlib.sha256(raw).hexdigest(),'memory_bytes':512*1024**2,
               'sandbox_ids':ids,'children':[{'pid':101,'start_ticks':'123'},{'pid':102,'start_ticks':'123'}]}
        def bind(scope,child):
            return dict(child,sandbox_id=ids[child['pid']-101],memory_device='/dev/ublkb7',
                        cwd=HERE/'nonexistent-fixture-dir',maps=[])
        with contextlib.ExitStack() as st:
            for name,value in [('owned',lambda p:raw),('bind',bind),('identity',lambda p:(50,'123')),
                               ('pagemap',lambda *a:({1,2},{1,2},{'identity_hash':'stable'})),
                               ('page_flags',lambda p:{x:0 for x in p}),('resident',lambda *a:{'available':False})]:
                st.enter_context(patch.object(R,name,value))
            st.enter_context(patch.object(R.os,'geteuid',return_value=0,create=True))
            st.enter_context(patch.object(R.os,'uname',return_value=types.SimpleNamespace(nodename='server1'),create=True))
            st.enter_context(patch.object(R.os,'sysconf',return_value=4096,create=True))
            st.enter_context(patch.object(Path,'read_text',return_value='boot'))
            st.enter_context(patch.object(R.signal,'SIGALRM',14,create=True))
            st.enter_context(patch.object(R.signal,'signal'))
            st.enter_context(patch.object(R.signal,'alarm',create=True))
            st.enter_context(patch.object(R.time,'sleep'))
            st.enter_context(patch.object(R.subprocess,'run',return_value=types.SimpleNamespace(stdout='MainPID=50\nUser=jwk\nGroup=jwk\n')))
            with contextlib.redirect_stdout(io.StringIO()) as output:R.collect_scope(scope)
        r=json.loads(output.getvalue().split('BEGIN_RETURN_REPORT')[1].split('END_RETURN_REPORT')[0])
        self.assertEqual(r['status'],'SCOPED_RAM_PAGE_AND_CACHE_OBSERVATIONS_COMPLETED')
        self.assertEqual(len(r['samples']),3)
        self.assertFalse(r['samples'][0]['rootfs'][0]['available'])
        self.assertEqual(r['samples'][0]['physical_page_observation']['all_selected_guest_ram']['shared_unique_bytes'],8192)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.root=HERE.parent/('.ram-test-'+uuid.uuid4().hex[:8]);self.root.mkdir(mode=0o755)
        self.work=self.root/'work';self.work.mkdir();self.children={};self.calls=[];self.counter=0
        self.fail_second=False;self.foreign=False;self.answer='done\n'
        def need(ok,why):
            if not ok:raise RuntimeError(why)
        def child(cmd,env,log,timeout):log.write_bytes(b'COW_RAM_READY')
        self.helper=types.SimpleNamespace(need=need,save=lambda p,r:p.write_text(json.dumps(r)),
                                         checked_process=child,read=lambda p:p.read_bytes(),ID=re.compile(r'[A-Za-z0-9_-]+'))
        self.report={'run_id':'a'*32,'snapshot_id':'snapshot','catalog_sha256':'b'*64,
                     'children':[],'released_children':[],'create_calls':0}

    def tearDown(self):
        assert self.root.resolve().parent==HERE.parent.resolve();shutil.rmtree(self.root)

    def restore(self,api,snapshot,run_id):
        self.counter+=1
        if self.fail_second and self.counter==2:raise RuntimeError('restore failed')
        sid='child-'+str(self.counter);self.children[sid]=True;return sid

    def call(self,method,path,data=None,timeout=20):
        self.calls.append((method,path));sid=path.rsplit('/',1)[1]
        if method=='DELETE':self.children[sid]=False;return 204,None
        if not self.children[sid]:return 404,None
        return 200,{'metadata':{'cow_ram_run':'foreign' if self.foreign else 'a'*32}}

    def run_live(self):
        reader=types.SimpleNamespace(find_firecrackers=lambda pid:[] if self.counter==0 else [101,102],identity=lambda pid:(50,'123'))
        real_read=Path.read_text
        def read(path,*a,**kw):
            return 'boot-fixture' if str(path).replace('\\','/')=='/proc/sys/kernel/random/boot_id' else real_read(path,*a,**kw)
        with patch.object(L,'H',self.helper,create=True),patch.object(L,'BASE',self.root), \
             patch.object(L,'PENDING',self.root/'pending.json'),patch.object(L,'empty'), \
             patch.object(L,'restore',side_effect=self.restore),patch.object(Path,'read_text',read), \
             patch.object(L.select,'select',return_value=([1],[],[])),patch.object(L.sys,'stdin',io.StringIO(self.answer)), \
             contextlib.redirect_stdout(io.StringIO()):
            L.lifecycle(types.SimpleNamespace(identity=(50,'500'),key='e2b_fixture',call=self.call),reader,
                        'def collect_scope(s): pass\n',self.work,self.report)

    def test_done_releases_two_but_does_not_claim_root_measurement_success(self):
        self.run_live()
        self.assertEqual(self.report['released_children'],['child-2','child-1'])
        self.assertNotIn('root_measurement_success',self.report)
        self.assertFalse((self.work/'config/aenv/credentials').exists())

    def test_failure_releases_known_first_child_without_retrying(self):
        self.fail_second=True
        with self.assertRaises(RuntimeError):self.run_live()
        self.assertEqual(self.counter,2);self.assertEqual(self.report['released_children'],['child-1'])

    def test_unknown_ownership_never_deleted(self):
        self.foreign=True;self.run_live()
        self.assertFalse(any(m=='DELETE' for m,p in self.calls))
        self.assertEqual(len(self.report['cleanup_errors']),2)

    def test_handoff_eof_cleans_known_children(self):
        self.answer=''
        with self.assertRaises(RuntimeError):self.run_live()
        self.assertEqual(len(self.report['released_children']),2)

    def test_thread_children_discovery_without_cgroup_v2(self):
        proc=self.root/'proc'
        def add(pid,parent,comm,threads):
            directory=proc/str(pid);directory.mkdir(parents=True)
            fields=['S',str(parent)]+['0']*17+['123']
            (directory/'stat').write_text(str(pid)+' ('+comm+') '+' '.join(fields))
            (directory/'comm').write_text(comm)
            for tid,children in threads.items():
                task=directory/'task'/str(tid);task.mkdir(parents=True)
                (task/'children').write_text(children)
        add(50,1,'server',{50:'',51:'101 102'})
        add(101,50,'firecracker',{101:''});add(102,50,'firecracker',{102:''})
        self.assertEqual(R.find_firecrackers(50,proc),[101,102])

    def test_relative_runtime_lower_normalizes_to_allowed_repository_file(self):
        base=self.root/'deployments/base';target=base/'state/repository/layer.commit'
        target.parent.mkdir(parents=True);target.write_bytes(b'fixture')
        short=self.root/'r/fc-a-base';cwd=short/'agentenv-fc-fixture/overlaybd';cwd.mkdir(parents=True)
        original=cwd/'../../../../deployments/base/state/repository/layer.commit'
        with patch.object(R,'BASE',base),patch.object(R,'SHORT',short):
            self.assertEqual(R.scoped_file_path(original),target.resolve())

    def test_normalization_does_not_allow_scope_escape_or_redirect(self):
        base=self.root/'base';short=self.root/'r'
        with patch.object(R,'BASE',base),patch.object(R,'SHORT',short):
            with self.assertRaisesRegex(RuntimeError,'outside'):
                R.scoped_file_path(base/'state/../../outside')
            with patch.object(Path,'resolve',return_value=self.root/'outside'):
                with self.assertRaisesRegex(RuntimeError,'Redirected'):
                    R.scoped_file_path(base/'state/inside')

    def released_receipt(self):
        directory=self.root/'relay/reports/node-a-cow-ram-old';directory.mkdir(parents=True)
        prior={'run_id':'c'*32,'status':'RAM_PAIR_RELEASED_RETURN_ROOT_MEASUREMENT_REPORT',
               'create_outcome_uncertain':False,'create_calls':2,'snapshot_id':'snapshot',
               'children':['old1','old2'],'released_children':['old2','old1'],
               'report_directory':str(directory)}
        (directory/'return.json').write_text(json.dumps(prior));return prior

    def test_explicit_released_run_is_backed_up_after_both_404_checks(self):
        prior=self.released_receipt();calls=[]
        def call(method,path):calls.append((method,path));return 404,None
        with patch.object(L,'H',self.helper,create=True),patch.object(L,'ROOT',self.root),patch.object(L,'empty'):
            result=L.reconcile_released(types.SimpleNamespace(call=call),prior,'c'*32,'snapshot',self.work)
        self.assertEqual(len(calls),2)
        self.assertEqual(json.loads((self.work/'previous-pending.json').read_text()),prior)
        self.assertTrue(result['root_measurement_success_not_inferred'])

    def test_release_reconciliation_refuses_uncertain_or_visible_prior_objects(self):
        prior=self.released_receipt()
        with patch.object(L,'H',self.helper,create=True),patch.object(L,'ROOT',self.root),patch.object(L,'empty'):
            api=types.SimpleNamespace(call=lambda *a:(200,{}))
            with self.assertRaisesRegex(RuntimeError,'still visible'):
                L.reconcile_released(api,prior,'c'*32,'snapshot',self.work)
            prior['create_outcome_uncertain']=True
            with self.assertRaisesRegex(RuntimeError,'not fully released'):
                L.reconcile_released(api,prior,'c'*32,'snapshot',self.work)


if __name__=='__main__':unittest.main(verbosity=2)
