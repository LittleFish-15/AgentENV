"""Control tests with fake API/Guest; no claim of target CoW or cache validation."""
import importlib.util
import json
from pathlib import Path
import shutil
import types
import unittest
import uuid
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('pair',HERE/'cow_pair_once.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


class Tests(unittest.TestCase):
    def setUp(self):
        self.root=HERE.parent/('.pair-test-'+uuid.uuid4().hex[:8]);self.root.mkdir(mode=0o755)
        self.base=self.root/'base';self.base.mkdir()
        self.work=self.root/'work';self.work.mkdir()
        self.calls=[];self.children={};self.counter=0;self.fail_second=False;self.foreign=False
        self.fail_log_save=False
        def need(ok,why):
            if not ok: raise RuntimeError(why)
        def save(path,obj):
            if self.fail_log_save and path.name.startswith('firecracker-'): raise OSError('disk error')
            path.write_text(json.dumps(obj))
        def child(command,env,log,timeout):log.write_bytes(b'COW_PAIR_GUEST_OK')
        self.helper=types.SimpleNamespace(need=need,save=save,read=lambda path:path.read_bytes(),
            checked_process=child,ID=__import__('re').compile(r'[A-Za-z0-9_-]+'),
            collect_fc_logs=lambda *a:{'files':{}},error_summary=lambda body,key:body)
        self.report={'snapshot_id':'snapshot','run_id':'a'*32,'parent_layers':{'layers':[]},
                     'create_calls':0,'create_outcome_uncertain':False,'children':[],'released_children':[],
                     'samples':{},'private_file_isolation_verified':False}

    def tearDown(self):
        assert self.root.resolve().parent==HERE.parent.resolve()
        shutil.rmtree(self.root)

    def call(self,method,path,data=None,timeout=20):
        self.calls.append((method,path,data))
        if path=='/v2/sandboxes?limit=3':return 200,[]
        if path=='/sandboxes':
            self.counter+=1
            self.assertEqual(data['templateID'],'snapshot')
            self.assertFalse(data['allow_internet_access'])
            self.assertEqual(data['timeout'],900)
            if self.fail_second and self.counter==2:return 500,{'message':'fixture failure'}
            sid='child-'+str(self.counter);self.children[sid]=True
            return 201,{'sandboxID':sid}
        sid=path.rsplit('/',1)[1]
        if method=='DELETE':self.children[sid]=False;return 204,None
        if not self.children.get(sid):return 404,None
        return 200,{'metadata':{'cow_pair_run':'foreign' if self.foreign else 'a'*32}}

    def run_pair(self):
        with patch.object(p,'H',self.helper),patch.object(p,'BASE',self.base), \
             patch.object(p,'PENDING',self.root/'pending.json'),patch.object(p.time,'sleep'), \
             patch.object(p,'process_observations',return_value={'available':False,'processes':[]}):
            p.run(types.SimpleNamespace(call=self.call,key='e2b_fixture'),self.work,self.report)

    def test_two_restores_capture_all_phases_and_release_own_children(self):
        self.run_pair()
        self.assertEqual(self.counter,2)
        self.assertTrue(self.report['private_file_isolation_verified'])
        self.assertEqual(self.report['released_children'],['child-2','child-1'])
        self.assertEqual(len(self.report['samples']),6)
        self.assertTrue(all(len(s['samples'])==3 for s in self.report['samples'].values()))
        self.assertFalse((self.work/'config/aenv/credentials').exists())
        self.assertEqual([c[1] for c in self.calls if c[0]=='DELETE'],['/sandboxes/child-2','/sandboxes/child-1'])

    def test_second_restore_failure_releases_first_without_retry(self):
        self.fail_second=True
        with self.assertRaisesRegex(RuntimeError,'Restore failed'):self.run_pair()
        self.assertEqual(self.counter,2)
        self.assertTrue(self.report['create_outcome_uncertain'])
        self.assertEqual(self.report['released_children'],['child-1'])

    def test_foreign_marker_is_not_deleted(self):
        self.foreign=True;self.run_pair()
        self.assertEqual(self.report['released_children'],[])
        self.assertFalse(any(c[0]=='DELETE' for c in self.calls))
        self.assertEqual(len(self.report['cleanup_errors']),2)

    def test_log_save_failure_does_not_skip_child_cleanup(self):
        self.fail_log_save=True;self.run_pair()
        self.assertEqual(len(self.report['released_children']),2)
        self.assertEqual(len(self.report['log_errors']),2)

    def test_correct_repository_directory_and_resource_budget(self):
        repo=self.base/'state/snapshot-store/repository/catalog/records';repo.mkdir(parents=True)
        record={'id':'snapshot','resources':{'cpu_count':1,'memory_mib':512,'disk_size_mib':65536},
                'committed':{'memory_layers':[{'digest':'sha256:'+'a'*64,'size':4096}],
                             'rootfs_layers':[{'Managed':{'digest':'sha256:'+'b'*64,'size':8192}}]}}
        (repo/'snapshot.json').write_text(json.dumps(record))
        with patch.object(p,'BASE',self.base),patch.object(p,'H',self.helper):
            r=p.layer_inventory('snapshot')
            self.assertIn('/repository/',r['layers'][0]['path'].replace('\\','/'))
            record['resources']['memory_mib']=1024;(repo/'snapshot.json').write_text(json.dumps(record))
            with self.assertRaisesRegex(RuntimeError,'budget'):p.layer_inventory('snapshot')

    def test_cache_summary_deduplicates_inodes_without_hiding_unknowns(self):
        row={'available':True,'dev':1,'inode':2,'file_bytes':100,'allocated_file_bytes':4096,'resident_page_bytes':4096}
        files={'a':row,'b':dict(row),'c':{'available':False}}
        layers=[{'kind':'memory','path':'a'},{'kind':'rootfs','path':'b'},{'kind':'rootfs','path':'c'},
                {'kind':'rootfs','origin':'External'}]
        r=p.summarize_sample(files,layers,{'available':False,'processes':[]})
        self.assertEqual(r['resident_regular_file_page_bytes'],4096)
        self.assertEqual(r['unavailable_files'],1)
        self.assertEqual(r['by_kind']['rootfs']['unresolved_external_layers'],1)
        self.assertNotIn('physical_shared_ram_bytes',r)

    def test_whole_process_rss_is_not_reported_as_guest_ram(self):
        r=p.summarize_sample({},[],{'processes':[{'pid':1,'smaps':{'available':True,
            'selected_lines':['Rss: 12 kB','Rss: 4 kB','Pss: 8 kB']}}]})
        smaps=r['processes']['processes'][0]['smaps']
        self.assertEqual(smaps['whole_process_bytes']['Rss'],16384)
        self.assertFalse(smaps['guest_ram_attribution'])

    def test_all_inaccessible_files_are_unknown_not_zero(self):
        r=p.summarize_sample({'a':{'available':False}},[{'kind':'memory','path':'a'}],{'processes':[]})
        self.assertIsNone(r['resident_regular_file_page_bytes'])
        self.assertIsNone(r['allocated_file_bytes'])
        self.assertFalse(r['complete_for_listed_regular_files'])


if __name__=='__main__':unittest.main(verbosity=2)
