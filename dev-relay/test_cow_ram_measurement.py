"""Synthetic control/arithmetic tests; target PFN/mincore validation remains pending."""
import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import types
import unittest
import uuid
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
R=module('ram_reader','cow_ram_readonly.py');L=module('ram_launcher','cow_ram_pair.py')


class Arithmetic(unittest.TestCase):
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


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.root=HERE.parent/('.ram-test-'+uuid.uuid4().hex[:8]);self.root.mkdir(mode=0o755)
        self.work=self.root/'work';self.work.mkdir();self.children={};self.calls=[];self.counter=0
        self.fail_second=False;self.foreign=False;self.answer='done\n'
        def need(ok,why):
            if not ok:raise RuntimeError(why)
        def child(cmd,env,log,timeout):log.write_bytes(b'COW_RAM_READY')
        self.helper=types.SimpleNamespace(need=need,save=lambda p,r:p.write_text(json.dumps(r)),
                                         checked_process=child,read=lambda p:p.read_bytes())
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


if __name__=='__main__':unittest.main(verbosity=2)
