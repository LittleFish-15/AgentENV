"""Restart-path regression with real record files and substituted Linux services."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import types
import unittest
import uuid
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
D=module('attestation_deploy','deploy_a_ub.py')
F=module('attestation_recovery','recover_a_modified_runtime.py')
def need(ok,why):
    if not ok:raise RuntimeError(why)

class Records(unittest.TestCase):
    def setUp(self):
        self.root=(HERE.parent/('.runtime-record-'+uuid.uuid4().hex[:8])).resolve();self.root.mkdir(mode=0o755)
        self.runtime=self.root/'runtime';self.runtime.mkdir();self.dest=self.root/'modified'
        (self.dest/'logs').mkdir(parents=True);(self.dest/'config').mkdir()
        (self.dest/'config/api-key').write_bytes(b'e2b_fixture')
        self.path=self.runtime/'runtime-attestation.json';self.pid=901;self.ticks='20';self.old_tick=None
        self.original_read_text=Path.read_text;self.original_stat=os.stat
        def safe(p,*args):
            need(p.resolve()==p and p.is_relative_to(self.root),'Outside/redirected');return p
        def directory(p):safe(p);p.mkdir(parents=True,exist_ok=True,mode=0o755)
        def stable(p,limit=1024**2):
            safe(p);raw=p.read_bytes();need(len(raw)<=limit,'too large');return raw,p.stat()
        def read_text(p,*a,**kw):
            if str(p).replace('\\','/').startswith('/proc/'):
                if str(p).endswith('ip_forward'):return '1'
                if self.old_tick is None:raise FileNotFoundError()
                fields=['0']*20;fields[19]=self.old_tick;return '900 (old) '+' '.join(fields)
            return self.original_read_text(p,*a,**kw)
        self.patches=[patch.object(D,'ROOT',self.root),patch.object(D,'RUNTIME',self.runtime),patch.object(D,'D',self.dest),
                      patch.object(D,'safe',safe),patch.object(D,'mkdir',directory),patch.object(D,'stable_file',stable),
                      patch.object(D,'properties',lambda unit:{'MainPID':str(self.pid)}),
                      patch.object(D.os,'getuid',lambda:1204,create=True),patch.object(D.os,'geteuid',lambda:1204,create=True),
                      patch.object(D.os,'getpid',lambda:self.pid),patch.object(Path,'read_text',read_text)]
        for p in self.patches:p.start()
        self.old={'pid':900,'start_ticks':'10','revision':D.REVISION,'uid':[1204]*4,'intended_executable':str(self.dest/'bin/server')}
        self.before=(json.dumps(self.old,indent=2,sort_keys=True)+'\n').encode();self.path.write_bytes(self.before)
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        assert self.root.parent==HERE.parent.resolve();shutil.rmtree(self.root)
    def value(self):
        return dict(self.old,pid=self.pid,start_ticks=self.ticks)
    def test_dead_old_record_backed_up_and_atomically_refreshed(self):
        D.publish_runtime_attestation(self.value())
        self.assertEqual(json.loads(self.path.read_bytes()),self.value())
        backups=list(self.runtime.glob('runtime-attestation-history-*.json'))
        self.assertEqual(len(backups),1);self.assertEqual(backups[0].read_bytes(),self.before)
        self.assertFalse(list(self.runtime.glob('runtime-attestation-new-*')))
    def test_missing_record_first_start_then_second_start_works(self):
        self.path.unlink();D.publish_runtime_attestation(self.value())
        self.pid=902;self.ticks='30';D.publish_runtime_attestation(self.value())
        self.assertEqual(json.loads(self.path.read_bytes())['pid'],902)
        self.assertEqual(len(list(self.runtime.glob('runtime-attestation-history-*'))),1)
    def test_live_old_process_or_unknown_record_is_not_overwritten(self):
        self.old_tick='10'
        with self.assertRaisesRegex(RuntimeError,'still alive'):D.publish_runtime_attestation(self.value())
        self.assertEqual(self.path.read_bytes(),self.before)
        self.old_tick=None;self.path.write_text('{"revision":"foreign"}')
        with self.assertRaisesRegex(RuntimeError,'Unknown'):D.publish_runtime_attestation(self.value())
        self.assertEqual(self.path.read_text(),'{"revision":"foreign"}')
    def test_reused_pid_with_different_start_ticks_is_old_identity(self):
        self.old_tick='999';D.publish_runtime_attestation(self.value())
        self.assertEqual(json.loads(self.path.read_bytes())['pid'],901)
    def test_current_identity_idempotent_but_different_data_preserved(self):
        D.publish_runtime_attestation(self.value());raw=self.path.read_bytes()
        D.publish_runtime_attestation(self.value())
        self.assertEqual(self.path.read_bytes(),raw)
        with self.assertRaisesRegex(RuntimeError,'Current-process'):D.publish_runtime_attestation(dict(self.value(),extra=True))
        self.assertEqual(self.path.read_bytes(),raw)
    def test_global_immutable_dump_remains_strict(self):
        with self.assertRaisesRegex(RuntimeError,'Existing different file'):D.dump(self.path,self.value())
        self.assertEqual(self.path.read_bytes(),self.before)
    def test_unit_change_before_publication_preserves_old_record(self):
        calls=[]
        def props(unit):
            calls.append(unit);return {'MainPID':str(901 if len(calls)==1 else 902)}
        with patch.object(D,'properties',props),self.assertRaisesRegex(RuntimeError,'Unit changed'):
            D.publish_runtime_attestation(self.value())
        self.assertEqual(self.path.read_bytes(),self.before)
        self.assertFalse(list(self.runtime.glob('runtime-attestation-new-*')))
    def test_full_inside_path_with_retained_record_reaches_server_exec_twice(self):
        device=self.root/'device';device.write_bytes(b'')
        original_open=os.open;execs=[];spawns=[]
        def opened(p,flags,*args):
            if str(p) in ('/dev/kvm','/dev/ublk-control','/dev/net/tun'):return original_open(device,os.O_RDWR)
            return original_open(p,flags,*args)
        def stated(p,*a,**kw):
            if str(p) in ('/proc/self/ns/net','/proc/self/ns/mnt'):return types.SimpleNamespace(st_ino=99)
            return self.original_stat(p,*a,**kw)
        def spawn(*a,**kw):spawns.append((a,kw));return types.SimpleNamespace(poll=lambda:None)
        def process(pid):return dict(self.value(),gid=[1205]*4,caps={'CapEff':D.CAPS},netns=99,mntns=99)
        with patch.object(D,'installed',return_value={'host_netns':1,'host_mntns':2}), \
             patch.object(D,'caps',return_value={k:D.CAPS for k in ('CapInh','CapPrm','CapEff','CapAmb')}), \
             patch.object(D.os,'getgroups',lambda:[1205,36,982],create=True),patch.object(D.os,'stat',stated), \
             patch.object(D.os,'O_CLOEXEC',0,create=True),patch.object(D.os,'open',opened),patch.object(D.subprocess,'Popen',spawn),patch.object(D.time,'sleep'), \
             patch.object(D,'process_identity',process),patch.object(D.os,'dup2'),patch.object(D.os,'chdir'), \
             patch.object(D.os,'execve',lambda *a:execs.append(a)):
            D.inside()
            self.pid=902;self.ticks='30';D.inside()
        self.assertEqual(len(execs),2);self.assertEqual(len(spawns),2)
        for args,kwargs in spawns:kwargs['stdout'].close()
        self.assertTrue(all(x[0]==self.dest/'bin/server' for x in execs))
        self.assertTrue(all(x[2]['AENV_API_KEY']=='e2b_fixture' for x in execs))
        self.assertTrue(all(x[1]['preexec_fn'] is D.drop_caps for x in spawns))
        self.assertEqual(json.loads(self.path.read_bytes())['pid'],902)
        self.assertEqual(len(list(self.runtime.glob('runtime-attestation-history-*'))),2)

class Patching(unittest.TestCase):
    def test_embedded_source_matches_and_only_exact_runtime_call_is_changed(self):
        tree=ast.parse((HERE/'deploy_a_ub.py').read_text())
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='publish_runtime_attestation')
        self.assertEqual(ast.dump(function),ast.dump(ast.parse(F.ATTESTATION_SOURCE).body[0]))
        old=subprocess.check_output(['git','show','ceb26a9167d67729b50681afd77df8c57e5a644e:dev-relay/deploy_a_ub.py'],cwd=HERE.parent)
        with patch.object(F,'H',types.SimpleNamespace(need=need)):
            new=F.patch_launcher(old)
            with self.assertRaises(RuntimeError):F.patch_launcher(new)
        restored=new.decode().replace(F.ATTESTATION_SOURCE+'\n\n','',1).replace('publish_runtime_attestation(attestation)',"dump(RUNTIME / 'runtime-attestation.json', attestation)",1)
        self.assertEqual(restored,old.decode())
        ast.parse(new)

if __name__=='__main__':unittest.main(verbosity=2)
