"""Scoped stale-socket guard tests; Linux service startup remains target-only."""
import ast
import errno
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
D=load('deploy_proxy_test','deploy_a_ub.py')
F=load('recovery_test','recover_a_modified_proxy.py')
def need(ok,why):
    if not ok:raise RuntimeError(why)

class Guard(unittest.TestCase):
    def run_guard(self,case='refused',archive=True):
        renames=[];checks=[];meta=types.SimpleNamespace(st_dev=1,st_ino=22,st_uid=1204,st_mode=stat.S_IFSOCK|0o600,st_mtime_ns=7)
        lockmeta=types.SimpleNamespace(st_dev=1,st_ino=11,st_uid=1204,st_mode=stat.S_IFREG|0o600)
        if case=='file':meta.st_mode=stat.S_IFREG|0o600
        if case=='foreign':meta.st_uid=99
        class FakePath:
            def __init__(self,p):self.p=p
            def __truediv__(self,s):return FakePath(self.p+'/'+s)
            def __eq__(self,o):return isinstance(o,FakePath) and self.p==o.p
            def __str__(self):return self.p
            def exists(self):return self.p.endswith('/api.sock') and case!='missing' or self.p.endswith('.lock')
            def stat(self):return lockmeta
            def lstat(self):
                checks.append('lstat')
                if case=='changed' and len(checks)>1:return types.SimpleNamespace(**dict(vars(meta),st_ino=23))
                return meta
        class Client:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def settimeout(self,*a):pass
            def connect(self,path):
                if case=='live':return
                raise OSError(errno.EACCES if case=='uncertain' else errno.ECONNREFUSED,'fixture')
        def safe(p,*args):
            if case=='redirect' and str(p).endswith('api.sock'):raise RuntimeError('Redirected')
            return p
        fcntl=types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *a:None)
        if case=='locked':fcntl.flock=lambda *a:(_ for _ in ()).throw(BlockingIOError())
        with patch.dict(sys.modules,{'fcntl':fcntl}),patch.object(D,'RUNTIME',FakePath('/runtime')), \
             patch.object(D,'safe',safe),patch.object(D.os,'getuid',lambda:1204,create=True), \
             patch.object(D.os,'geteuid',lambda:1204,create=True),patch.object(D.os,'fstat',lambda _:lockmeta), \
             patch.object(D.socket,'AF_UNIX',1,create=True),patch.object(D.socket,'socket',lambda *a:Client()),patch.object(D.os,'rename',lambda a,b:renames.append((str(a),str(b)))), \
             patch.object(D.secrets,'token_hex',lambda n:'ab'*n):
            try:result=D.prepare_inside_socket(FakePath('/runtime/api.sock'),9,archive)
            except Exception:
                self.assertEqual(renames,[]);raise
        return result,renames
    def test_refused_socket_archived_exact_leaf(self):
        result,renames=self.run_guard()
        self.assertEqual(renames,[('/runtime/api.sock','/runtime/api-stale-'+'ab'*12+'.sock')])
        self.assertEqual(result,renames[0][1])
    def test_dry_probe_and_missing_socket_do_not_mutate(self):
        self.assertEqual(self.run_guard(archive=False),('REFUSED_SOCKET_VERIFIED',[]))
        self.assertEqual(self.run_guard('missing'),(None,[]))
    def test_live_uncertain_foreign_redirect_changed_or_busy_preserved(self):
        for case in ['live','uncertain','file','foreign','redirect','changed','locked']:
            with self.subTest(case=case),self.assertRaises((RuntimeError,BlockingIOError)):self.run_guard(case)

class Patching(unittest.TestCase):
    def test_embedded_guard_matches_repository_function(self):
        tree=ast.parse((HERE/'deploy_a_ub.py').read_text())
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='prepare_inside_socket')
        self.assertEqual(ast.dump(function),ast.dump(ast.parse(F.GUARD_SOURCE).body[0]))
    def test_exact_old_launcher_guard_replaced_and_new_source_compiles(self):
        old=subprocess.check_output(['git','show','fdadce3f239d71ea0537465419ac0f9fb1074ecb:dev-relay/deploy_a_ub.py'],cwd=HERE.parent)
        with patch.object(F,'H',types.SimpleNamespace(need=need)):
            new=F.patched_launcher(old)
            with self.assertRaisesRegex(RuntimeError,'Unknown/already'):F.patched_launcher(new)
        self.assertEqual(new.count(b'def prepare_inside_socket('),1)
        self.assertEqual(new.count(b'prepare_inside_socket(unix, lock)\n'),1)
        restored=new.decode().replace(F.GUARD_SOURCE+'\n\n','',1).replace('prepare_inside_socket(unix, lock)',"require(not unix.exists() and not unix.is_symlink(), 'New API socket already exists; preserved')",1)
        self.assertEqual(restored,old.decode())
    def test_root_reactivation_preserves_original_and_exact_privilege_boundary(self):
        ast.parse('scope={}\n'+F.ROOT_START)
        self.assertIn("'User=jwk','Group=jwk'",F.ROOT_START)
        self.assertIn("'PrivateNetwork=yes','PrivateMounts=yes'",F.ROOT_START)
        self.assertIn("'Restart=no'",F.ROOT_START)
        self.assertNotIn("'restart'",F.ROOT_START)
        self.assertNotIn("'stop'",F.ROOT_START)
        self.assertNotIn('os.rename',F.ROOT_START)
        self.assertIn("p.get('LoadState')=='not-found'",F.ROOT_START)
    def test_active_unit_blocks_recovery(self):
        output=types.SimpleNamespace(stdout='LoadState=loaded\nActiveState=active\nMainPID=12\n')
        with patch.object(F,'H',types.SimpleNamespace(need=need)),patch.object(F.subprocess,'run',return_value=output),self.assertRaisesRegex(RuntimeError,'not absent'):
            F.absent()

if __name__=='__main__':unittest.main(verbosity=2)
