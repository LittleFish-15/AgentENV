"""Bounded parent lifecycle tests with fake API; no target execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import types
import unittest
import uuid
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cow_parent_tested', HERE / 'cow_parent_once.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class Tests(unittest.TestCase):
    def setUp(self):
        self.root = HERE.parent / ('.parent-' + uuid.uuid4().hex[:6])
        self.root.mkdir(mode=0o755)
        self.base = self.root / 'deployments/original'
        (self.base / 'deps/regctl/v0.11.5').mkdir(parents=True)
        (self.base / 'deps/regctl/v0.11.5/regctl').write_bytes(b'fixture')
        (self.base / 'installation.json').write_text(json.dumps({'node':'node-a','commit':'ae9c62693839ce7effa2b45df31c0039ae4f9fbc'}))
        (self.root / 'relay/reports').mkdir(parents=True)
        self.calls = []
        self.deleted = False
        self.marker = None
        self.create_status = 201
        self.fail_warmup = False
        self.bad_owner = False
        self.manifest = b'{"layers":[{"size":1}],"config":{"size":1}}'

    def tearDown(self):
        assert self.root.resolve().parent == HERE.parent.resolve()
        shutil.rmtree(self.root)

    def api(self, method, path, data=None, timeout=20):
        self.calls.append((method, path))
        if path == '/health': return 204, None
        if path == '/sandboxes-cold':
            self.assertEqual(data['cpuCount'], 1)
            self.assertEqual(data['memoryMB'], 512)
            self.assertFalse(data['autoPause'])
            self.assertFalse(data['allowInternetAccess'])
            self.marker = data['metadata']['cow_parent_run']
            return self.create_status, {'sandboxID':'owned-parent'}
        if path.endswith('/snapshots'): return 201, {'snapshotID':'owned-snapshot'}
        self.assertEqual(path, '/sandboxes/owned-parent')
        if method == 'DELETE': self.deleted = True; return 204, None
        if self.deleted: return 404, None
        return 200, {'metadata': {'cow_parent_run': 'foreign' if self.bad_owner else self.marker}}

    def run_fixture(self):
        def safe(path):
            path = Path(path)
            self.assertTrue(path.resolve().is_relative_to(self.root.resolve()))
            return path
        def read(path, limit=1024*1024):
            raw = safe(path).read_bytes()
            self.assertLessEqual(len(raw), limit)
            return raw
        def mkdtemp(prefix, dir):
            path=Path(dir)/(prefix+uuid.uuid4().hex[:5]);path.mkdir(mode=0o755);return str(path)
        def child(command, env, log, timeout):
            if 'manifest' in command: log.write_bytes(self.manifest)
            elif 'exec' in command:
                if self.fail_warmup: raise RuntimeError('Guest import failed')
                log.write_bytes(b'COW_PARENT_WORKLOAD_IMPORT_OK')
            else: log.write_bytes(b'copy complete')
        argv=['parent','--image','registry.example/repo@sha256:'+hashlib.sha256(self.manifest).hexdigest(),
              '--workdir','/repo','--warm-module','sample']
        with contextlib.ExitStack() as st:
            for name,value in [('ROOT',self.root),('BASE',self.base),('PENDING',self.root/'relay/cow-parent-node-a.pending.json'),
                               ('safe',safe),('read',read),('Api',lambda: types.SimpleNamespace(key='e2b_fixture',call=self.api)),
                               ('checked_process',child),('verify_layout',lambda *a:{'fixture':True})]:
                st.enter_context(patch.object(p,name,value))
            st.enter_context(patch.object(p.tempfile,'mkdtemp',mkdtemp))
            st.enter_context(patch.object(sys,'platform','linux'))
            st.enter_context(patch.object(sys,'argv',argv))
            st.enter_context(patch.object(p.socket,'gethostname',return_value='server1'))
            for name,value in [('getuid',1204),('geteuid',1204),('getgid',1205),('getegid',1205)]:
                st.enter_context(patch.object(p.os,name,return_value=value,create=True))
            st.enter_context(patch.object(p.os,'uname',return_value=types.SimpleNamespace(machine='aarch64'),create=True))
            st.enter_context(patch.object(p.os,'statvfs',return_value=types.SimpleNamespace(f_bavail=10000000,f_frsize=4096),create=True))
            st.enter_context(patch.object(p.os,'umask'))
            st.enter_context(patch.dict(p.os.environ,{'HOME':'/home/jwk'}))
            st.enter_context(patch.dict(sys.modules,{'fcntl':types.SimpleNamespace(flock=lambda *a:None,LOCK_EX=1,LOCK_NB=2)}))
            real_read=Path.read_text
            def proc_read(path,*a,**kw):
                if path.as_posix()=='/proc/self/status': return 'CapInh: 0\nCapPrm: 0\nCapEff: 0\nCapAmb: 0\n'
                return real_read(path,*a,**kw)
            st.enter_context(patch.object(Path,'read_text',proc_read))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                rc=p.main()
            report=json.loads(output.getvalue().split('BEGIN_RETURN_REPORT')[1].split('END_RETURN_REPORT')[0])
            return rc,report

    def test_capture_retains_snapshot_and_releases_only_own_parent(self):
        rc,r=self.run_fixture()
        self.assertEqual(rc,0)
        self.assertEqual(r['snapshot_id'],'owned-snapshot')
        self.assertTrue(r['parent_deleted'])
        self.assertTrue(r['temporary_cli_credentials_removed'])
        self.assertEqual(self.calls.count(('POST','/sandboxes-cold')),1)
        self.assertEqual([x for x in self.calls if x[0]=='DELETE'],[('DELETE','/sandboxes/owned-parent')])

    def test_failed_warmup_still_releases_known_parent(self):
        self.fail_warmup=True
        rc,r=self.run_fixture()
        self.assertEqual(rc,1)
        self.assertTrue(r['parent_deleted'])
        self.assertIsNone(r['snapshot_id'])

    def test_uncertain_create_is_not_retried_or_arbitrarily_deleted(self):
        self.create_status=500
        rc,r=self.run_fixture()
        self.assertEqual(rc,1)
        self.assertTrue(r['create_outcome_uncertain'])
        self.assertFalse(any(x[0]=='DELETE' for x in self.calls))
        self.assertEqual(self.calls.count(('POST','/sandboxes-cold')),1)
        before=list(self.calls)
        rc,r=self.run_fixture()
        self.assertEqual(r['status'],'PARENT_RECEIPT_EXISTS_NO_NEW_CREATE')
        self.assertEqual(self.calls,before)

    def test_foreign_ownership_marker_prevents_delete(self):
        self.bad_owner=True
        rc,r=self.run_fixture()
        self.assertEqual(rc,1)
        self.assertFalse(r['parent_deleted'])
        self.assertFalse(any(x[0]=='DELETE' for x in self.calls))


if __name__=='__main__': unittest.main(verbosity=2)
