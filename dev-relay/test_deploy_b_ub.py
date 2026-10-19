"""B adapter/config/staging controls; no SDK, root, service or remote execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import types
import unittest
import uuid
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('B_deployment_test', HERE / 'deploy_b_ub.py')
b = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = b
spec.loader.exec_module(b)
c = b.core


class Tests(unittest.TestCase):
    def setUp(self):
        self.path = HERE.parent / ('.b-unit-' + uuid.uuid4().hex[:6])
        self.path.mkdir(mode=0o755)
        self.real_stat = os.stat
        self.real_read = Path.read_text

    def tearDown(self):
        assert self.path.resolve().parent == HERE.parent.resolve()
        shutil.rmtree(self.path)

    def put(self, path, data, mode=0o600):
        self.assertTrue(Path(path).resolve().is_relative_to(self.path.resolve()))
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        if path.exists():
            if path.read_bytes() != data: raise RuntimeError('Existing different file preserved')
        else:
            with path.open('xb') as stream: stream.write(data)

    def test_B_config_uses_B_unit_paths_identity_and_shared_build_hashes(self):
        self.assertEqual(c.NODE, 'node-b')
        self.assertEqual(c.EXPECTED_HOST, 'agent1')
        self.assertEqual(c.UNIT, 'jwk-aenv-ub-b019f27-node-b.service')
        self.assertTrue(str(c.RUNTIME).endswith('ub-b-b019'))
        cfg = c.config_text()
        self.assertIn('node_id = "ub-node-b"', cfg)
        self.assertIn('service_instance_id = "jwk-aenv-ub-b019f27-node-b"', cfg)
        self.assertNotIn('ub-node-a', cfg)
        self.assertEqual(c.BINARIES['server'], 'e8ea6c30704ec511f0b2a479313bb4cd4f71d25adc5acb6548adafe5f980b231')

    def test_A_config_remains_identical_to_the_deployed_fdadce3_version(self):
        raw = subprocess.check_output(['git', 'show', 'fdadce3f239d71ea0537465419ac0f9fb1074ecb:dev-relay/deploy_a_ub.py'], cwd=HERE)
        old = types.ModuleType('old_A_config')
        old.__file__ = str(HERE / 'deploy_a_ub.py')
        exec(compile(raw, old.__file__, 'exec'), old.__dict__)
        spec = importlib.util.spec_from_file_location('new_A_config', HERE / 'deploy_a_ub.py')
        new = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(new)
        for mod in (old, new):
            mod.D = PurePosixPath('/home/jwk/agent/deployments/agentenv-ub-b019f27')
            mod.RUNTIME = PurePosixPath('/home/jwk/agent/r/ub-a-b019')
        self.assertEqual(old.config_text(), new.config_text())

    def test_B_stages_wrapper_and_library_with_dependency_hash_without_touching_A(self):
        dest = self.path / 'B'
        wrapper = dest / 'libexec/deploy_b_ub.py'
        with patch.object(c, 'D', dest), patch.object(c, 'LAUNCHER', wrapper), patch.object(c, 'put', self.put):
            dependencies = b.stage_b_launcher()
        self.assertEqual(wrapper.read_bytes(), (HERE / 'deploy_b_ub.py').read_bytes())
        library = dest / 'libexec/deploy_a_ub.py'
        self.assertEqual(dependencies, {library.name: hashlib.sha256(library.read_bytes()).hexdigest()})

    def prepare_fixture(self, active):
        base = self.path / 'original'
        base.mkdir()
        (base / 'installation.json').write_text(json.dumps({'revision': 'aenv-offline-install-start-v4',
            'node': 'node-b', 'boot_id': 'old', 'host_netns': 1, 'host_mntns': 2,
            'launcher': '/original/launcher', 'preserve': 'unchanged'}))
        (self.path / 'relay/reports').mkdir(parents=True)
        def safe(path, exists=False):
            p = Path(path)
            if not p.resolve().is_relative_to(self.path.resolve()): raise ValueError('outside')
            if exists and not p.exists(): raise ValueError('missing')
            return p
        def stable(path, limit=512*1024**2): return path.read_bytes(), path.stat()
        def directory(path): path.mkdir(parents=True, exist_ok=True, mode=0o755)
        def mkdtemp(prefix, dir):
            p = Path(dir) / ('run-' + uuid.uuid4().hex[:6]); p.mkdir(mode=0o755); return str(p)
        def read(p, *args, **kwargs):
            if p.as_posix() == '/proc/sys/kernel/random/boot_id': return 'new'
            return self.real_read(p, *args, **kwargs)
        def fs_stat(path, *args, **kwargs):
            value = Path(path).as_posix() if not isinstance(path, int) else ''
            if value.startswith('/proc/self/ns/'):
                return types.SimpleNamespace(st_ino=11 if value.endswith('/net') else 12)
            return self.real_stat(path, *args, **kwargs)
        patches = [patch.object(c, 'ROOT', self.path), patch.object(c, 'BASE', base),
                   patch.object(c, 'ARTIFACTS', self.path / 'incoming'), patch.object(c, 'identity'),
                   patch.object(c, 'no_caps'), patch.object(c, 'safe', safe), patch.object(c, 'mkdir', directory),
                   patch.object(c, 'put', self.put), patch.object(c, 'stable_file', stable),
                   patch.object(c, 'properties', return_value={'ActiveState': 'active' if active else 'inactive', 'MainPID': '123' if active else '0'}),
                   patch.object(b, 'original_receipt', side_effect=lambda: (json.loads((base / 'installation.json').read_text()), base / 'launcher')),
                   patch.object(c.tempfile, 'mkdtemp', mkdtemp), patch.object(Path, 'read_text', read),
                   patch.object(c.os, 'stat', fs_stat), patch.object(c.os, 'O_NOFOLLOW', 0, create=True),
                   patch.dict(sys.modules, {'fcntl': types.SimpleNamespace(flock=lambda *a: None, LOCK_EX=0, LOCK_NB=0)})]
        return base, patches

    def test_prepare_after_reboot_changes_only_original_launcher_context_fields(self):
        base, patches = self.prepare_fixture(False)
        with contextlib.ExitStack() as stack:
            for p in patches: stack.enter_context(p)
            before = json.loads((base / 'installation.json').read_text())
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(b.prepare(), 0)
            after = json.loads((base / 'installation.json').read_text())
            self.assertEqual({k for k in after if after[k] != before[k]}, {'boot_id', 'host_netns', 'host_mntns'})
            self.assertTrue((self.path / 'incoming/input-definition.json').is_file())

    def test_active_original_with_stale_boot_context_is_not_rewritten(self):
        base, patches = self.prepare_fixture(True)
        before = (base / 'installation.json').read_bytes()
        with contextlib.ExitStack() as stack:
            for p in patches: stack.enter_context(p)
            with self.assertRaises(RuntimeError): b.prepare()
        self.assertEqual((base / 'installation.json').read_bytes(), before)

    def test_root_printed_block_is_pinned_and_never_executed_by_wrapper(self):
        text = (HERE / 'start_b_both_REVIEW_ONLY.txt').read_bytes()
        self.assertEqual(hashlib.sha256(text).hexdigest(), b.ROOT_TEXT_SHA256)
        self.assertNotIn('setfacl', text.decode())
        self.assertNotIn('modprobe', text.decode())
        self.assertNotIn('usermod', text.decode())


if __name__ == '__main__':
    unittest.main(verbosity=2)
