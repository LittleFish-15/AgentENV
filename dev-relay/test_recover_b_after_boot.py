"""Reboot recovery controls; no real systemd/SDK/root actions."""
import ast
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import unittest
import uuid
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('restore_tested', HERE / 'recover_b_after_boot.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Tests(unittest.TestCase):
    def setUp(self):
        self.root = HERE.parent / ('.restore-' + uuid.uuid4().hex[:6])
        self.root.mkdir(mode=0o755)
        self.stack = contextlib.ExitStack()
        if os.name == 'nt':
            # Python 3.12's Windows 0700 ACL excludes the sandbox identity.
            # Only test fixtures use inherited ACLs; production Linux stays 0700.
            real_mkdir = Path.mkdir
            def fixture_mkdir(path, mode=0o777, parents=False, exist_ok=False):
                return real_mkdir(path, 0o755 if mode == 0o700 else mode, parents, exist_ok)
            self.stack.enter_context(patch.object(Path, 'mkdir', fixture_mkdir))
        self.stack.enter_context(patch.object(r, 'ROOT', self.root))
        self.stack.enter_context(patch.object(r, 'metadata', lambda p: r.safe(p).lstat()))
        self.stack.enter_context(patch.object(r, 'read', self.read))
        self.stack.enter_context(patch.object(r, 'digest', lambda p: hashlib.sha256(self.read(p)).hexdigest()))
        self.stack.enter_context(patch.object(r, 'unit_absent', return_value={}))
        self.stack.enter_context(patch.object(r, 'ports_free'))

    def tearDown(self):
        self.stack.close()
        assert self.root.resolve().parent == HERE.parent.resolve()
        shutil.rmtree(self.root)

    def read(self, path, limit=65536):
        raw = r.safe(path).read_bytes()
        r.require(len(raw) <= limit, 'Too big')
        return raw

    def fixture(self, old='11111111-1111-1111-1111-111111111111', stale=True):
        profile = list(r.PROFILES[1])
        base = self.root / 'deployments' / profile[1]
        runtime = self.root / 'r' / profile[2]
        (base / 'bin').mkdir(parents=True)
        (base / 'libexec').mkdir()
        (base / 'state').mkdir()
        (base / 'state/business-data').write_bytes(b'preserve')
        runtime.mkdir(parents=True)
        (runtime / 'definition.json').write_text('preserve-definition')
        hashes = {}
        for name in profile[7]:
            (base / 'bin' / name).write_bytes(name.encode())
            hashes[name] = hashlib.sha256(name.encode()).hexdigest()
        profile[7] = hashes
        launcher = base / 'libexec/deploy_b_ub.py'
        launcher.write_bytes(b'wrapper')
        library = base / 'libexec/deploy_a_ub.py'
        library.write_bytes(b'library')
        receipt = {'node': 'node-b', 'revision': profile[4], 'commit': profile[5],
                   'unit': profile[3], 'runtime': str(runtime), 'boot_id': old,
                   'host_netns': 1, 'host_mntns': 2, 'extra': 'preserve',
                   'launcher': str(launcher), 'launcher_sha256': r.digest(launcher),
                   'launcher_dependencies': {'deploy_a_ub.py': r.digest(library)}}
        (base / 'installation.json').write_text(json.dumps(receipt))
        if stale:
            (runtime / 'runtime-attestation.json').write_text(json.dumps({'revision': profile[4], 'pid': 123}))
            (runtime / 'host-proxy.json').write_text(json.dumps({'revision': profile[4], 'pid': 124}))
        work = self.root / 'report'
        work.mkdir()
        return tuple(profile), base, runtime, receipt, work

    def test_new_boot_archives_only_known_runtime_files_and_changes_three_fields(self):
        profile, base, runtime, before, work = self.fixture()
        plan = r.plan_profile(profile, '22222222-2222-2222-2222-222222222222', 11, 12)
        report = {'profiles': {}}
        r.apply_plan([plan], work, report)
        after = json.loads((base / 'installation.json').read_text())
        self.assertEqual({k for k in after if after[k] != before[k]}, {'boot_id', 'host_netns', 'host_mntns'})
        self.assertFalse((runtime / 'runtime-attestation.json').exists())
        self.assertTrue((work / 'modified/runtime-attestation.json').exists())
        self.assertEqual((runtime / 'definition.json').read_text(), 'preserve-definition')
        self.assertEqual((base / 'state/business-data').read_bytes(), b'preserve')
        self.assertEqual(json.loads((work / 'modified/installation-before.json').read_text()), before)

    def test_same_boot_stale_files_are_not_assumed_safe(self):
        profile, base, runtime, before, work = self.fixture()
        with self.assertRaisesRegex(RuntimeError, 'Same-boot'):
            r.plan_profile(profile, before['boot_id'], 1, 2)
        self.assertTrue((runtime / 'host-proxy.json').exists())
        self.assertEqual(json.loads((base / 'installation.json').read_text()), before)

    def test_same_boot_clean_context_can_be_reused_without_receipt_rewrite(self):
        profile, base, runtime, before, work = self.fixture(stale=False)
        raw = (base / 'installation.json').read_bytes()
        plan = r.plan_profile(profile, before['boot_id'], 1, 2)
        report = {'profiles': {}}
        r.apply_plan([plan], work, report)
        self.assertEqual((base / 'installation.json').read_bytes(), raw)
        self.assertFalse(report['profiles']['modified']['context_refreshed'])

    def test_changed_binary_blocks_before_mutation(self):
        profile, base, runtime, before, work = self.fixture()
        (base / 'bin/server').write_bytes(b'other')
        with self.assertRaisesRegex(RuntimeError, 'Binary differs'):
            r.plan_profile(profile, 'new', 11, 12)
        self.assertTrue((runtime / 'host-proxy.json').exists())

    def test_all_units_checked_before_first_archive(self):
        profile, base, runtime, before, work = self.fixture()
        plan = r.plan_profile(profile, 'new', 11, 12)
        with patch.object(r, 'unit_absent', side_effect=[{}, RuntimeError('unit active')]):
            with self.assertRaisesRegex(RuntimeError, 'active'):
                r.apply_plan([plan, plan], work, {'profiles': {}})
        self.assertTrue((runtime / 'host-proxy.json').exists())
        self.assertFalse((work / 'modified').exists())

    def test_changed_receipt_blocks_before_archive(self):
        profile, base, runtime, before, work = self.fixture()
        plan = r.plan_profile(profile, 'new', 11, 12)
        (base / 'installation.json').write_text(json.dumps(dict(before, extra='changed')))
        with self.assertRaisesRegex(RuntimeError, 'concurrently'):
            r.apply_plan([plan], work, {'profiles': {}})
        self.assertTrue((runtime / 'host-proxy.json').exists())

    def test_root_text_is_python_stdin_with_fixed_scope_not_shell_interpolation(self):
        source = r.ROOT_TEXT.split('\n', 1)[1].rsplit('\n', 1)[0]
        ast.parse(source)
        self.assertNotIn('$', r.ROOT_TEXT)
        for word in ('usermod', 'setfacl', 'setcap', 'reset-failed', "'stop'", "'restart'"):
            self.assertNotIn(word, source)
        self.assertIn("'User=jwk'", source)
        self.assertIn("'PrivateNetwork=yes'", source)
        self.assertIn("'Restart=no'", source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
