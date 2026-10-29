import importlib.util
from pathlib import Path
import unittest
import uuid

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('install', HERE / 'relay_install.py')
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


class InstallTests(unittest.TestCase):
    def test_repo_arguments_cannot_inject_shell_commands(self):
        for value in ('owner/repo;id', 'owner/repo\ncommand', 'https://example.com/repo', 'owner/repo extra'):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                install.launcher(value, 'owner/results')

    def test_control_and_results_must_differ(self):
        with self.assertRaises(RuntimeError):
            install.launcher('owner/one', 'owner/one')

    def test_launcher_contains_no_credentials_and_has_fixed_pinned_program(self):
        raw = install.launcher('owner/control', 'owner/results')
        self.assertNotIn(b'github_pat_', raw)
        self.assertNotIn(b'\r', raw)
        self.assertIn(install.RUNNER_NAME.encode(), raw)
        self.assertIn(b' enroll ', raw)
        self.assertIn(b' run\n', raw)

    def test_existing_different_entry_is_preserved(self):
        root = HERE.parents[1] / 't' / ('ri-' + uuid.uuid4().hex[:8])
        root.mkdir(mode=0o755, parents=True)
        target = root / 'start.sh'
        install.write_exact(target, b'original', 0o600)
        with self.assertRaises(RuntimeError):
            install.write_exact(target, b'different', 0o600)
        self.assertEqual(target.read_bytes(), b'original')

    def test_same_entry_can_be_reused_without_rewriting(self):
        root = HERE.parents[1] / 't' / ('ri-' + uuid.uuid4().hex[:8])
        root.mkdir(mode=0o755, parents=True)
        target = root / 'start.sh'
        install.write_exact(target, b'same', 0o600)
        before = target.stat().st_mtime_ns
        install.write_exact(target, b'same', 0o600)
        self.assertEqual(target.stat().st_mtime_ns, before)


if __name__ == '__main__':
    unittest.main()
