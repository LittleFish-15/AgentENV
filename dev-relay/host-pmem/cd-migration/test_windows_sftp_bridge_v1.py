import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('bridge', Path(__file__).with_name('windows_sftp_bridge_v1.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def test_sftp_injection_refused(self):
        for value in ('a\n!shell', '"unsafe"', 'a\\b', 'x\0y'):
            with self.assertRaises(RuntimeError):
                m.quote(value)
        self.assertEqual(m.quote('/home/jwk/agent/file with space'), '"/home/jwk/agent/file with space"')

    def test_expired_plan_before_transfer(self):
        with patch.object(m.time, 'time', return_value=10):
            with self.assertRaisesRegex(RuntimeError, 'expired'):
                m.validate({'sessionId': m.SESSION, 'version': 1, 'expiresAtUnix': 9})

    def test_hostkey_pinning_and_interactive_password_no_secret_argument(self):
        node = {'hostPublicKey': 'ssh-ed25519 AAAA', 'port': 22, 'address': '192.0.2.1'}
        with patch.object(m, 'ROOT', Path('fixture')), patch.object(Path, 'write_text'), \
             patch.object(m.shutil, 'which', return_value='sftp.exe'), patch.object(m.subprocess, 'run') as run:
            run.return_value.returncode = 0
            m.run_sftp('node-a', node, ['get "selected" "local"'], 'fixture')
            argv = run.call_args.args[0]
            for option in ('StrictHostKeyChecking=yes', 'BatchMode=no', 'PubkeyAuthentication=no',
                           'HostKeyAlgorithms=ssh-ed25519', 'NumberOfPasswordPrompts=1'):
                self.assertIn(option, argv)
            self.assertEqual(argv[-1], 'jwk@192.0.2.1')
            self.assertNotIn('input', run.call_args.kwargs)

    def test_empty_batch_no_connection(self):
        with patch.object(m.subprocess, 'run') as run:
            m.run_sftp('node-a', {}, [], 'fixture')
            run.assert_not_called()

    def test_redirect_credentials_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'redirect refused'):
            m.NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_unknown_partial_stops_before_sftp(self):
        from types import SimpleNamespace
        plan = {'objects': [{'sha256': 'a' * 64, 'bytes': 1}]}
        with patch.object(m.shutil, 'disk_usage', return_value=SimpleNamespace(free=2 * 1024**3)), \
             patch.object(Path, 'is_symlink', return_value=False), patch.object(Path, 'exists', return_value=True), \
             patch.object(m, 'run_sftp') as run:
            with self.assertRaisesRegex(RuntimeError, 'Prior partial'):
                m.transfer(plan, 'test', {})
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
