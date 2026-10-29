import copy
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('transfer', Path(__file__).with_name('round003_transfer.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.item = {'sha256': 'a' * 64, 'bytes': 8, 'sourcePath': '/home/jwk/agent/test.bin',
                     'sourceIdentity': [1, 2, 8, 4, 5],
                     'placements': [{'node': 'node-c', 'path': 'images/test', 'executable': False}]}
        self.manifest = {'sourceNode': 'node-a', 'objects': [self.item]}
        self.plan = {'manifest': self.manifest, 'sourceIdentity': {'bootId': 'fixed'}, 'expiresAtUnix': 200}

    def test_manifest_valid_and_duplicate_rejected(self):
        with patch.object(m, 'safe_path'):
            m.validate_manifest(self.manifest)
            self.manifest['objects'].append(copy.deepcopy(self.item))
            with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
                m.validate_manifest(self.manifest)

    def test_destination_traversal_refused(self):
        with patch.object(m, 'safe_path'):
            for path in ('/etc/key', '../key', 'images/../../key', 'C:\\key'):
                self.item['placements'][0]['path'] = path
                with self.assertRaisesRegex(RuntimeError, 'placement'):
                    m.validate_manifest(self.manifest)

    def test_export_expired_without_file_access(self):
        with patch.object(m.time, 'time', return_value=201), patch.object(m, 'safe_path') as file:
            with self.assertRaisesRegex(RuntimeError, 'expired'):
                m.export_one(self.plan, 'node-c', 'get ' + 'a' * 64, io.BytesIO())
            file.assert_not_called()

    def test_export_changed_boot_refused(self):
        with patch.object(m.time, 'time', return_value=100), patch.object(m, 'identity', return_value={'bootId': 'other'}):
            with self.assertRaisesRegex(RuntimeError, 'boot'):
                m.export_one(self.plan, 'node-c', 'get ' + 'a' * 64, io.BytesIO())

    def test_arbitrary_shell_and_ungranted_node_refused(self):
        with patch.object(m.time, 'time', return_value=100), patch.object(m, 'identity', return_value={'bootId': 'fixed'}):
            for command in ('sh', 'get ' + 'a' * 64 + ';id', 'get ../key', 'scp -f /etc/passwd'):
                with self.assertRaisesRegex(RuntimeError, 'selected object'):
                    m.export_one(self.plan, 'node-c', command, io.BytesIO())
            with self.assertRaisesRegex(RuntimeError, 'not granted'):
                m.export_one(self.plan, 'node-d', 'get ' + 'a' * 64, io.BytesIO())

    def test_ssh_host_pinning_and_no_interactive_auth(self):
        argv = m.ssh_command({'sourceAddress': '192.0.2.1', 'sourcePort': 22}, Path('/key'), Path('/known'), 'a' * 64)
        for value in ('BatchMode=yes', 'IdentitiesOnly=yes', 'StrictHostKeyChecking=yes',
                      'HostKeyAlias=aenv-cd-source', 'GlobalKnownHostsFile=/dev/null', 'ClearAllForwardings=yes'):
            self.assertIn(value, argv)
        self.assertEqual(argv[-1], 'get ' + 'a' * 64)

    def test_unselected_digest_refused(self):
        with patch.object(m.time, 'time', return_value=100), patch.object(m, 'identity', return_value={'bootId': 'fixed'}):
            with self.assertRaisesRegex(RuntimeError, 'not granted'):
                m.export_one(self.plan, 'node-c', 'get ' + 'b' * 64, io.BytesIO())

    def test_export_source_stat_change_stops_before_data(self):
        from types import SimpleNamespace
        changed = SimpleNamespace(st_dev=1, st_ino=2, st_size=9, st_mtime_ns=4, st_ctime_ns=5)
        source = io.BytesIO(b'selected'); source.fileno = lambda: 9
        out = io.BytesIO()
        with patch.object(m.time, 'time', return_value=100), patch.object(m, 'identity', return_value={'bootId': 'fixed'}), \
             patch.object(m, 'safe_path', return_value=Path('fixture')), patch.object(m.os, 'open', return_value=9), \
             patch.object(m.os, 'O_NOFOLLOW', 0, create=True), patch.object(m.os, 'O_NONBLOCK', 0, create=True), \
             patch.object(m.os, 'fdopen', return_value=source), patch.object(m.os, 'fstat', return_value=changed):
            with self.assertRaisesRegex(RuntimeError, 'changed since'):
                m.export_one(self.plan, 'node-c', 'get ' + 'a' * 64, out)
        self.assertEqual(out.getvalue(), b'')


if __name__ == '__main__':
    unittest.main()
