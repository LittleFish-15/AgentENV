import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location('bridge', Path(__file__).with_name('round004_windows_prepare.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def test_changed_authorization_preserved(self):
        from types import SimpleNamespace
        with patch.object(m, 'hostkeys', return_value=[]), patch.object(Path, 'resolve', lambda p: p), \
             patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=1204)), \
             patch.object(Path, 'read_bytes', return_value=b'other-user-key'), patch.object(Path, 'unlink') as unlink:
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                m.prepare({'node': 'node-a', 'oldAuthorizationSha256': '0' * 64})
            unlink.assert_not_called()

    def test_matching_owned_authorization_only_removed(self):
        from types import SimpleNamespace
        raw = b'exact-reviewed-grant'
        with patch.object(m, 'hostkeys', return_value=[]), patch.object(Path, 'resolve', lambda p: p), \
             patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=1204)), \
             patch.object(Path, 'read_bytes', return_value=raw), patch.object(Path, 'unlink') as unlink:
            row = m.prepare({'node': 'node-a', 'oldAuthorizationSha256': m.hashlib.sha256(raw).hexdigest()})
            self.assertTrue(row['directExportKeysRemoved'])
            unlink.assert_called_once()

    def test_unknown_partial_not_deleted(self):
        from types import SimpleNamespace
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=0o100600, st_uid=0)), \
             patch.object(Path, 'unlink') as unlink:
            with self.assertRaisesRegex(RuntimeError, 'Unexpected partial'):
                m.inspect_partial(Path('unknown.partial'))
            unlink.assert_not_called()


if __name__ == '__main__':
    unittest.main()
