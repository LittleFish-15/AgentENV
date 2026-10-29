import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('finalize', HERE / 'C_finalize_windows_artifacts_v1.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def test_destination_rejects_escape(self):
        for value in ('../file', '/etc/file', 'C:\\file', 'x/../../file'):
            with self.assertRaises(RuntimeError):
                m.destination(value)
        self.assertEqual(m.destination('artifacts/original/bin/aenv'), ('artifacts', 'original', 'bin', 'aenv'))

    def test_actual_file_hash_mismatch_stops_without_mutation(self):
        root = HERE / ('hash-test-' + uuid.uuid4().hex[:8]); root.mkdir(mode=0o755)
        path = (root / 'payload').resolve(); path.write_bytes(b'actual-content')
        real_fstat = m.os.fstat
        def owned(fd):
            s = real_fstat(fd)
            return SimpleNamespace(**{key: getattr(s, key) for key in
                ('st_mode', 'st_size', 'st_dev', 'st_ino', 'st_mtime_ns', 'st_ctime_ns')}, st_uid=1204)
        with patch.object(m.os, 'fstat', side_effect=owned), \
             patch.object(m.os, 'O_NOFOLLOW', 0, create=True), patch.object(m.os, 'O_NONBLOCK', 0, create=True):
            m.verify(path, {'bytes': 14, 'sha256': hashlib.sha256(b'actual-content').hexdigest()})
            with self.assertRaisesRegex(RuntimeError, 'SHA differs'):
                m.verify(path, {'bytes': 14, 'sha256': '0' * 64})
        self.assertEqual(path.read_bytes(), b'actual-content')

    def test_wrong_size_refused(self):
        root = HERE / ('size-test-' + uuid.uuid4().hex[:8]); root.mkdir(mode=0o755)
        path = (root / 'payload').resolve(); path.write_bytes(b'abc')
        with patch.object(m.os, 'O_NOFOLLOW', 0, create=True), patch.object(m.os, 'O_NONBLOCK', 0, create=True):
            with self.assertRaisesRegex(RuntimeError, 'type/owner/length'):
                m.verify(path, {'bytes': 999, 'sha256': '0' * 64})


if __name__ == '__main__':
    unittest.main()
