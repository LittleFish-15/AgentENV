"""Direct-catalog failure contracts; Linux O_DIRECT itself needs native tests."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import lazy
from test_lazy_cache import Harness


class DirectCatalog(unittest.TestCase):
    def test_catalog_uses_direct_reader_and_checks_complete_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / 'layer'
            data = b'a' * lazy.CHUNK + b'tail'
            path.write_bytes(data)
            original_open = os.open
            calls = []
            def opened(name, flags):
                calls.append(flags)
                return original_open(name, os.O_RDONLY)
            def chunk(fd, identity, offset, count):
                self.assertEqual(os.fstat(fd).st_size, len(data))
                return data[offset:offset + count]
            with patch.object(lazy.contract, 'linux_only'), \
                 patch.object(lazy.os, 'O_DIRECT', 0x4000, create=True), \
                 patch.object(lazy.os, 'O_NOFOLLOW', 0x20000, create=True), \
                 patch.object(lazy.os, 'O_CLOEXEC', 0x80000, create=True), \
                 patch.object(lazy.os, 'open', side_effect=opened), \
                 patch.object(lazy, 'direct_range', side_effect=chunk) as reader:
                result = lazy.prepare_direct({lazy.digest(data): (path, len(data))}, root)
                self.assertEqual(reader.call_count, 2)
                self.assertEqual(result['layers'][0]['chunks'], [lazy.digest(data[:lazy.CHUNK]), lazy.digest(b'tail')])
                self.assertTrue(calls[0] & 0x4000)
                with self.assertRaises(ValueError):
                    lazy.prepare_direct({'sha256:' + '0' * 64: (path, len(data))}, root)

    def test_direct_error_is_not_retried_as_buffered_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve();path = root / 'layer';path.write_bytes(b'data')
            with patch.object(lazy.contract, 'linux_only'), \
                 patch.object(lazy.os, 'O_DIRECT', 0, create=True), \
                 patch.object(lazy.os, 'O_NOFOLLOW', 0, create=True), \
                 patch.object(lazy.os, 'O_CLOEXEC', 0, create=True), \
                 patch.object(lazy.os, 'open', side_effect=OSError('direct unsupported')) as opened:
                with self.assertRaises(OSError):lazy.prepare_direct({lazy.digest(b'data'):(path,4)},root)
                self.assertEqual(opened.call_count, 1)


class FillAccounting(unittest.TestCase):
    def test_first_fill_hit_and_eviction_refill_are_distinct(self):
        h = Harness(blocks=6)
        reader = h.reader()
        reader.read(h.key, 0, 1);reader.read(h.key, 0, 1)
        for block in range(1,5):reader.read(h.key, block*lazy.CHUNK, 1)
        reader.read(h.key, 0, 1)
        state = h.request('status')
        self.assertEqual(state['firstFills'], 5)
        self.assertEqual(state['refills'], 1)
        self.assertEqual(state['successfulFills'], 6)
        self.assertEqual(state['poolBytes'], 4*lazy.CHUNK)
        self.assertLessEqual(state['readyBytes'], state['poolBytes'])


if __name__ == '__main__':unittest.main()
