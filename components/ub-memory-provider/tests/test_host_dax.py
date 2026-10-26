"""Host-side adapter tests. Mocked S_DAX is NOT pmem/UB hardware acceptance."""
from dataclasses import asdict
import hashlib
import mmap
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import types
import unittest
from unittest import mock

from aenv_ub_provider import host_dax, stored


class HostDax(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.gettempdir()) / ('host-dax-test-' + os.urandom(8).hex())
        self.root.mkdir(mode=0o777)
        self.path = (self.root / 'layer').resolve()
        self.data = bytes(range(256)) * 33
        self.path.write_bytes(self.data)
        self.replica = stored.Replica(str((self.root / 'b.sock').resolve()),
            'aenv_' + '1' * 32, '2' * 32,
            'sha256:' + hashlib.sha256(self.data).hexdigest(), len(self.data), stored.ALIGN)
        # Supply Unix open flags as zero on Windows only in the local model.
        def model_pread(fd, count, offset):
            os.lseek(fd, offset, os.SEEK_SET)
            return os.read(fd, count)
        proxy = types.SimpleNamespace(open=lambda path, flags: os.open(path, flags | getattr(os, 'O_BINARY', 0)),
            close=os.close, O_RDONLY=os.O_RDONLY,
            pread=getattr(os, 'pread', model_pread),
            O_CLOEXEC=getattr(os, 'O_CLOEXEC', 0), O_NOFOLLOW=getattr(os, 'O_NOFOLLOW', 0),
            O_NONBLOCK=getattr(os, 'O_NONBLOCK', 0))
        self.os_patch = mock.patch.object(host_dax, 'os', proxy)
        self.os_patch.start()
        self.addCleanup(self.os_patch.stop)
        self.validate = mock.patch.object(host_dax.fsdax, 'validate_fd', return_value={'activeDax': True})
        self.validator = self.validate.start()
        self.addCleanup(self.validate.stop)

    def mapping(self, replica=None):
        value = host_dax.StoredDaxMapping(str(self.path), replica or self.replica)
        self.addCleanup(value.close)
        return value

    def catalog(self):
        return {'version': 1, 'files': [{'path': str(self.path), 'replica': asdict(self.replica)}]}

    def test_non_dax_rejected_before_mapping_and_payload_reads(self):
        self.validator.side_effect = ValueError('no S_DAX')
        with mock.patch.object(host_dax.mmap, 'mmap') as mapping:
            with self.assertRaisesRegex(ValueError, 'S_DAX'):
                self.mapping()
            mapping.assert_not_called()

    def test_read_iter_uses_pread_without_mmap_and_checks_dax_on_each_read(self):
        with mock.patch.object(host_dax.mmap, 'mmap') as mapping:
            value = host_dax.StoredDaxMapping(str(self.path), self.replica, 'read_iter')
            self.addCleanup(value.close)
            self.assertEqual(value.read(4096 + 17, 300), self.data[17:317])
            mapping.assert_not_called()
            self.validator.side_effect = ValueError('DAX changed')
            with mock.patch.object(host_dax.os, 'pread') as pread:
                with self.assertRaisesRegex(ValueError, 'DAX changed'):
                    value.read(4096, 1)
                pread.assert_not_called()

    def test_read_iter_short_read_does_not_retry_or_fallback(self):
        value = host_dax.StoredDaxMapping(str(self.path), self.replica, 'read_iter')
        self.addCleanup(value.close)
        with mock.patch.object(host_dax.os, 'pread', return_value=b'') as pread:
            with self.assertRaisesRegex(OSError, 'Short Host DAX'):
                value.read(4096, 10)
            pread.assert_called_once()

    def test_read_iter_catalog_is_explicit_and_legacy_keeps_mmap(self):
        for version, expected in [(1, 'mmap'), (2, 'read_iter')]:
            catalog = self.catalog()
            if version == 2:
                catalog.update(version=2, access='read_iter')
            with mock.patch.object(host_dax, 'StoredDaxMapping') as mapping:
                host_dax.open_publication(catalog)
                self.assertEqual(mapping.call_args.args[2], expected)
        catalog.update(access='auto')
        with self.assertRaises(ValueError):
            host_dax.open_publication(catalog)

    def test_read_ranges_cover_header_gap_payload_and_padding(self):
        value = self.mapping()
        expected = self.replica.header().ljust(stored.HEADER_BYTES, b'\0') + self.data
        expected = expected.ljust(self.replica.mappingBytes, b'\0')
        for offset, length in [(0, 80), (64, 100), (4090, 32), (4096, 8192),
                               (4096 + len(self.data) - 3, 16), (self.replica.mappingBytes, 0)]:
            self.assertEqual(value.read(offset, length), expected[offset:offset + length])

    def test_invalid_ranges_fail(self):
        value = self.mapping()
        for offset, count in [(-1, 1), (0, -1), (0, stored.CHUNK + 1),
                              (self.replica.mappingBytes, 1), (True, 1)]:
            with self.assertRaises(ValueError):
                value.read(offset, count)

    def test_hash_mismatch_closes_opened_fd(self):
        bad = stored.replace(self.replica, layerDigest='sha256:' + '0' * 64)
        with mock.patch.object(host_dax.os, 'close', wraps=os.close) as close:
            with self.assertRaisesRegex(ValueError, 'content differs'):
                host_dax.StoredDaxMapping(str(self.path), bad)
            self.assertEqual(close.call_count, 1)

    def test_no_payload_is_retained_outside_mapping(self):
        value = self.mapping()
        value.read(4096, 1024)
        self.assertEqual({k for k, v in vars(value).items() if isinstance(v, (bytes, bytearray))}, {'header'})
        self.assertLess(len(value.header), stored.HEADER_BYTES)
        value.close()
        with self.assertRaises(RuntimeError):
            value.read(4096, 1)

    def test_fallback_and_duplicates_rejected_before_any_mapping(self):
        for change in ('fallback', 'duplicate'):
            catalog = self.catalog()
            if change == 'fallback':
                catalog['files'][0]['replica']['allowRepositoryFallback'] = True
            else:
                catalog['files'] *= 2
            with mock.patch.object(host_dax, 'StoredDaxMapping') as mapping:
                with self.assertRaises(ValueError):
                    host_dax.open_publication(catalog)
                mapping.assert_not_called()

    def test_later_open_failure_closes_previous_mapping(self):
        catalog = self.catalog()
        second = stored.replace(self.replica, objectName='aenv_' + '3' * 32, layerDigest='sha256:' + '4' * 64)
        catalog['files'].append({'path': str(self.root / 'second'), 'replica': asdict(second)})
        first = mock.Mock()
        with mock.patch.object(host_dax, 'StoredDaxMapping', side_effect=[first, OSError('missing')]):
            with self.assertRaises(OSError):
                host_dax.open_publication(catalog)
        first.close.assert_called_once_with()

    def test_busy_broker_cannot_unmap(self):
        broker, mapping = mock.Mock(), mock.Mock()
        broker.stop.side_effect = RuntimeError('reader live')
        with self.assertRaises(RuntimeError):
            host_dax.close_publication(broker, [mapping])
        mapping.close.assert_not_called()
        broker.stop.side_effect = None
        host_dax.close_publication(broker, [mapping])
        mapping.close.assert_called_once_with()

    def test_real_broker_wire_reads_dax_adapter_bytes_and_releases_lease(self):
        value = self.mapping()
        released = threading.Event()

        class Payload:
            def __init__(self, data):
                self.data = data

            def __len__(self):
                return len(self.data)

            def __radd__(self, prefix):
                return prefix + self.data

            def __del__(self):
                released.set()

        # Lifetime sentinel wraps the actual bytes read through the adapter.
        reader = types.SimpleNamespace(read=lambda offset, count: Payload(value.read(offset, count)))
        broker = stored.Broker([self.replica], [reader], uid=None)
        broker.uid = None
        server, client = socket.socketpair()
        client.settimeout(3)
        thread = threading.Thread(target=broker.handle, args=(server,))
        thread.start()
        try:
            r = self.replica
            client.sendall(stored.MAGIC + struct.pack('>H', 37) + r.objectName.encode()
                + bytes.fromhex(r.generation) + struct.pack('>QQ', r.fileBytes, r.mappingBytes)
                + bytes.fromhex(r.layerDigest[7:]))
            self.assertEqual(stored.recv_exact(client, 16), stored.RESPONSE.pack(stored.MAGIC, 0, 0))
            self.assertEqual(broker.active, 1)
            with self.assertRaises(RuntimeError):
                host_dax.close_publication(broker, [value])
            self.assertIsNotNone(value.mapping)
            client.sendall(struct.pack('>QI', 251, 517))
            self.assertEqual(stored.recv_exact(client, 16), stored.RESPONSE.pack(stored.MAGIC, 0, 517))
            self.assertEqual(stored.recv_exact(client, 517), self.data[251:768])
            self.assertTrue(released.wait(2), 'Idle lease retains its last payload')
        finally:
            client.close()
            thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual((broker.active, broker.reads, broker.bytes), (0, 1, 517))


if __name__ == '__main__':
    unittest.main()
