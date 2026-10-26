"""Source FD models and real broker threads; no UB hardware acceptance."""
import concurrent.futures
import ctypes
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import shutil
import uuid
import threading
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import direct, service, stored


class DirectSources(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.gettempdir()) / ('dr-' + uuid.uuid4().hex[:8])
        root.mkdir(mode=0o777)
        self.tmp = types.SimpleNamespace(name=str(root))
        self.addCleanup(shutil.rmtree, root)
        self.path = root.resolve() / 'lower'
        self.payload = bytes(range(256)) * 4100 + b'tail'
        self.path.write_bytes(self.payload)
        self.key = 'sha256:' + hashlib.sha256(self.payload).hexdigest()
        self.flags, self.reads = [], []
        def open_fd(path, flags):
            self.flags.append(flags)
            return os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        def readv(fd, buffers, offset):
            self.reads.append((offset, len(buffers[0])))
            os.lseek(fd, offset, os.SEEK_SET)
            data = os.read(fd, len(buffers[0]))
            buffers[0][:len(data)] = data
            return len(data)
        self.proxy = types.SimpleNamespace(open=open_fd, close=os.close, fstat=os.fstat,
            preadv=readv, sysconf=lambda key: 65536, O_DIRECT=0x4000, O_RDONLY=0,
            O_NOFOLLOW=0x20000, O_CLOEXEC=0x80000)
        p = patch.object(direct, 'os', self.proxy)
        p.start()
        self.addCleanup(p.stop)

    def sources(self):
        return {self.key: (self.path, len(self.payload))}

    def test_two_passes_use_same_fd_and_align_tail(self):
        files = direct.SourceSet(self.sources())
        self.addCleanup(files.close)
        with files.open(self.path) as stream:
            data = stream.read(stored.CHUNK) + stream.read(stored.CHUNK)
            self.assertEqual(stream.read(1), b'')
        self.assertEqual(data, self.payload)
        self.assertEqual(len(self.flags), 1)
        self.assertTrue(self.flags[0] & self.proxy.O_DIRECT)
        self.assertEqual(self.reads, [(0, 1048576), (1048576, 65536)] * 2)

    def test_changed_source_rejected_before_second_pass(self):
        files = direct.SourceSet(self.sources())
        self.addCleanup(files.close)
        self.path.write_bytes(self.payload + b'x')
        with self.assertRaisesRegex(ValueError, 'changed'):
            files.open(self.path).read(4096)

    def test_short_read_never_retries_buffered(self):
        self.proxy.preadv = lambda *args: 0
        with self.assertRaisesRegex(ValueError, 'Short direct'):
            direct.SourceSet(self.sources())
        self.assertEqual(len(self.flags), 1)

    def test_invalid_digest_never_initializes_sdk(self):
        backend = types.SimpleNamespace(initialize=lambda: self.fail('SDK called'))
        publisher = direct.Publisher(backend, Path(self.tmp.name) / 'journal')
        with self.assertRaisesRegex(ValueError, 'digest differs'):
            publisher.publish({'sha256:' + '0' * 64: (self.path, len(self.payload))}, '/x', 4194304)

    def test_unsupported_direct_io_stops_without_sdk(self):
        self.proxy.preadv = lambda *args: (_ for _ in ()).throw(OSError('EINVAL'))
        backend = types.SimpleNamespace(initialize=lambda: self.fail('SDK called'))
        with self.assertRaises(OSError):
            direct.Publisher(backend, Path(self.tmp.name) / 'journal').publish(self.sources(), '/x', 4194304)

    def test_non_tail_unaligned_read_rejected(self):
        stream = direct.DirectFile(self.path, len(self.payload))
        self.addCleanup(stream.close)
        with self.assertRaisesRegex(ValueError, 'Unaligned'):
            stream.read(3)

    def test_publish_uses_direct_factory_and_retains_failed_creation(self):
        backend = types.SimpleNamespace(initialize=lambda: None,
            allocate=lambda r: (_ for _ in ()).throw(RuntimeError('unknown allocation result')))
        publisher = direct.Publisher(backend, Path(self.tmp.name) / 'journal')
        with self.assertRaisesRegex(RuntimeError, 'unknown allocation'):
            publisher.publish(self.sources(), str(Path(self.tmp.name) / 'b'), 4194304)
        record = publisher.state['objects'][0]
        self.assertTrue(record['allocation_attempted'])
        self.assertFalse(record['creation_confirmed'])
        self.assertEqual(publisher.state['sourceReadMode'], 'O_DIRECT')

    def test_complete_publication_reads_back_one_object_without_buffered_source(self):
        memory, events = {}, []
        def allocate(replica):
            events.append('allocate')
            memory[replica.objectName] = bytearray(replica.mappingBytes)
        def mapping(replica, writable=False):
            events.append('writer' if writable else 'reader')
            target = memory[replica.objectName]
            def write(offset, data):
                self.assertTrue(writable)
                target[offset:offset + len(data)] = data
            return types.SimpleNamespace(read=lambda o, n: bytes(target[o:o+n]), write=write,
                close=lambda: events.append('close'), backing_coverage=replica.mappingBytes)
        backend = types.SimpleNamespace(initialize=lambda: events.append('initialize'),
                                        allocate=allocate, map=mapping)
        publisher = direct.Publisher(backend, Path(self.tmp.name) / 'journal')
        replicas, mappings = publisher.publish(self.sources(), str(Path(self.tmp.name) / 'b'), 4194304)
        self.assertEqual(events, ['initialize', 'allocate', 'writer', 'close', 'reader'])
        self.assertFalse(replicas[0].allowRepositoryFallback)
        self.assertTrue(publisher.published)
        self.assertEqual(mappings[0].read(stored.HEADER_BYTES, len(self.payload)), self.payload)
        self.assertEqual(len(self.flags), 1)


class Responses(unittest.TestCase):
    def test_blocked_sends_hold_global_payload_admission(self):
        broker = direct.Broker([], [], uid=0)
        entered = threading.Barrier(3)
        release = threading.Event()
        count_lock = threading.Lock()
        seen = []
        def read(offset, count):
            with count_lock:
                seen.append(offset)
                number = len(seen)
            if number <= 2:
                entered.wait(4)
                self.assertTrue(release.wait(4))
            return b'a' * count
        mapping = types.SimpleNamespace(read=read)
        stream = types.SimpleNamespace(settimeout=lambda t: None, sendall=lambda data: None)
        with concurrent.futures.ThreadPoolExecutor(3) as pool:
            jobs = [pool.submit(broker.send_payload, stream, mapping, i, 8) for i in range(2)]
            entered.wait(4)
            third = pool.submit(broker.send_payload, stream, mapping, 2, 8)
            try:
                self.assertEqual(broker.status()['activePayloadResponses'], 2)
                self.assertFalse(third.done())
            finally:
                release.set()
            for job in [*jobs, third]:
                job.result(4)
        self.assertEqual(broker.status()['peakPayloadResponses'], 2)
        self.assertEqual(broker.status()['activePayloadResponses'], 0)

    def test_send_failure_releases_budget_not_remote_ownership(self):
        broker = direct.Broker([], [], uid=0)
        stream = types.SimpleNamespace(settimeout=lambda t: None,
            sendall=lambda data: (_ for _ in ()).throw(BrokenPipeError()))
        mapping = types.SimpleNamespace(read=lambda o, n: b'a' * n)
        with self.assertRaises(BrokenPipeError):
            broker.send_payload(stream, mapping, 0, 3)
        self.assertEqual(broker.status()['activePayloadResponses'], 0)
        self.assertEqual(broker.status()['payloadFailures'], 1)
        self.assertFalse(broker.retiring)

    def test_direct_wire_matches_existing_protocol(self):
        broker = direct.Broker([], [], uid=0)
        sent = []
        stream = types.SimpleNamespace(settimeout=lambda t: None, sendall=sent.append)
        broker.send_payload(stream, types.SimpleNamespace(read=lambda o, n: b'abc'), 0, 3)
        self.assertEqual(b''.join(sent), stored.RESPONSE.pack(stored.MAGIC, 0, 3) + b'abc')

    def test_stale_peer_receipt_cannot_authorize_owner_release(self):
        manifest = {'ownerId': 'new', 'readers': ['b']}
        with patch.object(service, 'read_json', return_value={'version': 1, 'ownerId': 'old',
                'readerId': 'b', 'manifestSha256': service.identity(manifest), 'state': 'released'}):
            with self.assertRaisesRegex(ValueError, 'stale'):
                service.release_receipts({'operation': 'retire', 'peerReceipts': ['b.json']}, manifest)


@unittest.skipUnless(sys.platform == 'linux', 'Real O_DIRECT requires local Linux; never count this as UB test')
class NativeDirectIO(unittest.TestCase):
    def test_real_direct_tail(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve() / 'lower'
            data = b'abcd' * 262144 + b'eof'
            path.write_bytes(data)
            fd = os.open(path, os.O_RDONLY)
            try:
                os.fsync(fd)
                # Only this new synthetic test file. Never global drop_caches.
                os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                self.assertEqual(self.resident(fd, len(data)), 0)
            finally:
                os.close(fd)
            files = direct.SourceSet({'sha256:' + hashlib.sha256(data).hexdigest(): (path, len(data))})
            try:
                with files.open(path) as stream:
                    self.assertEqual(stream.read(stored.CHUNK) + stream.read(stored.CHUNK), data)
                    self.assertEqual(self.resident(stream.fileno(), len(data)), 0,
                                     'O_DIRECT test populated synthetic file PageCache')
            finally:
                files.close()

    @staticmethod
    def resident(fd, size):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                              ctypes.c_int, ctypes.c_int, ctypes.c_long]
        libc.mmap.restype = ctypes.c_void_p
        libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        address = libc.mmap(None, size, 0, 1, fd, 0)  # PROT_NONE, MAP_SHARED; no payload touch
        if address == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_errno(), 'Synthetic file observation mmap failed')
        try:
            pages = (size + os.sysconf('SC_PAGESIZE') - 1) // os.sysconf('SC_PAGESIZE')
            bits = (ctypes.c_ubyte * pages)()
            if libc.mincore(address, size, bits):
                raise OSError(ctypes.get_errno(), 'Synthetic file mincore failed')
            return sum(value & 1 for value in bits)
        finally:
            libc.munmap(address, size)


if __name__ == '__main__':
    unittest.main()
