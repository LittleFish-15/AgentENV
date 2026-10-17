"""Actual broker/publisher logic with an in-memory SDK double; no UB hardware."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import socket
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('ub_layer_broker', Path(__file__).with_name('ub_layer_broker.py'))
b = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = b
SPEC.loader.exec_module(b)


class FakeMapping:
    def __init__(self, backend, name, writable):
        self.backend, self.name, self.writable, self.closed = backend, name, writable, False
        backend.store['refs'][name] += 1

    def read(self, offset, length):
        if self.closed:
            raise ValueError('closed mapping')
        return bytes(self.backend.store['data'][self.name][offset:offset + length])

    def write(self, offset, data):
        if self.closed or not self.writable:
            raise ValueError('not writable')
        self.backend.store['data'][self.name][offset:offset + len(data)] = data

    def close(self):
        if not self.closed:
            self.closed = True
            self.backend.store['refs'][self.name] -= 1


class FakeSdk:
    def __init__(self, store=None, allocate_failure=False):
        self.store = store if store is not None else {'data': {}, 'refs': {}}
        self.mappings, self.allocations, self.deletions = [], [], []
        self.allocate_failure = allocate_failure
        self.finalized = False

    def initialize(self):
        self.finalized = False

    def allocate(self, replica):
        self.allocations.append(replica.objectName)
        if self.allocate_failure:
            raise b.SdkError('allocate', 6025)
        if replica.objectName in self.store['data']:
            raise b.SdkError('allocate', 6021)
        self.store['data'][replica.objectName] = bytearray(replica.mappingBytes)
        self.store['refs'][replica.objectName] = 0

    def map(self, replica, writable=False):
        if replica.objectName not in self.store['data']:
            raise b.SdkError('map', 6020)
        mapped = FakeMapping(self, replica.objectName, writable)
        self.mappings.append(mapped)
        return mapped

    def deallocate(self, replica):
        if self.store['refs'][replica.objectName]:
            raise b.SdkError('deallocate', 6017)
        self.deletions.append(replica.objectName)
        del self.store['data'][replica.objectName]

    def close_maps(self):
        for mapped in self.mappings:
            mapped.close()

    def finalize(self):
        assert all(m.closed for m in self.mappings)
        self.finalized = True


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.test_root = Path(__file__).resolve().parents[2]
        self.path = self.test_root / ('.ub-unit-' + uuid.uuid4().hex[:12])
        self.path.mkdir(mode=0o755)
        self.source = self.path / 'layer.commit'
        self.data = bytes(range(256)) * 1025
        self.source.write_bytes(self.data)
        self.digest = 'sha256:' + hashlib.sha256(self.data).hexdigest()
        self.sdk = FakeSdk()
        self.publisher = b.Publisher(self.sdk, self.path / 'receipt.json')
        self.replicas, self.maps = self.publisher.publish(
            {self.digest: (self.source, len(self.data))}, self.path / 'broker.sock', b.ALIGN)
        self.replica = self.replicas[0]

    def tearDown(self):
        self.sdk.close_maps()
        assert self.path.resolve().is_relative_to(self.test_root.resolve())
        shutil.rmtree(self.path)

    def connect(self, broker, replica=None):
        replica = replica or self.replica
        client, server = socket.socketpair()
        client.settimeout(2)
        thread = threading.Thread(target=broker.handle, args=(server,))
        thread.start()
        name = replica.objectName.encode()
        client.sendall(b.MAGIC + struct.pack('>H', len(name)) + name
                       + bytes.fromhex(replica.generation)
                       + struct.pack('>QQ', replica.fileBytes, replica.mappingBytes)
                       + bytes.fromhex(replica.layerDigest[7:]))
        return client, thread

    def ack(self, client):
        return b.RESPONSE.unpack(b.recv_exact(client, 16))

    def test_publish_full_content_header_tail_and_readonly(self):
        b.verify_mapping(self.replica, self.maps[0])
        self.assertEqual(self.maps[0].read(b.HEADER_BYTES, len(self.data)), self.data)
        raw = self.sdk.store['data'][self.replica.objectName]
        self.assertFalse(any(raw[b.HEADER_BYTES + len(self.data):]))
        with self.assertRaises(ValueError):
            self.maps[0].write(b.HEADER_BYTES, b'x')
        self.assertEqual(b.read_json(self.publisher.journal)['state'], 'ready')

    def test_same_object_import_has_no_allocate_or_delete(self):
        reader = FakeSdk(self.sdk.store)
        mapped = reader.map(self.replica)
        b.verify_mapping(self.replica, mapped)
        self.assertEqual(reader.allocations, [])
        mapped.close()
        reader.finalize()
        self.assertEqual(reader.deletions, [])
        self.publisher.cleanup()
        self.assertEqual(len(self.sdk.deletions), 1)

    def test_new_generation_reuses_ancestor_object_without_owning_or_deleting_it(self):
        child_data = b'changed child layer'
        child = self.path / 'child.commit'
        child.write_bytes(child_data)
        child_digest = 'sha256:' + hashlib.sha256(child_data).hexdigest()
        child_sdk = FakeSdk(self.sdk.store)
        child_publisher = b.Publisher(child_sdk, self.path / 'child.json')
        replicas, _ = child_publisher.publish(
            {self.digest: (self.source, len(self.data)), child_digest: (child, len(child_data))},
            self.path / 'child.sock', 2 * b.ALIGN, reuse=self.replicas)
        self.assertEqual(replicas[0].objectName, self.replica.objectName)
        self.assertEqual(replicas[0].generation, self.replica.generation)
        self.assertEqual(len(child_sdk.allocations), 1)
        self.assertEqual(len(child_publisher.state['borrowed']), 1)
        child_publisher.cleanup()
        self.assertEqual(len(child_sdk.deletions), 1)
        self.assertIn(self.replica.objectName, self.sdk.store['data'])
        b.verify_mapping(self.replica, self.maps[0])

    def test_all_borrowed_generation_creates_and_deletes_no_objects(self):
        borrower = FakeSdk(self.sdk.store)
        publisher = b.Publisher(borrower, self.path / 'borrowed.json')
        replicas, _ = publisher.publish({self.digest: (self.source, len(self.data))},
                                        self.path / 'borrowed.sock', b.ALIGN, reuse=self.replicas)
        self.assertEqual(replicas[0].objectName, self.replica.objectName)
        self.assertEqual(publisher.state['new_allocation_bytes'], 0)
        publisher.cleanup()
        self.assertEqual(borrower.allocations, [])
        self.assertEqual(borrower.deletions, [])
        b.verify_mapping(self.replica, self.maps[0])

    def test_reused_ancestor_needs_no_duplicate_file_on_the_new_node(self):
        image = self.path / 'remote-ancestor.json'
        b.atomic_json(image, {'lowers': [{'file': str(self.path / 'not-copied.commit'),
                                         'digest': self.digest, 'size': len(self.data)}]})
        sources = b.source_layers([image], reuse=self.replicas)
        self.assertEqual(sources[self.digest], (None, len(self.data)))
        borrower = FakeSdk(self.sdk.store)
        publisher = b.Publisher(borrower, self.path / 'nocopy.json')
        replicas, _ = publisher.publish(sources, self.path / 'nocopy.sock', b.ALIGN, reuse=self.replicas)
        self.assertEqual(replicas[0].objectName, self.replica.objectName)
        self.assertEqual(borrower.allocations, [])
        publisher.cleanup()

    def test_remote_mapping_blocks_owner_delete_until_reader_releases(self):
        reader = FakeSdk(self.sdk.store)
        mapped = reader.map(self.replica)
        with self.assertRaises(b.SdkError):
            self.publisher.cleanup()
        self.assertFalse(b.read_json(self.publisher.journal)['objects'][0]['delete_acknowledged'])
        mapped.close()
        self.publisher.cleanup()
        self.assertEqual(b.read_json(self.publisher.journal)['state'], 'freed')

    def test_broker_exact_range_counts_and_disconnect_releases_lease(self):
        broker = b.Broker(self.replicas, self.maps)
        client, thread = self.connect(broker)
        self.assertEqual(self.ack(client), (b.MAGIC, 0, 0))
        self.assertEqual(broker.active, 1)
        client.sendall(struct.pack('>QI', 7, 913))
        self.assertEqual(self.ack(client), (b.MAGIC, 0, 913))
        self.assertEqual(b.recv_exact(client, 913), self.data[7:920])
        with self.assertRaises(RuntimeError):
            broker.stop()
        client.close()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(broker.stop(), {'read_requests': 1, 'read_bytes': 913, 'active_leases': 0})

    def test_stale_generation_digest_and_size_are_rejected(self):
        for key, value in [('generation', 'f' * 32), ('layerDigest', 'sha256:' + 'e' * 64),
                           ('fileBytes', self.replica.fileBytes + 1), ('mappingBytes', 2 * b.ALIGN)]:
            with self.subTest(key=key):
                replica = b.replace(self.replica, **{key: value})
                broker = b.Broker(self.replicas, self.maps)
                client, thread = self.connect(broker, replica)
                self.assertEqual(self.ack(client), (b.MAGIC, 1, 0))
                client.close()
                thread.join(3)
                self.assertEqual(broker.active, 0)

    def test_invalid_ranges_are_errors_not_zero_bytes_success(self):
        for offset, length in [(len(self.data), 1), (2**64 - 1, 1), (0, 0), (0, b.CHUNK + 1)]:
            with self.subTest(offset=offset, length=length):
                broker = b.Broker(self.replicas, self.maps)
                client, thread = self.connect(broker)
                self.assertEqual(self.ack(client)[1], 0)
                client.sendall(struct.pack('>QI', offset, length))
                self.assertEqual(self.ack(client), (b.MAGIC, 1, 0))
                client.close()
                thread.join(3)

    def test_short_native_read_is_not_a_short_success(self):
        broker = b.Broker(self.replicas, self.maps)
        client, thread = self.connect(broker)
        self.ack(client)
        with patch.object(self.maps[0], 'read', return_value=b'bad'):
            client.sendall(struct.pack('>QI', 0, 10))
            self.assertEqual(self.ack(client), (b.MAGIC, 1, 0))
        client.close()
        thread.join(3)

    def test_retiring_rejects_new_acquire(self):
        broker = b.Broker(self.replicas, self.maps)
        broker.stop()
        client, thread = self.connect(broker)
        self.assertEqual(self.ack(client), (b.MAGIC, 1, 0))
        client.close()
        thread.join(3)

    def test_content_and_header_corruption_are_detected(self):
        raw = self.sdk.store['data'][self.replica.objectName]
        for offset in [0, b.HEADER_BYTES, b.HEADER_BYTES + len(self.data) - 1]:
            with self.subTest(offset=offset):
                raw[offset] ^= 1
                with self.assertRaises(ValueError):
                    b.verify_mapping(self.replica, self.maps[0])
                raw[offset] ^= 1

    def test_receipt_guard_prevents_new_name_retry(self):
        with self.assertRaises(ValueError):
            self.publisher.publish({self.digest: (self.source, len(self.data))}, self.path / 'b.sock', b.ALIGN)
        self.assertEqual(len(self.sdk.allocations), 1)

    def test_failed_unmap_does_not_delete_or_mark_freed(self):
        with patch.object(self.maps[0], 'close', side_effect=b.SdkError('unmap', 6012)):
            with self.assertRaises(b.SdkError):
                self.publisher.cleanup()
        self.assertEqual(self.sdk.deletions, [])
        self.assertNotEqual(b.read_json(self.publisher.journal)['state'], 'freed')
        self.assertFalse(self.maps[0].closed)

    def test_a_live_read_blocks_retirement_and_mapping_release(self):
        broker = b.Broker(self.replicas, self.maps)
        client, thread = self.connect(broker)
        self.ack(client)
        started, finish = threading.Event(), threading.Event()
        original_read = self.maps[0].read
        def pending_read(offset, length):
            started.set()
            if not finish.wait(3):
                raise RuntimeError('test read did not finish')
            return original_read(offset, length)
        try:
            with patch.object(self.maps[0], 'read', side_effect=pending_read):
                client.sendall(struct.pack('>QI', 0, 10))
                self.assertTrue(started.wait(2))
                with self.assertRaises(RuntimeError):
                    broker.stop()
                self.assertFalse(self.maps[0].closed)
                finish.set()
                self.assertEqual(self.ack(client), (b.MAGIC, 0, 10))
                self.assertEqual(b.recv_exact(client, 10), self.data[:10])
        finally:
            finish.set()
            client.close()
            thread.join(3)
        self.assertEqual(broker.active, 0)

    def test_confirmed_cleanup_allows_a_new_publication_and_preserves_history(self):
        self.publisher.cleanup()
        publisher = b.Publisher(self.sdk, self.publisher.journal)
        replicas, _ = publisher.publish({self.digest: (self.source, len(self.data))}, self.path / 'new.sock', b.ALIGN)
        self.assertNotEqual(replicas[0].objectName, self.replica.objectName)
        self.assertEqual(len(list(self.path.glob('owner-history-*.json'))), 1)
        publisher.cleanup()

    def test_budget_stops_before_allocate(self):
        sdk = FakeSdk()
        publisher = b.Publisher(sdk, self.path / 'budget.json')
        with self.assertRaises(ValueError):
            publisher.publish({self.digest: (self.source, len(self.data))}, self.path / 'b.sock', b.ALIGN - 1)
        self.assertEqual(sdk.allocations, [])
        self.assertFalse(publisher.journal.exists())

    def test_failed_allocate_retains_uncertain_name_and_never_deletes(self):
        sdk = FakeSdk(allocate_failure=True)
        publisher = b.Publisher(sdk, self.path / 'unknown.json')
        with self.assertRaises(b.SdkError):
            publisher.publish({self.digest: (self.source, len(self.data))}, self.path / 'b.sock', b.ALIGN)
        with self.assertRaises(RuntimeError):
            publisher.cleanup()
        state = b.read_json(publisher.journal)
        self.assertEqual(state['state'], 'unresolved_create')
        self.assertFalse(state['objects'][0]['creation_confirmed'])
        self.assertEqual(sdk.deletions, [])
        self.assertEqual(state['objects'][0]['replica']['objectName'], sdk.allocations[0])

    def test_bad_source_never_becomes_ready_and_own_create_can_be_cleaned(self):
        sdk = FakeSdk()
        publisher = b.Publisher(sdk, self.path / 'badsource.json')
        with self.assertRaises(ValueError):
            publisher.publish({'sha256:' + '0' * 64: (self.source, len(self.data))}, self.path / 'b.sock', b.ALIGN)
        self.assertFalse(publisher.published)
        publisher.cleanup()
        self.assertEqual(len(sdk.deletions), 1)

    def test_index_rejects_unready_duplicate_and_bad_namespace(self):
        path = self.path / 'index.json'
        for index in [b.index_for(self.replicas, 'retiring'), b.index_for(self.replicas * 2),
                      b.index_for([b.replace(self.replica, objectName='unrelated')])]:
            b.atomic_json(path, index)
            with self.assertRaises(ValueError):
                b.load_replicas(path)

    def test_index_roundtrip_rebinds_local_socket_and_keeps_identity(self):
        path = self.path / 'index.json'
        b.atomic_json(path, b.index_for(self.replicas))
        result = b.load_replicas(path, self.path / 'b.sock')[0]
        self.assertEqual(result.objectName, self.replica.objectName)
        self.assertEqual(result.generation, self.replica.generation)
        self.assertNotEqual(result.brokerSocket, self.replica.brokerSocket)

    def test_source_lower_selection_deduplicates_memory_and_rootfs(self):
        image = self.path / 'image.json'
        b.atomic_json(image, {'lowers': [{'file': str(self.source), 'digest': self.digest, 'size': len(self.data)}]})
        with patch.object(b, 'ROOT', self.path):
            selected = b.source_layers([image, image])
        self.assertEqual(selected, {self.digest: (self.source, len(self.data))})

    def test_source_selection_refuses_missing_remote_and_mismatched_size(self):
        image = self.path / 'image.json'
        for lower in [{'digest': self.digest, 'size': len(self.data)},
                      {'file': str(self.source), 'digest': self.digest, 'size': len(self.data) + 1},
                      {'file': str(self.source), 'digest': self.digest, 'size': len(self.data), 'targetFile': 'x'}]:
            b.atomic_json(image, {'lowers': [lower]})
            with patch.object(b, 'ROOT', self.path), self.assertRaises(ValueError):
                b.source_layers([image])

    @unittest.skipUnless(os.environ.get('AENV_UB_PROTOCOL_CLIENT'), 'compile the Rust wire test client first')
    def test_actual_rust_client_against_actual_python_broker(self):
        payload = bytes(range(256)) * 6144  # >1MiB, so the Rust client must split reads.
        source = self.path / 'large.commit'
        source.write_bytes(payload)
        digest = 'sha256:' + hashlib.sha256(payload).hexdigest()
        sdk = FakeSdk()
        publisher = b.Publisher(sdk, self.path / 'cross-language.json')
        replicas, mappings = publisher.publish({digest: (source, len(payload))}, self.path / 'w.sock', b.ALIGN)
        replica = replicas[0]
        broker = b.Broker(replicas, mappings)
        listener = socket.socket(socket.AF_INET if os.name == 'nt' else socket.AF_UNIX, socket.SOCK_STREAM)
        if os.name == 'nt':
            listener.bind(('127.0.0.1', 0))
            address = '127.0.0.1:' + str(listener.getsockname()[1])
        else:
            address = str(self.path / 'client.sock')
            listener.bind(address)
        listener.listen(1)
        def serve():
            client, _ = listener.accept()
            broker.handle(client)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            result = subprocess.run([os.environ['AENV_UB_PROTOCOL_CLIENT'], address,
                                     replica.objectName, replica.generation, replica.layerDigest,
                                     str(replica.fileBytes), str(replica.mappingBytes), 'read'],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('RUST_PYTHON_WIRE_TEST_PASSED', result.stdout)
        finally:
            listener.close()
            thread.join(3)
            sdk.close_maps()
        self.assertEqual(broker.active, 0)
        self.assertGreaterEqual(broker.reads, 3)
        publisher.cleanup()


if __name__ == '__main__':
    unittest.main(verbosity=2)
