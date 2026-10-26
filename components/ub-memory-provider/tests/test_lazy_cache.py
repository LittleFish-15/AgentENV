"""Demand-cache concurrency, integrity and wire tests without SDK/VM access."""
import copy
import contextlib
import io
import json
from pathlib import Path, PurePosixPath
import socket
import struct
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import contract, lazy, lazy_service, raw, stored


def socket_fixture_root():
    # Dry validation does not create these paths. Socket names must be short
    # even when the source checkout (or TMPDIR) is deeply nested on Linux.
    root = Path('/tmp').resolve() if sys.platform == 'linux' else Path(tempfile.gettempdir()).resolve()
    return root / ('aenv-lc-' + uuid.uuid4().hex[:12])


class Mapping:
    def __init__(self, slots=4):
        self.bytes = bytearray(slots * lazy.CHUNK)
        self.writes = []
        self.corrupt = False

    def write(self, offset, data):
        self.writes.append((offset, len(data)))
        self.bytes[offset:offset + len(data)] = data

    def read(self, offset, count):
        data = bytes(self.bytes[offset:offset + count])
        return bytes([data[0] ^ 1]) + data[1:] if self.corrupt else data


class Harness:
    def __init__(self, blocks=6, tail=137):
        self.parts = [bytes([i + 1]) * lazy.CHUNK for i in range(blocks)]
        if tail:
            self.parts.append(b'T' * tail)
        self.payload = b''.join(self.parts)
        self.key = lazy.digest(self.payload)
        self.value = {'version': 1, 'chunkBytes': lazy.CHUNK, 'layers': [
            {'digest': self.key, 'fileBytes': len(self.payload), 'chunks': [lazy.digest(p) for p in self.parts]}]}
        self.mapping, self.calls, self.records = Mapping(), [], []
        self.tokens = {'owner': 'a' * 64, 'node-b': 'b' * 64}
        def source(key, block):
            self.calls.append((key, block))
            return self.parts[block]
        self.cache = lazy.Cache(self.value, self.mapping, 4, source, 'c' * 32, self.tokens,
                                lambda state: self.records.append(copy.deepcopy(state)))
        self.request('open-reader')
        self.request('open-reader', reader='node-b')

    def request(self, operation, reader='owner', **fields):
        return self.cache.request(dict(operation=operation, reader=reader, token=self.tokens[reader],
                                       cacheId='c' * 32, **fields))

    def reader(self, name='owner', request=None):
        return lazy.Reader(self.value, self.mapping, 4, 'c' * 32, name, self.tokens[name],
                           request or self.cache.request)


class DemandCache(unittest.TestCase):
    def test_startup_and_status_do_not_load_payload(self):
        h = Harness()
        state = h.request('status')
        self.assertEqual((state['readyBytes'], state['backendBytes'], state['pins']), (0, 0, 0))
        self.assertEqual(state['poolBytes'], 4 * lazy.CHUNK)
        self.assertEqual((h.calls, h.mapping.writes), ([], []))

    def test_two_readers_share_one_fill_and_return_exact_ranges(self):
        h = Harness()
        a, b = h.reader(), h.reader('node-b')
        self.assertEqual(a.read(h.key, 123, 200), h.payload[123:323])
        self.assertEqual(b.read(h.key, 11, 77), h.payload[11:88])
        self.assertEqual(h.calls, [(h.key, 0)])
        self.assertEqual(h.request('status')['pins'], 0)
        self.assertTrue(any(record['pins'] for record in h.records))

    def test_cross_chunk_and_short_tail_are_exact(self):
        h = Harness()
        reader = h.reader()
        offset = lazy.CHUNK - 19
        self.assertEqual(reader.read(h.key, offset, 55), h.payload[offset:offset + 55])
        offset = len(h.payload) - 79
        self.assertEqual(reader.read(h.key, offset, 79), h.payload[offset:])
        self.assertEqual([block for _, block in h.calls], [0, 1, 6])

    def test_original_one_mib_broker_read_spans_sixteen_small_chunks(self):
        h = Harness(blocks=20)
        data = h.reader().read(h.key, 0, stored.CHUNK)
        self.assertEqual(data, h.payload[:stored.CHUNK])
        self.assertEqual(len(h.calls), 16)
        self.assertEqual(h.request('status')['pins'], 0)

    def test_legacy_one_mib_catalog_is_rejected(self):
        h = Harness()
        value = copy.deepcopy(h.value)
        value['chunkBytes'] = 1024 * 1024
        with self.assertRaises(ValueError):
            lazy.catalog(value)

    def test_concurrent_missing_chunk_has_one_loader_and_no_early_grant(self):
        h = Harness()
        entered, release = threading.Event(), threading.Event()
        original = h.cache.source
        def source(*args):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('test source gate')
            return original(*args)
        h.cache.source = source
        results, failures = [], []
        def read(name):
            try:
                results.append(h.reader(name).read(h.key, 0, 64))
            except BaseException as error:
                failures.append(error)
        first = threading.Thread(target=read, args=('owner',))
        second = threading.Thread(target=read, args=('node-b',))
        first.start()
        self.assertTrue(entered.wait(5))
        second.start()
        with h.cache.condition:
            self.assertEqual(h.cache.loading, 1)
            self.assertFalse(h.cache.leases)
        self.assertFalse(results)
        release.set()
        first.join(5)
        second.join(5)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(results, [h.parts[0][:64]] * 2)
        self.assertEqual(h.calls, [(h.key, 0)])

    def test_pinned_slot_cannot_be_reused_and_capacity_deadline_refuses(self):
        h = Harness()
        grants = [h.request('acquire', digest=h.key, block=i) for i in range(4)]
        before = bytes(h.mapping.bytes)
        with patch.object(lazy.time, 'monotonic', side_effect=[0, 31]):
            with self.assertRaisesRegex(TimeoutError, 'pinned/loading'):
                h.request('acquire', digest=h.key, block=4)
        self.assertEqual(bytes(h.mapping.bytes), before)
        h.request('release', lease=grants[1]['lease'])
        grant = h.request('acquire', digest=h.key, block=4)
        self.assertEqual(grant['slot'], grants[1]['slot'])
        self.assertEqual(h.mapping.read(grants[0]['slot'] * lazy.CHUNK, 100), h.parts[0][:100])

    def test_lru_reloads_evicted_data_without_reusing_live_token(self):
        h = Harness()
        for block in range(5):
            h.reader().read(h.key, block * lazy.CHUNK, 1)
        self.assertEqual(h.request('status')['evictions'], 1)
        h.reader().read(h.key, 0, 1)
        self.assertEqual([block for _, block in h.calls], [0, 1, 2, 3, 4, 0])

    def test_bad_backend_data_is_never_published(self):
        h = Harness()
        h.cache.source = lambda *_: b'bad'
        with self.assertRaisesRegex(ValueError, 'catalog'):
            h.reader().read(h.key, 0, 1)
        self.assertEqual(h.mapping.writes, [])
        self.assertEqual(h.request('status')['readyBytes'], 0)
        with self.assertRaisesRegex(RuntimeError, 'fill failed'):
            h.request('acquire', digest=h.key, block=0)

    def test_bad_ub_fill_readback_is_never_ready(self):
        h = Harness()
        h.mapping.corrupt = True
        with self.assertRaisesRegex(ValueError, 'readback'):
            h.reader().read(h.key, 0, 1)
        self.assertFalse(h.cache.leases)
        self.assertEqual(h.request('status')['fillErrors'], 1)

    def test_import_read_is_verified_before_return_and_bad_mapping_pin_is_preserved(self):
        h = Harness()
        h.reader().read(h.key, 0, 1)
        h.mapping.corrupt = True
        reader = h.reader('node-b')
        with self.assertRaisesRegex(ValueError, 'integrity'):
            reader.read(h.key, 0, 5)
        self.assertTrue(reader.failed)
        self.assertEqual(len(h.cache.leases), 1)

    def test_lost_acquire_response_retains_pin_and_poisoned_reader_does_not_retry(self):
        h = Harness()
        def disconnected(request):
            h.cache.request(request)
            raise BrokenPipeError('grant delivery uncertain')
        reader = h.reader('node-b', disconnected)
        with self.assertRaises(BrokenPipeError):
            reader.read(h.key, 0, 1)
        self.assertEqual(len(h.cache.leases), 1)
        with self.assertRaisesRegex(RuntimeError, 'uncertain'):
            reader.read(h.key, 0, 1)
        with self.assertRaises(RuntimeError):
            h.request('reader-release', reader='node-b')
        with self.assertRaises(RuntimeError):
            h.cache.freeze()

    def test_wrong_reader_stale_lease_and_credentials_are_rejected(self):
        h = Harness()
        grant = h.request('acquire', digest=h.key, block=0)
        with self.assertRaises(ValueError):
            h.request('release', reader='node-b', lease=grant['lease'])
        h.request('release', lease=grant['lease'])
        with self.assertRaises(ValueError):
            h.request('release', lease=grant['lease'])
        for field in ('cacheId', 'token', 'reader'):
            request = dict(operation='status', reader='owner', token=h.tokens['owner'], cacheId='c' * 32)
            request[field] = 'wrong'
            with self.assertRaises(ValueError):
                h.cache.request(request)

    def test_release_then_freeze_refuses_new_reads(self):
        h = Harness()
        h.reader('node-b').release()
        with self.assertRaises(RuntimeError):
            h.reader('node-b').read(h.key, 0, 1)
        with self.assertRaises(RuntimeError):
            h.cache.freeze()
        h.reader().release()
        h.cache.freeze()
        self.assertEqual(h.request('status')['state'], 'frozen')

    def test_duplicate_importer_admission_is_rejected(self):
        h = Harness()
        with self.assertRaisesRegex(RuntimeError, 'duplicate importer'):
            h.request('open-reader', reader='node-b')
        h.reader('node-b').release()
        with self.assertRaises(RuntimeError):
            h.request('open-reader', reader='node-b')

    def test_journal_failure_prevents_grant_and_all_further_operations(self):
        h = Harness()
        h.cache.journal = lambda state: (_ for _ in ()).throw(OSError('fsync failed'))
        with self.assertRaises(OSError):
            h.reader().read(h.key, 0, 1)
        self.assertTrue(h.cache.poisoned)
        self.assertEqual(len(h.cache.leases), 1)
        with self.assertRaises(RuntimeError):
            h.request('status')

    def test_released_pin_checkpoint_is_conservative_until_next_grant(self):
        h = Harness()
        initial = len(h.records)
        first = h.request('acquire', digest=h.key, block=0)
        self.assertIn(first['lease'], h.records[-1]['pins'])
        h.request('release', lease=first['lease'])
        self.assertNotIn(first['lease'], h.cache.leases)
        self.assertIn(first['lease'], h.records[-1]['pins'])
        self.assertEqual(len(h.records), initial + 1)
        second = h.request('acquire', reader='node-b', digest=h.key, block=0)
        self.assertEqual(set(h.records[-1]['pins']), {second['lease']})
        self.assertEqual(set(h.cache.leases), set(h.records[-1]['pins']))
        self.assertEqual(h.calls, [(h.key, 0)])

    def test_grants_remain_durable_and_retirement_flushes_released_pins(self):
        h = Harness()
        initial = len(h.records)
        reader = h.reader()
        for _ in range(10):
            self.assertEqual(reader.read(h.key, 7, 11), h.payload[7:18])
            self.assertFalse(h.cache.leases)
            # Ten grants require ten commits, not a second commit per release.
        self.assertEqual(len(h.records) - initial, 10)
        reader.release()
        h.reader('node-b').release()
        h.cache.freeze()
        self.assertEqual(h.records[-1]['pins'], {})
        self.assertTrue(h.records[-1]['frozen'])
        self.assertEqual(set(h.records[-1]['releasedReaders']), {'owner', 'node-b'})

    def test_failed_next_checkpoint_does_not_grant_or_forget_unknown_pins(self):
        h = Harness()
        unknown = h.request('acquire', reader='node-b', digest=h.key, block=0)
        known = h.request('acquire', digest=h.key, block=0)
        h.request('release', lease=known['lease'])
        h.cache.journal = lambda _: (_ for _ in ()).throw(OSError('checkpoint failed'))
        with self.assertRaises(OSError):
            h.request('acquire', digest=h.key, block=1)
        self.assertIn(unknown['lease'], h.cache.leases)
        self.assertIn(unknown['lease'], h.records[-1]['pins'])
        self.assertTrue(h.cache.poisoned)
        with self.assertRaises(RuntimeError):
            h.cache.freeze()

    def test_invalid_ranges_and_fields_do_not_trigger_backend_io(self):
        h = Harness()
        for block in (-1, 100, True, '0'):
            with self.assertRaises(ValueError):
                h.request('acquire', digest=h.key, block=block)
        with self.assertRaises(ValueError):
            h.request('status', extra=True)
        for offset, count in ((-1, 1), (0, 0), (0, stored.CHUNK + 1), (len(h.payload), 1)):
            with self.assertRaises(ValueError):
                h.reader().read(h.key, offset, count)
        self.assertEqual(h.calls, [])

    def test_stale_or_malformed_grant_never_reads_pool(self):
        h = Harness()
        for change in ({'cacheId': '0' * 32}, {'slot': 4}, {'bytes': 10}, {'sha256': 'sha256:' + '0' * 64}):
            def changed(request):
                value = h.cache.request(request)
                value.update(change)
                return value
            reader = h.reader(request=changed)
            with self.assertRaises(ValueError):
                reader.read(h.key, 0, 1)
            self.assertTrue(reader.failed)
        self.assertEqual(len(h.cache.leases), 4)


class Compatibility(unittest.TestCase):
    def setUp(self):
        # Production is Linux-only; exercise its UNIX pathname checks on Windows.
        patcher = patch.object(stored, 'Path', PurePosixPath)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_offline_catalog_checks_complete_identity_and_partial_tail(self):
        data = b'a' * (lazy.CHUNK + 13)
        path = Path(__file__).with_name('.lazy-source-' + uuid.uuid4().hex)
        try:
            path.write_bytes(data)
            value = lazy.prepare({lazy.digest(data): (path, len(data))})
            self.assertEqual(value['layers'][0]['chunks'], [lazy.digest(data[:lazy.CHUNK]), lazy.digest(data[lazy.CHUNK:])])
            with self.assertRaisesRegex(ValueError, 'committed'):
                lazy.prepare({'sha256:' + '0' * 64: (path, len(data))})
        finally:
            path.unlink(missing_ok=True)

    def test_manifest_separates_virtual_layers_from_real_cache_allocation(self):
        h = Harness(blocks=70)
        value = copy.deepcopy(h.value)
        value['layers'][0]['path'] = str(Path.cwd() / 'not-opened')
        manifest = lazy_service.new_manifest(value, stored.ALIGN, ['node-b'])
        self.assertEqual(manifest['pool']['mappingBytes'], stored.ALIGN)
        self.assertGreater(manifest['virtualLayers'][0]['mappingBytes'], manifest['pool']['mappingBytes'])
        self.assertNotIn('path', manifest['catalog']['layers'][0])
        for field, replacement in [('cacheId', 'bad'), ('format', 'native-raw-v1')]:
            bad = copy.deepcopy(manifest)
            bad[field] = replacement
            with self.assertRaises(ValueError):
                lazy_service.validate_manifest(bad)

    def test_catalog_file_pin_covers_the_exact_parsed_bytes(self):
        path = Path(__file__).with_name('.lazy-catalog-' + uuid.uuid4().hex)
        try:
            data = b'{"test":1}'
            path.write_bytes(data)
            self.assertEqual(lazy_service.read_json(path, lazy.digest(data)), {'test': 1})
            with self.assertRaises(ValueError):
                lazy_service.read_json(path, lazy.digest(b'different'))
        finally:
            path.unlink(missing_ok=True)

    def test_serve_dry_validation_does_not_initialize_sdk_or_read_payload(self):
        source = Path(__file__).with_name('.lazy-source-' + uuid.uuid4().hex)
        config_path = source.with_suffix('.config.json')
        catalog_path = source.with_suffix('.catalog.json')
        try:
            data = b'content'
            source.write_bytes(data)
            value = {'version': 1, 'chunkBytes': lazy.CHUNK, 'layers': [{'digest': lazy.digest(data),
                'fileBytes': len(data), 'chunks': [lazy.digest(data)], 'path': str(source.resolve())}]}
            encoded = json.dumps(value).encode()
            catalog_path.write_bytes(encoded)
            root = socket_fixture_root()
            config = {'version': 1, 'role': 'publish', 'workDir': str(root / 'new-lazy-work'),
                'adapter': str(Path(__file__).resolve()), 'adapterSha256': 'sha256:' + 'a' * 64,
                'region': 'default', 'maxCoverageBytes': 4194304, 'poolBytes': 4194304,
                'sourceRoot': str(source.parent.resolve()), 'catalog': str(catalog_path),
                'catalogSha256': lazy.digest(encoded), 'readers': ['node-b']}
            for invalid in (0, 9, True):
                config['maxConcurrentReads'] = invalid
                config_path.write_text(json.dumps(config), encoding='utf-8')
                with self.assertRaises(ValueError):
                    lazy_service.load_config(config_path)
            config['maxConcurrentReads'] = 4
            config_path.write_text(json.dumps(config), encoding='utf-8')
            self.assertEqual(lazy_service.load_config(config_path)[0]['maxConcurrentReads'], 4)
            bad = dict(config, workDir=str(root / ('x' * 120)))
            config_path.write_text(json.dumps(bad), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'socket path is too long'):
                lazy_service.load_config(config_path)
            config_path.write_text(json.dumps(config), encoding='utf-8')
            with patch.object(sys, 'argv', ['aenv-ub-lazy', 'serve', str(config_path)]), \
                    patch.object(lazy_service, 'serve') as serve, \
                    patch.object(lazy_service.sdk, 'NativeBackend') as sdk, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(lazy_service.main(), 0)
                serve.assert_not_called()
                sdk.assert_not_called()
                self.assertEqual(json.loads(output.getvalue())['state'], 'lazy_inputs_validated_no_sdk')
        finally:
            for path in (source, config_path, catalog_path):
                path.unlink(missing_ok=True)

    def test_import_credential_binds_exact_manifest_and_generation(self):
        h = Harness()
        manifest = lazy_service.new_manifest(h.value, stored.ALIGN, ['node-b'])
        path = Path(__file__).with_name('.lazy-manifest-' + uuid.uuid4().hex)
        credential_path, config_path = path.with_suffix('.credential.json'), path.with_suffix('.config.json')
        try:
            path.write_text(json.dumps(manifest), encoding='utf-8')
            credential = {'cacheId': manifest['cacheId'], 'reader': 'node-b', 'token': 'b' * 64,
                          'manifestSha256': lazy_service.service.identity(manifest)}
            credential_path.write_text(json.dumps(credential), encoding='utf-8')
            root = socket_fixture_root()
            config = {'version': 1, 'role': 'import', 'workDir': str(root / 'new-lazy-work'),
                'adapter': str(Path(__file__).resolve()), 'adapterSha256': 'sha256:' + 'a' * 64,
                'region': 'default', 'maxCoverageBytes': 4194304, 'manifest': str(path),
                'credential': str(credential_path), 'coordinationSocket': str(root / 'forward.sock')}
            config_path.write_text(json.dumps(config), encoding='utf-8')
            self.assertEqual(lazy_service.load_config(config_path)[3]['reader'], 'node-b')
            manifest['virtualLayers'][0]['objectName'] = 'aenv_' + 'e' * 32
            path.write_text(json.dumps(manifest), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'exact cache manifest'):
                lazy_service.load_config(config_path)
        finally:
            for item in (path, credential_path, config_path):
                item.unlink(missing_ok=True)

    def test_direct_source_uses_aligned_bounded_io_and_refuses_buffered_fallback(self):
        # Exercise the adapter with a real aligned anonymous buffer but modeled
        # Linux os.open/preadv. This is not a target O_DIRECT acceptance test.
        payload = b'X' * (lazy.CHUNK + 137)
        path = Path(__file__).with_name('.lazy-direct-' + uuid.uuid4().hex)
        try:
            path.write_bytes(payload)
            meta = path.stat()
            key = lazy.digest(payload)
            value = {'version': 1, 'chunkBytes': lazy.CHUNK, 'layers': [{'digest': key,
                'fileBytes': len(payload), 'chunks': [lazy.digest(payload[:lazy.CHUNK]), lazy.digest(payload[lazy.CHUNK:])],
                'path': str(path.resolve())}]}
            with contextlib.ExitStack() as stack:
                for name, flag in [('O_DIRECT', 0x100000), ('O_NOFOLLOW', 0x200000), ('O_CLOEXEC', 0x400000)]:
                    stack.enter_context(patch.object(lazy.os, name, flag, create=True))
                opened = stack.enter_context(patch.object(lazy.os, 'open', return_value=91))
                stack.enter_context(patch.object(lazy.os, 'close'))
                stat_call = stack.enter_context(patch.object(lazy.os, 'fstat', return_value=meta))
                def read(fd, buffers, offset):
                    data = payload[offset:offset + len(buffers[0])]
                    buffers[0][:len(data)] = data
                    self.assertEqual(len(buffers[0]) % 4096, 0)
                    return len(data)
                direct = stack.enter_context(patch.object(lazy.os, 'preadv', side_effect=read, create=True))
                sources = lazy.DirectSources(value, path.parent)
                self.assertEqual(sources.read(key, 1), payload[lazy.CHUNK:])
                self.assertTrue(opened.call_args.args[1] & 0x100000)
                direct.side_effect = OSError('O_DIRECT unavailable')
                with self.assertRaises(OSError):
                    sources.read(key, 0)
                stat_call.return_value = type('Meta', (), dict(st_dev=meta.st_dev, st_ino=meta.st_ino,
                    st_size=meta.st_size, st_mtime_ns=meta.st_mtime_ns + 1, st_ctime_ns=meta.st_ctime_ns))()
                before = direct.call_count
                with self.assertRaises(ValueError):
                    sources.read(key, 0)
                self.assertEqual(direct.call_count, before)
                sources.close()
        finally:
            path.unlink(missing_ok=True)

    def test_lazy_manifest_cannot_be_used_as_a_native_pmem_import(self):
        h = Harness()
        manifest = lazy_service.new_manifest(h.value, stored.ALIGN, ['node-b'])
        backend = type('Backend', (), {'initialize': lambda _: self.fail('must reject before SDK')})()
        images = raw.RawImages(backend, lambda state: None, stored.ALIGN)
        spec = {'objectId': 'test', 'generation': 'test', 'bytes': 2 * stored.CHUNK,
                'sha256': 'sha256:' + '0' * 64, 'socket': '/x'}
        with self.assertRaises(ValueError):
            images.imports([{'backing': spec}], manifest)

    def test_existing_stored_wire_reads_lazy_view_without_protocol_change(self):
        h = Harness()
        manifest = lazy_service.new_manifest(h.value, stored.ALIGN, [])
        replica = lazy_service.descriptors(manifest, '/test.sock')[0]
        # Use the real existing binary broker protocol. Credentials are modeled
        # only on this Windows-compatible socketpair; Linux retains SO_PEERCRED.
        broker = stored.Broker([replica], [lazy.LayerView(h.reader(), replica)], uid=None)
        broker.uid = None
        client, server = socket.socketpair()
        worker = threading.Thread(target=broker.handle, args=(server,))
        worker.start()
        try:
            client.sendall(stored.MAGIC + struct.pack('>H', 37) + replica.objectName.encode()
                           + bytes.fromhex(replica.generation) + struct.pack('>QQ', replica.fileBytes, replica.mappingBytes)
                           + bytes.fromhex(replica.layerDigest[7:]))
            self.assertEqual(stored.recv_exact(client, 16), stored.RESPONSE.pack(stored.MAGIC, 0, 0))
            client.sendall(struct.pack('>QI', lazy.CHUNK - 4, 10))
            self.assertEqual(stored.recv_exact(client, 16), stored.RESPONSE.pack(stored.MAGIC, 0, 10))
            self.assertEqual(stored.recv_exact(client, 10), h.payload[lazy.CHUNK - 4:lazy.CHUNK + 6])
        finally:
            client.close()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(broker.active, 0)
        self.assertEqual(h.request('status')['pins'], 0)

    def test_metadata_framing_carries_descriptors_only(self):
        h = Harness()
        left, right = socket.socketpair()
        try:
            request = dict(operation='acquire', reader='owner', token=h.tokens['owner'],
                           cacheId='c' * 32, digest=h.key, block=0)
            contract.send_json(left, request)
            grant = h.cache.request(contract.receive_json(right))
            contract.send_json(right, grant)
            received = contract.receive_json(left)
            self.assertEqual(received['state'], 'ready')
            self.assertLess(len(json.dumps(received)), 1024)
            self.assertNotIn('data', received)
        finally:
            left.close()
            right.close()


if __name__ == '__main__':
    unittest.main()
