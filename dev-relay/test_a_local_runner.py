"""Runner ownership/cleanup tests using actual Publisher and an in-memory SDK.
No native SDK, real Rust probe or remote node is executed by these tests.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import unittest
import uuid
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
WORK = HERE.parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


r = module('a_local_runner_test', HERE / 'run_a_local_layers.py')
s = module('a_local_smoke_test', WORK / 'tools/ub-snapshot/sdk_smoke.py')
t = module('a_local_broker_double', WORK / 'tools/ub-snapshot/test_broker.py')
b = s.b
ORIGINAL_GUARD = s.previous_guard


class Sdk(t.FakeSdk):
    @property
    def allocation_calls(self):
        return len(self.allocations)


class Broker:
    def __init__(self, replicas, mappings):
        self.replicas, self.mappings = replicas, mappings
        self.reads = 0

    def start(self, path):
        pass

    def stop(self):
        return {'read_requests': self.reads, 'read_bytes': self.reads * 8192, 'active_leases': 0}


class RunnerTests(unittest.TestCase):
    def setUp(self):
        # Keep paths short enough for the real Replica UNIX-name validation.
        self.path = WORK.parents[1] / ('.al-' + uuid.uuid4().hex[:5])
        self.path.mkdir(mode=0o755)
        self.fixtures = self.path / 'fixtures'
        self.fixtures.mkdir()
        payload = b'fixture stored bytes'
        source = self.fixtures / 'stored.commit'
        source.write_bytes(payload)
        for fmt in ('raw', 'tar', 'zfile'):
            b.atomic_json(self.fixtures / (fmt + '-image.json'), {'lowers': [
                {'file': str(source), 'digest': 'sha256:' + hashlib.sha256(payload).hexdigest(), 'size': len(payload)}]})
        self.pending = self.path / 'pending.json'
        self.backends = []
        self.patches = [patch.object(b, 'ROOT', self.path), patch.object(t.b, 'ROOT', self.path),
                        patch.object(r.tempfile, 'mkdtemp', self.case_directory),
                        patch.object(b, 'Broker', Broker), patch.object(s, 'probe', self.read_probe),
                        patch.object(s, 'previous_guard', self.guard),
                        patch.object(s, 'format_probe', self.format_probe),
                        patch.object(b, 'NativeBackend', self.sdk)]
        for p in self.patches:
            p.start()

    def case_directory(self, prefix, dir):
        # Linux production mkdtemp stays 0700. Windows sandbox tests use inherited
        # ACLs and a shorter path for the real UNIX socket-name length guard.
        path = Path(dir) / ('case-' + uuid.uuid4().hex[:5])
        path.mkdir(mode=0o755)
        return str(path)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        for sdk in self.backends:
            sdk.close_maps()
        assert self.path.resolve().parent == WORK.parents[1].resolve()
        shutil.rmtree(self.path)

    def guard(self, pending, node):
        if pending.exists() and b.read_json(pending)['state'] != 'COMPLETE_NO_OWNED_OBJECT':
            raise ValueError('unresolved previous run')

    def sdk(self, library):
        if self.backends:
            assert self.backends[-1].finalized
            assert not self.backends[-1].store['data']
        sdk = Sdk()
        self.backends.append(sdk)
        return sdk

    def read_probe(self, replica, broker):
        b.verify_mapping(replica, broker.mappings[0])
        broker.reads += 1

    def format_probe(self, program, replica, output, report):
        report['format_probe_exit_code'] = 0
        report['format_probe'] = {'LOCAL_TEST_DOUBLE_ONLY': True}

    def case(self):
        return r.run_case(s, self.path / 'probe', self.fixtures, self.path,
                          self.pending, self.path / 'bridge', 'raw')

    def suite(self):
        return r.run_suite(s, self.path / 'probe', self.fixtures, self.path,
                           self.pending, self.path / 'bridge')

    def test_three_formats_run_sequentially_and_release_each_object(self):
        results = self.suite()
        self.assertEqual([x['stored_format'] for x in results], ['raw', 'tar', 'zfile'])
        self.assertTrue(all(x['status'] == 'UB_LAYER_A_LOCAL_FORMAT_COMPLETED' for x in results))
        self.assertTrue(all(len(x.allocations) == len(x.deletions) == 1 for x in self.backends))
        self.assertTrue(all(x.finalized for x in self.backends))
        self.assertTrue(all(not x['cross_node_validation_executed'] for x in results))
        self.assertTrue(all('base_verified_after_peer_exit' not in x for x in results))

    def test_probe_failure_releases_owned_object_and_stops_before_next_format(self):
        with patch.object(s, 'format_probe', side_effect=RuntimeError('probe failed')):
            results = self.suite()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['status'], 'STOPPED_A_LOCAL_FORMAT')
        self.assertEqual(results[0]['state'], 'COMPLETE_NO_OWNED_OBJECT')
        self.assertTrue(self.backends[0].finalized)
        self.assertEqual(len(self.backends[0].deletions), 1)

    def test_reader_still_active_does_not_unmap_or_delete(self):
        with patch.object(Broker, 'stop', side_effect=RuntimeError('reader active')):
            result = self.case()
        self.assertEqual(result['state'], 'OWNERSHIP_OR_IMPORT_UNRESOLVED')
        self.assertEqual(len(self.backends[0].deletions), 0)
        self.assertFalse(self.backends[0].finalized)
        self.assertEqual(b.read_json(self.pending)['state'], result['state'])

    def test_unknown_allocation_keeps_receipt_and_prevents_second_random_object(self):
        def failed(library):
            sdk = Sdk(allocate_failure=True)
            self.backends.append(sdk)
            return sdk
        with patch.object(b, 'NativeBackend', failed):
            results = self.suite()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['state'], 'OWNERSHIP_OR_IMPORT_UNRESOLVED')
        before = self.pending.read_bytes()
        with self.assertRaises(ValueError):
            self.suite()
        self.assertEqual(self.pending.read_bytes(), before)
        self.assertEqual(len(self.backends), 1)

    def test_delete_failure_stops_and_keeps_owned_identity(self):
        original = self.sdk
        def failed(library):
            sdk = original(library)
            sdk.deallocate = lambda replica: (_ for _ in ()).throw(RuntimeError('delete failed'))
            return sdk
        with patch.object(b, 'NativeBackend', failed):
            results = self.suite()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['state'], 'OWNERSHIP_OR_IMPORT_UNRESOLVED')
        self.assertTrue(b.read_json(self.pending)['object_name'])
        self.assertFalse(self.backends[0].finalized)

    def test_completed_local_receipt_is_compatible_with_original_global_guard(self):
        output = self.path / 'relay/reports/node-a-ub-layer-sdk-local'
        output.mkdir(parents=True)
        record = {'version': 1, 'node': 'node-a', 'uid': 1204,
                  'role': 'owner-local-only', 'report_directory': str(output),
                  'state': 'COMPLETE_NO_OWNED_OBJECT'}
        b.atomic_json(self.pending, record)
        self.assertEqual(ORIGINAL_GUARD(self.pending, 'node-a'), record)
        record['state'] = 'OWNERSHIP_OR_IMPORT_UNRESOLVED'
        b.atomic_json(self.pending, record)
        with self.assertRaises(ValueError):
            ORIGINAL_GUARD(self.pending, 'node-a')

    def test_reviewed_helpers_import_without_native_sdk_initialization(self):
        with patch.object(r, 'ROOT', WORK.parents[1]), patch.object(r, 'SOURCE', WORK):
            imported = r.load_helpers()
        self.assertTrue(callable(imported.format_probe))

    def test_modified_helper_rejected_before_import(self):
        helper = self.path / 'source/tools/ub-snapshot'
        helper.mkdir(parents=True)
        (helper / 'sdk_smoke.py').write_text('raise RuntimeError("must never execute")')
        with patch.object(r, 'ROOT', self.path), patch.object(r, 'SOURCE', self.path / 'source'):
            with self.assertRaisesRegex(ValueError, 'differs from reviewed source'):
                r.load_helpers()


if __name__ == '__main__':
    unittest.main(verbosity=2)
