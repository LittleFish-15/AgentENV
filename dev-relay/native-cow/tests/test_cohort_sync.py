import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


S, REPORT = module('cohort_sync'), module('cohort_report')
EPOCH = 'a' * 32


def ready(node):
    return {'node': node, 'variant': 'native', 'epoch': EPOCH, 'runId': ('b' if node == 'node-a' else 'c') * 32,
            'sandboxIds': [node + '-1', node + '-2']}


def measured(r, sample=None):
    return {'node': r['node'], 'epoch': EPOCH, 'readySha256': S.digest(r),
            'sampleSha256': S.digest(sample if sample is not None else {})}


class Protocol(unittest.TestCase):
    def test_measure_requires_both_nodes_and_exact_epoch(self):
        a, b = ready('node-a'), ready('node-b')
        self.assertEqual(S.control_message('measure', 'native', EPOCH, {'node-a': a, 'node-b': b})['operation'], 'measure')
        with self.assertRaisesRegex(RuntimeError, 'Both node'):
            S.control_message('measure', 'native', EPOCH, {'node-a': a})
        b['epoch'] = 'd' * 32
        with self.assertRaisesRegex(RuntimeError, 'identity differs'):
            S.control_message('measure', 'native', EPOCH, {'node-a': a, 'node-b': b})

    def test_release_requires_both_sample_receipts_bound_to_readies(self):
        a, b = ready('node-a'), ready('node-b')
        readies = {'node-a': a, 'node-b': b}
        receipts = {'node-a': measured(a), 'node-b': measured(b)}
        self.assertEqual(S.control_message('release', 'native', EPOCH, readies, receipts)['measurements'], receipts)
        receipts['node-b']['readySha256'] = 'e' * 64
        with self.assertRaisesRegex(RuntimeError, 'receipt differs'):
            S.control_message('release', 'native', EPOCH, readies, receipts)

    def test_one_guest_or_duplicate_guest_refused(self):
        for ids in (['one'], ['one', 'one'], ['one', 'two', 'three']):
            r = ready('node-a')
            r['sandboxIds'] = ids
            with self.assertRaisesRegex(RuntimeError, 'two distinct'):
                S.valid_ready(r, 'node-a', 'native', EPOCH)

    def gate(self, corrupt=False, aborted=False):
        path = Path('/fixture')
        store, events = {}, []
        peer = ready('node-b')
        own = ready('node-a')
        cohort = types.SimpleNamespace(run_id=own['runId'], state={'samples': []}, owned=lambda sid: {'sandboxID': sid})
        def sample(phase, ids):
            events.append('sample')
            cohort.state['samples'].append({'phase': phase, 'ram': {'available': True}, 'ids': ids})
        cohort.sample = sample
        def put(file, value):
            events.append(file.name)
            store[file.name] = copy.deepcopy(value)
            if file.name == 'ready.json':
                store['measure.json'] = S.control_message('measure', 'native', EPOCH, {'node-a': copy.deepcopy(value), 'node-b': peer})
                if corrupt:
                    store['measure.json']['readies']['node-a']['runId'] = 'f' * 32
            if file.name == 'measured.json':
                store['release.json'] = S.control_message('release', 'native', EPOCH,
                    {'node-a': own, 'node-b': peer}, {'node-a': value, 'node-b': measured(peer)})
        if aborted:
            store['abort.json'] = {'epoch': EPOCH}
        with mock.patch.object(S, 'seed', return_value=path), mock.patch.object(S, 'put_once', side_effect=put), \
                mock.patch.object(S, 'optional', side_effect=lambda p: copy.deepcopy(store.get(p.name))):
            fence = S.Fence('node-a', 'native', EPOCH)
            if corrupt or aborted:
                with self.assertRaises(RuntimeError):
                    fence(cohort, own['sandboxIds'])
                result = None
            else:
                result = fence(cohort, own['sandboxIds'])
        return events, result

    def test_worker_samples_between_measure_and_release_receipts(self):
        events, result = self.gate()
        self.assertEqual(events, ['ready.json', 'sample', 'measured.json'])
        self.assertEqual(result['status'], 'COORDINATED_POST_WORKLOAD_HOLD_COMPLETED')
        self.assertFalse(result['atomicSnapshot'])
        self.assertFalse(result['synchronizedWorkloadStart'])

    def test_corrupt_control_fails_before_sampling(self):
        events, result = self.gate(corrupt=True)
        self.assertNotIn('sample', events)
        self.assertEqual(events[-1], 'failed.json')

    def test_abort_never_publishes_readiness_or_samples(self):
        events, result = self.gate(aborted=True)
        self.assertEqual(events, ['failed.json'])

    def test_report_checks_actual_sample_digest_on_both_nodes(self):
        readies = {node: ready(node) for node in S.NODES}
        samples = {node: {'phase': 'after_workload', 'ram': {'available': True}, 'startNs': 1, 'endNs': 2} for node in S.NODES}
        receipts = {node: measured(readies[node], samples[node]) for node in S.NODES}
        by = {(node, 'native'): {'cohort': {'runId': readies[node]['runId'], 'samples': [samples[node]],
               'pairedWindow': {'node': node, 'epoch': EPOCH, 'status': 'COORDINATED_POST_WORKLOAD_HOLD_COMPLETED',
                                'readies': readies, 'measurements': receipts}}} for node in S.NODES}
        self.assertEqual(REPORT.paired_window(by, 'native')['status'], 'COORDINATED_POST_WORKLOAD_HOLD_COMPLETED')
        samples['node-b']['endNs'] = 3
        self.assertEqual(REPORT.paired_window(by, 'native')['status'], 'NA_NO_COMPLETE_PAIRED_HOLD')

    def test_missing_pair_is_na_not_implicit_overlap(self):
        self.assertEqual(REPORT.paired_window({}, 'native')['status'], 'NA_NO_COMPLETE_PAIRED_HOLD')


if __name__ == '__main__':
    unittest.main()
