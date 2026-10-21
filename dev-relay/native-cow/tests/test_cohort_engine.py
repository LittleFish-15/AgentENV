import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cohort', HERE.parent / 'cohort_engine.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
RUN = 'a' * 32


class FakeApi:
    def __init__(self):
        self.guests = {}
        self.calls = []
        self.saved = []
        self.intercept = None
        self.next_id = 0

    def call(self, method, path, body=None, timeout=30):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method in ('POST', 'DELETE'):
            assert self.saved[-1]['openRequests'], 'No write-ahead intent'
            assert self.saved[-1]['openRequests'][-1]['route'] == path
        if self.intercept:
            value = self.intercept(method, path, body)
            if value is not None:
                return value
        if path == '/v2/sandboxes?limit=1':
            return 200, list(self.guests.values())[:1]
        if method == 'GET':
            sid = path.split('/')[2]
            return (200, self.guests[sid]) if sid in self.guests else (404, None)
        if method == 'DELETE':
            self.guests.pop(path.split('/')[2], None)
            return 204, None
        if path.endswith('/snapshots'):
            return 201, {'snapshotID': 'snapshot-own'}
        self.next_id += 1
        sid = 'guest-' + str(self.next_id)
        value = {'sandboxID': sid, 'metadata': {'cow_batch': RUN}}
        self.guests[sid] = value
        if path.endswith('/fork'):
            return 201, [{'sandbox': value, 'error': None}]
        return 201, value


def fixture(api=None, observe=None, execute=None, capacity=None, snapshot=None):
    api = api or FakeApi()
    initial = {'version': 1, 'phase': 'prepared', 'openRequests': [],
               'sandboxIds': [], 'outcomeUncertain': False}
    def observe_default(phase, sids):
        return {'phase': phase, 'available': True, 'sids': sids}
    def execute_default(sids, run_id, sample):
        sample()
        return [{'sandboxId': sid, 'passed': True, 'result': {
            'catalogSha256': 'c', 'sqlSha256': 's', 'fileCount': 1, 'fileBytes': 10}}
                for sid in sids]
    cohort = C.Cohort(api, initial, lambda s: api.saved.append(copy.deepcopy(s)),
                       observe or observe_default, execute or execute_default,
                       capacity or (lambda k: None), snapshot or (lambda s: {'snapshotId': s}), run_id=RUN)
    return api, cohort


class Tests(unittest.TestCase):
    def test_complete_lifecycle_no_parent_during_samples(self):
        api, cohort = fixture()
        result = cohort.run('ocidir://fixture')
        self.assertTrue(result['lifecyclePassed'])
        self.assertTrue(C.quiescent(result))
        self.assertEqual(result['snapshots'], ['snapshot-own'])
        self.assertEqual([s['phase'] for s in result['samples']],
                         ['before_workload', 'during_workload_unspecified', 'after_workload'])
        for sample in result['samples']:
            self.assertEqual(sample['sids'], ['guest-2', 'guest-3'])
        self.assertEqual(len([c for c in api.calls if c[0] == 'POST']), 4)
        self.assertFalse(api.guests)

    def test_timeout_empty_inventory_does_not_resolve_create(self):
        api = FakeApi()
        def intercept(method, path, body):
            if method == 'POST':
                raise TimeoutError()
        api.intercept = intercept
        _, cohort = fixture(api)
        result = cohort.run('image')
        self.assertTrue(result['outcomeUncertain'])
        self.assertEqual(result['phase'], 'needs_reconciliation')
        self.assertEqual(len(result['openRequests']), 1)
        self.assertEqual(len([c for c in api.calls if c[0] == 'POST']), 1)

    def test_partial_fork_known_parent_and_child_cleaned(self):
        api = FakeApi()
        def intercept(method, path, body):
            if path.endswith('/fork'):
                raise TimeoutError()
        api.intercept = intercept
        _, cohort = fixture(api)
        result = cohort.run('image')
        self.assertTrue(result['outcomeUncertain'])
        self.assertFalse(result['sandboxIds'])
        self.assertEqual(result['openRequests'][0]['kind'], 'fork')
        self.assertFalse(api.guests)

    def test_foreign_metadata_never_deleted(self):
        api = FakeApi()
        def intercept(method, path, body):
            if path == '/sandboxes/guest-1' and method == 'GET':
                return 200, {'sandboxID': 'guest-1', 'metadata': {'cow_batch': 'someone-else'}}
        api.intercept = intercept
        _, cohort = fixture(api)
        result = cohort.run('image')
        self.assertFalse(any(c[0] == 'DELETE' for c in api.calls))
        self.assertEqual(result['sandboxIds'], ['guest-1'])
        self.assertTrue(result['outcomeUncertain'])

    def test_capture_verifier_failure_retains_committed_reference(self):
        def snapshot(sid):
            raise RuntimeError('Wrong native identity')
        api, cohort = fixture(snapshot=snapshot)
        result = cohort.run('image')
        self.assertTrue(C.quiescent(result))
        self.assertFalse(result['lifecyclePassed'])
        self.assertEqual(result['snapshots'], ['snapshot-own'])
        self.assertEqual(len([c for c in api.calls if c[0] == 'POST']), 2)

    def test_observer_failure_does_not_invent_measurement(self):
        def observe(phase, sids):
            raise PermissionError()
        _, cohort = fixture(observe=observe)
        result = cohort.run('image')
        self.assertTrue(result['lifecyclePassed'])
        self.assertTrue(all(s['available'] is False for s in result['samples']))

    def test_failed_workload_still_cleans_all_owned_guests(self):
        def execute(*args):
            raise RuntimeError('workload failed')
        api, cohort = fixture(execute=execute)
        result = cohort.run('image')
        self.assertTrue(C.quiescent(result))
        self.assertFalse(result['lifecyclePassed'])
        self.assertFalse(api.guests)

    def test_delete_response_without_404_is_unresolved(self):
        api = FakeApi()
        api.intercept = lambda method, path, body: (204, None) if method == 'DELETE' else None
        _, cohort = fixture(api)
        result = cohort.run('image')
        self.assertTrue(result['outcomeUncertain'])
        self.assertTrue(result['sandboxIds'])
        self.assertEqual(result['phase'], 'needs_reconciliation')

    def test_nonempty_initial_inventory_zero_post(self):
        api = FakeApi()
        api.guests['other'] = {'sandboxID': 'other'}
        _, cohort = fixture(api)
        result = cohort.run('image')
        self.assertFalse(any(c[0] in ('POST', 'DELETE') for c in api.calls))
        self.assertEqual(result['phase'], 'inventory_unconfirmed')

    def test_capacity_failure_zero_post(self):
        def capacity(kind):
            raise RuntimeError('Insufficient capacity')
        api, cohort = fixture(capacity=capacity)
        result = cohort.run('image')
        self.assertTrue(C.quiescent(result))
        self.assertFalse(any(c[0] == 'POST' for c in api.calls))

    def test_pending_state_refused_before_any_write(self):
        with self.assertRaisesRegex(RuntimeError, 'not quiescent'):
            C.Cohort(None, {'version': 1, 'phase': 'active'}, lambda s: self.fail('write'),
                     None, None, None, None)

    def test_wrong_workload_content_is_failure(self):
        def execute(sids, *args):
            return [{'passed': True, 'result': {'catalogSha256': sid, 'sqlSha256': 'x',
                                               'fileCount': 1, 'fileBytes': 2}} for sid in sids]
        _, cohort = fixture(execute=execute)
        result = cohort.run('image')
        self.assertFalse(result['lifecyclePassed'])
        self.assertTrue(C.quiescent(result))


if __name__ == '__main__':
    unittest.main()
