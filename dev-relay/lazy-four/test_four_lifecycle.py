import copy
import importlib.util
from pathlib import Path
import unittest
import uuid

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


engine, lifecycle = load('cohort_engine'), load('four_lifecycle')


class Api:
    def __init__(self):
        self.guests, self.calls, self.n = {}, [], 0
        self.unknown_create = None
        self.failed_verify = False
        self.uncertain_delete = False

    def call(self, method, path, body=None, timeout=30):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == 'GET' and path == '/v2/sandboxes?limit=1':
            return 200, list(self.guests.values())[:1]
        if method == 'POST' and path in ('/sandboxes-cold', '/v2/sandboxes'):
            self.n += 1
            sid = str(uuid.UUID(int=self.n))
            self.guests[sid] = {'sandboxID': sid, 'metadata': copy.deepcopy(body['metadata'])}
            if self.n == self.unknown_create:
                raise TimeoutError('Lost creation response')
            return 201, {'sandboxID': sid}
        if method == 'POST' and path.endswith('/snapshots'):
            return 201, {'snapshotID': str(uuid.UUID(int=self.n + 100))}
        sid = path.split('/')[-1]
        if method == 'GET' and path.startswith('/sandboxes/'):
            if self.failed_verify:
                self.failed_verify = False
                raise OSError('Temporary ownership query failure')
            return (200, self.guests[sid]) if sid in self.guests else (404, None)
        if method == 'DELETE':
            if not self.uncertain_delete:
                self.guests.pop(sid, None)
            return 204, None
        raise AssertionError((method, path))


def template_rows():
    return [{'templateIndex': i, 'nativeTemplateId': str(uuid.UUID(int=100 + i)), 'sourceImage': str(i),
             'resources': {'memory_mib': 4096, 'cpu_count': 2}} for i in range(4)]


class LifecycleTests(unittest.TestCase):
    def batch(self, api=None):
        self.api = api or Api()
        self.states = {}
        def persist(index, state):
            self.states[index] = copy.deepcopy(state)
        return lifecycle.FourLifecycle(engine, self.api, 'a' * 32, {'node': 'fixture'}, persist,
            lambda kind: None, lambda index, sid: {'snapshotId': sid, 'committedRecordSha256': 'a' * 64})

    def test_four_parents_have_four_captures_and_no_live_parent_left(self):
        batch = self.batch()
        images = [dict(row, ociReference='fixture:' + str(i)) for i, row in enumerate(template_rows())]
        result = batch.prepare_parents(images)
        self.assertEqual(len(result), 4)
        self.assertEqual(len(self.api.guests), 0)
        self.assertEqual(sum(method == 'POST' and path.endswith('/snapshots') for method, path, _ in self.api.calls), 4)
        self.assertTrue(all(len(state['snapshots']) == 1 for state in self.states.values()))

    def test_eight_children_are_two_per_template_and_cleanup_is_scoped(self):
        batch = self.batch()
        jobs = batch.restore_pairs(template_rows())
        self.assertEqual(len(jobs), 8)
        for i in range(4):
            self.assertEqual({j['slot'] for j in jobs if j['templateIndex'] == i}, {0, 1})
        result = batch.cleanup()
        self.assertTrue(result['ownedGuestsReleased'])
        self.assertTrue(all(state['phase'] == 'quiesced' for state in self.states.values()))
        self.assertEqual(sum(method == 'DELETE' for method, _, _ in self.api.calls), 8)

    def test_unknown_creation_blocks_all_later_cases_and_is_not_retried(self):
        api = Api(); api.unknown_create = 3
        batch = self.batch(api)
        with self.assertRaises(TimeoutError):
            batch.restore_pairs(template_rows())
        result = batch.cleanup()
        self.assertTrue(result['outcomeUncertain'])
        self.assertFalse(result['ownedGuestsReleased'])
        with self.assertRaises(RuntimeError):
            batch.begin_case(3)
        self.assertEqual(sum(method == 'POST' for method, _, _ in api.calls), 3)

    def test_known_creation_ack_survives_ownership_query_failure(self):
        api = Api(); api.failed_verify = True
        batch = self.batch(api)
        with self.assertRaises(OSError):
            batch.restore_pairs(template_rows())
        result = batch.cleanup()
        self.assertTrue(result['ownedGuestsReleased'])
        self.assertFalse(result['outcomeUncertain'])
        self.assertEqual(sum(method == 'POST' for method, _, _ in api.calls), 1)

    def test_unconfirmed_delete_is_not_sent_twice(self):
        api = Api()
        batch = self.batch(api)
        batch.restore_pairs(template_rows())
        api.uncertain_delete = True
        self.assertFalse(batch.cleanup()['ownedGuestsReleased'])
        first = sum(method == 'DELETE' for method, _, _ in api.calls)
        batch.cleanup()
        self.assertEqual(sum(method == 'DELETE' for method, _, _ in api.calls), first)

    def test_recovery_cannot_change_recorded_runtime_context(self):
        batch = self.batch()
        batch.restore_pairs(template_rows())
        saved = {str(i): state for i, state in self.states.items()}
        with self.assertRaises(RuntimeError):
            lifecycle.FourLifecycle(engine, self.api, 'b' * 32, {'node': 'other'}, lambda *a: None,
                                    None, None, initial=saved)


if __name__ == '__main__':
    unittest.main()
