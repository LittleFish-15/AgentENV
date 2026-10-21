import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('capture_engine', HERE.parent / 'cohort_engine.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
SID = '11111111-2222-7333-8444-555555555555'
PIN = 'a' * 64


class Api:
    def __init__(self, state, records, saved):
        self.state, self.records, self.saved = state, records, saved
        self.calls = []
        self.inventory = []
        self.timeout_after_delete = False
        self.keep_record = False
    def call(self, method, route, body=None, timeout=30):
        self.calls.append((method, route))
        if route == '/v2/sandboxes?limit=1':
            return 200, self.inventory
        sid = route.split('/')[-1]
        if method == 'GET':
            return (200, {'templateID': sid}) if sid in self.records else (404, None)
        assert method == 'DELETE'
        assert self.saved[-1]['openRequests'][0]['kind'] == 'delete_capture'
        assert self.saved[-1]['outcomeUncertain'] is True
        if not self.keep_record:
            self.records.pop(sid, None)
        if self.timeout_after_delete:
            raise TimeoutError('Reply lost after deletion')
        return 204, None


def fixture():
    state = {'version': 1, 'phase': 'quiesced', 'sandboxIds': [], 'openRequests': [],
             'outcomeUncertain': False, 'snapshots': [SID], 'operations': [],
             'snapshotEvidence': [{'snapshotId': SID, 'committedRecordSha256': PIN}]}
    records, saved = {SID: PIN, 'unrelated': 'b' * 64}, []
    api = Api(state, records, saved)
    def run():
        return C.release_captures(api, state, lambda s: saved.append(copy.deepcopy(s)), records.get)
    return state, records, api, run


class Tests(unittest.TestCase):
    def test_exact_owned_capture_deleted_once_and_other_record_preserved(self):
        state, records, api, run = fixture()
        result = run()
        self.assertTrue(result['captureReleaseComplete'])
        self.assertTrue(C.quiescent(result))
        self.assertEqual(result['snapshots'], [])
        self.assertEqual(records, {'unrelated': 'b' * 64})
        self.assertEqual([c for c in api.calls if c[0] == 'DELETE'], [('DELETE', '/templates/' + SID)])

    def test_unknown_post_blocks_capture_release(self):
        state, records, api, run = fixture()
        state['openRequests'] = [{'kind': 'create'}]
        with self.assertRaisesRegex(RuntimeError, 'Unresolved non-release'):
            run()
        self.assertFalse(api.calls)
        self.assertIn(SID, records)

    def test_changed_record_is_never_deleted(self):
        state, records, api, run = fixture()
        records[SID] = 'c' * 64
        self.assertFalse(run()['captureReleaseComplete'])
        self.assertFalse(any(c[0] == 'DELETE' for c in api.calls))

    def test_missing_original_hash_preserves_snapshot(self):
        state, records, api, run = fixture()
        state['snapshotEvidence'] = []
        self.assertFalse(run()['captureReleaseComplete'])
        self.assertFalse(any(c[0] == 'DELETE' for c in api.calls))

    def test_nonempty_service_blocks_deletion(self):
        state, records, api, run = fixture()
        api.inventory = [{'sandboxID': 'other'}]
        self.assertFalse(run()['captureReleaseComplete'])
        self.assertFalse(any(c[0] == 'DELETE' for c in api.calls))

    def test_lost_delete_reply_reconciles_absence_without_second_delete(self):
        state, records, api, run = fixture()
        api.timeout_after_delete = True
        self.assertFalse(run()['captureReleaseComplete'])
        self.assertTrue(state['outcomeUncertain'])
        api.timeout_after_delete = False
        self.assertTrue(run()['captureReleaseComplete'])
        self.assertEqual(len([c for c in api.calls if c[0] == 'DELETE']), 1)
        self.assertTrue(C.quiescent(state))

    def test_pending_delete_with_record_present_is_not_reissued(self):
        state, records, api, run = fixture()
        api.keep_record = True
        self.assertFalse(run()['captureReleaseComplete'])
        self.assertFalse(run()['captureReleaseComplete'])
        self.assertEqual(len([c for c in api.calls if c[0] == 'DELETE']), 1)
        self.assertIn(SID, records)

    def test_already_absent_capture_is_confirmed_without_mutation(self):
        state, records, api, run = fixture()
        records.pop(SID)
        self.assertTrue(run()['captureReleaseComplete'])
        self.assertFalse(any(c[0] == 'DELETE' for c in api.calls))

    def test_repeated_completed_release_has_no_new_delete(self):
        state, records, api, run = fixture()
        run()
        self.assertTrue(run()['captureReleaseComplete'])
        self.assertEqual(len([c for c in api.calls if c[0] == 'DELETE']), 1)
        self.assertEqual(len(state['releasedSnapshots']), 1)

    def test_alias_is_not_accepted_as_delete_identity(self):
        state, records, api, run = fixture()
        state['snapshots'] = ['friendly-name']
        state['snapshotEvidence'] = [{'snapshotId': 'friendly-name', 'committedRecordSha256': PIN}]
        self.assertFalse(run()['captureReleaseComplete'])
        self.assertFalse(any(c[0] == 'DELETE' for c in api.calls))


if __name__ == '__main__':
    unittest.main()
