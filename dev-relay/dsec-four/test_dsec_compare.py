import copy, importlib.util, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name+'.py'))
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


m = load('compare_dsec_reference')
fixtures = load('test_dsec_report')


def inputs():
    jobs, events = fixtures.cohort()
    for job in jobs:
        job['resources'] = {'cpu_count': 2, 'memory_mib': 4096}
    event_rows = [{'instanceId': k[0], 'slot': k[1], 'events': v} for k, v in events.items()]
    def sample(phase, instant, cache, pss):
        return {'phase': phase, 'startNs': instant*10**9, 'endNs': (instant+.1)*10**9, 'heavySample': True,
                'host': {'memoryBytes': {'Cached': cache}}, 'hostPmemFiles': {'residentPageBytes': 1000},
                'ram': {'guests': [{'sandboxId': j['sandboxId'], 'wholeProcess': {'pss_bytes': pss}}
                                   for j in jobs]}}
    candidate = {'revision': 'dsec-four-report-v1', 'runId': 'new', 'jobs': jobs, 'commandOutcomes': event_rows,
        'status': 'NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED', 'ownedGuestsReleased': True,
        'observer': {'status': 'READONLY_OBSERVER_OWNER_FINISHED'},
        'rawObservations': [sample('before_replay', 9, 100, 10), sample('replay_window', 15, 200, 20),
                            sample('after_replay', 21, 250, 15)]}
    original = {'groups': [{'run_id': 'old', 'memory': {'all_fc_same_cycle': [
        {'valid': True, 'sum_fc_pss_bytes': 200, 'started_unix': 15, 'finished_unix': 15.1}], 'coverage': {}},
        'cache': {'jobs': copy.deepcopy(jobs), 'cache_timeseries': {'file_rows': [
            {'host_cached_delta_after_bytes': 180, 'lower_resident_bytes': 800, 'rootfs_upper_resident_bytes': 30}]},
            'experiment_comparison': {'io64_core_changes_used': False},
            'validation': {'all_cohort_guests_released': True, 'replay_completed_guests': 8}}}]}
    return candidate, original, event_rows


class Compare(unittest.TestCase):
    def test_known_delta_remains_observational_even_with_exact_events(self):
        candidate, original, events = inputs()
        result = m.compare(candidate, original, events)
        self.assertTrue(result['fullSameWorkloadComparisonAccepted'])
        self.assertEqual(result['observationalDeltas'][0]['candidateMinusOriginalBytes'], -40)
        self.assertFalse(result['observationalDeltas'][0]['causalSavingsAccepted'])
        self.assertIsNone(result['globalPhysicalSavingBytes'])

    def test_missing_original_per_command_blocks_final_comparison(self):
        candidate, original, _ = inputs()
        result = m.compare(candidate, original)
        self.assertFalse(result['fullSameWorkloadComparisonAccepted'])

    def test_failed_candidate_keeps_data_but_does_not_accept(self):
        candidate, original, events = inputs();candidate['status'] = 'STOPPED'
        result = m.compare(candidate, original, events)
        self.assertFalse(result['fullSameWorkloadComparisonAccepted'])
        self.assertTrue(result['lifecycleGaps'])

    def test_modified_reference_rejected(self):
        candidate, original, events = inputs()
        original['groups'][0]['cache']['experiment_comparison']['io64_core_changes_used'] = True
        with self.assertRaisesRegex(ValueError, 'true original'):
            m.compare(candidate, original, events)

    def test_cached_delta_uses_same_candidate_phase_pair(self):
        candidate, original, events = inputs()
        result = m.compare(candidate, original, events)
        self.assertEqual(result['candidate']['lastHostCachedDeltaBytes'], 150)
        self.assertEqual(result['candidate']['beforeReplayImmutablePmemFileResidentBytes'], 1000)
        self.assertIn('不是同一种', m.markdown(result))

    def test_missing_after_phase_does_not_substitute_maximum(self):
        candidate, original, events = inputs();candidate['rawObservations'].pop()
        result = m.compare(candidate, original, events)
        self.assertIsNone(result['candidate']['lastWholeFcPssSumBytes'])
        self.assertIsNone(result['candidate']['lastHostCachedDeltaBytes'])

    def test_missing_resource_evidence_blocks_full_acceptance(self):
        candidate, original, events = inputs()
        del original['groups'][0]['cache']['jobs'][0]['resources']
        result = m.compare(candidate, original, events)
        self.assertFalse(result['resourceEvidenceMatched'])
        self.assertFalse(result['fullSameWorkloadComparisonAccepted'])


if __name__ == '__main__': unittest.main()
