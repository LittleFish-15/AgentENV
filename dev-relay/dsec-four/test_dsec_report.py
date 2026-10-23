import importlib.util
from pathlib import Path
import unittest
import copy

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('report', HERE / 'dsec_report.py')
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def cohort():
    jobs, events = [], {}
    for i in range(4):
        for slot in (0, 1):
            row = {'instanceId': 'case'+str(i), 'slot': slot, 'replaySha256': str(i)*64,
                   'stepsCompleted': 2, 'failedCommands': 1, 'state': 'REPLAY_COMPLETED',
                   'sandboxId': str(i)+'-'+str(slot), 'originalTemplateId': 'orig'+str(i),
                   'replayStartedUnix': 10, 'replayFinishedUnix': 20}
            jobs.append(row)
            events[row['instanceId'], slot] = [{'step': 0, 'returnCode': 0}, {'step': 1, 'returnCode': 1}]
    return jobs, events


class Report(unittest.TestCase):
    def test_same_aggregate_failures_different_command_never_passes(self):
        jobs, events = cohort();other = copy.deepcopy(events)
        other['case0', 0] = [{'step': 0, 'returnCode': 1}, {'step': 1, 'returnCode': 0}]
        result = m.replay_comparison(jobs, jobs, events, other)
        self.assertFalse(result['sameReplayOutcomesAccepted'])

    def test_missing_original_events_remains_unverified(self):
        jobs, events = cohort()
        result = m.replay_comparison(jobs, jobs, events)
        self.assertTrue(result['identitiesMatch'])
        self.assertFalse(result['sameReplayOutcomesAccepted'])
        self.assertIsNone(result['pairs'][0]['exactCommandExitsMatch'])

    def test_matched_events_still_not_causal_net_benefit(self):
        jobs, events = cohort()
        result = m.replay_comparison(jobs, jobs, events, events)
        self.assertTrue(result['sameReplayOutcomesAccepted'])
        self.assertFalse(result['causalPerformanceGainEstablished'])

    def test_transport_failure_or_timeout_never_passes(self):
        jobs, events = cohort()
        for extra in ({'transportOk': False}, {'timedOut': True}, {'returnCode': 124}):
            new = copy.deepcopy(events);new['case0', 0][0].update(extra)
            self.assertFalse(m.replay_comparison(jobs, jobs, new, new)['sameReplayOutcomesAccepted'])

    def test_duplicate_slot_or_incomplete_job_rejected(self):
        jobs, events = cohort()
        jobs[0] = copy.deepcopy(jobs[1])
        self.assertFalse(m.replay_comparison(jobs, jobs, events, events)['sameReplayOutcomesAccepted'])

    def test_same_cycle_totals_do_not_sum_independent_peaks(self):
        jobs, _ = cohort()
        def sample(values):
            return {'ram': {'guests': [{'sandboxId': row['sandboxId'],
                        'wholeProcess': {'pss_bytes': value}} for row, value in zip(jobs, values)]}}
        samples = [sample([100, 1, 1, 1, 1, 1, 1, 1]), sample([1, 100, 1, 1, 1, 1, 1, 1])]
        result = m.summarize(samples, jobs)
        self.assertEqual(result['ranges']['wholeFcPssSumBytes']['max'], 107)
        self.assertIsNone(result['physicalNetSavingBytes'])

    def test_missing_one_guest_invalidates_sum_not_zero_fills(self):
        jobs, _ = cohort()
        sample = {'ram': {'guests': [{'sandboxId': r['sandboxId'], 'wholeProcess': {'pss_bytes': 1}} for r in jobs[:-1]]}}
        result = m.summarize([sample], jobs)
        self.assertEqual(result['ranges']['wholeFcPssSumBytes']['missingSamples'], 1)
        self.assertIsNone(result['ranges']['wholeFcPssSumBytes']['max'])

    def test_negative_sequential_difference_not_savings(self):
        row = {'sandboxId': 'a', 'wholeProcess': {'pss_bytes': 10},
               'guestRam': {'available': True, 'bytes': {'Pss': 12}}}
        result = m.sample_totals({'ram': {'guests': [row]}}, ['a'])
        self.assertEqual(result['fcOutsideGuestRamPssDifferenceBytes'], -2)
        self.assertIsNone(result['globalPhysicalSavingBytes'])

    def test_markdown_preserves_na_and_limits(self):
        jobs, events = cohort()
        report = {'status': 'LOCAL_FIXTURE_ONLY', 'measurementSummary': m.summarize([], jobs),
                  'replayComparison': m.replay_comparison(jobs, jobs, events)}
        text = m.markdown(report)
        self.assertIn('NA', text);self.assertIn('不能相加', text)


if __name__ == '__main__': unittest.main()
