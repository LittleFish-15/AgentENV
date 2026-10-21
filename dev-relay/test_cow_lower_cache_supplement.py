import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('supplement', Path(__file__).with_name('cow_lower_cache_supplement.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SupplementTests(unittest.TestCase):
    def setUp(self):
        self.jobs = [{'template_id': t, 'sandbox_id': t+s} for t in ('a', 'b') for s in ('1', '2')]
        self.files = {'common': {'file_id': 'common'}, 'a': {'file_id': 'a'}, 'b': {'file_id': 'b'}}
        self.refs = [{'kind': 'rootfs_lower', 'template_id': j['template_id'], 'sandbox_id': j['sandbox_id'], 'file_id': f}
                     for j in self.jobs for f in ('common', j['template_id'])]
        self.frame = {'complete_reference_inventory': True, 'errors': [], 'files': list(self.files.values()), 'references': self.refs}
        self.sample = {i: {'available': True, 'resident_bytes': 4096, 'file_bytes': 4000,
                          'allocated_bytes': 4096, 'page_span_bytes': 4096} for i in self.files}

    def test_truncated_old_complete_flag_rejected(self):
        self.frame['references'] = self.refs[:-2]
        self.assertIsNone(m.references(self.frame, self.jobs))

    def test_cross_template_dedup_and_page_rounding(self):
        files, pairs = m.references(self.frame, self.jobs)
        s = m.summarize(files, pairs, self.sample)
        self.assertEqual(s['global_unique_lower_resident_bytes'], 3*4096)
        self.assertEqual(sum(r['common_lower_resident_bytes'] for r in s['templates']), 4*4096)
        for r in s['templates']:
            self.assertEqual(r['common_lower_residency_fraction'], 1)
            self.assertEqual(r['independent_lower_cache_copy_model_saving_fraction'], .5)
            self.assertIsNone(r['current_lower_plus_upper_cache_shared_fraction'])

    def test_missing_is_na_not_zero(self):
        self.sample['a'] = {'available': False}
        files, pairs = m.references(self.frame, self.jobs)
        s = m.summarize(files, pairs, self.sample)
        self.assertIsNone(s['global_unique_lower_resident_bytes'])
        self.assertFalse(s['complete'])
        self.assertEqual(s['templates'][1]['common_lower_resident_bytes'], 8192)

    def test_duplicate_layer_not_counted_twice(self):
        self.frame['references'].append(copy.deepcopy(self.refs[0]))
        with self.assertRaises(RuntimeError):
            m.references(self.frame, self.jobs)

    def test_global_correction_retains_excluded_evidence(self):
        source = {'global_file_cache_sweeps_by_batch': [{'batch_number': 1, 'sweeps': [{'sample_id': '0'}, {'sample_id': '16'}]}]}
        text = 'history\n## 每批观测文件去重后的宿主机统计（完整采样窗口）\nold incorrect table\n批次 1：ok'
        result = m.correct_historical_global(source, text, {'0'})
        self.assertNotIn('old incorrect table', result)
        self.assertTrue(result.startswith('history'))
        self.assertEqual(source['historical_global_cache_correction']['excluded_sweeps'], [{'sample_id': '16'}])
        self.assertEqual(len(source['global_file_cache_sweeps_by_batch'][0]['sweeps']), 1)


if __name__ == '__main__':
    unittest.main()
