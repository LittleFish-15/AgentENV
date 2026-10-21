import contextlib
import importlib.util
from pathlib import Path
import types
import stat
import unittest
import uuid
from unittest import mock

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


RAM, DRIVER, REPORT = (module(name) for name in ('ram_observer', 'native_cohort', 'cohort_report'))


def guest(upper, lower, resident=4096):
    return {'rootfsUpper': {'available': True,
                           'files': [{'dev': 1, 'inode': upper}, {'dev': 1, 'inode': upper + 1}],
                           'lowerFileIdentities': [[1, lower]], 'residentPageBytes': resident}}


class UpperTests(unittest.TestCase):
    def test_legitimate_parent_path_normalized_within_scope(self):
        root = HERE / 't' / uuid.uuid4().hex[:8]
        config = root / 'nested'
        config.mkdir(parents=True)
        (root / 'layer').write_bytes(b'fixture')
        self.assertEqual(RAM.cache_path('../layer', config, (root,)), root / 'layer')

    def test_parent_path_outside_scope_refused(self):
        root = HERE / 't' / uuid.uuid4().hex[:8]
        config = root / 'nested'
        config.mkdir(parents=True)
        (root / 'layer').write_bytes(b'fixture')
        with self.assertRaisesRegex(RuntimeError, 'outside owned scope'):
            RAM.cache_path('../layer', config, (config,))

    def test_mutating_upper_is_na_instead_of_a_stable_charge(self):
        before = types.SimpleNamespace(st_mode=stat.S_IFREG, st_uid=1204, st_dev=1, st_ino=10,
                                       st_size=4096, st_mtime_ns=1, st_ctime_ns=1)
        after = types.SimpleNamespace(**{**vars(before), 'st_size': 8192})
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(RAM, 'upper_files', return_value=([
                {'kind': 'data', 'path': Path('fixture'), 'dev': 1, 'inode': 10}], {(1, 1)})))
            stack.enter_context(mock.patch.object(RAM.os, 'sysconf', return_value=4096, create=True))
            stack.enter_context(mock.patch.object(RAM.os, 'O_NOFOLLOW', 0, create=True))
            stack.enter_context(mock.patch.object(RAM.os, 'O_CLOEXEC', 0, create=True))
            stack.enter_context(mock.patch.object(RAM.os, 'O_NONBLOCK', 0, create=True))
            stack.enter_context(mock.patch.object(RAM.os, 'open', return_value=9))
            stack.enter_context(mock.patch.object(RAM.os, 'fstat', side_effect=[before, after]))
            closed = stack.enter_context(mock.patch.object(RAM.os, 'close'))
            stack.enter_context(mock.patch.object(RAM, 'resident_pages', return_value=1))
            result = RAM.upper_cache(Path('base'), Path('cwd'))
        self.assertFalse(result['available'])
        self.assertIn('changed during sampling', result['reason'])
        self.assertNotIn('residentPageBytes', result)
        closed.assert_called_once_with(9)

    def test_deduplicated_private_upper_count_is_not_cgroup_addend(self):
        result = RAM.aggregate_upper([guest(10, 1), guest(20, 1, 8192)])
        self.assertTrue(result['available'])
        self.assertEqual(result['residentPageBytes'], 12288)
        self.assertFalse(result['addToRuntimeCgroupTotal'])
        self.assertFalse(result['hostLowerAccessResidencyMeasured'])

    def test_upper_alias_between_guests_is_na(self):
        result = RAM.aggregate_upper([guest(10, 1), guest(10, 1)])
        self.assertFalse(result['available'])
        self.assertIsNone(result['residentPageBytes'])

    def test_upper_aliases_another_guest_lower_is_na(self):
        result = RAM.aggregate_upper([guest(10, 1), guest(20, 10)])
        self.assertFalse(result['available'])

    def test_missing_one_upper_is_not_zero(self):
        result = RAM.aggregate_upper([guest(10, 1), {'rootfsUpper': {'available': False}}])
        self.assertFalse(result['available'])
        self.assertIsNone(result['residentPageBytes'])

    def test_empty_file_has_zero_resident_pages_without_mmap(self):
        with mock.patch.object(RAM.ctypes, 'CDLL') as libc:
            self.assertEqual(RAM.resident_pages(10, 0, 4096), 0)
            libc.assert_not_called()

    def test_metadata_query_uses_prot_none_and_unmaps(self):
        calls = []
        def mmap(*args):
            calls.append(('mmap', args))
            return 65536
        def mincore(address, length, vector):
            vector[0], vector[1] = 1, 0
            return 0
        def munmap(*args):
            calls.append(('munmap', args))
            return 0
        libc = types.SimpleNamespace(mmap=mmap, mincore=mincore, munmap=munmap)
        with mock.patch.object(RAM.ctypes, 'CDLL', return_value=libc):
            self.assertEqual(RAM.resident_pages(10, 8192, 4096), 1)
        self.assertEqual(calls[0][1][2:4], (0, 1))
        self.assertEqual(calls[-1], ('munmap', (65536, 8192)))

    def test_mincore_failure_still_unmaps_without_zero_result(self):
        mmap = mock.Mock(return_value=65536)
        mincore = mock.Mock(return_value=-1)
        munmap = mock.Mock(return_value=0)
        with mock.patch.object(RAM.ctypes, 'CDLL', return_value=types.SimpleNamespace(mmap=mmap, mincore=mincore, munmap=munmap)):
            with self.assertRaisesRegex(RuntimeError, 'unavailable'):
                RAM.resident_pages(10, 4096, 4096)
        munmap.assert_called_once_with(65536, 4096)

    def test_cache_query_refuses_oversize_and_invalid_page_size(self):
        for size, page in ((2 * 1024**3 + 1, 4096), (4096, 6000), (-1, 4096)):
            with self.subTest(size=size, page=page), self.assertRaisesRegex(RuntimeError, 'bound'):
                RAM.resident_pages(10, size, page)


class ProviderTests(unittest.TestCase):
    def test_process_and_coverage_cannot_become_physical_ub_charge(self):
        fields = {'ActiveState': 'active', 'User': 'jwk', 'Group': 'jwk', 'MainPID': '100', 'ControlGroup': '/owned'}
        prepared = {'node': 'node-b', 'sourceImage': DRIVER.SOURCE, 'logicalBudgetBytes': 64 * 1024**2}
        owner = {'state': 'serving', 'format': 'native-raw-v1', 'role': 'import', 'objects': [],
                 'imports': [{'backing_coverage_bytes': 128 * 1024**2}], 'manifestSha256': 'sha256:test'}
        observer = types.SimpleNamespace(whole_process_metrics=lambda *a: {'available': True, 'rss_bytes': 4096, 'pss_bytes': 2048})
        with mock.patch.object(DRIVER, 'unit_fields', return_value=fields), \
                mock.patch.object(DRIVER, 'ticks', return_value='200'), \
                mock.patch.object(DRIVER, 'load', side_effect=[prepared, owner]), \
                mock.patch.object(DRIVER, 'cgroup_memory', return_value={'available': True, 'currentBytes': 8192}):
            result = DRIVER.provider_metrics('node-b', observer)
        self.assertTrue(result['available'])
        self.assertEqual(result['allocationRecords'], 0)
        self.assertEqual(result['sdkReportedBackingCoverageBytes'], 128 * 1024**2)
        self.assertIsNone(result['physicalUBChargedBytes'])
        self.assertFalse(result['coverageIsPhysicalCharge'])

    def test_sampler_end_time_covers_all_components(self):
        order = []
        observer = types.SimpleNamespace(collect_ram=lambda *a: order.append('ram') or {})
        api = types.SimpleNamespace(pid=100, ticks='200', cgroup='/owned')
        def now():
            order.append('clock')
            return len(order)
        with mock.patch.object(DRIVER.time, 'time_ns', side_effect=now), \
                mock.patch.object(DRIVER, 'cgroup_memory', side_effect=lambda *a: order.append('runtime') or {}), \
                mock.patch.object(DRIVER, 'provider_metrics', side_effect=lambda *a: order.append('provider') or {}):
            result = DRIVER.sample_node(api, observer, Path('/owned'), 'node-a', 'after_workload', ['one', 'two'])
        self.assertEqual(order, ['clock', 'ram', 'runtime', 'provider', 'clock'])
        self.assertLess(result['startNs'], result['endNs'])
        self.assertFalse(result['atomicSnapshot'])


if __name__ == '__main__':
    unittest.main()
