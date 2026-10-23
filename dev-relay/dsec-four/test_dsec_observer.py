import ctypes
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('dsec_observer', HERE / 'dsec_observer.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Observer(unittest.TestCase):
    def test_four_gib_ram_is_bound_to_api_not_named_mapping_size(self):
        size = 4 * 1024**3
        start = 0x1000000000
        text = f'{start:x}-{start+size:x} rw-p 00000000 00:01 12 /dev/ublkb7\nRss: 4 kB\nPss: 2 kB\n'
        regions = [{'base_host_virt_addr': start, 'size': size, 'offset': 0}]
        with patch.object(m.os, 'sysconf', return_value=4096, create=True):
            maps = m.parse_guest_smaps(text, '/dev/ublkb7', size, regions)
            self.assertEqual(sum(x['end']-x['start'] for x in maps), size)
            with self.assertRaisesRegex(RuntimeError, 'cover expected RAM'):
                m.parse_guest_smaps(text, '/dev/ublkb7', 512*1024**2, regions)
        self.assertEqual(m.sum_vma_metrics(maps)['Pss'], 2048)
        self.assertIsNone(m.sum_vma_metrics(maps)['Pss_Anon'])

    def test_clipped_smaps_does_not_prorate_pss(self):
        text = '1000-5000 rw-p 00000000 00:00 0\nPss: 12 kB\nRss: 16 kB\n'
        with patch.object(m.os, 'sysconf', return_value=4096, create=True):
            maps = m.parse_guest_smaps(text, '/dev/ublkb1', 8192,
                [{'base_host_virt_addr': 8192, 'size': 8192, 'offset': 0}])
        self.assertTrue(maps[0]['smaps_metrics_omitted_due_to_clipping'])
        self.assertIsNone(m.sum_vma_metrics(maps)['Pss'])

    def test_optional_pss_classification_absent_retains_total(self):
        def read(path, limit):
            return 'VmRSS: 12 kB\n' if path.name == 'status' else 'Rss: 12 kB\nPss: 8 kB\n'
        with patch.object(m, 'identity', return_value=(1, '77')), patch.object(m, 'bounded_text', side_effect=read):
            result = m.whole_process_metrics(9, '77')
        self.assertTrue(result['available'])
        self.assertEqual(result['pss_bytes'], 8192)
        self.assertIsNone(result['rollupBytes']['Pss_Anon'])

    def test_rollup_permission_missing_keeps_status_rss(self):
        def read(path, limit):
            if path.name == 'smaps_rollup':
                raise PermissionError()
            return 'VmRSS: 12 kB\n'
        with patch.object(m, 'identity', return_value=(1, '77')), patch.object(m, 'bounded_text', side_effect=read):
            result = m.whole_process_metrics(9, '77')
        self.assertTrue(result['available'])
        self.assertEqual(result['rss_bytes'], 12288)
        self.assertIsNone(result['pss_bytes'])

    def test_pid_reuse_rejects_partial_process_metrics(self):
        with patch.object(m, 'identity', side_effect=[(1, '77'), (1, '78')]), \
             patch.object(m, 'bounded_text', return_value='VmRSS: 12 kB\nPss: 8 kB\n'):
            result = m.whole_process_metrics(9, '77')
        self.assertFalse(result['available'])
        self.assertNotIn('pss_bytes', result)

    def test_pressure_missing_does_not_discard_meminfo(self):
        def read(path, limit):
            if path.name != 'meminfo':
                raise FileNotFoundError()
            return 'Cached: 80 kB\nBuffers: 20 kB\nMemAvailable: 100 kB\n'
        with patch.object(m, 'bounded_text', side_effect=read):
            result = m.host_observation()
        self.assertTrue(result['available'])
        self.assertEqual(result['memoryBytes']['Cached'], 81920)
        self.assertEqual(result['pressure'], dict(cpu=None, memory=None, io=None))

    def test_cgroup_hybrid_chooses_memory_v1(self):
        membership = '0::/unified.service\n4:cpu,cpuacct:/owned.service\n7:memory:/system.slice/owned.service\n'
        mounts = ('24 1 0:21 / /sys/fs/cgroup/unified rw - cgroup2 cgroup rw\n'
                  '25 1 0:22 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n')
        version, path = m.memory_cgroup_directory(membership, mounts)
        self.assertEqual(version, 'v1')
        self.assertEqual(path, Path('/sys/fs/cgroup/memory/system.slice/owned.service'))

    def test_cgroup_mount_subroot_and_escaped_path(self):
        version, path = m.memory_cgroup_directory('0::/group/task.service\n',
            '24 1 0:21 /group /sys/fs/cgroup/my\\040mount rw - cgroup2 cgroup rw\n')
        self.assertEqual(version, 'v2')
        self.assertEqual(path, Path('/sys/fs/cgroup/my mount/task.service'))

    def test_cgroup_invalid_membership_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Invalid cgroup path'):
            m.memory_cgroup_directory('0::/../other\n', '')

    def test_cgroup_stat_and_usage_survive_missing_pressure(self):
        directory = HERE
        def read(path, limit):
            if path.name == 'cgroup': return '7:memory:/own\n'
            if path.name == 'mountinfo': return 'ignored'
            if path.name == 'memory.usage_in_bytes': return '12345\n'
            if path.name == 'memory.stat': return 'rss 8192\ncache 4096\npgfault 20\n'
            raise FileNotFoundError()
        with patch.object(m, 'identity', return_value=(1, '77')), \
             patch.object(m, 'bounded_text', side_effect=read), \
             patch.object(m, 'memory_cgroup_directory', return_value=('v1', directory)):
            result = m.cgroup_memory(8, '77')
        self.assertTrue(result['available'])
        self.assertEqual(result['currentBytes'], 12345)
        self.assertEqual(result['stat']['pgfault'], 20)
        self.assertIsNone(result['pressure'])
        self.assertNotIn('statBytes', result)

    def test_pmem_separate_from_ram_and_actual_access(self):
        pin = [{'dev': 99, 'inode': 17, 'size': 8192, 'path': '/base.ext4'}]
        text = ('1000-3000 r--s 00000000 08:01 17 /base.ext4\nRss: 8 kB\nPss: 4 kB\n'
                '4000-6000 rw-p 00000000 08:01 18 /dev/ublkb1\nRss: 8 kB\nPss: 6 kB\n')
        with patch.object(m.os, 'major', return_value=8, create=True), \
             patch.object(m.os, 'minor', return_value=1, create=True):
            result = m.pmem_mappings(text, pin)
        self.assertEqual(len(result['mappings']), 1)
        self.assertEqual(result['bytes']['Pss'], 4096)
        self.assertIsNone(result['accessResidentIntersectionBytes'])
        self.assertTrue(result['overlapsHostFilePagecache'])

    def test_pmem_wrong_inode_not_inferred_by_path(self):
        pin = [{'dev': 99, 'inode': 17, 'size': 8192, 'path': '/base.ext4'}]
        result = m.pmem_mappings('1000-3000 r--s 00000000 08:01 18 /base.ext4\nPss: 4 kB\n', pin)
        self.assertFalse(result['available'])
        self.assertIsNone(result['bytes']['Pss'])

    def test_pmem_writable_alias_rejected(self):
        pin = [{'dev': 99, 'inode': 17, 'size': 8192, 'path': '/base.ext4'}]
        with patch.object(m.os, 'major', return_value=8, create=True), \
             patch.object(m.os, 'minor', return_value=1, create=True), self.assertRaisesRegex(RuntimeError, 'permissions'):
            m.pmem_mappings('1000-3000 rw-s 00000000 08:01 17 /base.ext4\n', pin)

    def test_mincore_bound_separates_large_raw_from_upper(self):
        with self.assertRaisesRegex(RuntimeError, 'bound'):
            m.resident_pages(1, 3*1024**3, 4096)
        with self.assertRaisesRegex(RuntimeError, 'bound'):
            m.resident_pages(1, 9*1024**3, 4096, max_bytes=9*1024**3)
        calls = []
        class Function:
            def __init__(self, call): self.call = call
            def __call__(self, *args): return self.call(*args)
        class Lib:
            mmap = Function(lambda addr, length, prot, flags, fd, offset:
                            calls.append((length, prot, flags, offset)) or 0x100000)
            mincore = Function(lambda addr, length, vector: 0)
            munmap = Function(lambda addr, length: 0)
        with patch.object(m.ctypes, 'CDLL', return_value=Lib()):
            count = m.resident_pages(1, 3*1024**3, 4096, max_bytes=8*1024**3)
        self.assertEqual(count, 0)
        self.assertEqual(len(calls), 48)
        self.assertTrue(all(row[1:3] == (0, 1) for row in calls))
        self.assertEqual(sum(row[0] for row in calls), 3*1024**3)

    def test_required_explicit_ram_contract(self):
        with self.assertRaises(TypeError):
            m.collect_ram(Path('/base'), 1, '9', ['sid'])
        result = m.collect_ram(Path('/base'), 1, '9', ['sid'], expected_bytes={})
        self.assertFalse(result['available'])
        self.assertIn('contracts differ', result['reason'])


if __name__ == '__main__':
    unittest.main()
