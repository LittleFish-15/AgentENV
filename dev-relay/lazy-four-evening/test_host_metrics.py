import importlib.util
from pathlib import Path
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('host_metrics',Path(__file__).with_name('host_metrics.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class HostMetricsTests(unittest.TestCase):
    def test_missing_psi_does_not_discard_memory(self):
        def read(path,*args,**kwargs):
            if path.name=='meminfo':return 'MemAvailable: 100 kB\nCached: 90 kB\nDirty: 1 kB\n'
            if path.name=='loadavg':return '0.0 0.0 0.0 1/1 1'
            raise FileNotFoundError()
        with mock.patch.object(Path,'read_text',read):value=m.host_observation(Path('/fixture'))
        self.assertTrue(value['available']);self.assertTrue(value['partial'])
        self.assertEqual(value['memoryBytes']['Cached'],90*1024)
        self.assertIsNone(value['memoryBytes']['SwapFree'])
        self.assertFalse(value['pressure']['memory']['available'])

    def test_controller_mounts_and_namespace_root_mapping(self):
        mountinfo='1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n2 0 0:2 / /sys/fs/cgroup/memory rw - cgroup memory rw,memory\n'
        values=list(m.candidates('/system.slice/test.service',mountinfo))
        self.assertEqual([x[0] for x in values],[2,1])
        self.assertTrue(values[1][2].as_posix().endswith('/memory/system.slice/test.service'))
        namespaced='1 0 0:1 /system.slice /scope rw - cgroup2 cgroup rw\n'
        self.assertTrue(list(m.candidates('/system.slice/test.service',namespaced))[0][2].as_posix().endswith('/scope/test.service'))
        with self.assertRaises(ValueError):list(m.candidates('/system.slice/../other',mountinfo))

    def test_v1_read_keeps_v1_semantics(self):
        mountinfo='1 0 0:1 / /cgroup/memory rw - cgroup memory rw,memory\n'
        def read(path,*args,**kwargs):
            if path.name=='memory.usage_in_bytes':return '8192\n'
            if path.name=='memory.stat':return 'rss 4096\ncache 2048\ntotal_rss 4096\n'
            raise FileNotFoundError()
        with mock.patch.object(Path,'resolve',lambda p,**kw:p),mock.patch.object(Path,'read_text',read):
            result=m.cgroup_memory('/unit',mountinfo=mountinfo)
        self.assertTrue(result['available']);self.assertEqual(result['version'],1)
        self.assertEqual(result['currentBytes'],8192)
        self.assertNotIn('anon',result['statBytes'])

    def test_missing_controller_is_na(self):
        result=m.cgroup_memory('/unit',mountinfo='')
        self.assertFalse(result['available']);self.assertIsNone(result['currentBytes'])


if __name__=='__main__':unittest.main()
