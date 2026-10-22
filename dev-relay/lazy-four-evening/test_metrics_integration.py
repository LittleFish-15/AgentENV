import ast
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class MetricIntegrationTests(unittest.TestCase):
    def test_cohort_uses_partial_host_values(self):
        cohort=load('lazy_four_cohort_metrics_v2')
        def read(p,*args,**kwargs):
            if p.name=='meminfo':return 'MemAvailable: 200000000 kB\nCached: 12345 kB\nDirty: 0 kB\n'
            if p.name=='loadavg':return '0.0 0.0 0.0 1/1 1'
            raise FileNotFoundError()
        with mock.patch.object(Path,'read_text',read):value=cohort.host_observation()
        self.assertTrue(value['available']);self.assertTrue(value['partial'])
        self.assertEqual(value['memoryBytes']['Cached'],12345*1024)
        self.assertFalse(value['pressure']['memory']['available'])
        self.assertIsNone(value['memoryBytes']['SwapFree'])

    def test_runtime_reads_mount_declared_v1_controller(self):
        rt=load('four_runtime_metrics_v2')
        # Same mount structure as both returned nodes, without target identity.
        mount='57 51 0:35 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec shared:13 - cgroup cgroup rw,seclabel,memory\n'
        def read(p,*args,**kwargs):
            if p.name=='memory.usage_in_bytes':return '16384'
            if p.name=='memory.stat':return 'rss 8192\ncache 4096\ntotal_rss 8192\n'
            raise FileNotFoundError()
        with mock.patch.object(Path,'resolve',lambda p,**kw:p),mock.patch.object(Path,'read_text',read):
            value=rt.cgroup_memory('/system.slice/test.service',mountinfo=mount)
        self.assertTrue(value['available']);self.assertEqual(value['version'],1)
        self.assertEqual(value['currentBytes'],16384)
        self.assertEqual(value['scope'],'runtime_unit_charge_including_retained_pools_and_helpers')
        self.assertFalse(value['UBPhysicalChargeComplete'])

    def test_generated_pin_matches_exact_runtime_and_old_functions_unchanged(self):
        cohort=load('lazy_four_cohort_metrics_v2')
        raw=(HERE/'four_runtime_metrics_v2.py').read_bytes()
        self.assertEqual(cohort.PINS['four_runtime'],hashlib.sha256(raw).hexdigest())
        old=HERE.parent.parent/'lazy-four-20261022/delivery'
        for name,candidate,replaced in [('four_runtime.py','four_runtime_metrics_v2.py','cgroup_memory'),
                                         ('lazy_four_cohort.py','lazy_four_cohort_metrics_v2.py','host_observation')]:
            before=(old/name).read_text(encoding='utf-8');after=(HERE/candidate).read_text(encoding='utf-8')
            new={n.name:ast.get_source_segment(after,n) for n in ast.parse(after).body if isinstance(n,(ast.ClassDef,ast.FunctionDef))}
            for node in ast.parse(before).body:
                if isinstance(node,(ast.ClassDef,ast.FunctionDef)) and node.name!=replaced:
                    self.assertEqual(ast.get_source_segment(before,node),new[node.name],node.name)

if __name__=='__main__':unittest.main()
