import importlib.util,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('preflight55',Path(__file__).with_name('cow55_preflight.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Preflight(unittest.TestCase):
    def test_private_api_fields_not_returned(self):
        row={'templateID':'id','envVars':{'key':'secret'},'accessToken':'secret','aliases':['swb-example','bad space'],'memoryMB':4096}
        got=m.projection([row],'templates')[0]
        self.assertEqual(got,{'templateID':'id','aliases':['swb-example'],'memoryMB':4096})
    def test_memory_not_rss(self):
        got=m.memory_info('MemAvailable: 123 kB\nCached: 456 kB\nUnselected: 99 kB')
        self.assertEqual(got,{'MemAvailable_bytes':123*1024,'Cached_bytes':456*1024})
    def test_missing_memavailable_not_zero(self):self.assertNotIn('MemAvailable_bytes',m.memory_info('Cached: 2 kB'))
    def test_route_outside_readonly_scope_rejected(self):
        with self.assertRaises(RuntimeError):m.api('test','/sandboxes-cold')
    def test_traversal_cgroup_rejected(self):
        with self.assertRaises(RuntimeError):m.cgroups('/../../etc')
    def test_no_active_cgroup_not_unlimited(self):self.assertFalse(m.cgroups('')['available'])
    def test_unexpected_api_shape_rejected(self):
        with self.assertRaises(RuntimeError):m.projection({'items':[]},'templates')

if __name__=='__main__':unittest.main()
