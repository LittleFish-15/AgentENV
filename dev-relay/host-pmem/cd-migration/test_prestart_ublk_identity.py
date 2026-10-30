import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('identity',Path(__file__).with_name('prestart_ublk_identity.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
    def args(self):
        return dict(reserved_gid=60001,owned_units={'experiment':'unit-incarnation'},
          processes=[dict(pid=42,ticks='123',allGids=[60001,1205],primaryGid=60001,stable=True,
            uids=[1204]*4,unit='experiment',unitIdentity='unit-incarnation',executableSha256='daemon-hash')],
          group_members=[],scan_complete=True,executable_hashes={'daemon-hash'})
    def info(self):return dict(uid=1204,gid=60001,pid=-1,state=0)
    def test_actual_prestart_pid_minus_one_supported(self):
        self.assertEqual(m.attribute(self.info(),**self.args())['pid'],42)
    def test_same_jwk_but_other_group_not_authorized(self):
        self.assertIsNone(m.attribute({**self.info(),'gid':1205},**self.args()))
    def test_other_unit_using_reserved_group_blocks(self):
        args=self.args();args['processes'].append({**args['processes'][0],'pid':43,'unit':'other'})
        with self.assertRaises(ValueError):m.attribute(self.info(),**args)
    def test_incomplete_scan_blocks(self):
        args=self.args();args['scan_complete']=False
        with self.assertRaises(ValueError):m.attribute(self.info(),**args)
    def test_started_pid_must_match(self):
        with self.assertRaises(ValueError):m.attribute({**self.info(),'pid':43,'state':1},**self.args())
    def test_changed_unit_incarnation_blocks(self):
        args=self.args();args['processes'][0]['unitIdentity']='different'
        with self.assertRaises(ValueError):m.attribute(self.info(),**args)
if __name__=='__main__':unittest.main()
