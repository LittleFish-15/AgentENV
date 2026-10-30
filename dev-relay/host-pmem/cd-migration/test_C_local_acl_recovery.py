import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
spec=importlib.util.spec_from_file_location('recover',Path(__file__).with_name('C_run_maintenance_v15.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
    def test_backup_cannot_redirect_to_another_device(self):
        with self.assertRaises(RuntimeError):m.validate_backup('/dev/obmm',b'# file: /dev/ublkc0\nuser::rw-\n')
        with self.assertRaises(RuntimeError):m.validate_backup('/dev/obmm',b'# file: /dev/obmm\n# file: /etc/shadow\n')
    def test_outside_acl_change_is_preserved(self):
        module=SimpleNamespace(checked=Mock(return_value=b'other ACL'),tool=lambda x:x)
        item={'path':'/dev/obmm','inode':1,'rdev':2,'backup':'acl-obmm.txt','appliedAclSha256':'0'*64}
        original=b'# file: /dev/obmm\nuser::rw-\n'
        with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=m.stat.S_IFCHR,st_ino=1,st_rdev=2)),patch.object(m,'trusted',return_value=original):
            with self.assertRaisesRegex(RuntimeError,'outside this task'):m.restore_one(module,SimpleNamespace(atomic=Mock()),item,{'acl':[]})
        self.assertTrue(all(call.args[0][0]=='getfacl' for call in module.checked.call_args_list))
    def test_already_original_acl_needs_no_setfacl(self):
        original=b'# file: /dev/obmm\nuser::rw-\n'
        module=SimpleNamespace(checked=Mock(return_value=original),tool=lambda x:x)
        item={'path':'/dev/obmm','inode':1,'rdev':2,'backup':'acl-obmm.txt','appliedAclSha256':'0'*64};record={'acl':[]}
        with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=m.stat.S_IFCHR,st_ino=1,st_rdev=2)),patch.object(m,'trusted',return_value=original):
            m.restore_one(module,SimpleNamespace(atomic=Mock()),item,record)
        self.assertTrue(record['acl'][0]['restored'])
        self.assertTrue(all(call.args[0][0]=='getfacl' for call in module.checked.call_args_list))
if __name__=='__main__':unittest.main()
