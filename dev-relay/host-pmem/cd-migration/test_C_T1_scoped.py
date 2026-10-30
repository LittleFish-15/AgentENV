import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock,Mock,patch

HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('scoped_demo',HERE/'C_run_maintenance_v8.py')
base=load('base_tests',HERE/'test_C_T1_demo_v4.py');base.m=m

class Lifecycle(base.Tests):
    def setUp(self):
        guard=patch.object(m,'verify_baseline');guard.start();self.addCleanup(guard.stop)
    def test_existing_ublk_blocks_permission_setup(self):
        # Existing devices are checked; the old global-empty gate no longer applies.
        with patch.object(m,'BASELINE_DEVICES',[]),patch.object(m.ScopedDevicePermissions,'start') as start:
            self.demo().install_udev_rule();start.assert_called_once()
    def test_ublk_leftovers_prevent_rule_removal_not_force_deleted(self):
        d=self.demo();d.permissions=SimpleNamespace(stop=Mock(),grants=[{'device':'ublkc7','inode':1,'rdev':2}])
        d.state['ownedUblkPermissionGrants']=d.permissions.grants
        with patch.object(Path,'exists',lambda path:path.name=='ublkc7'),patch.object(Path,'lstat',return_value=SimpleNamespace(st_ino=1,st_rdev=2)),patch.object(Path,'unlink') as unlink:
            with self.assertRaisesRegex(RuntimeError,'Owned ublk device remains'):d.restore_udev_rule()
            unlink.assert_not_called()

class Permissions(unittest.TestCase):
    def watcher(self):
        with patch.object(m,'BASELINE_DEVICES',[{'path':'/dev/ublkc0'},{'path':'/dev/ublkb0'}]):
            return m.ScopedDevicePermissions(SimpleNamespace(state={'units':{}}))
    def meta(self,uid=0,gid=0,mode=0o600):
        return SimpleNamespace(st_dev=1,st_ino=20,st_rdev=30,st_uid=uid,st_gid=gid,st_mode=m.stat.S_IFCHR|mode)
    def call(self,w,**kwargs):
        return patch.multiple(m.os,O_PATH=0x200000,O_NOFOLLOW=0x20000,O_CLOEXEC=0x80000,chown=Mock(),create=True)
    def test_existing_device_never_opened_or_queried(self):
        w=self.watcher();w.query=Mock()
        with patch.object(m.os,'open') as opened:w.consider('ublkc0');opened.assert_not_called()
        w.query.assert_not_called()
    def test_new_root_owned_device_is_not_retagged(self):
        w=self.watcher();w.query=Mock(return_value={'id':9,'uid':0,'gid':0,'pid':999,'state':0})
        with self.call(w),patch.object(m.os,'open',return_value=7),patch.object(m.os,'close'),patch.object(m.os,'fstat',return_value=self.meta()),patch.object(m.os,'chown') as chown,patch.object(m.os,'chmod') as chmod:
            w.consider('ublkc9');chown.assert_not_called();chmod.assert_not_called()
        self.assertEqual(len(w.rejected),1)
    def test_unrelated_jwk_daemon_is_not_retagged(self):
        w=self.watcher();w.query=Mock(return_value={'id':9,'uid':1204,'gid':1205,'pid':999,'state':0})
        w.authorized_process=Mock(return_value=None)
        with self.call(w),patch.object(m.os,'open',return_value=7),patch.object(m.os,'close'),patch.object(m.os,'fstat',return_value=self.meta()),patch.object(m.os,'chown') as chown:
            w.consider('ublkc9');chown.assert_not_called()
    def test_reused_device_id_does_not_receive_permissions(self):
        w=self.watcher();row={'id':9,'uid':1204,'gid':1205,'pid':999,'state':0}
        w.query=Mock(side_effect=[row,{**row,'uid':0,'pid':123}]);w.authorized_process=Mock(return_value=('original','123'))
        with self.call(w),patch.object(m.os,'open',return_value=7),patch.object(m.os,'close'),patch.object(m.os,'fstat',return_value=self.meta()),patch.object(m.os,'chown') as chown:
            w.consider('ublkc9');chown.assert_not_called()
    def test_confirmed_owned_device_uses_pinned_inode_not_dev_path(self):
        w=self.watcher();w.query=Mock(return_value={'id':9,'uid':1204,'gid':1205,'pid':999,'state':0})
        w.authorized_process=Mock(return_value=('original','123'))
        stream=MagicMock();stream.__enter__.return_value=stream
        with self.call(w),patch.object(m.os,'open',return_value=7),patch.object(m.os,'close'),patch.object(m.os,'fstat',side_effect=[self.meta(),self.meta(1204,1205)]),patch.object(Path,'lstat',return_value=self.meta()),patch.object(Path,'open',return_value=stream),patch.object(m.os,'fsync'),patch.object(m.os,'chown') as chown,patch.object(m.os,'chmod') as chmod:
            w.consider('ublkc9')
            chown.assert_called_once_with('/proc/self/fd/7',1204,1205)
            chmod.assert_called_once_with('/proc/self/fd/7',0o600)
        self.assertEqual(len(w.grants),1)
    def test_no_eviction_global_rule_or_device_deletion(self):
        source=(HERE/'C_run_maintenance_v8.py').read_text()
        for forbidden in ('posix_fadvise','--reload-rules','UBLK_CMD_DEL_DEV','Shutdown','kill -9'):
            self.assertNotIn(forbidden,source)
        d=SimpleNamespace(state={});m.Demo.advise_sources(d)
        self.assertFalse(d.state['cacheComparisonAccepted'])
        self.assertIsNone(d.state['avoidedHostFilePageCacheBytes'])

if __name__=='__main__':unittest.main()
