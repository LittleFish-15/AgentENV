"""Mount transaction behavior with modeled system calls, never real mounts."""
import copy
from pathlib import Path
import stat
import struct
import sys
import types
import unittest
from unittest import mock

from aenv_ub_provider import host_pmem as p, host_pmem_mount as m


class MountTests(unittest.TestCase):
    def setUp(self):
        self.saved, self.commands = [], []
        self.namespace = (1, 77)
        self.volume = p.VolumeStatus('8ea26803-3d68-4d17-8c13-e88c846e3802',7,1,240,0,2**22,0,0,0,0,0,0)
        self.instance = m.ReadonlyMount(self.namespace, self.volume, Path('/owned/mount'),
                                       lambda value:self.saved.append(copy.deepcopy(value)))
        self.mounted = {'id':80,'device':'240:0','root':'/','filesystem':'ext4',
                        'options':{'ro','nodev','nosuid','noexec'},'superOptions':{'ro','dax=always'}}

    def test_validate_rejects_cached_writable_wrong_device_and_wrong_root(self):
        for value in (None,{**self.mounted,'device':'240:1'},
                      {**self.mounted,'superOptions':{'ro'}},
                      {**self.mounted,'options':{'rw'}},
                      {**self.mounted,'root':'/some-subtree'}):
            with self.assertRaises(RuntimeError):self.instance.validate_mount(value)

    def test_namespace_change_stops_before_mount_operations(self):
        with mock.patch.object(m,'namespace_identity',return_value=(1,78)),mock.patch.object(m,'command') as cmd:
            with self.assertRaises(RuntimeError):self.instance.mount()
            with self.assertRaises(RuntimeError):self.instance.unmount()
            cmd.assert_not_called()

    def test_unknown_mount_result_can_be_explicitly_unmounted_by_exact_identity(self):
        self.instance.state['phase']='mount_unconfirmed'
        with mock.patch.object(m,'namespace_identity',return_value=self.namespace), \
             mock.patch.object(m,'mounted_at',side_effect=[self.mounted,None]), \
             mock.patch.object(m,'command') as cmd:
            self.instance.unmount()
            cmd.assert_called_once_with('umount','--',self.instance.target)
            self.assertEqual(self.saved[-1]['phase'],'mount_absent')

    def test_changed_mount_id_never_unmounted(self):
        self.instance.state['phase']='mounted';self.instance.mount_id=79
        with mock.patch.object(m,'namespace_identity',return_value=self.namespace), \
             mock.patch.object(m,'mounted_at',return_value=self.mounted),mock.patch.object(m,'command') as cmd:
            with self.assertRaises(RuntimeError):self.instance.unmount()
            cmd.assert_not_called()

    def test_busy_unmount_is_preserved_without_force_or_lazy_retry(self):
        self.instance.state['phase']='mounted';self.instance.mount_id=80
        with mock.patch.object(m,'namespace_identity',return_value=self.namespace), \
             mock.patch.object(m,'mounted_at',return_value=self.mounted), \
             mock.patch.object(m,'command',side_effect=RuntimeError('busy')) as cmd:
            with self.assertRaises(RuntimeError):self.instance.unmount()
            self.assertEqual(self.saved[-1]['phase'],'unmount_unconfirmed')
            self.assertEqual(cmd.call_count,1)

    def test_mountinfo_decodes_space_and_refuses_stacked_mount(self):
        line='80 79 240:0 / /owned/a\\040b ro,nosuid,nodev,noexec - ext4 /dev/ubpmem_ro7 ro,dax=always\n'
        with mock.patch.object(m.Path,'read_text',return_value=line):
            self.assertEqual(m.mounted_at('/owned/a b')['device'],'240:0')
        with mock.patch.object(m.Path,'read_text',return_value=line+line):
            with self.assertRaises(RuntimeError):m.mounted_at('/owned/a b')

    def test_mount_uses_readonly_noload_and_persists_intent_first(self):
        # Model only paths/commands; actual mount options remain production code.
        target=mock.Mock();parent=mock.Mock();device=mock.Mock()
        target.parent=parent;target.resolve.return_value=target;parent.resolve.return_value=parent
        target.lstat.return_value=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o700)
        parent.stat.return_value=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o700)
        target.is_absolute.return_value=True;target.iterdir.return_value=iter([])
        device.lstat.return_value=types.SimpleNamespace(st_mode=stat.S_IFBLK,st_rdev=99)
        self.instance.target=target
        directory=mock.MagicMock();directory.__truediv__.return_value=device
        def command(*args):
            self.assertEqual(self.saved[-1]['phase'],'mount_intent')
            self.commands.append(args)
        with mock.patch.object(m,'namespace_identity',return_value=self.namespace), \
             mock.patch.object(m,'mounted_at',side_effect=[None,self.mounted]), \
             mock.patch.object(m,'Path',return_value=directory), \
             mock.patch.object(m,'no_readahead',return_value={'beforeSectors':256,'afterSectors':0}), \
             mock.patch.object(m,'os',types.SimpleNamespace(makedev=lambda a,b:99)), \
             mock.patch.object(m,'command',side_effect=command):
            self.instance.mount()
        self.assertEqual(self.commands[0][4],'ro,noload,dax=always,nodev,nosuid,noexec')
        self.assertEqual(self.saved[-1]['phase'],'mounted')

    def test_read_ahead_changes_only_the_verified_new_device(self):
        calls=[];gets=iter([256,0])
        def ioctl(fd,operation,argument,mutate=None):
            calls.append(operation)
            if operation==0x1263:struct.pack_into('=Q',argument,0,next(gets))
            else:self.assertEqual((operation,argument),(0x1262,0))
        fake=types.SimpleNamespace(O_RDONLY=0,O_NOFOLLOW=1,O_CLOEXEC=2,
            open=mock.Mock(return_value=31),close=mock.Mock(),makedev=lambda a,b:99,
            fstat=mock.Mock(return_value=types.SimpleNamespace(st_mode=stat.S_IFBLK,st_rdev=99)))
        with mock.patch.object(m,'os',fake),mock.patch.dict(sys.modules,{'fcntl':types.SimpleNamespace(ioctl=ioctl)}):
            result=m.no_readahead('/dev/ubpmem_ro7',self.volume)
        self.assertEqual(calls,[0x1263,0x1262,0x1263])
        self.assertEqual(result,{'beforeSectors':256,'afterSectors':0})
        fake.close.assert_called_once_with(31)

    def test_read_ahead_wrong_device_never_issues_ioctl(self):
        ioctl=mock.Mock()
        fake=types.SimpleNamespace(O_RDONLY=0,O_NOFOLLOW=1,O_CLOEXEC=2,
            open=mock.Mock(return_value=31),close=mock.Mock(),makedev=lambda a,b:99,
            fstat=mock.Mock(return_value=types.SimpleNamespace(st_mode=stat.S_IFBLK,st_rdev=100)))
        with mock.patch.object(m,'os',fake),mock.patch.dict(sys.modules,{'fcntl':types.SimpleNamespace(ioctl=ioctl)}):
            with self.assertRaises(ValueError):m.no_readahead('/dev/ubpmem_ro7',self.volume)
        ioctl.assert_not_called()


if __name__=='__main__':unittest.main()
