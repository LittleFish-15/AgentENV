"""Composed cleanup ordering; SDK/namespace/mount/kernel operations are modeled."""
import contextlib
from pathlib import Path
import types
import unittest
from unittest import mock

from aenv_ub_provider import host_pmem_session as s, raw


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.events=[]
        self.volume=types.SimpleNamespace(record={'phase':'serving'})
        def retire_volume():
            self.events.append('destroy_and_absence');self.volume.record['phase']='local_volume_absent'
        self.volume.retire=mock.Mock(side_effect=retire_volume)
        self.volume.confirm_absent=mock.Mock()
        self.volume.reconcile_creation_for_retirement=mock.Mock(side_effect=RuntimeError('unresolved query'))
        self.lease=mock.Mock(volume=self.volume)
        self.lease.attach.side_effect=lambda *_:self.events.append('attach') or mock.Mock()
        self.lease.close.side_effect=lambda:self.events.append('close_sdk_lease')
        self.mount=mock.Mock(state={'phase':'new'})
        def mount():self.events.append('mount');self.mount.state['phase']='mounted'
        def unmount():self.events.append('unmount');self.mount.state['phase']='mount_absent'
        self.mount.mount.side_effect=mount;self.mount.unmount.side_effect=unmount
        self.stack=contextlib.ExitStack()
        for target,attr,value in (
                (s,'prepare_work',mock.Mock(return_value=Path('/private/session'))),
                (s.Path,'read_text',mock.Mock(return_value='boot-id')),
                (s,'atomic_json',mock.Mock()),
                (s.host_pmem_mount,'private_namespace',mock.Mock(return_value=(1,77))),
                (s.host_pmem,'open_control',mock.Mock(return_value=123)),
                (s.host_pmem,'Control',mock.Mock()),
                (s.host_pmem_lease,'acquire',mock.Mock(return_value=self.lease)),
                (s.host_pmem_mount,'ReadonlyMount',mock.Mock(return_value=self.mount)),
                (s.host_pmem,'verify_dax_file',mock.Mock(return_value={'state':'local_dax_file_verified','netSavingsBytes':None})),
                (s.os,'close',mock.Mock(side_effect=lambda fd:self.events.append('close_control')))):
            self.stack.enter_context(mock.patch.object(target,attr,value))
        source={'objectId':'image1','generation':'gen1','bytes':2**22,
                'sha256':'sha256:'+'a'*64,'socket':'/owned/data.sock'}
        publication={'version':1,'ownerId':'b'*32,'mode':'pmem','readers':['peer'],
                     'replicas':[raw.shape(source,'aenv_'+'c'*32)]}
        self.session=s.MountedSession('/private/session',source,1204,50,'1234',publication)

    def tearDown(self):self.stack.close()

    def test_full_local_path_releases_mount_then_volume_then_lease(self):
        self.session.start()
        self.session.verify('payload.bin',4096,'a'*64)
        result=self.session.retire()
        self.assertEqual(self.events,['attach','mount','unmount','destroy_and_absence','close_sdk_lease','close_control'])
        self.assertEqual(result['phase'],'local_resources_released')
        self.assertFalse(result['sharedBackingReleaseAuthorized'])

    def test_busy_unmount_retains_volume_and_sdk_lease(self):
        self.session.start();self.mount.unmount.side_effect=RuntimeError('busy mount')
        with self.assertRaises(RuntimeError):self.session.retire()
        self.volume.retire.assert_not_called();self.lease.close.assert_not_called()
        s.os.close.assert_not_called()

    def test_rootfs_child_blocks_mount_and_sdk_retirement_until_confirmed_exit(self):
        self.session.start()
        consumer=types.SimpleNamespace(retired=False)
        self.session.retain_consumer(consumer)
        with self.assertRaisesRegex(RuntimeError,'consumer not retired'):self.session.retire()
        self.mount.unmount.assert_not_called();self.lease.close.assert_not_called()
        consumer.retired=True
        self.session.retire()
        self.assertEqual(self.events[-3:],['destroy_and_absence','close_sdk_lease','close_control'])

    def test_unknown_create_never_closes_sdk_lease(self):
        self.lease.attach.side_effect=RuntimeError('lost create reply')
        self.volume.record['phase']='create_unconfirmed'
        with self.assertRaises(RuntimeError):self.session.start()
        with self.assertRaises(RuntimeError):self.session.retire()
        self.lease.close.assert_not_called();self.volume.retire.assert_not_called()
        self.mount.mount.assert_not_called()

    def test_bad_file_validation_preserves_resources_until_explicit_retire(self):
        self.session.start();s.host_pmem.verify_dax_file.side_effect=ValueError('S_DAX absent')
        with self.assertRaises(ValueError):self.session.verify('payload.bin',4096,'a'*64)
        self.mount.unmount.assert_not_called();self.lease.close.assert_not_called()
        self.session.retire()
        self.assertEqual(self.session.record['phase'],'local_resources_released')

    def test_reject_path_escape_before_file_io(self):
        self.session.start()
        for name in ('../file','/etc/passwd','sub/file','..','x\\y'):
            with self.assertRaises(ValueError):self.session.verify(name,4096,'a'*64)
        s.host_pmem.verify_dax_file.assert_not_called()

    def test_ambiguous_destroy_queries_absence_and_never_reissues_destroy(self):
        self.session.start();self.volume.record['phase']='destroy_unconfirmed'
        def absent():self.volume.record['phase']='local_volume_absent'
        self.volume.confirm_absent.side_effect=absent
        self.session.retire()
        self.volume.confirm_absent.assert_called_once();self.volume.retire.assert_not_called()


if __name__=='__main__':unittest.main()
