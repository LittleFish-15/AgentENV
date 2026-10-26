"""FD ownership and authentication model checks; no target kernel operations."""
import array
import contextlib
import errno
import socket
import stat
import struct
import types
import unittest
from unittest import mock

from aenv_ub_provider import host_pmem as pmem, host_pmem_lease as lease


class LeaseTests(unittest.TestCase):
    def test_close_refuses_unconfirmed_volume_and_preserves_all_fds(self):
        stream = mock.Mock()
        value = lease.NativeLease(stream, [pmem.Segment(30, 0, 4096)], {})
        value.volume = types.SimpleNamespace(record={'phase': 'create_unconfirmed'})
        with mock.patch.object(lease.os, 'close') as close:
            with self.assertRaises(RuntimeError):value.close()
            close.assert_not_called();stream.close.assert_not_called()
            value.volume.record['phase'] = 'local_volume_absent'
            value.close();value.close()
            close.assert_called_once_with(30);stream.close.assert_called_once()

    def test_attach_failure_retains_transaction_and_does_not_close(self):
        stream = mock.Mock()
        value = lease.NativeLease(stream, [pmem.Segment(30, 0, 4096)], {'ownerPid': 50})
        control = mock.Mock(page_size=4096)
        control.create.side_effect = OSError(errno.EIO, 'unknown create')
        records = []
        with self.assertRaises(OSError):value.attach(control, records.append)
        with self.assertRaises(RuntimeError):value.close()
        self.assertEqual(records[-1]['source'], {'ownerPid': 50})
        self.assertEqual(value.volume.record['phase'], 'create_unconfirmed')
        stream.close.assert_not_called()

    def test_truncated_scm_message_closes_all_received_fds(self):
        stream = mock.Mock()
        flags = getattr(socket, 'MSG_CTRUNC', 8)
        stream.recvmsg.return_value = (b'F', [(1, 1, array.array('i', [30, 31]).tobytes())], flags, None)
        fake_socket = types.SimpleNamespace(CMSG_SPACE=lambda n:n+16, SOL_SOCKET=1, SCM_RIGHTS=1,
                                           MSG_CMSG_CLOEXEC=0x40000000, MSG_CTRUNC=flags, MSG_TRUNC=32)
        with mock.patch.object(lease, 'socket', fake_socket), mock.patch.object(lease.os, 'close') as close:
            with self.assertRaises(ValueError):lease.receive_segments(stream, [4096, 4096])
            self.assertEqual(set(call.args[0] for call in close.call_args_list), {30, 31})


class AcquireTests(unittest.TestCase):
    def setUp(self):
        self.events, self.uid = [], 0
        self.spec = {'objectId': 'test-image', 'generation': 'run1', 'sha256': 'sha256:'+'a'*64,
                     'bytes': 2*1024**2, 'socket': '/run/owned/data.sock'}
        self.stream = mock.Mock()
        self.stream.getsockopt.return_value = struct.pack('3i', 50, 1204, 1205)
        self.stream.connect.side_effect = lambda path:self.events.append(('connect', self.uid))
        self.path = mock.Mock()
        self.path.parent = mock.Mock()
        self.path.parent.resolve.return_value = self.path.parent
        self.path.parent.stat.return_value = types.SimpleNamespace(st_uid=1204, st_mode=stat.S_IFDIR|0o700)
        self.path.lstat.return_value = types.SimpleNamespace(st_uid=1204, st_mode=stat.S_IFSOCK|0o600)
        self.fake_os = types.SimpleNamespace(getuid=lambda:0, geteuid=lambda:self.uid,
                                             seteuid=self.seteuid, close=mock.Mock())
        self.fake_socket = types.SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, SOL_SOCKET=1,
                                                SO_PEERCRED=17, socket=mock.Mock(return_value=self.stream))
        self.response = {'version':2,'state':'ready','backing':self.spec,'privateCow':False,
                         'source':'ub','cacheMode':'nc','segmentLengths':[2*1024**2]}
        self.stack = contextlib.ExitStack()
        for target, attr, value in ((lease,'os',self.fake_os),(lease,'socket',self.fake_socket),
                                     (lease,'Path',mock.Mock(return_value=self.path)),
                                     (lease,'sys',types.SimpleNamespace(platform='linux')),
                                     (lease,'process_ticks',mock.Mock(return_value='1234')),
                                     (lease.contract,'send_json',mock.Mock()),
                                     (lease.contract,'receive_json',mock.Mock(side_effect=lambda stream:self.response)),
                                     (lease,'receive_segments',mock.Mock(return_value=[pmem.Segment(30,0,2*1024**2)])),
                                     (lease.host_pmem,'Control',mock.Mock())):
            self.stack.enter_context(mock.patch.object(target,attr,value))

    def tearDown(self):self.stack.close()

    def seteuid(self, uid):
        self.events.append(('seteuid',uid));self.uid=uid

    def test_connect_uses_owner_identity_then_restores_root_before_handoff(self):
        result=lease.acquire(self.spec,1204,50,'1234')
        self.assertEqual(self.events,[('seteuid',1204),('connect',1204),('seteuid',0)])
        self.assertEqual(self.uid,0)
        self.assertEqual(result.source['ownerPid'],50)
        self.assertFalse(result.source['crossNodePhysicalIdentityAccepted'])

    def test_connect_failure_restores_root_and_closes_socket(self):
        self.stream.connect.side_effect=OSError('connect failed')
        with self.assertRaises(OSError):lease.acquire(self.spec,1204,50,'1234')
        self.assertEqual(self.uid,0);self.stream.close.assert_called_once()

    def test_wrong_peer_rejected_before_request_or_fd_handoff(self):
        self.stream.getsockopt.return_value=struct.pack('3i',51,1204,1205)
        with self.assertRaises(PermissionError):lease.acquire(self.spec,1204,50,'1234')
        lease.contract.send_json.assert_not_called()
        lease.receive_segments.assert_not_called()
        self.assertEqual(self.uid,0)

    def test_changed_backing_or_segment_layout_rejected_before_fd_handoff(self):
        for response in ({**self.response,'backing':{**self.spec,'generation':'other'}},
                         {**self.response,'segmentLengths':[4096]},
                         {**self.response,'source':'host-pagecache'}):
            self.response=response
            with self.assertRaises(ValueError):lease.acquire(self.spec,1204,50,'1234')
            lease.receive_segments.assert_not_called()

    def test_fd_validation_failure_closes_handoff_without_any_kernel_create(self):
        lease.host_pmem.Control.return_value.validate_segments.side_effect=ValueError('wrong FD')
        with self.assertRaises(ValueError):lease.acquire(self.spec,1204,50,'1234')
        self.fake_os.close.assert_called_once_with(30)
        self.stream.close.assert_called_once()
