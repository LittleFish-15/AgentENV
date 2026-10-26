"""Userspace ABI/lifecycle tests. No kernel, UB or mount acceptance is claimed."""
import copy
from dataclasses import replace
import errno
import hashlib
from pathlib import Path
import struct
import types
import unittest
from unittest import mock

from aenv_ub_provider import host_pmem as p
from aenv_ub_provider import fsdax


UUID = '8ea26803-3d68-4d17-8c13-e88c846e3802'


class KernelModel:
    def __init__(self):
        self.live = None
        self.events = []
        self.create_error = None
        self.destroy_error = None
        self.query_error = None
        self.openers = self.active_io = 0
        self.lose_destroy_reply = False

    def ioctl(self, fd, command, request, mutate):
        self.events.append(command)
        self.assert_request(fd == 123 and mutate is True)
        version, _, volume_uuid = p.HEADER.unpack_from(request)
        self.assert_request(version == 1)
        if command == p.CREATE:
            if self.create_error:
                raise OSError(self.create_error, 'create failed')
            count = struct.unpack_from('=I', request, 4)[0]
            lengths = [p.SEGMENT.unpack_from(request, 24 + i * 24)[3] for i in range(count)]
            self.live = (volume_uuid, sum(lengths))
        elif command == p.QUERY:
            if self.query_error:
                raise OSError(self.query_error, 'query failed')
            if self.live is None:
                raise OSError(errno.ENOENT, 'absent')
            self.assert_request(volume_uuid == self.live[0])
            request[:] = p.STATUS.pack(1, 0, volume_uuid, 7, 1, 240, 0,
                                       self.live[1], self.openers, self.active_io, 2, 8192, 3, 12288)
        elif command == p.DESTROY:
            self.assert_request(struct.unpack_from('=I', request, 24)[0] == 7)
            if self.destroy_error:
                raise OSError(self.destroy_error, 'destroy failed')
            self.live = None
            if self.lose_destroy_reply:
                raise OSError(errno.EINTR, 'reply uncertain')
        else:
            raise AssertionError('Unexpected ioctl')

    @staticmethod
    def assert_request(condition):
        if not condition:
            raise AssertionError('Malformed ABI request')


class HostPmem(unittest.TestCase):
    def setUp(self):
        self.kernel = KernelModel()
        self.control = p.Control(123, self.kernel.ioctl, 4096)
        self.control.validate_segments = mock.Mock()
        self.saved = []
        def save(record):
            self.saved.append(copy.deepcopy(record))
            self.kernel.events.append(record['phase'])
        self.volume = p.LocalVolume(self.control, save)
        self.segments = [p.Segment(40, 0, 8192), p.Segment(41, 4096, 4096)]

    def test_abi_sizes_numbers_and_zero_unused_segments(self):
        request = p.create_request(UUID, self.segments, 4096)
        self.assertEqual((p.SEGMENT.size, len(request), p.STATUS.size), (24, 792, 96))
        self.assertEqual((p.CREATE, p.QUERY, p.DESTROY), (0x4318b800, 0xc060b801, 0x4060b802))
        self.assertEqual(p.HEADER.unpack_from(request), (1, 2, p.identity(UUID)))
        self.assertEqual(p.SEGMENT.unpack_from(request, 48), (41, 0, 4096, 4096))
        self.assertEqual(request[72:], bytes(720))

    def test_reject_invalid_shapes_before_any_ioctl(self):
        for segments in ([], [p.Segment(True, 0, 4096)], [p.Segment(-1, 0, 4096)],
                         [p.Segment(1, 1, 4096)], [p.Segment(1, 0, 0)],
                         [p.Segment(1, 0, p.MAX_BYTES), p.Segment(2, 0, 4096)],
                         [p.Segment(1, 2 ** 64 - 4096, 4096)], self.segments * 17):
            with self.assertRaises(ValueError):
                self.volume.create(segments)
        self.assertEqual(self.kernel.events, [])

    def test_reject_wrong_status_uuid_version_reserved_and_state(self):
        valid = bytearray(p.STATUS.pack(1, 0, p.identity(UUID), 1, 1, 240, 0, 4096, *([0] * 6)))
        for offset, value in ((0, 2), (4, 1), (8, 1), (28, 0), (32, 0)):
            bad = valid.copy()
            struct.pack_into('=I', bad, offset, value)
            with self.assertRaises(ValueError):p.parse_status(bad, UUID)

    def test_intent_precedes_create_and_query_confirms_full_length(self):
        observed = self.volume.create(self.segments)
        self.assertEqual(observed.bytes, 12288)
        self.assertEqual(observed.dax_span_bytes, 12288)
        self.assertLess(self.kernel.events.index('create_intent'), self.kernel.events.index(p.CREATE))
        self.assertEqual(self.saved[-1]['phase'], 'serving')

    def test_save_failure_prevents_kernel_mutation_and_retry(self):
        def fail(_):raise OSError('journal fsync failed')
        volume = p.LocalVolume(self.control, fail)
        with self.assertRaises(OSError):volume.create(self.segments)
        self.assertEqual(self.kernel.events, [])
        with self.assertRaises(RuntimeError):volume.create(self.segments)

    def test_failed_create_is_not_retried_or_implicitly_destroyed(self):
        self.kernel.create_error = errno.EIO
        with self.assertRaises(OSError):self.volume.create(self.segments)
        self.assertTrue(self.saved[-1]['regionSealsMayRemain'])
        with self.assertRaises(RuntimeError):self.volume.create(self.segments)
        with self.assertRaises(RuntimeError):self.volume.retire()
        self.assertEqual(self.kernel.events.count(p.CREATE), 1)
        self.assertNotIn(p.DESTROY, self.kernel.events)

    def test_eexist_never_adopts_other_volume(self):
        self.kernel.create_error = errno.EEXIST
        with self.assertRaises(OSError):self.volume.create(self.segments)
        with self.assertRaises(RuntimeError):self.volume.confirm()
        self.assertNotIn(p.QUERY, self.kernel.events)

    def test_query_failure_retains_own_intent_for_query_only_reconciliation(self):
        self.kernel.query_error = errno.EIO
        with self.assertRaises(OSError):self.volume.create(self.segments)
        self.assertEqual(self.saved[-1]['phase'], 'query_unconfirmed')
        with self.assertRaises(RuntimeError):self.volume.create(self.segments)
        self.kernel.query_error = None
        self.volume.confirm()
        self.assertEqual(self.saved[-1]['phase'], 'serving')
        self.assertEqual(self.kernel.events.count(p.CREATE), 1)

    def test_mount_or_io_blocks_destroy(self):
        self.volume.create(self.segments)
        for openers, io in ((1, 0), (0, 1)):
            self.kernel.openers, self.kernel.active_io = openers, io
            with self.assertRaises(RuntimeError):self.volume.retire()
            self.assertEqual(self.saved[-1]['phase'], 'retire_busy')
        self.assertNotIn(p.DESTROY, self.kernel.events)

    def test_kernel_busy_race_preserves_volume_and_can_be_rechecked(self):
        self.volume.create(self.segments)
        self.kernel.destroy_error = errno.EBUSY
        with self.assertRaises(OSError):self.volume.retire()
        self.assertIsNotNone(self.kernel.live)
        self.kernel.destroy_error = None
        self.volume.retire()
        self.assertEqual(self.saved[-1]['phase'], 'local_volume_absent')
        self.assertFalse(self.saved[-1]['sharedBackingReleaseAuthorized'])

    def test_lost_destroy_reply_reconciles_by_query_without_repeating_destroy(self):
        self.volume.create(self.segments)
        self.kernel.lose_destroy_reply = True
        with self.assertRaises(OSError):self.volume.retire()
        with self.assertRaises(RuntimeError):self.volume.retire()
        self.volume.confirm_absent()
        self.assertEqual(self.kernel.events.count(p.DESTROY), 1)
        self.assertEqual(self.saved[-1]['phase'], 'local_volume_absent')
        self.assertFalse(self.saved[-1]['sharedBackingReleaseAuthorized'])

    def test_unknown_destroy_failure_not_retried(self):
        self.volume.create(self.segments)
        self.kernel.destroy_error = errno.ESTALE
        with self.assertRaises(OSError):self.volume.retire()
        with self.assertRaises(RuntimeError):self.volume.retire()
        with self.assertRaises(RuntimeError):self.volume.confirm_absent()
        self.assertEqual(self.kernel.events.count(p.DESTROY), 1)

    def test_successful_destroy_requires_followup_absence(self):
        self.volume.create(self.segments)
        self.volume.retire()
        self.assertEqual(self.kernel.events[-3:], [ 'destroy_acknowledged', p.QUERY, 'local_volume_absent'])
        self.assertFalse(self.saved[-1]['sharedBackingReleaseAuthorized'])


class DaxReadPath(unittest.TestCase):
    def run_read(self, *, invalid_dax=False, wrong_device=False, short=False,
                 bad_digest=False, no_dax=False, write_error=errno.EROFS):
        payload = b'actual-test-pattern' * 257
        volume = p.VolumeStatus(UUID, 7, 1, 240, 0, 4 * 1024 ** 2, 1, 0, 0, 0, 0, 0)
        after = replace(volume, dax_accesses=0 if no_dax else 1,
                        dax_span_bytes=0 if no_dax else 8192)
        control = types.SimpleNamespace(query=mock.Mock(side_effect=[volume, after]))
        fake_os = types.SimpleNamespace(O_RDONLY=0, O_WRONLY=1, O_CLOEXEC=2,
                                       O_NOFOLLOW=4, O_NONBLOCK=8,
                                       makedev=lambda major, minor: 99,
                                       close=mock.Mock(),
                                       pread=mock.Mock(return_value=payload[:-1] if short else payload))
        fake_os.open = mock.Mock(side_effect=[40, OSError(write_error, 'write open rejected')]
                                 if write_error is not None else [40, 41])
        observed = {'device': 98 if wrong_device else 99, 'inode': 123,
                    'activeDax': True, 'readonlyMount': True}
        validator = mock.Mock(side_effect=ValueError('S_DAX absent')) if invalid_dax else mock.Mock(return_value=observed)
        expected = '0' * 64 if bad_digest else hashlib.sha256(payload).hexdigest()
        self.fake_os = fake_os
        with mock.patch.object(p, 'os', fake_os), mock.patch.object(fsdax, 'validate_fd', validator):
            return p.verify_dax_file(control, volume, Path(__file__).resolve(), len(payload), expected)

    def test_matching_device_dax_digest_and_erofs_still_not_crossnode_acceptance(self):
        result = self.run_read()
        self.assertEqual(result['state'], 'local_dax_file_verified')
        self.assertGreater(result['preadBytes'], 0)
        self.assertFalse(result['crossNodePhysicalIdentityAccepted'])
        self.assertIsNone(result['netSavingsBytes'])
        self.fake_os.close.assert_called_once_with(40)

    def test_non_dax_or_other_volume_rejected_before_payload_read(self):
        for settings in ({'invalid_dax': True}, {'wrong_device': True}):
            with self.assertRaises(ValueError):self.run_read(**settings)
            self.fake_os.pread.assert_not_called()
            self.fake_os.close.assert_called_once_with(40)

    def test_short_read_digest_mismatch_and_no_dax_access_fail(self):
        for settings, error in (({'short': True}, OSError), ({'bad_digest': True}, ValueError),
                                ({'no_dax': True}, ValueError)):
            with self.assertRaises(error):self.run_read(**settings)
            self.fake_os.close.assert_called_once_with(40)

    def test_permission_denial_does_not_count_as_readonly_filesystem(self):
        with self.assertRaises(OSError):self.run_read(write_error=errno.EACCES)

    def test_unexpected_writable_open_is_closed_without_write(self):
        with self.assertRaises(RuntimeError):self.run_read(write_error=None)
        self.assertEqual(self.fake_os.close.call_args_list, [mock.call(41), mock.call(40)])


if __name__ == '__main__':
    unittest.main()
