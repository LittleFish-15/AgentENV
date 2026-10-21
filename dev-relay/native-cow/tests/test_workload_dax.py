import ctypes
import importlib.util
import os
from pathlib import Path
import struct
import types
import unittest
from unittest import mock
import uuid

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


W, REPORT = module('public_workload'), module('cohort_report')


class DaxTests(unittest.TestCase):
    def observer(self, attributes=0x00200000, supported=0x00200000, mask=0x7ff, inode=13, size=4, rc=0):
        calls = []
        def statx(fd, path, flags, requested, buffer):
            calls.append((fd, path, flags, requested))
            raw = bytearray(256)
            struct.pack_into('=I', raw, 0, mask)
            struct.pack_into('=Q', raw, 8, attributes)
            struct.pack_into('=QQ', raw, 32, inode, size)
            struct.pack_into('=Q', raw, 56, supported)
            buffer.raw = bytes(raw)
            return rc
        with mock.patch.object(W.sys, 'platform', 'linux'), mock.patch.object(ctypes, 'CDLL', return_value=types.SimpleNamespace(statx=statx)):
            observe, available = W.make_dax_observer()
        return observe, available, calls

    def test_effective_dax_bit_on_exact_fd(self):
        observe, available, calls = self.observer()
        self.assertTrue(available['available'])
        self.assertTrue(observe(42, types.SimpleNamespace(st_ino=13, st_size=4)))
        self.assertEqual(calls, [(42, b'', 0x1000, 0x7ff)])

    def test_supported_non_dax_is_false_not_unknown(self):
        observe, _, _ = self.observer(attributes=0)
        self.assertIs(observe(42, types.SimpleNamespace(st_ino=13, st_size=4)), False)

    def test_missing_support_mask_cannot_claim_dax_even_with_set_attribute(self):
        observe, _, _ = self.observer(supported=0)
        self.assertIsNone(observe(42, types.SimpleNamespace(st_ino=13, st_size=4)))

    def test_failed_statx_or_mismatched_identity_is_unknown(self):
        for kwargs in ({'rc': -1}, {'inode': 99}, {'size': 99}, {'mask': 0}):
            with self.subTest(kwargs=kwargs):
                observe, _, _ = self.observer(**kwargs)
                self.assertIsNone(observe(42, types.SimpleNamespace(st_ino=13, st_size=4)))

    def test_missing_libc_symbol_is_observation_gap(self):
        with mock.patch.object(W.sys, 'platform', 'linux'), mock.patch.object(ctypes, 'CDLL', return_value=object()):
            observe, available = W.make_dax_observer()
        self.assertFalse(available['available'])
        self.assertIsNone(observe(42, None))

    def file(self):
        directory = HERE / 't' / uuid.uuid4().hex[:8]
        directory.mkdir(parents=True)
        path = directory / 'source.py'
        path.write_bytes(b'fixture\n')
        return path

    def test_attributes_bracket_read_on_same_fd(self):
        path = self.file()
        calls = []
        with mock.patch.object(W.os, 'O_NOFOLLOW', 0, create=True), mock.patch.object(W.os, 'O_NONBLOCK', 0, create=True):
            data, dax = W.read_observed(path, 8, lambda fd, meta: calls.append((fd, meta.st_ino)) or True)
        self.assertEqual(data, b'fixture\n')
        self.assertTrue(dax)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])

    def test_changed_effective_dax_is_unknown(self):
        path = self.file()
        with mock.patch.object(W.os, 'O_NOFOLLOW', 0, create=True), mock.patch.object(W.os, 'O_NONBLOCK', 0, create=True):
            data, dax = W.read_observed(path, 8, mock.Mock(side_effect=[True, False]))
        self.assertIsNone(dax)
        self.assertEqual(len(data), 8)

    def test_oversized_read_rejected_before_content_read_or_statx(self):
        path = self.file()
        observe = mock.Mock()
        with mock.patch.object(W.os, 'O_NOFOLLOW', 0, create=True), mock.patch.object(W.os, 'O_NONBLOCK', 0, create=True):
            with self.assertRaisesRegex(RuntimeError, 'bounded read set'):
                W.read_observed(path, 1, observe)
        observe.assert_not_called()

    def test_unknown_is_not_buffered_or_zero_shared_bytes(self):
        value = W.dax_summary([(True, 10), (False, 20), (None, 30)])
        self.assertEqual(value['daxReadPayloadBytes'], 10)
        self.assertEqual(value['nonDaxReadPayloadBytes'], 20)
        self.assertEqual(value['unknownReadPayloadBytes'], 30)
        self.assertIsNone(value['allReadFilesDax'])
        self.assertIsNone(value['physicalSharedBytes'])

    def test_report_validates_counts_against_actual_payload(self):
        result = {'fileCount': 2, 'fileBytes': 30, 'fileDax': W.dax_summary([(True, 10), (True, 20)])}
        report = {'cohort': {'workloads': [{'passed': True, 'result': result} for _ in range(2)]}}
        value = REPORT.dax_evidence(report)
        self.assertTrue(value['allReadFilesDax'])
        self.assertEqual(value['daxReadPayloadBytes'], 60)
        self.assertFalse(value['payloadBytesAreResidentOrDeduplicatedBytes'])
        self.assertIsNone(value['physicalSharedBytes'])
        result['fileBytes'] = 31
        self.assertIsNone(REPORT.dax_evidence(report)['allReadFilesDax'])


if __name__ == '__main__':
    unittest.main()
