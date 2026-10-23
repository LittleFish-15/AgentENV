"""FS-DAX protocol and lease tests; mocks do not attest DAX/KVM/UB hardware."""
import ctypes
from pathlib import Path
import stat
import struct
import sys
import threading
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import fsdax, raw


class FsDaxTests(unittest.TestCase):
    def test_host_pagecache_provider_has_separate_protocol_and_refuses_ram(self):
        provider = fsdax.HostPagecacheProvider([(self.spec, [(80, 4096)])])
        request = dict(self.request, version=4, privateCow=False)
        with patch.object(fsdax, 'validate_fd') as validate:
            _, response = provider.prepare_handoff(request)
            validate.assert_called_once_with(80, 4096, fs_dax=False)
        self.assertEqual(response['source'], 'host-pagecache')
        self.assertEqual(response['cacheMode'], 'host-pagecache')
        self.assertIs(response['privateCow'], False)
        with self.assertRaises(ValueError): provider.prepare_handoff(dict(request, privateCow=True))
        with self.assertRaises(ValueError): provider.prepare_handoff(dict(request, version=3))
    def test_active_dax_type_size_and_readonly_mount_are_independent_gates(self):
        # Exercise the actual ABI decoding with synthetic statx output. This is
        # intentionally not called a successful DAX mapping test.
        class Statx:
            def __call__(self, fd, path, flags, mask, output):
                data = bytearray(256)
                struct.pack_into('=Q', data, 8, attrs[0])
                struct.pack_into('=Q', data, 40, 4096)
                struct.pack_into('=Q', data, 56, attrs[1])
                ctypes.memmove(output, bytes(data), 256)
                return 0
        attrs = [0x200000, 0x200000]
        info = types.SimpleNamespace(st_mode=stat.S_IFREG|0o444, st_size=4096,
                                     st_dev=1, st_ino=2)
        fake_fcntl = types.SimpleNamespace(fcntl=lambda *args: 0, F_GETFL=3)
        with patch.dict(sys.modules, {'fcntl': fake_fcntl}), \
                patch.object(fsdax.os, 'fstat', return_value=info), \
                patch.object(fsdax.os, 'O_ACCMODE', 3, create=True), \
                patch.object(fsdax.os, 'O_SYNC', 0x101000, create=True), \
                patch.object(fsdax.os, 'ST_RDONLY', 1, create=True), \
                patch.object(fsdax.os, 'fstatvfs', return_value=types.SimpleNamespace(f_flag=1), create=True) as vfs, \
                patch.object(fsdax.ctypes, 'CDLL', return_value=types.SimpleNamespace(statx=Statx())):
            result = fsdax.validate_fd(80, 4096)
            self.assertIs(result['crossNodePhysicalIdentityAccepted'], False)
            attrs[0] = 0
            with self.assertRaisesRegex(ValueError, 'S_DAX'): fsdax.validate_fd(80, 4096)
            attrs[0], attrs[1] = 0x200000, 0
            with self.assertRaisesRegex(ValueError, 'S_DAX'): fsdax.validate_fd(80, 4096)
            attrs[1] = 0x200000
            vfs.return_value.f_flag = 0
            with self.assertRaisesRegex(ValueError, 'readonly mount'): fsdax.validate_fd(80, 4096)
            info.st_mode = stat.S_IFCHR
            with self.assertRaisesRegex(ValueError, 'regular FD'): fsdax.validate_fd(80, 4096)

    def setUp(self):
        self.spec = {'objectId': 'base', 'generation': 'one', 'sha256': 'sha256:'+'a'*64,
                     'bytes': 4096, 'socket': '/private/provider.sock'}
        self.provider = fsdax.FsDaxProvider([(self.spec, [(80, 4096)])])
        self.request = {key: self.spec[key] for key in ('objectId', 'generation', 'sha256', 'bytes')}
        self.request.update(version=3, operation='acquire', privateCow=True)

    def test_protocol_separates_fsdax_from_raw_nc_and_checks_each_acquisition(self):
        with patch.object(fsdax, 'validate_fd') as validate:
            segments, response = self.provider.prepare_handoff(self.request)
            validate.assert_called_once_with(80, 4096)
        self.assertEqual(segments, [(80, 4096)])
        self.assertEqual(response['source'], 'fs-dax')
        self.assertEqual(response['cacheMode'], 'fs-dax')
        self.assertNotIn('segmentLengths', response)
        nc = raw.RawProvider([(self.spec, [(80, 4096)])])
        with self.assertRaises(ValueError):
            nc.prepare_handoff(self.request)

    def test_identity_protocol_and_raw_device_mismatches_fail_closed(self):
        for key, value in [('version', 2), ('version', True), ('privateCow', 1),
                           ('generation', 'old'), ('bytes', 8192), ('extra', True)]:
            req = dict(self.request, **{key: value})
            with self.assertRaises((ValueError, KeyError)):
                self.provider.prepare_handoff(req)
        with patch.object(fsdax, 'validate_fd', side_effect=ValueError('not DAX')):
            with self.assertRaises(ValueError):
                self.provider.prepare_handoff(self.request)

    def test_readonly_pmem_uses_same_source_without_ram_claim(self):
        request = dict(self.request, privateCow=False)
        with patch.object(fsdax, 'validate_fd'):
            _, response = self.provider.prepare_handoff(request)
        self.assertIs(response['privateCow'], False)

    def test_retiring_refuses_handoff_and_active_child_prevents_stop(self):
        provider = self.provider
        provider.active = 1
        with self.assertRaisesRegex(RuntimeError, 'leases are still active'):
            provider.stop()
        self.assertFalse(provider.retiring)
        provider.active = 0
        provider.retiring = True
        class Stream:
            def settimeout(self, _): pass
            def close(self): pass
        stream = Stream()
        provider.connections.add(stream)
        with patch.object(fsdax.n, 'same_uid'), patch.object(fsdax.n, 'receive_json', return_value=self.request), \
                patch.object(fsdax, 'validate_fd'), patch.object(fsdax.n, 'send_json') as send:
            provider.handle(stream)
            send.assert_not_called()
        self.assertEqual(provider.active, 0)
        self.assertFalse(provider.connections)

    def test_lease_lives_until_consumer_eof_and_handoff_failure_drops_only_own_lease(self):
        entered, eof = threading.Event(), threading.Event()
        class Stream:
            def settimeout(self, _): pass
            def close(self): pass
            def sendmsg(self, *args): return 1
            def recv(self, _):
                entered.set()
                if not eof.wait(5): raise TimeoutError('test consumer timeout')
                return b''
        # Mock only ancillary transport constants on Windows; RawProvider's
        # admission, active counter, retirement and finally logic are real.
        with patch.object(fsdax.n, 'same_uid'), patch.object(fsdax.n, 'receive_json', return_value=self.request), \
                patch.object(fsdax, 'validate_fd'), patch.object(fsdax.n, 'send_json'), \
                patch.object(raw.socket, 'SCM_RIGHTS', 1, create=True):
            stream = Stream()
            self.provider.connections.add(stream)
            thread = threading.Thread(target=self.provider.handle, args=(stream,))
            thread.start()
            try:
                self.assertTrue(entered.wait(3))
                self.assertEqual(self.provider.active, 1)
                with self.assertRaises(RuntimeError): self.provider.stop()
            finally:
                eof.set(); thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(self.provider.active, 0)
            failed = Stream()
            failed.sendmsg = lambda *args: 0
            self.provider.handle(failed)
            self.assertEqual(self.provider.active, 0)


if __name__ == '__main__':
    unittest.main()
