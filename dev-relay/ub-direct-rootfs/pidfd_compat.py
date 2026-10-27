"""pidfd compatibility without a numeric-PID signal fallback.

ABI checked against retained GNU sys/pidfd.h and Linux AArch64 asm-generic
unistd.h. Raw syscall fallback is restricted to AArch64 and missing symbols;
an actual permission/kernel error is propagated, never retried via another API.
"""
import ctypes
import errno
import os
import platform
import signal


class PidfdOps:
    def __init__(self, os_api=None, signal_api=None, libc=None, machine=None):
        self._os = os if os_api is None else os_api
        sig_api = signal if signal_api is None else signal_api
        self._python_open = getattr(self._os, 'pidfd_open', None)
        self._python_send = getattr(sig_api, 'pidfd_send_signal', None)
        self._native_open = self._native_send = self._syscall = None
        self.backends = {'open': 'python', 'send': 'python'}
        if callable(self._python_open) and callable(self._python_send):
            return
        self._libc = ctypes.CDLL(None, use_errno=True) if libc is None else libc
        if not callable(self._python_open):
            self._native_open = getattr(self._libc, 'pidfd_open', None)
            if self._native_open is not None:
                self._native_open.argtypes = [ctypes.c_int, ctypes.c_uint]
                self._native_open.restype = ctypes.c_int
            self.backends['open'] = 'libc' if self._native_open is not None else 'aarch64-syscall'
        if not callable(self._python_send):
            self._native_send = getattr(self._libc, 'pidfd_send_signal', None)
            if self._native_send is not None:
                self._native_send.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
                self._native_send.restype = ctypes.c_int
            self.backends['send'] = 'libc' if self._native_send is not None else 'aarch64-syscall'
        if 'aarch64-syscall' in self.backends.values():
            arch = platform.machine() if machine is None else machine
            if arch not in ('aarch64', 'arm64'):
                raise RuntimeError('pidfd libc symbols missing; raw ABI is approved only for AArch64')
            self._syscall = getattr(self._libc, 'syscall', None)
            if self._syscall is None:
                raise RuntimeError('No supported pidfd interface; numeric-PID signalling forbidden')
            self._syscall.argtypes = [ctypes.c_long]
            self._syscall.restype = ctypes.c_long

    @staticmethod
    def _checked(value, operation):
        if value < 0:
            number = ctypes.get_errno() or errno.EIO
            raise OSError(number, operation + ': ' + os.strerror(number))
        return int(value)

    def open(self, pid):
        if type(pid) is not int or not 0 < pid <= 0x7fffffff:
            raise ValueError('A positive process identity is required')
        if callable(self._python_open):
            return self._python_open(pid, 0)
        if self._native_open is not None:
            return self._checked(self._native_open(pid, 0), 'pidfd_open')
        return self._checked(self._syscall(ctypes.c_long(434), ctypes.c_int(pid), ctypes.c_uint(0)), 'pidfd_open')

    def send(self, fd, sig):
        if type(fd) is not int or not 0 <= fd <= 0x7fffffff or sig not in (0, signal.SIGTERM):
            raise ValueError('Only signal 0 or SIGTERM through a valid pidfd is permitted')
        if callable(self._python_send):
            return self._python_send(fd, int(sig), None, 0)
        if self._native_send is not None:
            return self._checked(self._native_send(fd, int(sig), None, 0), 'pidfd_send_signal')
        return self._checked(self._syscall(ctypes.c_long(424), ctypes.c_int(fd), ctypes.c_int(sig),
                                           ctypes.c_void_p(None), ctypes.c_uint(0)), 'pidfd_send_signal')

    def self_check(self):
        # Signal 0 only checks the caller's own pidfd permissions; no signal is delivered.
        fd = self.open(self._os.getpid())
        try:
            self.send(fd, 0)
        finally:
            self._os.close(fd)
