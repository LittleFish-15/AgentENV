import ctypes
import errno
import importlib.util
import signal
import types
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('pidfd_impl', Path(__file__).with_name('pidfd_compat.py'))
impl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(impl)


class Function:
    def __init__(self, result): self.result, self.calls = result, []
    def __call__(self, *args):
        self.calls.append([getattr(arg, 'value', arg) for arg in args])
        return self.result


class PidfdCompatibility(unittest.TestCase):
    def os_stub(self):
        self.closed = []
        return types.SimpleNamespace(getpid=lambda: 101, close=self.closed.append)

    def test_python_self_check_only_signal_zero_and_close(self):
        o = self.os_stub(); o.pidfd_open = Function(41); send = Function(None)
        ops = impl.PidfdOps(o, types.SimpleNamespace(pidfd_send_signal=send), libc=types.SimpleNamespace())
        ops.self_check()
        self.assertEqual(o.pidfd_open.calls, [[101, 0]])
        self.assertEqual(send.calls, [[41, 0, None, 0]])
        self.assertEqual(self.closed, [41])

    def test_missing_python_uses_libc_pidfd(self):
        opened, send = Function(42), Function(0)
        ops = impl.PidfdOps(self.os_stub(), types.SimpleNamespace(),
                           libc=types.SimpleNamespace(pidfd_open=opened, pidfd_send_signal=send))
        self.assertEqual(ops.open(303), 42); ops.send(42, signal.SIGTERM)
        self.assertEqual(opened.calls, [[303, 0]])
        self.assertEqual(send.calls, [[42, 15, None, 0]])

    def test_missing_libc_uses_only_aarch64_pidfd_syscalls(self):
        call = Function(43)
        ops = impl.PidfdOps(self.os_stub(), types.SimpleNamespace(), libc=types.SimpleNamespace(syscall=call), machine='aarch64')
        self.assertEqual(ops.open(303), 43); call.result = 0; ops.send(43, signal.SIGTERM)
        self.assertEqual(call.calls, [[434, 303, 0], [424, 43, 15, None, 0]])

    def test_wrong_raw_abi_refused(self):
        with self.assertRaises(RuntimeError):
            impl.PidfdOps(self.os_stub(), types.SimpleNamespace(), libc=types.SimpleNamespace(syscall=Function(0)), machine='x86_64')

    def test_python_permission_error_is_not_retried(self):
        o = self.os_stub(); calls = []
        def denied(*args): calls.append(args); raise PermissionError(errno.EPERM, 'denied')
        o.pidfd_open = denied
        ops = impl.PidfdOps(o, types.SimpleNamespace(pidfd_send_signal=Function(None)), libc=types.SimpleNamespace())
        with self.assertRaises(PermissionError): ops.open(303)
        self.assertEqual(len(calls), 1)

    def test_kernel_error_is_not_retried(self):
        call = Function(-1); ctypes.set_errno(errno.ENOSYS)
        ops = impl.PidfdOps(self.os_stub(), types.SimpleNamespace(), libc=types.SimpleNamespace(syscall=call), machine='aarch64')
        with self.assertRaises(OSError) as caught: ops.open(303)
        self.assertEqual(caught.exception.errno, errno.ENOSYS)
        self.assertEqual(len(call.calls), 1)

    def test_unsupported_signal_and_invalid_fd_refused(self):
        call = Function(0)
        ops = impl.PidfdOps(self.os_stub(), types.SimpleNamespace(), libc=types.SimpleNamespace(syscall=call), machine='aarch64')
        for fd, sig in ((-1, 15), (2**32+43, 15), (43, 9)):
            with self.assertRaises(ValueError): ops.send(fd, sig)
        self.assertEqual(call.calls, [])

    def test_mixed_python_and_libc_interfaces(self):
        o = self.os_stub(); o.pidfd_open = Function(44); send = Function(0)
        ops = impl.PidfdOps(o, types.SimpleNamespace(), libc=types.SimpleNamespace(pidfd_send_signal=send))
        self.assertEqual(ops.open(303), 44); ops.send(44, 15)
        self.assertEqual(ops.backends, {'open': 'python', 'send': 'libc'})

    def test_failed_self_check_closes_own_fd(self):
        o = self.os_stub(); ctypes.set_errno(errno.EPERM)
        ops = impl.PidfdOps(o, types.SimpleNamespace(), libc=types.SimpleNamespace(pidfd_open=Function(45), pidfd_send_signal=Function(-1)))
        with self.assertRaises(OSError): ops.self_check()
        self.assertEqual(self.closed, [45])


if __name__ == '__main__': unittest.main()
