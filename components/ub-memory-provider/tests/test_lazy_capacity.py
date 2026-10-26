"""Actual Cache condition/pin and MetadataServer stop methods, no SDK or VM."""
import sys
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import lazy
from test_lazy_cache import Harness


class CapacityWait(unittest.TestCase):
    def start_waiter(self, h, read=None):
        waiting = threading.Event()
        results, errors = [], []
        original_wait = h.cache.condition.wait
        def wait(timeout):
            waiting.set()
            return original_wait(timeout)
        h.cache.condition.wait = wait
        def acquire():
            try:
                results.append(read() if read else h.request('acquire', reader='node-b', digest=h.key, block=4))
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=acquire, daemon=True)
        thread.start()
        self.assertTrue(waiting.wait(5), 'capacity waiter did not reach condition wait')
        return thread, results, errors

    def test_actual_reader_survives_transient_capacity_pressure(self):
        h = Harness()
        grants = [h.request('acquire', digest=h.key, block=i) for i in range(4)]
        reader = h.reader('node-b')
        thread, results, errors = self.start_waiter(h, lambda: reader.read(h.key, 4 * lazy.CHUNK, 20))
        try:
            h.request('release', lease=grants[0]['lease'])
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(results, [h.parts[4][:20]])
            self.assertFalse(reader.failed)
            self.assertEqual(reader.active_reads, 0)
            self.assertEqual(len(h.cache.leases), 3)
        finally:
            with h.cache.condition:
                h.cache.poisoned = True
                h.cache.condition.notify_all()
            thread.join(5)

    def test_pin_release_wakes_capacity_waiter_without_overwriting_other_pins(self):
        h = Harness()
        grants = [h.request('acquire', digest=h.key, block=i) for i in range(4)]
        before = bytes(h.mapping.bytes)
        thread, results, errors = self.start_waiter(h)
        try:
            self.assertFalse(results)
            self.assertEqual(bytes(h.mapping.bytes), before)
            h.request('release', lease=grants[2]['lease'])
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(results[0]['slot'], grants[2]['slot'])
            for i in (0, 1, 3):
                self.assertEqual(h.mapping.read(grants[i]['slot'] * lazy.CHUNK, 20), h.parts[i][:20])
            self.assertEqual(h.cache.stats['capacityWaits'], 1)
            self.assertEqual(h.cache.stats['evictions'], 1)
            self.assertEqual(h.calls.count((h.key, 4)), 1)
        finally:
            with h.cache.condition:
                h.cache.poisoned = True
                h.cache.condition.notify_all()
            thread.join(5)

    def test_closed_admission_wakes_waiter_without_touching_payload(self):
        h = Harness()
        for i in range(4):
            h.request('acquire', digest=h.key, block=i)
        before = bytes(h.mapping.bytes)
        thread, results, errors = self.start_waiter(h)
        with h.cache.condition:
            h.cache.poisoned = True
            h.cache.condition.notify_all()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(results)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], RuntimeError)
        self.assertEqual(bytes(h.mapping.bytes), before)
        self.assertEqual(len(h.cache.leases), 4)

    def test_spurious_wakeup_uses_original_deadline(self):
        h = Harness()
        for i in range(4):
            h.request('acquire', digest=h.key, block=i)
        before = bytes(h.mapping.bytes)
        with patch.object(lazy.time, 'monotonic', side_effect=[100, 110, 131]):
            with patch.object(h.cache.condition, 'wait', return_value=True) as wait:
                with self.assertRaises(TimeoutError):
                    h.request('acquire', digest=h.key, block=4)
                wait.assert_called_once_with(20)
        self.assertEqual(h.cache.stats['capacityWaits'], 1)
        self.assertEqual(bytes(h.mapping.bytes), before)
        self.assertEqual(len(h.cache.leases), 4)


class MetadataStop(unittest.TestCase):
    def server(self, alive=False, worker=False):
        server = lazy.MetadataServer(lambda request: {})
        server.listener = types.SimpleNamespace(close=Mock())
        server.thread = types.SimpleNamespace(join=Mock(), is_alive=lambda: alive)
        server.path = types.SimpleNamespace(exists=lambda: True, stat=lambda: types.SimpleNamespace(st_ino=3), unlink=Mock())
        server.inode = 3
        if worker:
            server.workers.add(object())
        return server

    def test_unconfirmed_accept_thread_cannot_report_stopped_or_remove_socket(self):
        server = self.server(alive=True)
        with self.assertRaisesRegex(RuntimeError, 'accept thread'):
            server.stop()
        self.assertTrue(server.stop_event.is_set())
        server.thread.join.assert_called_once_with(2)
        server.path.unlink.assert_not_called()

    def test_live_worker_still_prevents_stopping(self):
        server = self.server(worker=True)
        with self.assertRaisesRegex(RuntimeError, 'workers'):
            server.stop()
        server.path.unlink.assert_not_called()

    def test_confirmed_exit_removes_only_owned_socket(self):
        server = self.server()
        server.stop()
        server.path.unlink.assert_called_once_with()
        server = self.server()
        server.inode = 99
        server.stop()
        server.path.unlink.assert_not_called()


if __name__ == '__main__':
    unittest.main()
