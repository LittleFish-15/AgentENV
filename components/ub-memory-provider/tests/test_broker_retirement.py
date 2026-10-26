"""Broker retirement confirmation; no SDK, kernel or Guest execution."""
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider.stored import Broker


class BrokerRetirement(unittest.TestCase):
    def broker(self, alive):
        broker = Broker([], [])
        broker.listener = types.SimpleNamespace(close=Mock())
        broker.thread = types.SimpleNamespace(join=Mock(), is_alive=lambda: alive)
        broker.path_identity = 123
        broker.path = types.SimpleNamespace(exists=lambda: True,
            stat=lambda: types.SimpleNamespace(st_ino=123), unlink=Mock())
        return broker

    def test_unconfirmed_accept_exit_preserves_socket_and_refuses_retirement(self):
        broker = self.broker(True)
        with self.assertRaisesRegex(RuntimeError, 'accept thread'):
            broker.stop()
        self.assertTrue(broker.retiring)
        broker.thread.join.assert_called_once_with(2)
        broker.path.unlink.assert_not_called()

    def test_confirmed_accept_exit_with_no_workers_can_finish(self):
        broker = self.broker(False)
        result = broker.stop()
        self.assertEqual(result['active_leases'], 0)
        broker.thread.join.assert_called_once_with(2)
        broker.path.unlink.assert_called_once_with()

    def test_live_lease_refuses_before_stopping_listener(self):
        broker = self.broker(False)
        broker.active = 1
        with self.assertRaisesRegex(RuntimeError, 'leases still active'):
            broker.stop()
        self.assertFalse(broker.retiring)
        broker.listener.close.assert_not_called()
        broker.path.unlink.assert_not_called()


if __name__ == '__main__':
    unittest.main()
