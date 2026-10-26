"""Exercise the actual stored broker response boundary without SDK/VM access."""
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import stored


class Stream:
    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.data = data


class Mapping:
    def read(self, offset, count):
        return b'a' * count


class PayloadAccounting(unittest.TestCase):
    def test_success_does_not_invent_completed_requests(self):
        broker = stored.Broker([], [])
        stream = Stream()
        broker.send_payload(stream, Mapping(), 0, 5)
        self.assertEqual(stream.data[-5:], b'aaaaa')
        self.assertEqual(broker.read_status(), {
            'nodeReadRequests': 0, 'nodeReadBytes': 0, 'activeLeases': 0,
            'activePayloadResponses': 0, 'payloadFailures': 0})
        # handle(), after a successful response, owns request/byte accounting.

    def test_mapping_error_and_short_read_are_recorded(self):
        broker = stored.Broker([], [])
        class BrokenMapping:
            def read(self, offset, count):
                raise OSError('mapping read failed')
        with self.assertRaises(OSError): broker.send_payload(Stream(), BrokenMapping(), 0, 5)
        class ShortMapping:
            def read(self, offset, count): return b'a'
        with self.assertRaises(ValueError): broker.send_payload(Stream(), ShortMapping(), 0, 5)
        self.assertEqual(broker.read_status()['payloadFailures'], 2)
        self.assertEqual(broker.read_status()['activePayloadResponses'], 0)

    def test_disconnected_response_is_failed_not_successful(self):
        broker = stored.Broker([], [])
        class Disconnected(Stream):
            def sendall(self, data): raise BrokenPipeError('response lost')
        with self.assertRaises(BrokenPipeError): broker.send_payload(Disconnected(), Mapping(), 0, 5)
        self.assertEqual(broker.read_status()['payloadFailures'], 1)
        self.assertEqual(broker.read_status()['activePayloadResponses'], 0)

    def test_inflight_count_spans_mapping_and_response(self):
        broker = stored.Broker([], [])
        entered, release = threading.Event(), threading.Event()
        errors = []
        class Held(Stream):
            def sendall(self, data):
                entered.set()
                if not release.wait(3): raise TimeoutError('test release absent')
        def respond():
            try: broker.send_payload(Held(), Mapping(), 0, 5)
            except BaseException as error: errors.append(error)
        worker = threading.Thread(target=respond)
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertEqual(broker.read_status()['activePayloadResponses'], 1)
        finally:
            release.set(); worker.join(3)
        self.assertFalse(worker.is_alive()); self.assertFalse(errors)
        self.assertEqual(broker.read_status()['activePayloadResponses'], 0)


if __name__ == '__main__': unittest.main()
