"""Run the control loop with owned-resource models; no SDK or kernel access."""
import contextlib
import copy
import io
from pathlib import Path
import stat
import sys
import threading
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import service


class Stream:
    def __init__(self, request, disconnected=False):
        self.request = request
        self.disconnected = disconnected
        self.replies = []

    def settimeout(self, value):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class Control:
    def __init__(self, streams):
        self.streams = iter(streams)
        self.closed = False

    def bind(self, path):
        pass

    def listen(self, count):
        pass

    def accept(self):
        return next(self.streams), None

    def close(self):
        self.closed = True


class Location:
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

    def __truediv__(self, suffix):
        return Location(self.name + '/' + suffix)

    def mkdir(self, **kwargs):
        pass

    def stat(self):
        return types.SimpleNamespace(st_mode=stat.S_IFREG)


class Lifecycle(unittest.TestCase):
    def exercise(self, streams, cleanup_error=None):
        journal, receipts, cleanup, stopped = [], [], [], []
        provider = types.SimpleNamespace(condition=threading.Condition(), active=0, retiring=False,
                                         start=lambda path: None, stop=lambda: stopped.append(True))
        def release(**kwargs):
            cleanup.append(kwargs)
            if cleanup_error:
                raise cleanup_error
        images = types.SimpleNamespace(entries=[], published=True, imports=lambda *a: None, cleanup=release)
        backend = types.SimpleNamespace(configure_region=lambda r: None)
        def write(path, value):
            if str(path).endswith('/owner.json'):
                journal.append(copy.deepcopy(value))
            elif str(path).endswith('/release.json'):
                receipts.append(copy.deepcopy(value))
        def send(stream, reply):
            stream.replies.append(reply)
            if stream.disconnected:
                raise BrokenPipeError('Owned client closed the control connection')
        control = Control(streams)
        config = {'workDir': '/owned/generation', 'role': 'import', 'mode': 'pmem',
                  'adapter': '/owned/adapter.so', 'adapterSha256': 'sha256:' + 'a' * 64,
                  'maxCoverageBytes': 1, 'region': 'test', 'readerId': 'peer'}
        manifest = {'version': 1, 'ownerId': 'generation', 'mode': 'pmem', 'readers': ['peer'], 'replicas': []}
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {'fcntl': types.SimpleNamespace(
                flock=lambda *a: None, LOCK_EX=1, LOCK_NB=2)}))
            stack.enter_context(patch.object(service, 'Path', Location))
            stack.enter_context(patch.object(service, 'ordinary_linux'))
            stack.enter_context(patch.object(service, 'identity_bytes', return_value=config['adapterSha256']))
            stack.enter_context(patch.object(service, 'atomic_json', side_effect=write))
            stack.enter_context(patch.object(service.os, 'open', return_value=91))
            stack.enter_context(patch.object(service.os, 'close'))
            stack.enter_context(patch.object(service.os, 'chmod'))
            stack.enter_context(patch.object(service.os, 'umask'))
            stack.enter_context(patch.object(service.os, 'O_NOFOLLOW', 0, create=True))
            stack.enter_context(patch.object(service.os, 'O_CLOEXEC', 0, create=True))
            stack.enter_context(patch.object(service.raw, 'NativeRawBackend', return_value=backend))
            stack.enter_context(patch.object(service.raw, 'RawImages', return_value=images))
            stack.enter_context(patch.object(service.raw, 'RawProvider', return_value=provider))
            stack.enter_context(patch.object(service.socket, 'socket', return_value=control))
            stack.enter_context(patch.object(service.socket, 'AF_UNIX', 1, create=True))
            stack.enter_context(patch.object(service.contract, 'same_uid'))
            stack.enter_context(patch.object(service.contract, 'receive_json', side_effect=lambda s: s.request))
            stack.enter_context(patch.object(service.contract, 'send_json', side_effect=send))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            failure = None
            try:
                service.serve(config, [], manifest)
            except Exception as error:
                failure = error
        return journal, receipts, cleanup, stopped, control, failure

    def test_lost_refusal_does_not_terminate_owner(self):
        rejected = Stream({'operation': 'retire'}, disconnected=True)
        approved = Stream({'operation': 'retire', 'peerReceipts': []})
        journal, receipts, cleanup, stopped, control, failure = self.exercise([rejected, approved])
        self.assertIsNone(failure)
        self.assertEqual(rejected.replies[0]['state'], 'refused')
        self.assertEqual(approved.replies, [{'state': 'released'}])
        self.assertEqual(journal[-1]['state'], 'released')
        self.assertEqual(len(cleanup), 1)
        self.assertEqual(len(stopped), 1)
        self.assertEqual(len(receipts), 1)
        self.assertTrue(control.closed)

    def test_lost_completion_preserves_durable_release(self):
        client = Stream({'operation': 'retire', 'peerReceipts': []}, disconnected=True)
        journal, receipts, cleanup, stopped, control, failure = self.exercise([client])
        self.assertIsNone(failure)
        self.assertEqual(journal[-1]['state'], 'released')
        self.assertNotIn('unresolved_preserved', [r['state'] for r in journal])
        self.assertEqual(receipts[0]['state'], 'released')
        self.assertEqual(cleanup, [{'readers_released': True}])
        self.assertTrue(control.closed)

    def test_cleanup_failure_is_not_masked_by_reply_handling(self):
        client = Stream({'operation': 'retire', 'peerReceipts': []})
        journal, receipts, cleanup, stopped, control, failure = self.exercise(
            [client], RuntimeError('Own resource release failed'))
        self.assertIsInstance(failure, RuntimeError)
        self.assertEqual(journal[-1]['state'], 'unresolved_preserved')
        self.assertFalse(receipts)
        self.assertFalse(client.replies)
        self.assertTrue(control.closed)


if __name__ == '__main__':
    unittest.main()
