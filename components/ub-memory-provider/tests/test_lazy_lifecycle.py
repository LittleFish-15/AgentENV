"""Exercise lazy importer cleanup order with owned-resource models, no SDK."""
import contextlib
import copy
import io
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import lazy_service
from test_control_lifecycle import Control, Location, Stream


class LazyLifecycle(unittest.TestCase):
    def exercise(self, streams, admission_error=None, unmap_error=None, release_error=None,
                 role='import', peer_released=True, outstanding_pin=False, active_read=False,
                 failed_reader=False, startup_failed_reader=False, metadata_stop_error=None):
        events, journal = [], []
        control = Control(streams)
        accepted = []
        accept = control.accept
        def accept_control():
            result = accept(); accepted.append(True); return result
        control.accept = accept_control
        mapping = types.SimpleNamespace(backing_coverage=4194304)
        def admit(operation):
            if operation == 'status':
                events.append('status')
                return {'state': 'serving', 'pins': 0}
            self.assertEqual(operation, 'open-reader')
            events.append('admit')
            if admission_error:
                raise admission_error
            return {'state': 'reader-opened'}
        def close_maps():
            events.append('unmap')
            if unmap_error:
                raise unmap_error
        def release():
            events.append('release-reader')
            if release_error:
                raise release_error
        def record_map(*args, **kwargs):
            self.assertEqual(kwargs, {'writable': True} if role == 'publish' else {})
            events.append('map')
            return mapping
        backend = types.SimpleNamespace(configure_region=lambda region: None,
            initialize=lambda: events.append('initialize'), map=record_map,
            allocate=lambda pool: events.append('allocate'), deallocate=lambda pool: events.append('delete'),
            close_maps=close_maps, finalize=lambda: events.append('finalize'))
        def quiesce():
            if active_read:raise RuntimeError('Active mapping read remains')
        reader = types.SimpleNamespace(rpc=admit, release=release, quiesce=quiesce,
            status=lambda: {'maxConcurrentReads':1, 'activeReads':0,
                            'readerFailed':startup_failed_reader or (failed_reader and bool(accepted))})
        broker = lazy_service.stored.Broker([], [])
        broker.reads, broker.bytes = 7, 100
        broker.start = lambda path: None
        broker.stop = lambda: events.append('stop-broker')
        config = {'workDir': '/owned/new-lazy', 'role': role, 'adapter': '/owned/adapter.so',
            'adapterSha256': 'sha256:' + 'a' * 64, 'region': 'test', 'maxCoverageBytes': 4194304,
            'coordinationSocket': '/owned/forwarded.sock', 'sourceRoot': '/owned/snapshots'}
        manifest = {'cacheId': 'c' * 32, 'pool': {'objectName': 'aenv_' + 'd' * 32, 'mappingBytes': 4194304},
                    'catalog': {}, 'readers': ['owner', 'node-b']}
        credential = {'reader': 'node-b', 'token': 'b' * 64}
        sources = types.SimpleNamespace(read=lambda *args: None, close=lambda: events.append('close-sources'))
        coordinator = types.SimpleNamespace(condition=threading.Condition(), poisoned=False, loading=0,
            leases={'uncertain': {}} if outstanding_pin else {}, released={'node-b'} if peer_released else set(),
            request=lambda request: None, freeze=lambda: events.append('freeze-cache'))
        def stop_metadata():
            events.append('stop-metadata')
            if metadata_stop_error:
                raise metadata_stop_error
        metadata = types.SimpleNamespace(start=lambda path: None, stop=stop_metadata)
        def write(path, value):
            if str(path).endswith('/owner.json'):
                journal.append(copy.deepcopy(value))
        def send(stream, reply):
            stream.replies.append(reply)
            if stream.disconnected:
                raise BrokenPipeError('control client closed')
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {'fcntl': types.SimpleNamespace(
                flock=lambda *args: None, LOCK_EX=1, LOCK_NB=2)}))
            stack.enter_context(patch.object(lazy_service, 'Path', Location))
            stack.enter_context(patch.object(lazy_service.service, 'ordinary_linux'))
            stack.enter_context(patch.object(lazy_service.service, 'identity_bytes', return_value=config['adapterSha256']))
            stack.enter_context(patch.object(lazy_service, 'atomic_json', side_effect=write))
            stack.enter_context(patch.object(lazy_service.os, 'open', return_value=91))
            stack.enter_context(patch.object(lazy_service.os, 'close'))
            stack.enter_context(patch.object(lazy_service.os, 'chmod'))
            stack.enter_context(patch.object(lazy_service.os, 'umask'))
            stack.enter_context(patch.object(lazy_service.os, 'O_NOFOLLOW', 0, create=True))
            stack.enter_context(patch.object(lazy_service.os, 'O_CLOEXEC', 0, create=True))
            stack.enter_context(patch.object(lazy_service.sdk, 'NativeBackend', return_value=backend))
            stack.enter_context(patch.object(lazy_service.lazy, 'Reader', return_value=reader))
            stack.enter_context(patch.object(lazy_service.lazy, 'DirectSources', return_value=sources))
            stack.enter_context(patch.object(lazy_service.lazy, 'Cache', return_value=coordinator))
            stack.enter_context(patch.object(lazy_service.lazy, 'MetadataServer', return_value=metadata))
            stack.enter_context(patch.object(lazy_service, 'descriptors', return_value=[]))
            stack.enter_context(patch.object(lazy_service.stored, 'Broker', return_value=broker))
            stack.enter_context(patch.object(lazy_service.socket, 'socket', return_value=control))
            stack.enter_context(patch.object(lazy_service.socket, 'AF_UNIX', 1, create=True))
            stack.enter_context(patch.object(lazy_service.contract, 'same_uid'))
            stack.enter_context(patch.object(lazy_service.contract, 'receive_json', side_effect=lambda stream: stream.request))
            stack.enter_context(patch.object(lazy_service.contract, 'send_json', side_effect=send))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            error = None
            try:
                lazy_service.serve(config, None, manifest, credential)
            except Exception as failure:
                error = failure
        return events, journal, error

    def test_importer_unmaps_and_finalizes_before_remote_release(self):
        stream = Stream({'operation': 'retire'})
        events, journal, error = self.exercise([stream])
        self.assertIsNone(error)
        self.assertEqual(events, ['admit', 'initialize', 'map', 'stop-broker', 'unmap', 'finalize', 'release-reader'])
        self.assertEqual(journal[-1]['state'], 'released')
        self.assertEqual(stream.replies, [{'state': 'released'}])

    def test_active_reader_blocks_sdk_unmap_and_remote_release(self):
        control = Stream({'operation': 'retire'})
        events, journal, error = self.exercise([control], active_read=True)
        self.assertIsInstance(error, RuntimeError)
        self.assertNotIn('unmap', events)
        self.assertNotIn('finalize', events)
        self.assertNotIn('release-reader', events)
        self.assertEqual(journal[-1]['state'], 'unresolved_preserved')

    def test_status_includes_node_reads_and_does_not_release_any_resources(self):
        status, retire = Stream({'operation': 'status'}), Stream({'operation': 'retire'})
        events, journal, error = self.exercise([status, retire])
        self.assertIsNone(error)
        self.assertEqual(status.replies, [{'state': 'serving', 'pins': 0, 'nodeReadRequests': 7,
            'nodeReadBytes': 100, 'maxConcurrentReads':1, 'activeReads':0, 'activeLeases':0,
            'activePayloadResponses':0, 'payloadFailures':0, 'coordinatorStatusAvailable':True,'readerFailed':False}])
        self.assertLess(events.index('status'), events.index('stop-broker'))

    def test_failed_reader_retirement_never_unmaps_or_releases(self):
        for role in ('publish','import'):
            stream=Stream({'operation':'retire'})
            events,journal,error=self.exercise([stream],role=role,failed_reader=True)
            self.assertIsInstance(error,StopIteration)
            self.assertEqual(stream.replies[0]['state'],'refused')
            for operation in ('stop-broker','release-reader','unmap','delete','finalize'):
                self.assertNotIn(operation,events)

    def test_failed_reader_status_reports_unknown_coordinator_without_rpc(self):
        stream=Stream({'operation':'status'})
        events,journal,error=self.exercise([stream],failed_reader=True)
        self.assertIsInstance(error,StopIteration)
        self.assertNotIn('status',events)
        self.assertEqual(stream.replies[0]['state'],'unresolved_preserved')
        self.assertIsNone(stream.replies[0]['pins'])
        self.assertFalse(stream.replies[0]['coordinatorStatusAvailable'])

    def test_failure_during_startup_does_not_announce_serving(self):
        events,journal,error=self.exercise([],startup_failed_reader=True)
        self.assertIsInstance(error,RuntimeError)
        self.assertIn('during startup',str(error))
        self.assertEqual(journal[-1]['state'],'unresolved_preserved')
        for operation in ('release-reader','unmap','delete','finalize'):
            self.assertNotIn(operation,events)

    def test_failed_unmap_never_acknowledges_remote_release(self):
        events, journal, error = self.exercise([Stream({'operation': 'retire'})], unmap_error=OSError('unmap failed'))
        self.assertIsInstance(error, OSError)
        self.assertNotIn('release-reader', events)
        self.assertEqual(journal[-1]['state'], 'unresolved_preserved')

    def test_uncertain_remote_release_is_preserved(self):
        events, journal, error = self.exercise([Stream({'operation': 'retire'})], release_error=BrokenPipeError('ack lost'))
        self.assertIsInstance(error, BrokenPipeError)
        self.assertEqual(events[-3:], ['unmap', 'finalize', 'release-reader'])
        self.assertEqual(journal[-1]['state'], 'unresolved_preserved')

    def test_duplicate_admission_is_rejected_before_sdk_initialization(self):
        events, journal, error = self.exercise([], admission_error=RuntimeError('reader already admitted'))
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(events, ['admit'])
        self.assertEqual(journal[-1]['state'], 'unresolved_preserved')

    def test_control_disconnect_after_cleanup_keeps_released_state(self):
        stream = Stream({'operation': 'retire'}, disconnected=True)
        events, journal, error = self.exercise([stream])
        self.assertIsNone(error)
        self.assertEqual(journal[-1]['state'], 'released')
        self.assertEqual(events.count('release-reader'), 1)

    def test_owner_stops_metadata_and_unmaps_before_deleting_pool(self):
        stream = Stream({'operation': 'retire'})
        events, journal, error = self.exercise([stream], role='publish')
        self.assertIsNone(error)
        self.assertEqual(events, ['initialize', 'allocate', 'map', 'admit', 'stop-broker',
            'release-reader', 'freeze-cache', 'stop-metadata', 'close-sources', 'unmap', 'delete', 'finalize'])
        self.assertTrue(journal[-1]['deleteAcknowledged'])
        self.assertEqual(journal[-1]['state'], 'released')

    def test_unconfirmed_metadata_stop_preserves_sdk_pool(self):
        events, journal, error = self.exercise([Stream({'operation': 'retire'})], role='publish',
            metadata_stop_error=RuntimeError('accept thread still alive'))
        self.assertIsInstance(error, RuntimeError)
        self.assertIn('stop-metadata', events)
        for operation in ('close-sources', 'unmap', 'delete', 'finalize'):
            self.assertNotIn(operation, events)
        self.assertEqual(journal[-1]['state'], 'unresolved_preserved')
        self.assertNotIn('deleteAcknowledged', journal[-1])

    def test_owner_refuses_retirement_with_live_peer_or_uncertain_pin(self):
        for options in ({'peer_released': False}, {'outstanding_pin': True}):
            stream = Stream({'operation': 'retire'})
            events, journal, error = self.exercise([stream], role='publish', **options)
            # StopIteration ends this model's finite input queue; production
            # keeps accepting control requests after the refusal.
            self.assertIsInstance(error, StopIteration)
            self.assertEqual(stream.replies[0]['state'], 'refused')
            for operation in ('stop-broker', 'release-reader', 'unmap', 'delete', 'finalize'):
                self.assertNotIn(operation, events)


if __name__ == '__main__':
    unittest.main()
