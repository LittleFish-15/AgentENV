"""SDK calls are mocked; no native library or hardware is initialized."""
import types
import unittest
from unittest import mock
from aenv_ub_provider import demand_native as n, raw


class NativeDemandTests(unittest.TestCase):
    def backend(self):
        backend=object.__new__(n.ReclaimingNativeBackend)
        backend.coverage_by_object={'retired':128,'still-live':128}
        backend.mappings=[types.SimpleNamespace(closed=True),types.SimpleNamespace(closed=False)]
        return backend

    def test_only_acknowledged_deallocation_releases_coverage(self):
        backend=self.backend();replica=types.SimpleNamespace(objectName='retired')
        with mock.patch.object(raw.NativeRawBackend,'deallocate') as delete:
            backend.deallocate(replica)
        delete.assert_called_once_with(replica)
        self.assertEqual(backend.coverage_by_object,{'still-live':128})
        self.assertEqual(len(backend.mappings),1)

    def test_unknown_deletion_retains_charge_and_handles(self):
        backend=self.backend();replica=types.SimpleNamespace(objectName='retired')
        with mock.patch.object(raw.NativeRawBackend,'deallocate',side_effect=TimeoutError('unknown')):
            with self.assertRaises(TimeoutError):backend.deallocate(replica)
        self.assertIn('retired',backend.coverage_by_object)
        self.assertEqual(len(backend.mappings),2)

    def test_live_or_uncertain_chunks_block_finalize(self):
        publisher=n.NativeChunkPublisher('adapter','a'*64,'region','/private',lambda _:None,None,None,256)
        publisher.backend=mock.Mock()
        publisher.records={'object':{'phase':'allocated','deleteAcknowledged':False}}
        with self.assertRaises(ValueError):publisher.finalize()
        publisher.backend.finalize.assert_not_called()

    def test_missing_node_receipt_never_deletes_owner(self):
        publisher=n.NativeChunkPublisher('adapter','a'*64,'region','/private',lambda _:None,None,mock.Mock(),256)
        publisher.backend=mock.Mock();publisher.records={'object':{'phase':'ready','generation':'gen'}}
        publisher.view_controller.retire.return_value={'objectName':'object','generation':'gen','releasedNodes':['a']}
        with self.assertRaises(ValueError):publisher.retire({'objectName':'object','generation':'gen'},('a','b'))
        publisher.backend.deallocate.assert_not_called()

    def test_busy_native_fd_lease_never_deletes_owner(self):
        publisher=n.NativeChunkPublisher('adapter','a'*64,'region','/private',lambda _:None,None,mock.Mock(),256)
        publisher.backend=mock.Mock();publisher.records={'object':{'phase':'ready','generation':'gen'}}
        publisher.view_controller.retire.return_value={'objectName':'object','generation':'gen','releasedNodes':['a','b']}
        provider=mock.Mock();provider.stop.side_effect=RuntimeError('active fd lease')
        publisher.live={'object':(mock.Mock(),[],provider,types.SimpleNamespace(objectName='object'))}
        with self.assertRaises(RuntimeError):publisher.retire({'objectName':'object','generation':'gen'},('a','b'))
        publisher.backend.deallocate.assert_not_called()


if __name__=='__main__':unittest.main()
