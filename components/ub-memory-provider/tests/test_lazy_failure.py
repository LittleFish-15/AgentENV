"""Fail-closed tests for the actual demand Reader; no SDK/hardware claims."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import lazy,lazy_service,stored
from test_lazy_cache import Harness


class FailedReader(unittest.TestCase):
    def test_integrity_failure_closes_admission_and_preserves_pin(self):
        h=Harness();h.reader().read(h.key,0,1)
        reader=h.reader('node-b');h.mapping.corrupt=True
        with self.assertRaisesRegex(ValueError,'integrity'):reader.read(h.key,0,5)
        self.assertTrue(reader.failed)
        self.assertEqual(len(h.cache.leases),1)
        h.mapping.corrupt=False
        with self.assertRaises(RuntimeError):reader.read(h.key,0,5)
        with self.assertRaises(RuntimeError):reader.release()
        self.assertEqual(len(h.cache.leases),1)

    def test_mapping_exception_records_failure_before_new_calls(self):
        h=Harness();h.reader().read(h.key,0,1);records=[]
        reader=lazy.Reader(h.value,h.mapping,4,'c'*32,'node-b',h.tokens['node-b'],h.cache.request,
                           failure_journal=records.append)
        def broken(*args):raise OSError('mapping unavailable')
        h.mapping.read=broken
        with self.assertRaises(OSError):reader.read(h.key,0,1)
        self.assertEqual(records,[{'readerFailed':True,'reader':'node-b','cacheId':'c'*32}])
        self.assertEqual(reader.active_reads,0)
        with self.assertRaises(RuntimeError):reader.read(h.key,0,1)
        self.assertEqual(len(records),1)

    def test_status_of_failed_reader_is_local_and_does_not_retry(self):
        h=Harness();reader=h.reader();reader.poison()
        reader.request=lambda request:(_ for _ in ()).throw(AssertionError('No coordinator request permitted'))
        broker=stored.Broker([],[]);broker.payload_failures=2
        status=lazy_service.reader_status(reader,broker)
        self.assertEqual(status['state'],'unresolved_preserved')
        self.assertFalse(status['coordinatorStatusAvailable'])
        self.assertIsNone(status['pins']);self.assertTrue(status['readerFailed'])
        self.assertEqual(status['payloadFailures'],2)

    def test_status_disconnect_poisoned_once_and_keeps_counts_unknown(self):
        h=Harness();calls=[]
        def disconnected(request):calls.append(request);raise BrokenPipeError('status lost')
        reader=h.reader(request=disconnected);broker=stored.Broker([],[])
        first=lazy_service.reader_status(reader,broker)
        second=lazy_service.reader_status(reader,broker)
        self.assertEqual(len(calls),1)
        for status in (first,second):
            self.assertEqual(status['state'],'unresolved_preserved');self.assertIsNone(status['pins'])
            self.assertTrue(status['readerFailed'])

    def test_failure_journal_error_cannot_reopen_admission(self):
        h=Harness()
        def broken(_):raise OSError('failure journal unavailable')
        reader=lazy.Reader(h.value,h.mapping,4,'c'*32,'owner',h.tokens['owner'],h.cache.request,failure_journal=broken)
        with self.assertRaises(OSError):reader.poison()
        self.assertTrue(reader.failed)
        with self.assertRaises(RuntimeError):reader.read(h.key,0,1)

if __name__=='__main__':unittest.main()
