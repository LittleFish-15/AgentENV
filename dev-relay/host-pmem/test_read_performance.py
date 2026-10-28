import unittest
from read_performance import summarize,locality

class PerformanceTests(unittest.TestCase):
    def rows(self):
        return [{'kind':'content_read','source':'one','digest':'digest','offset':0,'bytes':1048576,
                 'from_ub':True,'allowed_lower':True,'start_ns':1000000100,'end_ns':1000001100},
                {'kind':'content_read','source':'two','digest':'digest','offset':0,'bytes':1048576,
                 'from_ub':True,'allowed_lower':True,'start_ns':1000000200,'end_ns':1000009200}]
    def mapping(self):
        return {k:{'sandboxId':k,'rangesByDigest':{'digest':[{'fileOffset':0,'bytes':1048576,'locality':route}]}}
                for k,route in [('one','local'),('two','cross-node')]}
    def observer(self):
        return {'read_tracking_version':1,'dropped_records':0,'errors':0,'unsupported_context_calls':0,
                'active_reads':0,'failed_or_cancelled_reads':0,'drained_through_ns':3000000000,'records_written':2}
    def test_wall_window_not_summed_concurrent_latencies(self):
        r=summarize(self.rows(),self.mapping(),1000000000,3000000000,self.observer())
        self.assertTrue(r['completeWindowAccepted']);self.assertEqual(r['windowAverageMiBps'],1)
        self.assertEqual(r['successfulLatency']['p99Ns'],9000)
        self.assertEqual({g['locality'] for g in r['groups']},{'local','cross-node'})
    def test_drop_or_missing_failure_stats_refuse_complete_acceptance(self):
        for stats in ({**self.observer(),'dropped_records':1},{'records_written':2}):
            self.assertFalse(summarize(self.rows(),self.mapping(),1000000000,3000000000,stats)['completeWindowAccepted'])
    def test_unattributed_read_is_not_assigned_to_other_sandbox(self):
        mapping=self.mapping();del mapping['two']
        r=summarize(self.rows(),mapping,1000000000,3000000000,self.observer())
        self.assertEqual(r['unattributedRecords'],1);self.assertFalse(r['completeWindowAccepted'])
    def test_mixed_and_unknown_source_ranges(self):
        event=self.rows()[0]
        mapping={'rangesByDigest':{'digest':[{'fileOffset':0,'bytes':524288,'locality':'local'},
                    {'fileOffset':524288,'bytes':524288,'locality':'cross-node'}]}}
        self.assertEqual(locality(event,mapping),'mixed')
        mapping['rangesByDigest']['digest'].pop()
        self.assertEqual(locality(event,mapping),'unknown')
    def test_upper_reads_are_not_reported_as_lower_throughput(self):
        events=self.rows();events[1]['allowed_lower']=False
        r=summarize(events,self.mapping(),1000000000,3000000000,self.observer())
        self.assertEqual(r['nonLowerReadRecordsExcluded'],1)
        self.assertEqual(r['completedBytesIncludingRepeatedReads'],1048576)
        self.assertEqual(r['perSandbox'][0]['sandboxId'],'one')
if __name__=='__main__':unittest.main()
