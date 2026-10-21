import copy,importlib.util,io,json,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('access_pages',Path(__file__).parent/'rootfs-access/page_accounting.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class PageAccounting(unittest.TestCase):
    def setUp(self):
        self.header={'kind':'header','version':1,'pid':77,'clock':'CLOCK_MONOTONIC','build_patch_sha256':'a'*64}
        self.bindings={s:{'sandbox_id':s,'template_id':'t','lower_keys':{(1,2)},'upper_keys':{(1,3 if s=='a' else 4)}} for s in ('a','b')}
        self.windows={s:(100,200) for s in ('a','b')};self.files={(1,2):{'file_bytes':16384,'path':'/fixture'}}
        self.records=[dict(kind='read',seq=i,source=s,dev=1,inode=2,file_bytes=16384,offset=offset,bytes=8192,
            direct_io=False,allowed_lower=True,start_ns=110,end_ns=120) for i,(s,offset) in enumerate([('a',0),('b',4096)])]
        self.status={'pid':77,'mono_ns':300,'records_written':2,'dropped_records':0,'errors':0,'unsupported_context_calls':0}
    def run_read(self):
        stream=iter([json.dumps(self.header)]+[json.dumps(x) for x in self.records])
        return m.read_sets(stream,self.status,self.bindings,self.windows,self.files,'a'*64)
    def test_shared_resident_intersection_not_entire_warm_file(self):
        sets,audit=self.run_read();resident={(1,2,i) for i in range(4)}
        r=m.pair_statistics(sets['a'],sets['b'],resident)
        self.assertEqual(r['shared_accessed_host_pagecache_bytes'],4096)
        self.assertEqual(r['accessed_resident_union_bytes'],12288)
        self.assertAlmostEqual(r['shared_pool_fraction'],1/3)
        self.assertEqual(r['duplicate_avoidance_fraction'],.25)
        self.assertEqual(r['shared_participation_fraction'],.5)
    def test_evicted_common_page_not_counted_as_shared_cache(self):
        sets,_=self.run_read();r=m.pair_statistics(sets['a'],sets['b'],{(1,2,0),(1,2,2)})
        self.assertEqual(r['both_accessed_lower_bytes'],4096);self.assertEqual(r['shared_accessed_host_pagecache_bytes'],0)
    def test_direct_io_excluded(self):
        self.records[1]['direct_io']=True;sets,audit=self.run_read()
        self.assertFalse(sets['b']);self.assertEqual(audit['direct_lower_reads'],1)
    def test_upper_excluded(self):
        self.records[1].update(inode=4,allowed_lower=False);sets,audit=self.run_read()
        self.assertFalse(sets['b']);self.assertEqual(audit['upper_reads'],1)
    def test_missing_sequence_rejected(self):
        self.records[1]['seq']=3
        with self.assertRaises(ValueError):self.run_read()
    def test_drop_error_and_fallback_rejected(self):
        for key in ('dropped_records','errors','unsupported_context_calls'):
            self.status[key]=1
            with self.subTest(key=key),self.assertRaises(ValueError):self.run_read()
            self.status[key]=0
    def test_identity_and_window_changes_rejected(self):
        self.records[1]['inode']=999
        with self.assertRaises(ValueError):self.run_read()
        self.records[1]['inode']=2;self.records[1]['start_ns']=99
        with self.assertRaises(ValueError):self.run_read()
    def test_zero_reads_stay_zero_not_full_file(self):
        self.status['records_written']=0;self.records=[];sets,_=self.run_read()
        result=m.pair_statistics(sets['a'],sets['b'],{(1,2,0)})
        self.assertTrue(result['zero_observed_buffered_reads']);self.assertIsNone(result['shared_pool_fraction'])
    def test_page_rounding(self):
        self.assertEqual(list(m.pages(4095,2,4096)),[0,1])
        self.assertEqual(list(m.pages(4096,1,4096)),[1])

if __name__=='__main__':unittest.main()
