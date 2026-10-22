import base64, importlib.util, types, unittest, zlib
from pathlib import Path
from unittest.mock import Mock

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('residual',HERE/'rootfs-access/residual_baseline.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)


def probe(bits):
    return {'whole_lower_resident_bytes':sum(bits)*4096,'whole_lower_files':[{'dev':1,'inode':2,'file_bytes':len(bits)*4096,
        'resident_bytes':sum(bits)*4096,'residency_vector_zlib_base64':base64.b64encode(zlib.compress(bytes(bits))).decode()}]}


class BaselineTests(unittest.TestCase):
    def test_initial_residual_new_pages_and_eviction_are_not_confused(self):
        old=probe([1,1,0,0]);current=probe([0,1,1,1])
        row={'template_id':'t','sandbox_ids':['a','b'],'whole_lower_host_pagecache_bytes':12288,
             'shared_accessed_host_pagecache_bytes':8192,'accessed_resident_union_bytes':12288}
        f={'residency_probe':current,'accessed_page_ranges':{'a':{'1:2':[[1,3]]},'b':{'1:2':[[1,2]]}},
           'templates':[row],'global_same_template_shared_accessed_resident_bytes':8192}
        m.enrich(f,old,{'t':{(1,2)}});r=f['baseline_page_accounting']
        self.assertEqual(r['initial_lower_resident_bytes'],8192)
        self.assertEqual(r['initial_pages_still_resident_bytes'],4096)
        self.assertEqual(r['initial_pages_no_longer_resident_bytes'],4096)
        self.assertEqual(r['resident_outside_initial_page_set_bytes'],8192)
        self.assertEqual(r['net_lower_resident_change_bytes'],4096)
        self.assertEqual(row['common_read_resident_from_initial_page_set_bytes'],4096)
        self.assertEqual(row['common_read_resident_outside_initial_page_set_bytes'],4096)
    def test_tampered_bitmap_total_rejected(self):
        p=probe([1,0]);p['whole_lower_resident_bytes']=0
        with self.assertRaisesRegex(RuntimeError,'total differs'):m.bitmaps(p)
    def test_cross_template_common_baseline_pages_are_globally_deduplicated(self):
        rows=[{'template_id':tid,'sandbox_ids':[tid+'a',tid+'b'],'whole_lower_host_pagecache_bytes':8192,
               'shared_accessed_host_pagecache_bytes':4096,'accessed_resident_union_bytes':4096} for tid in ('x','y')]
        f={'residency_probe':probe([1,1]),'templates':rows,'global_same_template_shared_accessed_resident_bytes':4096,
           'accessed_page_ranges':{sid:{'1:2':[[0,1]]} for row in rows for sid in row['sandbox_ids']}}
        m.enrich(f,probe([1,0]),{'x':{(1,2)},'y':{(1,2)}})
        self.assertEqual(f['baseline_page_accounting']['common_read_resident_from_initial_page_set_bytes'],4096)
        m.enrich(f,probe([0,0]),{'x':{(1,2)},'y':{(1,2)}})
        self.assertEqual(f['baseline_page_accounting']['common_read_resident_from_initial_page_set_bytes'],0)
        self.assertEqual(f['baseline_page_accounting']['common_read_resident_outside_initial_page_set_bytes'],4096)
    def test_invalid_boolean_bitmap_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'Invalid complete'):m.bitmaps(probe([2,0]))
    def test_range_membership_respects_file_identity(self):
        idx=m.range_index({'1:2':[[1,2],[10,1]]})
        self.assertTrue(m.contains(idx,(1,2,2)));self.assertFalse(m.contains(idx,(1,2,3)))
        self.assertFalse(m.contains(idx,(1,3,1)));self.assertTrue(m.contains(idx,(1,2,10)))
    def test_unknown_prior_attempt_rejected_without_api_actions(self):
        api=Mock();env=types.SimpleNamespace(ROOT=Path('/own'),B=types.SimpleNamespace(read_json=lambda _: {'run_id':'other','status':'STOPPED_COW4_ACCESS'}))
        with self.assertRaisesRegex(RuntimeError,'Unexpected prior'):m.reconcile(env,(1,'1'),api)
        api.call.assert_not_called()


if __name__=='__main__':unittest.main()
