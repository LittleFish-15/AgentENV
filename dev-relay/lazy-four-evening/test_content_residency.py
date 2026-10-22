import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import content_residency as c
class ContentAccounting(unittest.TestCase):
 def test_access_intersection_is_not_whole_residency(self):
  r=c.summarize({'A':{'hash':[[0,8192],[4096,8192]]},'B':{'hash':[[4096,12288]]}},
                {'hash':[[0,16384]]},window_id='one',sets_validated=True)
  self.assertEqual((r['fullReadyContentBytes'],r['accessedReadyUnionBytes'],r['sharedByAtLeastTwoGuestsBytes']),(16384,12288,4096))
  self.assertEqual(r['duplicateParticipationBytes'],4096);self.assertIsNone(r['physicalNetSavingBytes'])
 def test_cross_node_four_guests_count_unique_content_once(self):
  r=c.summarize({g:{'h':[[0,4096]]} for g in ('a1','a2','b1','b2')},{'h':[[0,4096]]},window_id='pair',sets_validated=True)
  self.assertEqual(r['guestParticipationBytes'],16384);self.assertEqual(r['allGuestIntersectionBytes'],4096)
  self.assertEqual(r['duplicateParticipationBytes'],12288)
 def test_missing_or_uncoordinated_evidence_is_unknown_not_zero(self):
  with self.assertRaises(ValueError):c.summarize({'a':{},'b':{}},{},window_id='x',sets_validated=False)
 def test_real_read_ranges_are_bound_and_page_aligned(self):
  row={'kind':'content_read','source':'s','digest':'d','file_bytes':8192,'allowed_lower':True,'from_ub':True,'start_ns':10,'end_ns':20,'offset':1,'bytes':2}
  bound={'s':{'guest':'g','layers':{'d':8192}}}
  self.assertEqual(c.observed_access([row],bound,{'g':(1,30)}),{'g':{'d':[[0,4096]]}})
  self.assertEqual(c.observed_access([row],bound,{'g':(1,15)}),{'g':{}})
  row['from_ub']=False
  with self.assertRaises(ValueError):c.observed_access([row],bound,{'g':(1,30)})
 def test_tail_and_same_content_references_are_not_double_counted(self):
  snapshot={'state':'residency-snapshot','scope':'logical-ready-content-not-physical-increment','ranges':[['h',0,65536,0],['h',65536,3,1]],'readyBytes':65539}
  self.assertEqual(c.ready_ranges(snapshot),{'h':[[0,65539]]})
  snapshot['ranges'][1][3]=0
  with self.assertRaises(ValueError):c.ready_ranges(snapshot)
if __name__=='__main__':unittest.main()
