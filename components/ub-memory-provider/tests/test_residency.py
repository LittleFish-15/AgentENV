import json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import lazy
from test_lazy_cache import Harness
class ResidencySnapshots(unittest.TestCase):
 def test_empty_snapshot_does_not_fill_or_pin(self):
  h=Harness();r=lazy.collect_residency(lambda req:h.request(**req))
  self.assertEqual(r['ranges'],[]);self.assertEqual(r['readyBytes'],0)
  self.assertEqual(h.calls,[]);self.assertEqual(h.cache.leases,{})
 def test_snapshot_freezes_content_across_eviction_and_never_releases_pins(self):
  h=Harness(blocks=6);h.reader().read(h.key,0,1)
  header=h.request('residency-open');before=h.request('status')
  for i in range(1,6):h.reader().read(h.key,i*lazy.CHUNK,1)
  page=h.request('residency-page',snapshot=header['snapshot'],offset=0)
  self.assertEqual(page['entries'][0][1],0)
  self.assertNotIn((h.key,0),h.cache.entries)
  grant=h.request('acquire',digest=h.key,block=5)
  h.request('residency-close',snapshot=header['snapshot'])
  self.assertIn(grant['lease'],h.cache.leases)
  self.assertEqual(before['readyBytes'],lazy.CHUNK)
 def test_other_reader_and_superseded_snapshot_are_rejected(self):
  h=Harness();a=h.request('residency-open')
  with self.assertRaises(ValueError):h.request('residency-page',reader='node-b',snapshot=a['snapshot'],offset=0)
  h.request('residency-open')
  with self.assertRaises(ValueError):h.request('residency-page',snapshot=a['snapshot'],offset=0)
 def test_paged_response_fits_wire_and_reassembles_exact_ready_set(self):
  h=Harness(blocks=30);h.cache.slots=32
  reader=h.reader();reader.slots=32
  for i in range(30):reader.read(h.key,i*lazy.CHUNK,1)
  def request(req):
   r=h.request(**req);self.assertLessEqual(len(lazy.contract.canonical(r)),4096)
   return json.loads(json.dumps(r))
  r=lazy.collect_residency(request)
  self.assertEqual(len(r['ranges']),30);self.assertEqual(r['readyBytes'],30*lazy.CHUNK)
 def test_bad_page_is_not_zero_and_diagnostic_failure_does_not_poison_reader(self):
  h=Harness();h.reader().read(h.key,0,1)
  def request(req):
   r=h.request(**req)
   if req['operation']=='residency-page':r['next']=999
   return r
  with self.assertRaises(ValueError):lazy.collect_residency(request)
  reader=h.reader(request=lambda req:(_ for _ in ()).throw(ValueError('metadata unavailable')))
  with self.assertRaises(ValueError):reader.observe('residency-open')
  self.assertFalse(reader.failed);self.assertFalse(h.cache.poisoned)
if __name__=='__main__':unittest.main()
