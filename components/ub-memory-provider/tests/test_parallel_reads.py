"""Actual Python thread coordination and lease tests; no SDK performance claims."""
import concurrent.futures,sys,threading,time,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import lazy
from test_lazy_cache import Harness
class ParallelReads(unittest.TestCase):
 def reader(self,h,count=2,request=None):
  return lazy.Reader(h.value,h.mapping,4,'c'*32,'owner',h.tokens['owner'],request or h.cache.request,count)
 def warm(self,h,blocks):
  for block in blocks:h.reader().read(h.key,block*lazy.CHUNK,1)
 def test_two_reads_overlap_and_cannot_retire_during_pinned_mapping_access(self):
  h=Harness();self.warm(h,(0,1));reader=self.reader(h)
  original=h.mapping.read;entered=threading.Barrier(3);finish=threading.Event()
  def read(offset,count):
   with h.cache.condition:self.assertTrue(any(e.slot*lazy.CHUNK==offset and e.pins>0 for e in h.cache.entries.values()))
   entered.wait(timeout=4);self.assertTrue(finish.wait(4));return original(offset,count)
  h.mapping.read=read
  with concurrent.futures.ThreadPoolExecutor(2) as pool:
   futures=[pool.submit(reader.read,h.key,i*lazy.CHUNK,20) for i in (0,1)]
   try:
    entered.wait(timeout=4);self.assertEqual(reader.status()['activeReads'],2)
    self.assertEqual(len(h.cache.leases),2)
    with self.assertRaisesRegex(RuntimeError,'Active mapping reads'):reader.release()
    self.assertNotIn('owner',h.cache.released)
   finally:finish.set()
   self.assertEqual([f.result(4) for f in futures],[h.parts[0][:20],h.parts[1][:20]])
  self.assertFalse(h.cache.leases);reader.release();self.assertTrue(reader.closed)
  with self.assertRaises(RuntimeError):reader.read(h.key,0,1)
 def test_admission_is_bounded_without_holding_a_mapping_pin_for_waiters(self):
  h=Harness();self.warm(h,(0,1,2));reader=self.reader(h);entered=threading.Barrier(3);finish=threading.Event()
  original=h.mapping.read;counter=0;lock=threading.Lock()
  def read(offset,count):
   nonlocal counter
   with lock:counter+=1;number=counter
   if number<=2:entered.wait(timeout=4);self.assertTrue(finish.wait(4))
   return original(offset,count)
  h.mapping.read=read
  with concurrent.futures.ThreadPoolExecutor(3) as pool:
   first=[pool.submit(reader.read,h.key,i*lazy.CHUNK,1) for i in (0,1)]
   entered.wait(timeout=4);third=pool.submit(reader.read,h.key,2*lazy.CHUNK,1)
   try:
    deadline=time.monotonic()+3
    while not reader.status()['queuedReadWaits'] and time.monotonic()<deadline:time.sleep(.001)
    self.assertEqual(reader.status()['activeReads'],2);self.assertFalse(third.done());self.assertEqual(len(h.cache.leases),2)
   finally:finish.set()
   [f.result(4) for f in (*first,third)]
  self.assertEqual(reader.status()['peakActiveReads'],2);self.assertFalse(h.cache.leases)
 def test_lost_parallel_grant_preserves_unknown_pins_and_closes_new_admission(self):
  h=Harness();self.warm(h,(0,1));entered=threading.Event();finish=threading.Event();original=h.mapping.read
  def request(req):
   response=h.cache.request(req)
   if req['operation']=='acquire' and req['block']==1:raise ConnectionError('Lost grant response')
   return response
  reader=self.reader(h,request=request)
  def read(offset,count):entered.set();self.assertTrue(finish.wait(4));return original(offset,count)
  h.mapping.read=read
  with concurrent.futures.ThreadPoolExecutor(2) as pool:
   first=pool.submit(reader.read,h.key,0,1);self.assertTrue(entered.wait(4))
   second=pool.submit(reader.read,h.key,lazy.CHUNK,1)
   try:
    with self.assertRaises(ConnectionError):second.result(4)
    self.assertTrue(reader.failed)
    with self.assertRaises(RuntimeError):reader.read(h.key,2*lazy.CHUNK,1)
    self.assertEqual(len(h.cache.leases),2)
   finally:finish.set()
   with self.assertRaises(RuntimeError):first.result(4)
  self.assertEqual(reader.active_reads,0);self.assertEqual(len(h.cache.leases),2)
  with self.assertRaises(RuntimeError):reader.release()
  with self.assertRaises(RuntimeError):h.cache.freeze()
 def test_limits_and_serial_default_are_explicit(self):
  h=Harness();self.assertEqual(h.reader().status()['maxConcurrentReads'],1)
  for count in (0,9,True,1.5):
   with self.assertRaises(ValueError):self.reader(h,count)
if __name__=='__main__':unittest.main()
