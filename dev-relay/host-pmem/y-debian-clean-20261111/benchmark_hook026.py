"""Unchanged SDK benchmark with observation barriers outside batch timing."""
import asyncio,importlib.util,json,os,pathlib,time
P=pathlib.Path;BASE=P('/home/jwk/aenv-y-clean-20261111');CONTROL=BASE/'anchor026/control';GROUP=os.environ['ANCHOR_GROUP026'];SEQ=0
def event(phase,edge,ids):
 global SEQ
 SEQ+=1;name=GROUP+'-'+str(SEQ).zfill(4);path=CONTROL/(name+'.json')
 value={'group':GROUP,'phase':phase,'edge':edge,'sandboxIds':ids,'unixNs':time.time_ns(),'monotonicNs':time.monotonic_ns()}
 temp=CONTROL/(name+'.tmp');temp.write_text(json.dumps(value)+'\n');temp.replace(path)
 return CONTROL/(name+'.ack')
spec=importlib.util.spec_from_file_location('original_benchmark',BASE/'g4-benchmark_sandbox_lifecycle.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);original=m.Benchmark.batches_for
async def observed(self,phase,*args,**kwargs):
 formal=phase in ('create','pause','resume','delete') and self.current_round==1
 async def sync(edge):
  ack=event(phase,edge,list(self.live));deadline=time.monotonic()+90
  while not ack.exists():
   if time.monotonic()>deadline:raise TimeoutError('Observer barrier timed out')
   await asyncio.sleep(.01)
  response=json.loads(ack.read_text());assert response['ok'],response
 if formal:await sync('before')
 try:return await original(self,phase,*args,**kwargs)
 finally:
  if formal:await sync('after')
m.Benchmark.batches_for=observed
if __name__=='__main__':raise SystemExit(asyncio.run(m.main_async(m.parse_args())))
