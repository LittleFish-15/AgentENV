"""User changes G7 to anchor-retained optimized Y; preserve old033 as control."""
import ast,json,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
source=(H/'Y_g7_run033_bound.py').read_text(encoding='utf-8').replace("W=B/'g7-20261112-033'","W=B/'g7-20261112-035'")
# Bound program uses exactly the same Go requests/timing and logging supervisors.
helper=(H/'g7_anchor035.py').read_text(encoding='utf-8');source=source.replace('def main():',helper+'\ndef main():',1)
start=source.index('def authorize_g7_dropin(');end=source.index('class G7Anchor:',start)
source=source[:start]+'''def authorize_g7_dropin(existing,mode,current):
 prior=str(B/'g7-20261112-033/runtime_diagnostic.py') if mode=='diagnostic' else str(current/'runtime_diagnostic.py')
 expected='[Service]\\nExecStart=\\nExecStart=/usr/bin/python3 -I -B '+prior+' inside\\n'
 assert existing==expected,'Unexpected existing logging configuration preserved'
 return prior

'''+source[end:]
needle=' assert inventory()==[] and not W.exists()'
addition=''' anchor_controller=None;owned_runs=[]
 def inventory_ok():return inventory()==[] if anchor_controller is None else anchor_controller.inventory_ok()
 def wait_client(process,timeout):
  deadline=time.monotonic()+timeout
  while process.poll() is None:
   if anchor_controller is not None:anchor_controller.verify()
   if time.monotonic()>deadline:raise TimeoutError('Own G7 client deadline')
   time.sleep(.1)
  return process.returncode
 assert inventory_ok() and not W.exists()'''
assert needle in source;source=source.replace(needle,addition,1)
source=source.replace("'anchor':False","'anchor':True")
source=source.replace("    tag='g7-'+mode+'-'+uuid.uuid4().hex", "    tag='g7-'+mode+'-'+uuid.uuid4().hex;owned_runs.append(tag);save(W/'owned-runs.json',owned_runs)")
source=source.replace("  result.update(expectedFC=1000,G6ArchivedFC=600,poolDifferenceExplicitlyAcceptedByUser=True)","  result.update(protocol='Y running-anchor optimized G7',poolPolicy='natural stable, includes one anchor',G6ArchivedFC=600,G6UsesAnchor=False,ordinaryControl='g7-20261112-033/formal')")
source=source.replace("  for mode in ('formal','diagnostic'):","  for mode in ('diagnostic','formal'):")
source=source.replace('assert inventory()==[]','assert inventory_ok()')
source=source.replace("assert pre['valid'] and inventory()==[]","assert pre['valid'] and inventory_ok()")
source=source.replace("sha(W/'runtime_formal.py'),'Previous G7 supervisor source differs'","sha(W/'runtime_diagnostic.py'),'Previous G7 supervisor source differs'")
source=source.replace("   elif mode=='diagnostic':raise RuntimeError('Formal G7 logging dropin disappeared before diagnostic')","   else:raise RuntimeError('Known G7 diagnostic dropin missing; preserved')")
source=source.replace("   initial=pool();runenv=", "   result['stage']=mode+'_anchor_create';anchor_controller=G7Anchor(d,template,key,mode);anchor_controller.create()\n   initial=pool();runenv=")
source=source.replace("pool(1000)","pool()")
source=source.replace("    assert stable>=5,'FC pool not stable'","    assert stable>=5,'FC pool not stable'\n    assert 301<=len(last)<=1001,'Natural pool plus anchor outside configured range'")
source=source.replace("client.wait(timeout=900)","wait_client(client,900)").replace("client.wait(timeout=1800)","wait_client(client,1800)")
source=source.replace("   result['stage']=mode+'_pool_after_prewarm';beforepool=", "   anchor_controller.checkpoint('after_prewarm100');result['stage']=mode+'_pool_after_prewarm';beforepool=")
source=source.replace("   startpool=pool();assert inventory_ok()", "   startpool=pool();anchor_controller.checkpoint('main_warmup_complete');assert inventory_ok()")
source=source.replace("'G6ArchivedPool':600,'poolDifferenceAcceptedByUser':True", "'G6ArchivedPool':600,'G6UsesAnchor':False,'anchorId':anchor_controller.id,'anchorFC':anchor_controller.fc,'poolIncludesOneRunningAnchor':True,'poolDifferenceAcceptedByUser':True")
source=source.replace("   result['modes'][mode]={'summary':summary,'manifest':manifest}","   anchor_controller.checkpoint('measured_workload_complete');result['modes'][mode]={'summary':summary,'manifest':manifest}")
needle="  result['stage']='complete';result['success']=True"
insert="""   if mode=='diagnostic':
    operations=[json.loads(line) for line in (d/'result/operations.jsonl').read_text().splitlines()]
    gate=g7_anchor_poll_gate(data.decode(),operations);save(d/'envd-poll-gate.json',gate);result['envdPollGate']=gate
    assert gate['passed'],'Anchor diagnostic create envd poll still above20ms; formal5 not run'
   anchor_controller.cleanup();anchor_controller=None;assert inventory()==[]
   result['modes'][mode]['anchorCleanupVerified']=True
  result['stage']='complete';result['success']=True"""
assert needle in source;source=source.replace(needle,insert)
needle="  save(W/'result.json',result)"
insert="""  if anchor_controller is not None:
   try:result['ownedRunCleanupIds']=anchor_controller.cleanup_benchmark_runs(set(owned_runs))
   except BaseException as cleanup_error:result.update(success=False,ownedRunCleanupError=type(cleanup_error).__name__+': '+str(cleanup_error)[:1000])
   try:anchor_controller.cleanup()
   except BaseException as cleanup_error:result.update(success=False,anchorCleanupError=type(cleanup_error).__name__+': '+str(cleanup_error)[:1000])
  try:result['finalInventoryCount']=len(inventory());result['success']=result['success'] and result['finalInventoryCount']==0
  except BaseException as cleanup_error:result.update(success=False,inventoryError=str(cleanup_error)[:1000])
  save(W/'result.json',result)"""
assert needle in source;source=source.replace(needle,insert)
# Preserve the experiment if cycles is unavailable: use a labelled CPU-clock profile.
needle="    time.sleep(.5);assert perf.poll() is None,'G7 perf cycles/cgroup unsupported; do not substitute silently'"
replacement="""    time.sleep(.5);manifest['perfEvent']='cycles'
    if perf.poll() is not None:
     manifest['cyclesUnavailableExit']=perf.returncode;manifest['perfEvent']='cpu-clock';manifest['perfEventDiffersFromG6']=True
     fallbacklog=(d/'perf-fallback.log').open('xb');opened.append(fallbacklog)
     perf=subprocess.Popen(['perf','record','-a','-e','cpu-clock','-G','system.slice/'+U,'-F','199','--call-graph','dwarf,8192','--clockid','mono','-o',str(d/'perf.data')],stdout=fallbacklog,stderr=subprocess.STDOUT,start_new_session=True)
     time.sleep(.5);assert perf.poll() is None,'Both scoped perf events unavailable'
    save(d/'manifest.json',manifest)"""
assert needle in source;source=source.replace(needle,replacement)
source=source.replace("if p.name in ('lifecycle-go','go1.27.4.linux-amd64.tar.gz','perf.data')", "if p.name.startswith('perf.data') or p.name in ('lifecycle-go','go1.27.4.linux-amd64.tar.gz')")
ast.parse(source,feature_version=(3,11))
# Synthetic target/warmup mixture validates the gate's sandbox/round filtering.
tree=ast.parse(helper);function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='g7_anchor_poll_gate')
import re
ns={'json':json,'re':re};exec(compile(ast.Module(body=[function],type_ignores=[]),'poll_gate','exec'),ns)
def fixture(value):
 ops=[];logs=[]
 for phase,root in [('create','create_sandbox'),('resume','resume_sandbox')]:
  for i in range(101):
   sid=phase+str(i);ops.append({'sandbox_id':sid,'phase':phase,'round':1 if i else 0,'status':'ok'})
   logs.append(json.dumps({'target':'agentenv::sandbox::envd','span':{'name':'wait_for_ready'},'spans':[{'name':root,'sandbox_id':sid}],'fields':{'message':'close','time.busy':'1µs','time.idle':str(value if i else 1000)+'ms'}}))
 return '\n'.join(logs),ops
assert ns['g7_anchor_poll_gate'](*fixture(3))['passed']
assert not ns['g7_anchor_poll_gate'](*fixture(40))['passed']
try:ns['g7_anchor_poll_gate']('\n'.join(fixture(3)[0].splitlines()[1:]),fixture(3)[1])
except AssertionError:raise AssertionError('Removed only warmup must not affect target coverage')
try:ns['g7_anchor_poll_gate']('\n'.join(fixture(3)[0].splitlines()[:1]+fixture(3)[0].splitlines()[2:]),fixture(3)[1])
except AssertionError:pass
else:raise AssertionError('Missing measured poll must reject gate')
class_node=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='G7Anchor');exec(compile(ast.Module(body=[class_node],type_ignores=[]),'anchor_cleanup','exec'),ns)
def cleanup_fixture(wrong=False,lost=False):
 a=ns['G7Anchor'].__new__(ns['G7Anchor']);a.id=None if lost else 'own-anchor';a.intent=True;a.cleaned=False;a.metadata={'tag':'own'};a.template='template';a.persist=lambda:None
 a.inventory=lambda:[{'sandboxID':'own-anchor','metadata':{'tag':'own'}},{'sandboxID':'foreign','metadata':{'tag':'foreign'}}]
 deleted=[]
 def request(method,path,body=None,allow404=False):
  if method=='DELETE':deleted.append(path);return None
  if deleted:return None
  return {'metadata':{'tag':'wrong' if wrong else 'own'},'templateID':'template'}
 a.request=request
 try:a.cleanup()
 except AssertionError:
  assert wrong and not deleted;return
 assert not wrong and deleted==['/sandboxes/own-anchor'] and a.cleaned
cleanup_fixture();cleanup_fixture(lost=True);cleanup_fixture(wrong=True)
def bundle(text):return ast.literal_eval(next(n.value for n in ast.parse(text).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BUNDLE' for t in n.targets)))
assert bundle(source)==bundle((H/'Y_g7_run033_bound.py').read_text(encoding='utf-8'))
assert len(source.encode())<256*1024
(H/'Y_g7_anchor035_bound.py').write_bytes(source.encode())
chunk=(H/'Y_g7_chunk029.py').read_text().replace('/g7-20261112/evidence.tar.gz','/g7-20261112-035/evidence.tar.gz');(H/'Y_g7_chunk035.py').write_text(chunk,encoding='utf-8')
print(json.dumps({'status':'G7_ANCHOR035_PREPARED','formalRounds':5,'diagnosticFirst':True,'createPollGateMeanMs':20,'clientBytesUnchanged':True,'anchorCleanupRegressionCases':3,'pollGateRegressionCases':4,'sourceBytes':len(source.encode())}))
