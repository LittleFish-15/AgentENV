"""Fix known G7 dropin recovery; keep workload requests/timing unchanged."""
import ast,hashlib,json,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
source=(H/'Y_g7_run032_bound.py').read_text(encoding='utf-8').replace("W=B/'g7-20261112-032'","W=B/'g7-20261112-033'")
function='''
def authorize_g7_dropin(existing,mode,current):
 def body(path):return '[Service]\\nExecStart=\\nExecStart=/usr/bin/python3 -I -B '+path+' inside\\n'
 if mode=='formal':
  prior='/home/jwk/aenv-y-clean-20261111/g7-20261112-031/runtime_formal.py'
 elif mode=='diagnostic':prior=str(current/'runtime_formal.py')
 else:raise ValueError('Unknown G7 mode')
 if existing!=body(prior):raise RuntimeError('Existing logging dropin differs from the exact known G7 configuration; preserved')
 return prior
'''
source=source.replace('def main():',function+'\ndef main():',1)
needle="  failed=json.loads((B/'g7-20261112-031/result.json').read_text())"
source=source.replace(needle,"  prior_attempt=json.loads((B/'g7-20261112-032/result.json').read_text())\n  assert prior_attempt['success'] is False and prior_attempt['modes']=={} and prior_attempt['errorType']=='AssertionError','032 outcome differs; preserve state'\n"+needle,1)
needle="   if drop.exists():assert mode=='diagnostic' and drop.read_text().endswith(str(W/'runtime_formal.py')+' inside\\n')"
replacement="""   if drop.exists() or drop.is_symlink():
    assert not drop.is_symlink() and drop.stat().st_uid==0 and not drop.stat().st_mode&0o022,'Untrusted logging dropin preserved'
    existing=drop.read_text();prior=authorize_g7_dropin(existing,mode,W)
    # Every accepted previous wrapper must match this exact mode's known source.
    assert sha(P(prior))==sha(W/'runtime_formal.py'),'Previous G7 supervisor source differs'
    (d/'dropin-before.conf').write_text(existing)
   elif mode=='diagnostic':raise RuntimeError('Formal G7 logging dropin disappeared before diagnostic')"""
assert source.count(needle)==1;source=source.replace(needle,replacement)
source=source.replace("   assert inventory()==[];d=W/mode;directory(d)","   result['stage']=mode+'_configure';assert inventory()==[];d=W/mode;directory(d)")
source=source.replace("   directory(d/'prewarm100');client,tag=launch(d/'prewarm100',1,False);assert client.wait(timeout=900)==0","   result['stage']=mode+'_prewarm100';directory(d/'prewarm100');client,tag=launch(d/'prewarm100',1,False);assert client.wait(timeout=900)==0,mode+' prewarm client failed; see prewarm100/client.log'")
source=source.replace("   beforepool=pool(1000);offset=","   result['stage']=mode+'_pool_after_prewarm';beforepool=pool(1000);offset=")
source=source.replace("   client,tag=launch(d,5 if mode=='formal' else 1,True);end=","   result['stage']=mode+'_main_warmup';client,tag=launch(d,5 if mode=='formal' else 1,True);end=")
source=source.replace("   (d/'CONTINUE').write_text('start');", "   result['stage']=mode+'_measuring';(d/'CONTINUE').write_text('start');")
source=source.replace("   assert client.wait(timeout=1800)==0","   assert client.wait(timeout=1800)==0,mode+' measured client failed; see client.log'")
source=source.replace("  result['success']=True","  result['stage']='complete';result['success']=True")
needle=" except BaseException as e:result.update(errorType=type(e).__name__,error=str(e)[:2000]);raise"
assert needle in source
source=source.replace(needle," except BaseException as e:\n  # Complete the evidence-collection operation even if the experiment failed.\n  # Never turn result.success into true or continue another workload on failure.\n  result.update(errorType=type(e).__name__,error=str(e)[:2000])")
source=source.replace("'error':result.get('error')}","'error':result.get('error'),'errorType':result.get('errorType'),'stage':result.get('stage')}")
source=source.replace("  if perf is not None:\n   os.killpg(perf.pid,signal.SIGINT);perf.wait(timeout=30)","  if perf is not None:\n   if perf.poll() is None:\n    try:os.killpg(perf.pid,signal.SIGINT)\n    except ProcessLookupError:pass\n   try:perf.wait(timeout=30)\n   except subprocess.TimeoutExpired:\n    os.killpg(perf.pid,signal.SIGKILL);perf.wait(timeout=10)\n   result['perfCleanupExitCode']=perf.returncode")
ast.parse(source,feature_version=(3,11))
tree=ast.parse(source);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='authorize_g7_dropin');ns={};exec(compile(ast.Module(body=[node],type_ignores=[]),'dropin_guard','exec'),ns);authorize=ns['authorize_g7_dropin']
class ResumeTests(unittest.TestCase):
 def test_known_failed_attempt_can_resume(self):
  p='/home/jwk/aenv-y-clean-20261111/g7-20261112-031/runtime_formal.py';s='[Service]\nExecStart=\nExecStart=/usr/bin/python3 -I -B '+p+' inside\n';self.assertEqual(authorize(s,'formal',Path('/new-g7')),p)
 def test_formal_to_diagnostic_keeps_expected_transition(self):
  w=Path('/new-g7');p=str(w/'runtime_formal.py');s='[Service]\nExecStart=\nExecStart=/usr/bin/python3 -I -B '+p+' inside\n';self.assertEqual(authorize(s,'diagnostic',w),p)
 def test_unrelated_or_changed_configuration_preserved(self):
  for s in ('[Service]\nExecStart=/other/service\n','[Service]\nExecStart=\nExecStart=/usr/bin/python3 -I -B /home/jwk/aenv-y-clean-20261111/g7-20261112-031/runtime_formal.py inside\nEnvironment=EXTRA=changed\n'):
   with self.assertRaises(RuntimeError):authorize(s,'formal',Path('/new-g7'))
suite=unittest.defaultTestLoader.loadTestsFromTestCase(ResumeTests);r=unittest.TextTestRunner().run(suite);assert r.wasSuccessful()
# Embedded client and supervisors must be byte-identical to032.
def bundle(text):return ast.literal_eval(next(n.value for n in ast.parse(text).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BUNDLE' for t in n.targets)))
assert bundle(source)==bundle((H/'Y_g7_run032_bound.py').read_text(encoding='utf-8'))
(H/'Y_g7_run033_bound.py').write_bytes(source.encode())
chunk=(H/'Y_g7_chunk029.py').read_text().replace('/g7-20261112/evidence.tar.gz','/g7-20261112-033/evidence.tar.gz');ast.parse(chunk);(H/'Y_g7_chunk033.py').write_text(chunk,encoding='utf-8')
print(json.dumps({'status':'G7_033_PREPARED','guardRegressionTests':3,'embeddedClientAndSupervisorBytesUnchanged':True,'sourceBytes':len(source.encode())}))
