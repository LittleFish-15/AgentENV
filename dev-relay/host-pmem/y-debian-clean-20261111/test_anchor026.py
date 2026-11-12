import ast,asyncio,json,pathlib,types,unittest
H=pathlib.Path(__file__).resolve().parent
t=ast.parse((H/'observer026.py').read_text(encoding='utf-8'));n=next(n for n in t.body if isinstance(n,ast.FunctionDef) and n.name=='procstat');scope={};exec(compile(ast.Module(body=[n],type_ignores=[]),'<stat>','exec'),scope)
t=ast.parse((H/'benchmark_hook026.py').read_text(encoding='utf-8'));n=next(n for n in t.body if isinstance(n,ast.AsyncFunctionDef) and n.name=='observed');HOOK=compile(ast.Module(body=[n],type_ignores=[]),'<hook>','exec')
class Tests(unittest.TestCase):
 def test_proc_fields_with_parentheses_in_name(self):
  values=['S']+['0']*44
  for i,v in [(7,11),(9,13),(11,17),(12,19),(19,23),(40,29)]:values[i]=str(v)
  r=scope['procstat']('123 (fc ) worker) '+' '.join(values));self.assertEqual([r[k] for k in ('minflt','majflt','utime','stime','starttime','guest_ticks')],[11,13,17,19,23,29])
 def hook(self,phase,fail=False):
  calls=[]
  def event(p,e,ids):
   calls.append(e);return types.SimpleNamespace(exists=lambda:True,read_text=lambda:'{"ok":true}')
  async def original(*args,**kwargs):
   calls.append('original')
   if fail:raise ValueError('original failure')
   return 7
  env={'event':event,'original':original,'json':json,'time':__import__('time'),'asyncio':asyncio};exec(HOOK,env)
  obj=types.SimpleNamespace(current_round=1,live={'sid':{}})
  if fail:
   with self.assertRaisesRegex(ValueError,'original failure'):asyncio.run(env['observed'](obj,phase,[]))
  else:self.assertEqual(asyncio.run(env['observed'](obj,phase,[])),7)
  return calls
 def test_hooks_surround_original_only(self):self.assertEqual(self.hook('create'),['before','original','after'])
 def test_warmup_not_barrier_instrumented(self):self.assertEqual(self.hook('warmup_create'),['original'])
 def test_original_error_preserved_with_after_snapshot(self):self.assertEqual(self.hook('resume',True),['before','original','after'])
if __name__=='__main__':unittest.main()
