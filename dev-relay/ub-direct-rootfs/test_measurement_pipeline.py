import ast,base64,copy,importlib.util,json,sys,types,unittest,zlib
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).parent
if sys.platform=='win32':sys.modules['fcntl']=types.ModuleType('fcntl')
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,HERE/file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
pipeline=load('pipeline','AB_deletefix_measurement_pipeline_v1.py')
exit_pair=load('exit_pair','AB_deletefix_exit_pair_v1.py')

class PipelineChecks(unittest.TestCase):
 def smoke(self):
  sid='smoke';life={'runId':'94cdf2e7927e466e80a3c0e0853d87a4','sandboxIds':[],'openRequests':[],
    'outcomeUncertain':False,'operations':[{'kind':'create','httpStatus':201,'ack':{'sandboxIds':[sid]}},
      {'kind':'delete','httpStatus':204,'route':'/sandboxes/'+sid}]}
  server={'pid':1};report={'status':'A_DELETEFIX_REAL_GUEST_READ_AND_NORMAL_DELETE_PASSED','ordinaryDeletePassed':True,
   'forcedCleanupUsed':False,'read':{'serverIdentity':server,'sandboxId':sid},'deleteHttpStatus':204,'guestExitConfirmed':True,
   'privateRootfsDeviceRemoved':True,'localUBReadersReleased':True,'journal':life}
  state={'version':1,'phase':'active','directPairRunId':life['runId'],'sandboxIds':[],'openRequests':[],'outcomeUncertain':False}
  return report,life,state,server
 def test_only_confirmed_smoke_can_close_empty_active_marker(self):
  args=self.smoke();exit_pair.completed_smoke_contract(*args)
  for change in ('http','pending','flag'):
   report,life,state,server=copy.deepcopy(args)
   if change=='http':life['operations'][1]['httpStatus']=500
   elif change=='pending':state['openRequests']=[{'kind':'create'}]
   else:report['privateRootfsDeviceRemoved']=False
   with self.assertRaises(RuntimeError):exit_pair.completed_smoke_contract(report,life,state,server)
 def test_no_original_start_after_failed_pair_gate(self):
  fake=types.SimpleNamespace(__file__='/fixture/exit.py',main=lambda:1,WORK=Path('/fixture/pair'))
  class Folder:
   st_uid=0;st_mode=0o700
   def __truediv__(self,key):return self
   def mkdir(self,**kwargs):pass
   def resolve(self,**kwargs):return self
   def stat(self):return self
   def __str__(self):return '/fixture'
  calls=[]
  with patch.object(pipeline.os,'getuid',lambda:0,create=True),patch.object(pipeline.os,'geteuid',lambda:0,create=True),\
       patch.object(pipeline.os,'uname',lambda:types.SimpleNamespace(nodename='agent1'),create=True),\
       patch.object(pipeline,'ROOT',Folder()),patch.object(pipeline,'loaded',lambda name:fake),\
       patch.object(pipeline,'put'),patch.object(pipeline,'measure',side_effect=lambda *a:calls.append(a)):
   self.assertEqual(pipeline.run('finish-b',{'history':{},'peer':{}}),1)
  self.assertEqual(calls,[])
 def test_all_relay_phases_parse_and_pin_source_context(self):
  raw=(HERE/'AB_deletefix_measurement_pipeline_v1.py').read_bytes()
  context={'history':{'synthetic':True},'peer':None}
  for phase,node in [('ready-a','a'),('ready-b','b'),('release-a','a'),('finish-b','b'),('original-a','a'),('full-b','b')]:
   text=pipeline.relay(phase,node,context,raw)
   body=text.split("<<'DELETEFIX_MEASUREMENT_PIPELINE'\n",1)[1].rsplit('\nDELETEFIX_MEASUREMENT_PIPELINE',1)[0]
   tree=ast.parse(body,feature_version=(3,11));strings=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
   decoded=[]
   for value in strings:
    try:decoded.append(zlib.decompress(base64.b64decode(value)))
    except Exception:pass
   self.assertIn(raw,decoded);self.assertIn(pipeline.canonical(context),decoded)
   self.assertIn(phase,strings)
 def test_component_digests_match_built_packages(self):
  for name,item in pipeline.COMPONENTS.items():self.assertEqual(pipeline.raw_component(name),(HERE/item['filename']).read_bytes())
 def test_validation_flush_rejects_shared_memory_alias_before_action(self):
  class Device:
   def __init__(self,name):self.name=name
   def stat(self):return types.SimpleNamespace(st_ino=123)
   def __str__(self):return self.name
  binding={'rootfsDevice':'/dev/ublkb13','requiredUB':True,'upperPrivateVerified':True}
  with patch.object(exit_pair,'Path',Device),patch.object(exit_pair.subprocess,'Popen') as launch:
   with self.assertRaisesRegex(RuntimeError,'memory device alias'):
    exit_pair.prepare_fresh_private_read(binding,13,None)
   launch.assert_not_called()

if __name__=='__main__':unittest.main()
