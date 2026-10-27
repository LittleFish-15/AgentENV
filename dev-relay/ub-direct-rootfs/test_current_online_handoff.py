import ast,hashlib,importlib.util,io,json,unittest,urllib.error
from pathlib import Path
from unittest.mock import patch
import types
HERE=Path(__file__).parent
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,HERE/file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
export=load('stage_export','A_export_current_online_handoff_v2.py')
online=load('transport3','AB_deletefix_measurement_online_v3.py')

class CurrentStage(unittest.TestCase):
 def flags(self):return {'readyEnvelope':True,'exitIntent':False,'releaseReceipt':False,'aExitEnvelope':False,'measurementStarted':False}
 def life(self):return {'phase':'active','sandboxIds':['known'],'openRequests':[],'outcomeUncertain':False}
 def test_existing_ready_means_b_not_restart_a(self):self.assertEqual(export.choose_stage(self.flags(),self.life()),'ready-b')
 def test_completed_a_exit_means_b_finish(self):
  flags=self.flags();flags.update(exitIntent=True,releaseReceipt=True,aExitEnvelope=True)
  life=self.life();life.update(phase='quiesced',sandboxIds=[])
  self.assertEqual(export.choose_stage(flags,life),'finish-b')
 def test_partial_unknown_or_missing_ready_rejected(self):
  for change in ({'exitIntent':True},{'releaseReceipt':True},{'readyEnvelope':False}):
   flags=self.flags();flags.update(change)
   with self.assertRaises(RuntimeError):export.choose_stage(flags,self.life())
  life=self.life();life['openRequests']=[{'kind':'create'}]
  with self.assertRaises(RuntimeError):export.choose_stage(self.flags(),life)
 def test_measurement_directory_is_not_claimed_complete(self):
  flags=self.flags();flags['measurementStarted']=True
  self.assertEqual(export.choose_stage(flags,self.life()),'measurement-attempt-present')
 def test_api_raw_is_first_and_header_is_explicit(self):
  raw=b'code';requests=[]
  class Open:
   def open(self,request,timeout):requests.append(request);return io.BytesIO(raw)
  self.assertEqual(online.fetch('x.py','a'*40,hashlib.sha256(raw).hexdigest(),4,Open()),raw)
  self.assertTrue(requests[0].full_url.startswith('https://api.github.com/'))
  self.assertEqual(requests[0].get_header('Accept'),'application/vnd.github.raw+json')
 def test_no_mutating_runtime_methods_called_by_exporter(self):
  tree=ast.parse((HERE/'A_export_current_online_handoff_v2.py').read_text())
  calls={node.func.attr for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)}
  self.assertFalse(calls&{'create','delete','run_online','activate','prepare','persist','normal_release'})
 def test_next_command_uses_api_first_and_parses(self):
  text=online.online_command('ready-b','b',{'synthetic':True},'a'*40,'b'*64,8076)
  body=text.split("<<'ONLINE_MEASUREMENT_RELAY'\n",1)[1].rsplit('\nONLINE_MEASUREMENT_RELAY',1)[0]
  ast.parse(body,feature_version=(3,11))
  self.assertIn("urls=[('api-raw'",body)
 def test_production_download_uses_curl_api_header(self):
  raw=b'fixed';pin=hashlib.sha256(raw).hexdigest()
  with patch.object(online.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=raw,stderr=b'')) as call:
   self.assertEqual(online.fetch('x.py','a'*40,pin,len(raw)),raw)
   args=call.call_args.args[0]
   self.assertEqual(args[0],'curl');self.assertIn('Accept: application/vnd.github.raw+json',args)
   self.assertTrue(args[-1].startswith('https://api.github.com/'))

if __name__=='__main__':unittest.main()
