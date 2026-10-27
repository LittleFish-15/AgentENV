import ast,base64,hashlib,importlib.util,io,json,sys,types,unittest,urllib.error,zlib
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('online',HERE/'AB_deletefix_measurement_online_v1.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Replies:
 def __init__(self,replies):self.replies=list(replies);self.urls=[]
 def open(self,request,timeout):
  self.urls.append(request.full_url);value=self.replies.pop(0)
  if isinstance(value,Exception):raise value
  return io.BytesIO(value)

class OnlineTransport(unittest.TestCase):
 def test_raw_and_api_use_fixed_commit_and_same_digest(self):
  raw=b'print("pinned")\n';pin=hashlib.sha256(raw).hexdigest()
  first=Replies([raw]);self.assertEqual(m.fetch('x.py','a'*40,pin,len(raw),first),raw)
  second=Replies([urllib.error.URLError('offline'),json.dumps({'encoding':'base64','content':base64.b64encode(raw).decode()}).encode()])
  self.assertEqual(m.fetch('x.py','a'*40,pin,len(raw),second),raw)
  self.assertEqual(len(second.urls),2);self.assertTrue(all('a'*40 in url for url in first.urls+second.urls))
 def test_corrupt_success_response_is_not_executed_or_retried(self):
  replies=Replies([b'corrupt',b'good'])
  with self.assertRaises(RuntimeError):m.fetch('x.py','a'*40,hashlib.sha256(b'good').hexdigest(),4,replies)
  self.assertEqual(len(replies.urls),1)
 def test_download_failure_stops(self):
  replies=Replies([TimeoutError(),urllib.error.URLError('unavailable')])
  with self.assertRaisesRegex(RuntimeError,'no pipeline phase started'):m.fetch('x.py','a'*40,'b'*64,1,replies)
 def test_context_capsule_is_private_not_in_download_url(self):
  context={'private-marker':'SYNTHETIC_PRIVATE_CONTEXT','peer':{'version':1}}
  command=m.online_command('ready-a','a',context,'a'*40,'b'*64,1234)
  python=command.split("<<'ONLINE_MEASUREMENT_RELAY'\n",1)[1].rsplit('\nONLINE_MEASUREMENT_RELAY',1)[0]
  tree=ast.parse(python,feature_version=(3,11))
  strings=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
  decoded=[]
  for value in strings:
   try:decoded.append(json.loads(zlib.decompress(base64.b64decode(value))))
   except Exception:pass
  self.assertIn(context,decoded)
  self.assertNotIn('SYNTHETIC_PRIVATE_CONTEXT',command)
  self.assertNotIn('AB_deletefix_measurement_pipeline_v1.py',command) # only small adapter bootstrap
 def test_only_relay_formatter_is_replaced(self):
  raw=b'def run(phase,context):\n return (phase,context,callable(relay))\n'
  context={'immutable':'value'}
  with patch.object(m.os,'getuid',lambda:0,create=True),patch.object(m.os,'geteuid',lambda:0,create=True),\
       patch.object(m.os,'uname',lambda:types.SimpleNamespace(nodename='server1'),create=True),\
       patch.object(m,'read_cached',return_value=b'checked'),patch.object(m,'ensure_code',return_value=(Path('/fixture/pipeline.py'),raw)):
   self.assertEqual(m.run_online('ready-a',context,'a'*40,'b'*64,1),('ready-a',context,True))
 def test_wrong_node_never_loads_pipeline(self):
  with patch.object(m.os,'getuid',lambda:0,create=True),patch.object(m.os,'geteuid',lambda:0,create=True),\
       patch.object(m.os,'uname',lambda:types.SimpleNamespace(nodename='agent1'),create=True),patch.object(m,'ensure_code') as fetch:
   with self.assertRaises(RuntimeError):m.run_online('ready-a',{},'a'*40,'b'*64,1)
   fetch.assert_not_called()

if __name__=='__main__':unittest.main()
