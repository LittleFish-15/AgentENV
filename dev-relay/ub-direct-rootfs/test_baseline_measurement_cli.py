import importlib.util,io,json,stat,types,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('cli_prepare',Path(__file__).with_name('baseline_measurement_cli.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class P:
    def __init__(self,fs,name):self.fs,self.name=fs,name
    def __truediv__(self,part):return P(self.fs,self.name+'/'+part)
    def __str__(self):return self.name
    def __eq__(self,other):return isinstance(other,P) and self.name==other.name
    def exists(self):return self.name in self.fs
    def is_symlink(self):return False
    def resolve(self,strict=True):
        if not self.exists():raise FileNotFoundError(self.name)
        return self
    def mkdir(self,mode):
        if self.exists():raise FileExistsError(self.name)
        self.fs[self.name]=None
    def stat(self):return types.SimpleNamespace(st_mode=(stat.S_IFDIR|0o700) if self.fs[self.name] is None else stat.S_IFREG|0o600,st_uid=1204)

class Stream(io.BytesIO):
    def __init__(self,path):super().__init__();self.path=path
    def fileno(self):return 5
    def close(self):self.path.fs[self.path.name]=self.getvalue();super().close()

class CLI(unittest.TestCase):
    def test_loopback_from_running_environment_not_missing_cli_file(self):
        self.assertEqual(m.baseline_endpoint({b'API_ADDR':b'127.0.0.1:18080'}),18080)
        for env in ({},{b'API_ADDR':b'0.0.0.0:18080'},{b'API_ADDR':b'127.0.0.1:80'}):
            with self.assertRaises(RuntimeError):m.baseline_endpoint(env)
    def execute(self,fs):
        api=types.SimpleNamespace(port=18080,key='e2b_SYNTHETIC_TEST_ONLY',stable=lambda:None)
        opened=[]
        def create(path,flags,mode):
            if path.exists():raise FileExistsError(str(path))
            opened.append(path);return path
        with patch.object(m.os,'open',side_effect=create),patch.object(m.os,'fdopen',side_effect=lambda p,*a:Stream(p)),\
             patch.object(m.os,'chown',create=True),patch.object(m.os,'fchown',create=True),\
             patch.object(m.os,'fchmod',create=True),patch.object(m.os,'fsync'),patch.object(m.os,'O_NOFOLLOW',0,create=True):
            return m.baseline_cli_config(P(fs,'/base'),api,lambda p:fs[p.name]),opened
    def test_missing_cli_tree_is_prepared_then_verified(self):
        fs={'/base':None};result,opened=self.execute(fs)
        self.assertTrue(result['createdCredentials']);self.assertEqual(len(opened),1)
        for name in ('cli','cli/config','cli/config/aenv','cli/cache','cli/tmp'):self.assertIn('/base/'+name,fs)
        self.assertNotIn('e2b_SYNTHETIC_TEST_ONLY',json.dumps(result))
        self.assertNotIn('/base/config/runtime.toml',fs)
    def test_matching_existing_config_not_rewritten(self):
        fs={'/base':None};self.execute(fs);before=dict(fs)
        result,opened=self.execute(fs);self.assertFalse(result['createdCredentials']);self.assertEqual(opened,[]);self.assertEqual(fs,before)
    def test_conflicting_config_preserved(self):
        fs={'/base':None};self.execute(fs);fs['/base/cli/config/aenv/credentials']=b'url="http://127.0.0.1:18081"\napi_key="other"\n';before=dict(fs)
        with self.assertRaisesRegex(RuntimeError,'preserved'):self.execute(fs)
        self.assertEqual(fs,before)

if __name__=='__main__':unittest.main()
