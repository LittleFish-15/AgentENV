import ast,hashlib,importlib.util,types,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
class MemoryPath:
    objects={}
    def __new__(cls,path):
        name=str(path)
        if name not in cls.objects:
            obj=super().__new__(cls);obj.name=name;obj.data=b'';cls.objects[name]=obj
        return cls.objects[name]
    def __truediv__(self,name):return MemoryPath(self.name+'/'+name)
    def __str__(self):return self.name
    def is_file(self):return self.name=='/etc/pki/tls/certs/ca-bundle.crt'
    def is_dir(self):return False
    def stat(self):return types.SimpleNamespace(st_size=len(self.data))
    def read_bytes(self):return self.data
    def write_bytes(self,raw):self.data=raw
class Resume(unittest.TestCase):
    def test_ca_function_reaches_hash_and_bundle(self):
        MemoryPath.objects={};raw=b'public-test-certificate-content';MemoryPath('/etc/pki/tls/certs/ca-bundle.crt').data=raw
        text=(H/'Y_resume002.py').read_text(encoding='utf-8');tree=ast.parse(text)
        node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='prepare_private_ca')
        namespace={'P':MemoryPath,'hashlib':hashlib,'os':types.SimpleNamespace(chown=lambda *a:None,chmod=lambda *a:None)}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<ca-function>','exec'),namespace)
        b=types.SimpleNamespace(BASE=MemoryPath('/build'),JWK=types.SimpleNamespace(pw_uid=1002,pw_gid=1002),STATE={},mkdir=lambda p:None,
          probe=lambda *a,**k:{'code':0,'stdout':'HTTP 200; ssl_verify 0'},save=lambda:None,
          sha_file=lambda p:hashlib.sha256(p.read_bytes()).hexdigest())
        value=namespace['prepare_private_ca'](b,{})
        self.assertEqual(value,'/build/network-ca005/bundle.pem')
        self.assertEqual(b.STATE['private_ca005']['sources'][0]['sha256'],hashlib.sha256(raw).hexdigest())
    def test_no_global_prefix_rewrite_or_source_patch(self):
        text=(H/'Y_resume002.py').read_text(encoding='utf-8')
        self.assertNotIn('hashlisha256',text);self.assertIn('hashlib.sha256',text)
        self.assertNotIn('initial-pool.patch',text);self.assertIn("'build','--locked','--release','-j','4'",text)
        self.assertIn('Source',text.replace('source','Source'))
if __name__=='__main__':unittest.main()
