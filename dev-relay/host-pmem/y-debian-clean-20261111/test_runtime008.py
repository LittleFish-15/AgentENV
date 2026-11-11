"""Check device-ownership boundaries without privileges or device operations."""
import ast,contextlib,hashlib,io,json,pathlib,stat,types,unittest
H=pathlib.Path(__file__).resolve().parent
source=(H/'device_broker008.py').read_text(encoding='utf-8')
nodes=[n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name in ('signature','process','grant')]
CODE=compile(ast.Module(body=nodes,type_ignores=[]),'<broker-functions>','exec')
class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.uid=1002;self.binary=b'verified-own-daemon';self.calls=[];self.closed=[];self.status_uid=1002;self.group='/system.slice/own.service';self.bad_binary=False
        outer=self
        class Proc:
            def __init__(self,path):self.path=path
            def __truediv__(self,name):return Proc(self.path+'/'+name)
            def read_text(self):
                if self.path.endswith('/status'):return 'Uid:\t'+'\t'.join([str(outer.status_uid)]*4)+'\n'
                if self.path.endswith('/cgroup'):return '0::'+outer.group+'\n'
                if self.path.endswith('/stat'):return '123 (daemon) '+' '.join(['S']+['0']*18+['456'])
                raise AssertionError(self.path)
            def stat(self):return types.SimpleNamespace(st_dev=1,st_ino=7,st_size=19,st_mtime_ns=200)
            def open(self,mode):return io.BytesIO(b'other-daemon' if outer.bad_binary else outer.binary)
        fake_pathlib=types.SimpleNamespace(Path=lambda *parts:Proc('/'.join(map(str,parts))))
        self.env={'UID':1002,'CGROUP':'/system.slice/own.service','DAEMON_SHA':hashlib.sha256(self.binary).hexdigest(),
          'VERIFIED':{},'pathlib':fake_pathlib,'hashlib':hashlib,'re':__import__('re'),'json':json,'stat':stat,
          'ROOT':pathlib.PurePosixPath('/run/own'),'ctypes':types.SimpleNamespace(CDLL=lambda *a,**kw:types.SimpleNamespace(fchownat=lambda *args:self.calls.append(args) or 0),c_uint=lambda x:x)}
        exec(CODE,self.env)
    def test_process_requires_own_uid(self):
        self.status_uid=0
        with self.assertRaises(AssertionError):self.env['process'](123)
    def test_process_requires_own_cgroup(self):
        self.group='/system.slice/other.service'
        with self.assertRaises(AssertionError):self.env['process'](123)
    def test_process_requires_verified_daemon(self):
        self.bad_binary=True
        with self.assertRaises(AssertionError):self.env['process'](123)
    def test_process_accepts_exact_owned_daemon(self):self.assertEqual(self.env['process'](123),'456')
    def grant(self,race=False,excluded=False):
        old=types.SimpleNamespace(st_dev=1,st_ino=55,st_rdev=100,st_uid=0,st_mode=stat.S_IFCHR|0o600)
        new=types.SimpleNamespace(st_dev=1,st_ino=56,st_rdev=100,st_uid=0,st_mode=stat.S_IFCHR|0o600)
        class Node:
            name='ublkc10'
            def __init__(self):self.calls=0
            def lstat(self):self.calls+=1;return new if race and self.calls>1 else old
        self.env['os']=types.SimpleNamespace(open=lambda *a:9,fstat=lambda fd:old,close=lambda fd:self.closed.append(fd),O_PATH=0,O_NOFOLLOW=0,O_CLOEXEC=0)
        self.env['process']=lambda pid:'456'
        self.env['subprocess']=types.SimpleNamespace(run=lambda *a,**kw:types.SimpleNamespace(returncode=0,stdout=json.dumps({'id':10,'pid':123})))
        with contextlib.redirect_stdout(io.StringIO()):return self.env['grant'](Node(),{(1,55,100)} if excluded else set())
    def test_original_device_never_opened_or_granted(self):
        self.assertFalse(self.grant(excluded=True));self.assertEqual(self.calls,[]);self.assertEqual(self.closed,[])
    def test_device_inode_reuse_never_granted(self):
        with self.assertRaises(AssertionError):self.grant(race=True)
        self.assertEqual(self.calls,[]);self.assertEqual(self.closed,[9])
    def test_verified_inode_granted_without_changing_group(self):
        self.assertTrue(self.grant());self.assertEqual(self.calls,[(9,b'',1002,0xffffffff,0x1000)]);self.assertEqual(self.closed,[9])
if __name__=='__main__':unittest.main()
