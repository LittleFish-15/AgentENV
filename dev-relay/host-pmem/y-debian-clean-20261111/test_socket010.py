"""Regression: socket activation must not stat a protected jwk home path."""
import ast,asyncio,contextlib,io,json,pathlib,types,unittest
H=pathlib.Path(__file__).resolve().parent
class SocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_activated_socket_disables_path_cleanup_without_home_access(self):
        source=(H/'auth_proxy010.py').read_text(encoding='utf-8');tree=ast.parse(source)
        main=next(n for n in tree.body if isinstance(n,ast.AsyncFunctionDef) and n.name=='main')
        calls=[]
        class Cred:
            def __init__(self,name=''):self.name=name
            def __truediv__(self,name):return Cred(name)
            def read_text(self):return json.dumps({'client_uid':1002})
            def stat(self):raise AssertionError('Filesystem stat is forbidden in this test')
        class Listener:
            def setblocking(self,value):calls.append(('blocking',value))
        class Server:
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
            async def serve_forever(self):calls.append(('serve',True))
        async def start_server(callback,**kwargs):
            self.assertIs(kwargs.get('cleanup_socket'),False)
            self.assertEqual(set(kwargs),{'sock','cleanup_socket'});return Server()
        def require(ok,message):
            if not ok:raise RuntimeError(message)
        namespace={'os':types.SimpleNamespace(geteuid=lambda:65001,getpid=lambda:123,environ={'LISTEN_PID':'123','LISTEN_FDS':'1','CREDENTIALS_DIRECTORY':'protected'}),
          'pathlib':types.SimpleNamespace(Path=Cred),'json':json,'require':require,'socket':types.SimpleNamespace(socket=lambda **kwargs:Listener()),
          'asyncio':types.SimpleNamespace(start_unix_server=start_server)}
        exec(compile(ast.Module(body=[main],type_ignores=[]),'<proxy-main>','exec'),namespace)
        with contextlib.redirect_stdout(io.StringIO()):await namespace['main']()
        self.assertEqual(calls,[('blocking',False),('serve',True)])
if __name__=='__main__':unittest.main()
