import ast,importlib.util,json,stat,struct,types,unittest
from pathlib import Path,PurePosixPath
from unittest.mock import patch
HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('cohort',HERE/'layoutfix_cohort.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class SocketPath:
    def __truediv__(self,part):return self
    def resolve(self,strict=True):return self
    def stat(self):return types.SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=1204)
    def __str__(self):return '/scoped/firecracker.socket'
class Layout(unittest.TestCase):
    def source(self):return (HERE/'prepare_original_measurement_template_v3.py').read_text()
    def test_missing_target_directories_are_not_readonly_prerequisites(self):
        tree=ast.parse(self.source());loop=next(n for n in ast.walk(tree) if isinstance(n,ast.For) and isinstance(n.iter,ast.Tuple)
                  and any(isinstance(x,ast.Name) and x.id=='src' for x in n.iter.elts))
        src=PurePosixPath('/source');repo=PurePosixPath('/baseline')
        required=eval(compile(ast.Expression(loop.iter),'<required-existing-dirs>','eval'),{'src':src,'repo':repo})
        self.assertNotIn(repo/'managed-layers',required);self.assertNotIn(repo/'snapshots',required)
        self.assertIn(src/'managed-layers',required)
    def test_all_new_directory_creation_is_after_durable_intent(self):
        s=self.source();begin=s.index("pipeline.put(receipt_dir/'intent.json'")
        self.assertLess(begin,s.index('if not p.exists():p.mkdir'))
        self.assertIn("'directoriesToCreate':[str(p) for p in target_directories if not p.exists()]",s)
        self.assertLess(s.index('if not p.exists():p.mkdir'),s.index('os.link(p,repo/name'))
    def test_original_default_fc_work_path_matches_original_source(self):
        tree=ast.parse((HERE/'layoutfix_comparison_body.py').read_text())
        assignment=next(n for n in ast.walk(tree) if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Subscript)
                        and isinstance(n.targets[0].slice,ast.Constant) and n.targets[0].slice.value=='fcWorkDir')
        expr=compile(ast.Expression(assignment.value),'<actual-path-resolution>','eval')
        value=eval(expr,{'Path':PurePosixPath,'config':{'home_path':'/baseline/state','firecracker':{}}})
        self.assertEqual(value,'/baseline/state/firecracker-work')
        value=eval(expr,{'Path':PurePosixPath,'config':{'home_path':'/baseline/state','firecracker':{'work_dir':'/fixed/work'}}})
        self.assertEqual(value,'/fixed/work')
    def request(self,peer_pid=42,status=200,body=None):
        import socket,http.client
        client=types.SimpleNamespace(settimeout=lambda *a:None,connect=lambda *a:None,close=lambda:None,
          getsockopt=lambda *a:struct.pack('3i',peer_pid,1204,1205))
        calls=[];response=types.SimpleNamespace(status=status,read=lambda size:body or b'{"instanceID":"00000000-0000-0000-0000-000000000001","accessTokenHash":"do-not-export"}')
        connection=types.SimpleNamespace(request=lambda *a:calls.append(a),getresponse=lambda:response,close=lambda:None)
        with patch.object(socket,'AF_UNIX',1,create=True),patch.object(socket,'socket',return_value=client),patch.object(socket,'SO_PEERCRED',17,create=True),patch.object(http.client,'HTTPConnection',return_value=connection):
            result=m.fc_sandbox_identity(SocketPath(),42)
        return result,calls
    def test_no_log_required_exact_peer_mmds_returns_only_id(self):
        sid,calls=self.request();self.assertEqual(calls,[('GET','/mmds')]);self.assertEqual(sid,'00000000-0000-0000-0000-000000000001')
    def test_wrong_unix_peer_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'peer process'):self.request(peer_pid=43)
    def test_missing_identity_or_bad_response_rejected(self):
        with self.assertRaises(RuntimeError):self.request(status=500)
        with self.assertRaises(RuntimeError):self.request(body=b'{}')
if __name__=='__main__':unittest.main()
