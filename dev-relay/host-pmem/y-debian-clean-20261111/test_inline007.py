"""Exercise the inline path without network, subprocesses, credentials or root."""
import ast,base64,contextlib,datetime,hashlib,io,json,os,pathlib,tempfile,types,unittest
H=pathlib.Path(__file__).resolve().parent
SOURCE=(H/'Y_debian_inline_entry007.py').read_text(encoding='utf-8')
tree=ast.parse(SOURCE)
FUNCTIONS=ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('validate','run_task')],type_ignores=[])
CODE=compile(FUNCTIONS,'<inline-entry-functions>','exec')
sha=lambda raw:hashlib.sha256(raw).hexdigest()
wire=lambda value:json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def need(ok,reason):
    if not ok:raise RuntimeError(reason)
class InlineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name);self.root.joinpath('jobs').mkdir()
        self.job=json.loads((H/'debian-runtime006-publication.private.json').read_text(encoding='utf-8'))['jobs'][0]
        self.job={**self.job,'rootEntrySha256':sha(SOURCE.encode())}
        self.job['sourceInlineBase64']=base64.b64encode((H/'Y_sdk_runtime005_bound.py').read_bytes()).decode()
        self.started=[];self.reports=[]
        def fake_popen(*args,**kwargs):
            self.started.append(args)
            return types.SimpleNamespace(returncode=0,poll=lambda:0)
        def forbidden_run(*args,**kwargs):raise AssertionError('Git or another subprocess.run was invoked')
        fake_os=types.SimpleNamespace(**{name:getattr(os,name) for name in dir(os)})
        fake_os.O_NOFOLLOW=getattr(os,'O_NOFOLLOW',0)
        self.env={'STATE':self.root,'SESSION':self.job['sessionId'],'Path':pathlib.Path,'need':need,'sha':sha,'wire':wire,
          'json':json,'base64':base64,'hashlib':hashlib,'os':fake_os,'re':__import__('re'),'time':__import__('time'),
          'API':types.SimpleNamespace(timestamp=lambda s:datetime.datetime.fromisoformat(s).timestamp(),redact=lambda raw,tokens:raw),
          'child_environment':lambda x:{},'subprocess':types.SimpleNamespace(Popen=fake_popen,run=forbidden_run,DEVNULL=-3),
          'save':lambda path,value:path.write_bytes(wire(value)),
          'read':lambda path,limit=0:path.read_bytes(),
          'mkdir':lambda path:path.mkdir(exist_ok=True),
          'publish_report':lambda client,node,job,report:self.reports.append(report)}
        self.env['fetch']=lambda client,path:{'node':self.job['node'],'sessionId':self.job['sessionId'],'mode':'manual','stop':False,'jobIds':[self.job['jobId']]} if '/queues/' in path else self.job
        exec(CODE,self.env)
    def tearDown(self):self.temp.cleanup()
    def run_task(self):
        with contextlib.redirect_stdout(io.StringIO()):self.env['run_task'](types.SimpleNamespace(token='control-placeholder'),types.SimpleNamespace(token='result-placeholder'),self.job['node'],self.job['identity'],self.job['rootEntrySha256'])
    def test_unchanged_worker_runs_without_git(self):
        self.run_task();self.assertEqual(len(self.started),1);self.assertEqual(self.reports[0]['exitCode'],0)
        self.assertEqual((self.root/'jobs'/self.job['jobId']/'task.py').read_bytes(),(H/'Y_sdk_runtime005_bound.py').read_bytes())
    def test_changed_worker_rejected_before_execution(self):
        self.job['sourceInlineBase64']=base64.b64encode(b'changed').decode()
        with self.assertRaisesRegex(RuntimeError,'Pinned Python source differs'):self.run_task()
        self.assertEqual(self.started,[])
    def test_oversized_body_rejected(self):
        self.job['sourceInlineBase64']='A'*349529
        with self.assertRaisesRegex(RuntimeError,'exceeds bound'):self.run_task()
        self.assertEqual(self.started,[])
    def test_wrong_entry_pin_rejected(self):
        self.job['rootEntrySha256']='0'*64
        with self.assertRaisesRegex(RuntimeError,'Task entry binding differs'):
            self.env['validate'](self.job,self.job['identity'],self.job['node'],sha(SOURCE.encode()))
    def test_unknown_prior_execution_never_retried(self):
        folder=self.root/'jobs'/self.job['jobId'];folder.mkdir();(folder/'state.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError,'Unknown prior outcome'):self.run_task()
        self.assertEqual(self.started,[])
    def test_upgrade_transform_is_exact_idempotent_and_rejects_unknown(self):
        installer=ast.parse((H/'Y_upgrade_inline007.py').read_text(encoding='utf-8'))
        nodes=[n for n in installer.body if isinstance(n,ast.Assign) or isinstance(n,ast.FunctionDef) and n.name=='transform']
        namespace={'hashlib':hashlib};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<upgrade-transform>','exec'),namespace)
        original=(H/'Y_debian_clean_entry.py').read_bytes();updated=(H/'Y_debian_inline_entry007.py').read_bytes()
        self.assertEqual(namespace['transform'](original),updated)
        self.assertEqual(namespace['transform'](updated),updated)
        with self.assertRaisesRegex(AssertionError,'Entry differs'):namespace['transform'](b'unrecognized entry')
if __name__=='__main__':unittest.main()
