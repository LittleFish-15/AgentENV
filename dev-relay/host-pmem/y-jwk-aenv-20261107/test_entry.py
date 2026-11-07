"""Protocol regression checks against the generated native Y entry; no remote execution."""
import ast,copy,datetime,importlib.util,json,os,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
H=Path(__file__).resolve().parent
if sys.platform=='win32':
    sys.modules.setdefault('fcntl',types.SimpleNamespace(LOCK_EX=2,LOCK_NB=4,flock=lambda *a:None))
spec=importlib.util.spec_from_file_location('y_entry_under_test',H/'Y_root_entry_v1.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
class Validation(unittest.TestCase):
    def setUp(self):
        self.current={'hostname':'fixture','machineId':'fixture-machine','bootId':'fixture-boot','kernel':'fixture-kernel','architecture':'x86_64'}
        self.pin='c'*64
        self.job={'schema':1,'sessionId':e.SESSION,'node':'node-y','jobId':'y-test-001','identity':self.current.copy(),
          'rootEntrySha256':self.pin,'humanApproved':True,'scope':'read-only-diagnosis',
          'notBefore':'2026-01-01T00:00:00+00:00','expiresAt':'2099-01-01T00:00:00+00:00',
          'entry':{'repo':'LittleFish-15/AgentENV','path':'dev-relay/host-pmem/y-jwk-aenv-20261107/fixture.py',
                   'commit':'a'*40,'blob':'b'*40,'sha256':'d'*64,'bytes':100},'seconds':20,'argv':[]}
    def valid(self): e.validate(self.job,self.current,'node-y',self.pin)
    def denied(self):
        with self.assertRaises(RuntimeError):self.valid()
    def test_accept_exact_binding(self):self.valid()
    def test_boot_change(self):self.job['identity']['bootId']='other';self.denied()
    def test_node_change(self):self.job['node']='node-a';self.denied()
    def test_entry_change(self):self.job['rootEntrySha256']='0'*64;self.denied()
    def test_no_authorization(self):self.job['humanApproved']=False;self.denied()
    def test_expired(self):self.job['expiresAt']='2020-01-01T00:00:00+00:00';self.denied()
    def test_not_yet_valid(self):self.job['notBefore']='2099-01-01T00:00:00+00:00';self.denied()
    def test_other_repository(self):self.job['entry']['repo']='other/repo';self.denied()
    def test_path_escape(self):self.job['entry']['path']='dev-relay/host-pmem/../unreviewed.py';self.denied()
    def test_unreviewed_location(self):self.job['entry']['path']='anything/run.py';self.denied()
    def test_unbounded_runtime(self):self.job['seconds']=10801;self.denied()
    def test_unbounded_source(self):self.job['entry']['bytes']=256*1024+1;self.denied()
    def test_no_secrets_in_task_env(self):
        env=e.child_environment({'GITHUB_TOKEN':'secret','E2B_API_KEY':'secret','CONTROL_TOKEN':'secret','NO_PROXY':'127.0.0.1'})
        self.assertFalse(any(k in env for k in ('GITHUB_TOKEN','E2B_API_KEY','CONTROL_TOKEN')))
        self.assertEqual(env['NO_PROXY'],'127.0.0.1')
    def test_y_isolation(self):
        self.assertEqual(e.SESSION,'y-aenv-20261107-v1')
        self.assertEqual(str(e.ROOT).replace('\\','/'),'/home/jwk/y-aenv-control')
    def test_bootstrap_hash(self):
        self.assertEqual(e.BOOTSTRAP['sha256'],e.sha((H/'Y_inventory_v1.py').read_bytes()))
    def test_exit_and_process_group_guards(self):
        source=(H/'Y_root_entry_v1.py').read_text()
        self.assertIn('start_new_session=True',source)
        self.assertIn('os.killpg(p.pid,signal.SIGKILL)',source)
        self.assertIn("need(report.get('state')=='completed' and report.get('exitCode')==0",source)
        self.assertIn("raise RuntimeError('Unknown prior outcome; no retry')",source)
    def test_config_drops_sensitive_fields(self):
        tree=ast.parse((H/'Y_inventory_v1.py').read_text())
        selected=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('file_info','safe_config') or isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='SAFE_KEYS' for x in n.targets)]
        import tempfile,tomllib
        ns={'P':Path,'stat':__import__('stat'),'tomllib':tomllib,'hashlib':__import__('hashlib'),'call':lambda a:None}
        exec(compile(ast.Module(body=selected,type_ignores=[]),'<inventory-functions>','exec'),ns)
        with tempfile.TemporaryDirectory(dir=H) as d:
            p=Path(d)/'config.toml';p.write_text('api_key="fixture-secret"\n[pool]\nlow_watermark=300\nhigh_watermark=1000\n[auth]\npath="fixture-secret-path"\n')
            result=ns['safe_config'](p)
            self.assertEqual(result['selected_values'],{'pool.low_watermark':300,'pool.high_watermark':1000})
            self.assertNotIn('fixture-secret',json.dumps(result))
if __name__=='__main__':unittest.main()
