import ast, hashlib, importlib.util, json, unittest, tempfile, os
from unittest.mock import patch
from pathlib import Path

HERE=Path(__file__).resolve().parent
def load(name):
    s=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('cow55_replay');root=load('cow55_memlock_repair')

class Recovery(unittest.TestCase):
    def setUp(self):
        self.build={'original_identity':[2464930,'24073603'],'cases':['preserved']}
        self.raw=json.dumps({'run_id':'323ff7550463486f89ebf66264d39257','status':'STOPPED_COW55_REPLAY','replay_completed_guests':0}).encode()
        self.receipt={'revision':'cow55-original-memlock-repair-v1','status':'A_ORIGINAL_MEMLOCK_RESTART_VERIFIED',
            'unit':'jwk-aenv-ae9c626-node-a.service','new_limit_bytes':2147483648,
            'previous_run_id':'323ff7550463486f89ebf66264d39257','previous_pending_sha256':hashlib.sha256(self.raw).hexdigest(),
            'original_before':[2464930,'24073603'],'original_after':[3000000,'99999999']}
    def test_copy_preserves_historical_build_identity(self):
        result=m.repaired_build(self.build,self.raw,self.receipt)
        self.assertEqual(self.build['original_identity'],[2464930,'24073603'])
        self.assertEqual(result['original_identity'],[3000000,'99999999'])
        self.assertEqual(result['cases'],self.build['cases'])
    def test_wrong_unit_limit_status_or_identity_rejected(self):
        for key,value in [('unit','other.service'),('status','RESTART_SUBMITTED'),('new_limit_bytes',-1),
                          ('original_after',self.build['original_identity']),('original_before',[12,'34']),('previous_run_id','other')]:
            with self.subTest(key=key),self.assertRaises(RuntimeError):m.repaired_build(self.build,self.raw,dict(self.receipt,**{key:value}))
    def test_changed_receipt_rejected(self):
        with self.assertRaises(RuntimeError):m.repaired_build(self.build,self.raw+b' ',self.receipt)
    def test_started_replay_not_reclassified(self):
        raw=json.dumps(dict(json.loads(self.raw),replay_completed_guests=1)).encode()
        with self.assertRaises(RuntimeError):m.repaired_build(self.build,raw,dict(self.receipt,previous_pending_sha256=hashlib.sha256(raw).hexdigest()))
    def test_root_script_is_inline_and_bounded(self):
        tree=ast.parse(root.ROOT_SOURCE)
        commands=[n.args[0] for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='run']
        self.assertEqual(len(commands),3)
        self.assertEqual(ast.literal_eval(commands[1]),['/usr/bin/systemctl','daemon-reload'])
        self.assertEqual(commands[2].elts[1].value,'restart')
        self.assertEqual(commands[2].elts[2].id,'UNIT')
        self.assertNotIn('exec(',root.ROOT_SOURCE)
        self.assertNotIn('prlimit(',root.ROOT_SOURCE)
        self.assertIn('Fresh daemon not verified',root.ROOT_SOURCE)
    def test_published_receipt_readable_but_not_publicly_writable(self):
        tree=ast.parse(root.ROOT_SOURCE)
        save=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='save')
        mkdir=os.mkdir
        # Windows sandbox fixtures must inherit the workspace ACL; production
        # root receipt mode is checked independently below.
        with patch.object(os,'mkdir',side_effect=lambda p,mode=0o777,**kw:mkdir(p,0o755 if os.name=='nt' else mode,**kw)), tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            path=Path(tmp)/'receipt.json';value={'status':'fixture_nonsecret'}
            scope={'RECEIPT':path,'result':value,'json':json,'os':os}
            exec(compile(ast.Module(body=[save],type_ignores=[]),'<save-function-test>','exec'),scope)
            with patch.object(os,'chmod',wraps=os.chmod) as chmod:
                scope['save']()
            chmod.assert_called_once_with(path.with_suffix('.tmp'),0o644)
            self.assertEqual(json.loads(path.read_text()),value)
            self.assertFalse(path.with_suffix('.tmp').exists())

if __name__=='__main__':unittest.main()
