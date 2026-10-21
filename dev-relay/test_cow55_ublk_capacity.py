import ast, importlib.util, unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('capacity',Path(__file__).with_name('cow55_ublk_capacity.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
tree=ast.parse(m.ROOT_SOURCE)
functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('need','require_quiescent','perform_maintenance')]
scope={};exec(compile(ast.Module(body=functions,type_ignores=[]),'<reviewed-maintenance-functions>','exec'),scope)

class CapacityMaintenance(unittest.TestCase):
    def run_flow(self,state=None,fail=None):
        calls=[]
        def op(name,result=None):
            def invoke():
                calls.append(name)
                if fail==name:raise RuntimeError(name+' failed')
                return result
            return invoke
        state=state or {'loaded':True,'refcnt':0,'holders':[],'char_devices':[],'block_devices':[]}
        try:
            scope['perform_maintenance'](op('stop'),op('inspect',state),op('unload'),op('load256'),op('verify'),op('recover'))
            return calls,None
        except Exception as e:return calls,e
    def test_success_orders_recovery_before_completion(self):
        calls,error=self.run_flow();self.assertIsNone(error)
        self.assertEqual(calls,['stop','inspect','unload','load256','verify','recover'])
    def test_unknown_character_devices_prevent_unload(self):
        calls,error=self.run_flow({'loaded':True,'refcnt':0,'holders':[],'char_devices':['ublkc15'],'block_devices':[]})
        self.assertIsNotNone(error);self.assertEqual(calls,['stop','inspect','recover'])
    def test_reference_holder_or_block_prevents_unload(self):
        for key,value in [('refcnt',1),('holders',['other']),('block_devices',['ublkb0'])]:
            state={'loaded':True,'refcnt':0,'holders':[],'char_devices':[],'block_devices':[]};state[key]=value
            calls,error=self.run_flow(state)
            with self.subTest(key=key):self.assertIsNotNone(error);self.assertNotIn('unload',calls);self.assertEqual(calls[-1],'recover')
    def test_stop_unload_load_or_verify_failure_attempts_recovery(self):
        for phase in ('stop','unload','load256','verify'):
            with self.subTest(phase=phase):
                calls,error=self.run_flow(fail=phase);self.assertIsNotNone(error);self.assertEqual(calls[-1],'recover')
                self.assertEqual(calls.count('stop'),1);self.assertLessEqual(calls.count('unload'),1)
    def test_failed_recovery_is_not_success(self):
        calls,error=self.run_flow(fail='recover');self.assertIn('Recovery requires review',str(error))
    def test_no_force_or_other_service_stop(self):
        lists=[n for n in ast.walk(tree) if isinstance(n,ast.List)]
        unit_changes=[]
        for n in lists:
            if len(n.elts)>1 and isinstance(n.elts[0],ast.Name) and n.elts[0].id=='SYSTEMCTL' and isinstance(n.elts[1],ast.Constant) and n.elts[1].value in ('start','stop','restart'):
                unit_changes.append((n.elts[1].value,n.elts[2].id))
        self.assertEqual(sorted(unit_changes),[('start','UNIT'),('stop','UNIT')])
        self.assertNotIn("'--force'",m.ROOT_SOURCE);self.assertNotIn("'-f'",m.ROOT_SOURCE)
        self.assertNotIn('os.chown',m.ROOT_SOURCE);self.assertNotIn('os.setxattr',m.ROOT_SOURCE)
    def test_receipt_public_read_mode_and_unit_retention(self):
        self.assertIn('os.chmod(tmp,0o644)',m.ROOT_SOURCE)
        self.assertIn("retained=Path('/run/systemd/system')/UNIT",m.ROOT_SOURCE)
        self.assertIn("need(read_file(retained,0,65536)==fragment_bytes",m.ROOT_SOURCE)
        self.assertIn("'module_unload_requests':0",m.ROOT_SOURCE)
    def test_printed_root_program_parses(self):
        ast.parse(m.ROOT_SOURCE)

if __name__=='__main__':unittest.main()
