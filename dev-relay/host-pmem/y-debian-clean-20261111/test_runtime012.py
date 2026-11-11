import ast,pathlib,unittest
H=pathlib.Path(__file__).resolve().parent
tree=ast.parse((H/'Y_start_runtime012.py').read_text(encoding='utf-8'))
node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='reset_failed_proxies')
scope={};exec(compile(ast.Module(body=[node],type_ignores=[]),'<proxy-state>','exec'),scope)
class ProxyStateTests(unittest.TestCase):
    def run_state(self,code,state):
        calls=[]
        scope['reset_failed_proxies'](lambda args:{'code':code,'stdout':state+'\n'},lambda args:calls.append(args),['own.service'])
        return calls
    def test_unloaded_inactive_needs_no_reset(self):self.assertEqual(self.run_state(4,'inactive'),[])
    def test_loaded_inactive_needs_no_reset(self):self.assertEqual(self.run_state(0,'inactive'),[])
    def test_failed_resets_only_named_unit(self):self.assertEqual(self.run_state(0,'failed'),[['systemctl','reset-failed','own.service']])
    def test_active_preserved(self):
        with self.assertRaises(AssertionError):self.run_state(0,'active')
    def test_query_error_stops(self):
        with self.assertRaises(AssertionError):self.run_state(1,'inactive')
    def test_empty_state_stops(self):
        with self.assertRaises(AssertionError):self.run_state(4,'')
if __name__=='__main__':unittest.main()
