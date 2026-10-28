import ast,importlib.util,unittest
from pathlib import Path
P=Path(__file__).with_name('AB_inspect_graceful_close_v1.py')
spec=importlib.util.spec_from_file_location('close_inspect',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Scope(unittest.TestCase):
    def test_journal_summary_excludes_private_plan_and_keeps_pending(self):
        source={'phase':'active','plan':{'private':'payload'},'groups':{'original':{'phase':'restoring','cases':{'0':{'sandboxIds':[],
            'openRequests':[{'id':'request','kind':'create'}],'outcomeUncertain':True,'runtimeContext':{'secret':'omit'}}}}}}
        out=m.request_summary(source)
        self.assertNotIn('plan',out);self.assertNotIn('runtimeContext',out['groups']['original']['cases']['0'])
        self.assertTrue(out['groups']['original']['cases']['0']['outcomeUncertain'])
    def test_inactive_service_not_probed(self):
        self.assertEqual(m.inventory(Path('/unused'),{'MainPID':'0','ActiveState':'inactive'})['reason'],'unit not active')
    def test_no_control_mutation_or_service_stop(self):
        source=P.read_text();tree=ast.parse(source)
        self.assertIn("{'operation':'status'}",source)
        for forbidden in ("{'operation':'retire'",'SIGKILL','SIGTERM','systemctl stop','systemctl restart','drop_caches','modprobe','rmmod'):
            self.assertNotIn(forbidden,source)
        requests=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='request']
        self.assertEqual(len(requests),1);self.assertEqual(ast.literal_eval(requests[0].args[0]),'GET')
if __name__=='__main__':unittest.main()
