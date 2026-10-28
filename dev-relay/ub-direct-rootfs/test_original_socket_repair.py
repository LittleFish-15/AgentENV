import ast,importlib.util,types,unittest,tomllib
from pathlib import Path,PurePosixPath
from unittest.mock import patch
P=Path(__file__).with_name('B_repair_original_socket_path_v1.py')
spec=importlib.util.spec_from_file_location('repair',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Repair(unittest.TestCase):
    def config(self):return b'home_path = "/home/jwk/agent/deployments/agentenv-ae9c626-baseline/state"\n[firecracker]\nbinary_path = "/fixed/original/fc"\n[ublk]\ndaemon_binary_path = "/fixed/original/daemon"\n'
    def test_long_path_and_short_path_budgets_and_only_deployment_fields(self):
        with patch.object(m,'ROOT',PurePosixPath('/home/jwk/agent')),patch.object(m,'BASE',PurePosixPath('/home/jwk/agent/deployments/agentenv-ae9c626-baseline')):
            new,short,logs,counts=m.configured(self.config())
        self.assertEqual(counts['oldSocketPathBytes'],114);self.assertLessEqual(counts['newSocketPathBytes'],107)
        parsed=tomllib.loads(new.decode());old=tomllib.loads(self.config().decode())
        self.assertEqual(parsed['ublk'],old['ublk']);self.assertEqual(parsed['firecracker']['binary_path'],old['firecracker']['binary_path'])
        self.assertEqual(parsed['firecracker']['log_level'],'Error')
    def test_existing_work_override_is_not_silently_changed(self):
        with self.assertRaisesRegex(RuntimeError,'overrides'):m.configured(self.config().replace(b'[firecracker]',b'[firecracker]\nwork_dir="/other"'))
    def test_no_api_post_delete_no_module_or_force_signals(self):
        source=P.read_text();tree=ast.parse(source)
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='api']
        self.assertTrue(calls);self.assertTrue(all(ast.literal_eval(n.args[0])=='GET' for n in calls))
        for text in ('SIGKILL','modprobe','rmmod','drop_caches','delete_dev','os.kill'):self.assertNotIn(text,source)
    def test_restart_wait_checks_new_identity_health_and_inventory(self):
        old={'pid':1};new={'pid':2};calls=[]
        props={'MainPID':'2','ActiveState':'active','Job':''}
        with patch.object(m.subprocess,'run',side_effect=lambda argv,**kw:(calls.append(argv) or types.SimpleNamespace(returncode=0))),\
             patch.object(m,'properties',return_value=props),patch.object(m,'identity',return_value=new),\
             patch.object(m,'api',side_effect=lambda method,path:(204,None) if path=='/health' else (200,[])):
            result=m.restart_and_wait(old)
        self.assertEqual(result,props);self.assertEqual(calls,[['systemctl','restart','--no-block',m.UNIT]])
    def test_unchanged_process_does_not_pass_restart(self):
        old={'pid':1};clock=iter((0,1,2,3,4,130))
        with patch.object(m.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)),\
             patch.object(m,'properties',return_value={'MainPID':'1','ActiveState':'active','Job':''}),\
             patch.object(m,'identity',return_value=old),patch.object(m,'api') as api,\
             patch.object(m.time,'monotonic',side_effect=lambda:next(clock)),patch.object(m.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'not confirmed'):m.restart_and_wait(old)
        api.assert_not_called()
if __name__=='__main__':unittest.main()
