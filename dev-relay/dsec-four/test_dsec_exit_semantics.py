"""Exercise the CLI final status with successful replay but failed reporting."""
import contextlib, importlib.util, io, json, stat, sys, types, unittest
from pathlib import Path
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('exit_packet',HERE/'A_dsec_four_v5.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class ExitStatus(unittest.TestCase):
    def run_cli(self,report_fails):
        writes=[];requests=[]
        result={'status':'NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED','ownedGuestsReleased':True}
        batch=types.SimpleNamespace(stop=types.SimpleNamespace(set=lambda:None),wait_observer=lambda:None,
            run_replay=lambda:result,observer_request=lambda *a:requests.append(a),
            rt=types.SimpleNamespace(save=lambda path,value:writes.append((path.name,value))))
        def report(scope):
            if report_fails:raise RuntimeError('Injected derived report failure')
            return 0
        fakefcntl=types.SimpleNamespace(flock=lambda *a:None,LOCK_EX=1,LOCK_NB=2)
        with contextlib.ExitStack() as stack:
            for target,name,value,create in ((m.sys,'argv',['entry','replay'],False),(m.sys,'platform','linux',False),
                (m.os,'uname',lambda:types.SimpleNamespace(machine='aarch64'),True),(m.socket,'gethostname',lambda:'server1',False),
                (m.os,'getuid',lambda:1204,True),(m.os,'geteuid',lambda:1204,True),(m.os,'umask',lambda x:None,False),
                (m.os,'open',lambda *a,**k:88,False),(m.os,'close',lambda *a:None,False),
                (m.os,'fstat',lambda fd:types.SimpleNamespace(st_mode=stat.S_IFREG,st_uid=1204),False),
                (m.os,'O_NOFOLLOW',0,True),(m.os,'O_CLOEXEC',0,True),(m.signal,'signal',lambda *a:None,False),
                (m.signal,'SIGHUP',1,True),(m,'build_run',lambda args:batch,False),
                (m,'module',lambda name:types.SimpleNamespace(report=report),False)):
                stack.enter_context(patch.object(target,name,value,create=create))
            stack.enter_context(patch.dict(sys.modules,{'fcntl':fakefcntl}))
            stack.enter_context(patch.object(Path,'exists',return_value=True))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code=m.main()
        return code,writes,requests,result

    def test_reporting_failure_returns_nonzero_without_replaying_or_hiding_cleanup(self):
        code,writes,requests,result=self.run_cli(True)
        self.assertEqual(code,1)
        self.assertTrue(result['ownedGuestsReleased'])
        self.assertFalse(result['reportGenerationPassed'])
        self.assertEqual([name for name,_ in writes],['report-generation-stop.json'])
        self.assertEqual(requests,[('owner_finished',[])])

    def test_replay_and_report_success_returns_zero(self):
        code,writes,requests,result=self.run_cli(False)
        self.assertEqual(code,0);self.assertFalse(writes)
        self.assertTrue(result['reportGenerationPassed'])


if __name__=='__main__':unittest.main()
