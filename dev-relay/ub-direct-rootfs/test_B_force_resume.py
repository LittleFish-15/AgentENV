import base64,copy,importlib.util,json,sys,types,unittest,uuid,zlib
from pathlib import Path
HERE=Path(__file__).parent
if sys.platform=='win32':sys.modules['fcntl']=types.ModuleType('fcntl')
scope={'__name__':'test_resume'}
exec(compile((HERE/'B_force_resume_deletefix_v1.py').read_bytes(),'<B force packet>','exec'),scope)
raw=zlib.decompress(base64.b64decode(scope['ORIGINAL_Z64']))
old=types.ModuleType('original');old.__file__='<original>';exec(compile(raw,old.__file__,'exec'),old.__dict__)
exec(compile(scope['FINISH_SOURCE'],'<finish>','exec'),old.__dict__)

class ResumeTests(unittest.TestCase):
    def prior(self):
        return {'node':'b','status':'STOPPED_B_RECOVERY_PRESERVE_STATE',
         'reason':'B old processes/cgroup did not exit; no forced kill or deployment','deleteIntents':[],
         'signalIntents':[{'role':'old-server','pid':2723514,'signal':'SIGTERM'}],
         'oldServer':{'startTicks':'62254196'},'oldDaemon':{'startTicks':'62254283'}}
    def test_exact_timeout_allowed(self):self.assertTrue(scope['reviewed_timeout'](self.prior()))
    def test_other_partial_actions_rejected(self):
        for change in ({'node':'a'},{'deleteIntents':[0]},{'stageIntent':'anything'},{'signalIntents':[]},{'status':'done'}):
            value=self.prior();value.update(change);self.assertFalse(scope['reviewed_timeout'](value))
    def test_remaining_main_pid_blocks_all_post_exit_work(self):
        runtime=types.SimpleNamespace(m=types.SimpleNamespace(UNIT='old',properties=lambda unit:{'MainPID':'2723514'}))
        with self.assertRaises(RuntimeError):old.finish(runtime,{},None,None,{},None,None,b'',{}, {},'new',None,b'',None)
    def test_post_exit_staging_with_proxy_already_gone(self):
        work=(HERE/('force-resume-test-'+uuid.uuid4().hex)).resolve();work.mkdir();old.WORK=work
        old.residual_chars=lambda captured:[]
        provider={'id':'fixture'};units={'unchanged':True};calls=[]
        runtime=types.SimpleNamespace(m=types.SimpleNamespace(UNIT='old',properties=lambda unit:{'MainPID':'0'}),provider=provider,original_units=units)
        helpers=types.SimpleNamespace(checkpoint=lambda value:None,devices_absent=lambda ids:True,
            install_owner_code=lambda path,raw:calls.append('install'))
        health={'status':'DIRECT_GUEST_RUNTIME_HEALTHY_NO_GUEST_YET','CLI_list_count':0}
        def as_owner(argv,timeout):
            mode=argv[-2];calls.append(mode)
            return types.SimpleNamespace(returncode=0,stdout='BEGIN_DIRECT_GUEST_RUNTIME_REPORT\n'+json.dumps(health)+'\nEND_DIRECT_GUEST_RUNTIME_REPORT\n' if mode=='health' else '{}',stderr='')
        deploy=types.SimpleNamespace(check_provider=lambda node:provider,preserve_units=lambda m,node:units,
            as_owner=as_owner,activate=lambda:{'status':'submitted'},D=Path('/fixture/D2'),BINARIES={'uvm-ublk-daemon':'pin'})
        controller=types.SimpleNamespace(provider_status=lambda rt:{'activeLeases':0,'activePayloadResponses':0},document=lambda path:({},'hash'))
        result={};docs={'state.json':({},'hash')}
        try:
            old.finish(runtime,{},None,{}, {},helpers,deploy,b'',result,docs,'new',Path('/fixture/entry'),b'entry',controller)
            self.assertEqual(calls,['install','prepare','health'])
            self.assertEqual(result['status'],'B_OLD_COHORT_RECOVERED_DELETEFIX_HEALTHY_NO_GUEST')
        finally:
            for child in work.iterdir():child.unlink()
            work.rmdir()

if __name__=='__main__':unittest.main()
