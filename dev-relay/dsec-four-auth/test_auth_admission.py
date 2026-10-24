import copy,importlib.util,types,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('auth_four',H/'A_dsec_four_auth_v1.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def completed_smoke(context):
    ids=['11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222']
    labels=['restored-0','restored-1','private-copy-up','peer-remains-original','writer-keeps-private-value','peer-after-writer-exit']
    return {'functional':{'children':ids,'upperSnapshotRestorePassed':True,'privateCopyUpIsolationPassed':True,
        'peerSurvivesWriterExit':True,'explicitDaxAndInstructionProbesPassed':True},
        'commands':[{'label':label,'exitCode':0,'sandboxId':ids[i%2]} for i,label in enumerate(labels)],
        'journal':{'runtimeContext':context,'phase':'quiesced','lifecyclePassed':True,'outcomeUncertain':False,
        'openRequests':[],'sandboxIds':[],'operations':[
            *[{'kind':'create','route':'/v2/sandboxes','httpStatus':201,'ack':{'sandboxIds':[sid]}} for sid in ids],
            *[{'kind':'delete','route':'/sandboxes/'+sid,'httpStatus':204} for sid in ids]]}}

class Admission(unittest.TestCase):
    def test_full_success(self):m.validate_completed_smoke(completed_smoke({'pid':12}),{'pid':12})
    def test_unknown_request_blocks_even_empty_inventory(self):
        x=completed_smoke({});x['journal']['openRequests']=[{'kind':'create'}]
        with self.assertRaisesRegex(RuntimeError,'journal'):m.validate_completed_smoke(x,{})
    def test_failed_command_blocks(self):
        x=completed_smoke({});x['commands'][2]['exitCode']=1
        with self.assertRaisesRegex(RuntimeError,'command'):m.validate_completed_smoke(x,{})
    def test_missing_functional_proof_blocks(self):
        for key in ['upperSnapshotRestorePassed','privateCopyUpIsolationPassed','peerSurvivesWriterExit','explicitDaxAndInstructionProbesPassed']:
            x=completed_smoke({});x['functional'][key]=False
            with self.assertRaisesRegex(RuntimeError,'functional'):m.validate_completed_smoke(x,{})
    def test_pid_reuse_or_different_context_blocks(self):
        with self.assertRaisesRegex(RuntimeError,'journal'):m.validate_completed_smoke(completed_smoke({'ticks':'1'}),{'ticks':'2'})
    def test_unacknowledged_delete_blocks(self):
        x=completed_smoke({});x['journal']['operations'][-1]['httpStatus']=500
        with self.assertRaisesRegex(RuntimeError,'operations'):m.validate_completed_smoke(x,{})
    def test_wrong_deleted_guest_blocks(self):
        x=completed_smoke({});x['journal']['operations'][-1]['route']='/sandboxes/foreign'
        with self.assertRaisesRegex(RuntimeError,'operations'):m.validate_completed_smoke(x,{})
    def test_missing_or_duplicate_command_blocks(self):
        x=completed_smoke({});x['commands'][-1]=copy.deepcopy(x['commands'][0])
        with self.assertRaisesRegex(RuntimeError,'command'):m.validate_completed_smoke(x,{})
    def test_no_replay_after_parent_failure(self):
        seen=[]
        def invoke(mode):seen.append(mode);return 1
        self.assertEqual(m.run_all_phases(invoke),1);self.assertEqual(seen,['parents'])
    def test_sequential_phases_propagate_replay_failure(self):
        seen=[]
        def invoke(mode):seen.append(mode);return 0 if mode=='parents' else 1
        self.assertEqual(m.run_all_phases(invoke),1);self.assertEqual(seen,['parents','replay'])
    def test_new_namespace_does_not_overwrite_old_measurements(self):
        self.assertEqual(m.WORK.name,'dsec-four-auth-v1')
        self.assertEqual(m.CORE,'2c2c0ea573f97a0ce8fc64f2dfb79d60b7089a14')
        text=(H/'dsec_four_auth_body.py').read_text(encoding='utf-8')
        self.assertIn('updates/auth-order-fix-v1/activation-proof.json',text)
        self.assertIn('dsec-real-template-smoke-v3/return.json',text)
        self.assertNotIn('updates/pmem-id-fix-v1/activation-proof.json',text)

if __name__=='__main__':unittest.main()
