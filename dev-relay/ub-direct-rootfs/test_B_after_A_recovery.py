import ast,copy,importlib.util,sys,types,unittest
from pathlib import Path
HERE=Path(__file__).parent
if sys.platform=='win32':sys.modules['fcntl']=types.ModuleType('fcntl')
spec=importlib.util.spec_from_file_location('b_continue',HERE/'b_after_a_recovery_body.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fixture():
    # Contract fixture only. It is never written as a target receipt.
    provider={'ownerId':'owner','manifestSha256':'manifest','activeLeases':0,'activePayloadResponses':0}
    return {'aRecovery':{'reports':{'cleanup':{'status':'A_REVIEWED_DEAD_UBLK_DEVICES_REMOVED',
     'deletedConfirmed':[12,13],'oldJournalRewritten':False,
     'after':{'resources':{'processes':[],'unit':{'MainPID':'0'},'devices':{'x':None},'sysfsRemaining':[]},'provider':provider}}}},
     'aSmoke':{'status':'A_DELETEFIX_REAL_GUEST_READ_AND_NORMAL_DELETE_PASSED','ordinaryDeletePassed':True,
      'guestExitConfirmed':True,'privateRootfsDeviceRemoved':True,'localUBReadersReleased':True,
      'forcedCleanupUsed':False,'sharedObjectsRetired':False,'deleteHttpStatus':204,
      'journal':{'sandboxIds':[],'openRequests':[],'outcomeUncertain':False},'providerAfter':dict(provider)}}


class ContinuationChecks(unittest.TestCase):
    def test_evidenced_A_recovery_plus_regression_context(self):m.context_contract(fixture(),'owner','manifest')
    def test_wrong_owner_or_manifest(self):
        for owner,manifest in [('other','manifest'),('owner','other')]:
            with self.assertRaises(RuntimeError):m.context_contract(fixture(),owner,manifest)
    def test_incomplete_A_regression_rejected(self):
        for key,val in [('ordinaryDeletePassed',False),('guestExitConfirmed',False),('deleteHttpStatus',500),
                        ('forcedCleanupUsed',True),('sharedObjectsRetired',True)]:
            value=fixture();value['aSmoke'][key]=val
            with self.subTest(key=key),self.assertRaises(RuntimeError):m.context_contract(value,'owner','manifest')
    def test_remaining_A_resource_or_reader_rejected(self):
        value=fixture();value['aRecovery']['reports']['cleanup']['after']['resources']['devices']['x']={}
        with self.assertRaises(RuntimeError):m.context_contract(value,'owner','manifest')
        value=fixture();value['aSmoke']['providerAfter']['activeLeases']=1
        with self.assertRaises(RuntimeError):m.context_contract(value,'owner','manifest')
    def test_no_allocations_or_delete_in_B_entry(self):
        tree=ast.parse((HERE/'b_after_a_recovery_body.py').read_text())
        attributes={node.func.attr for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)}
        self.assertFalse(attributes&{'create','delete','activate','prepare','release_guest','recover_owned'})
        body=(HERE/'b_after_a_recovery_body.py').read_text()
        self.assertIn('ORIGINAL_B_GUEST_NOT_LIVE_CONTINUITY_NOT_PROVEN',body)
        self.assertIn('cont.new_backend_reads(before,after)',body)
    def test_cached_only_read_cannot_pass(self):
        scope={'__name__':'test_loaded_B'};exec(compile((HERE/'B_after_A_recovery_v1.py').read_bytes(),'<packet>','exec'),scope)
        cont=scope['embedded']('continuation',scope['CONTINUE_Z64'],scope['CONTINUE_SHA'])
        first={'source':'image','trace':'trace','requests':10,'bytesIncludingRepeatedReads':4096}
        with self.assertRaises(RuntimeError):cont.new_backend_reads(first,dict(first))
        self.assertEqual(cont.new_backend_reads(first,{**first,'requests':11,'bytesIncludingRepeatedReads':8192}),1)


if __name__=='__main__':unittest.main()
