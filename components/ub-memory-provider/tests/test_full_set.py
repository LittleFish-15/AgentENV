"""Metadata extension contracts, not multi-provider hardware acceptance."""
import copy,hashlib,sys,tempfile,unittest
from dataclasses import replace
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import full_set,service,stored


def fragment(number,contents):
    refs=[stored.Replica(str(Path(tempfile.gettempdir())/('f'+str(number)+'.sock')),
          'aenv_'+format(number*100+i,'032x'),format(number*100+i,'032x'),digest,size,4*1024**2,False)
          for i,(digest,size) in enumerate(contents)]
    manifest={'version':1,'ownerId':format(number,'032x'),'mode':'stored-direct','readers':['node-b'],
              'replicas':[full_set.semantic(row) for row in refs]}
    return manifest,stored.index_for(refs)


class FullSet(unittest.TestCase):
    def setUp(self):
        self.one='sha256:'+hashlib.sha256(b'old').hexdigest()
        self.two='sha256:'+hashlib.sha256(b'new').hexdigest()
        self.old=fragment(1,[(self.one,3)])
        self.new=fragment(2,[(self.two,3)])
        self.sources={self.one:(Path.cwd()/'old',3),self.two:(Path.cwd()/'new',3)}
        self.quantum=128*1024**2
        self.plan=full_set.plan_extension(self.sources,*self.old,self.quantum,self.quantum,2*self.quantum)

    def test_only_missing_content_is_published(self):
        result=full_set.publication_input(self.plan)
        self.assertEqual([r['digest'] for r in result['lowers']],[self.two])
        self.assertEqual(self.plan['newMappingBytes'],4*1024**2)
        self.assertEqual(self.plan['projectedTotalCoverageBytes'],2*self.quantum)
        self.assertEqual(self.plan['newCoverageBudgetBytes'],self.quantum)
        self.assertFalse(self.plan['SDKCalled']);self.assertEqual(self.plan['newAllocations'],0)

    def test_budget_shortfall_does_not_emit_publication_or_runtime_index(self):
        plan=full_set.plan_extension(self.sources,*self.old,self.quantum,self.quantum,self.quantum)
        self.assertFalse(plan['withinDeclaredBudget'])
        with self.assertRaises(ValueError):full_set.publication_input(plan)
        with self.assertRaises(ValueError):full_set.compose(plan,[self.old,self.new])

    def test_composition_keeps_both_actual_brokers_and_owner_lifetimes(self):
        result=full_set.compose(self.plan,[self.old,self.new])
        self.assertEqual(len({r['brokerSocket'] for r in result['runtimeIndex']['replicas']}),2)
        self.assertEqual(len(result['owners']),2)
        self.assertEqual(result['objectsCopied'],0);self.assertFalse(result['ownerRetirementCombined'])
        self.assertFalse(result['liveLeasesAttested'])
        self.assertEqual(result['runtimeIndex']['replicas'][0],self.old[1]['replicas'][0])

    def test_node_local_socket_differences_do_not_change_shared_content_identity(self):
        a=full_set.compose(self.plan,[self.old,self.new])
        imports=copy.deepcopy([self.old,self.new])
        for n,(_,index) in enumerate(imports):
            for row in index['replicas']:row['brokerSocket']=str(Path(tempfile.gettempdir())/('b'+str(n)+'.sock'))
        b=full_set.compose(self.plan,imports,'node-b')
        self.assertEqual(a['contentSetSha256'],b['contentSetSha256'])
        self.assertNotEqual(a['runtimeIndex'],b['runtimeIndex'])

    def test_missing_duplicate_or_unregistered_generation_is_refused(self):
        with self.assertRaises(ValueError):full_set.compose(self.plan,[self.old])
        with self.assertRaises(ValueError):full_set.compose(self.plan,[self.old,self.old,self.new])
        with self.assertRaises(ValueError):full_set.compose(self.plan,[self.old,self.new],'unknown-node')
        duplicate=fragment(3,[(self.one,3)])
        with self.assertRaises(ValueError):full_set.compose(self.plan,[self.old,self.new,duplicate])

    def test_replacing_old_object_or_enabling_fallback_is_refused(self):
        changed=copy.deepcopy(self.old)
        for row in (changed[0]['replicas'][0],changed[1]['replicas'][0]):row['generation']='f'*32
        with self.assertRaisesRegex(ValueError,'Retained'):full_set.compose(self.plan,[changed,self.new])
        changed=copy.deepcopy(self.new)
        for row in (changed[0]['replicas'][0],changed[1]['replicas'][0]):row['allowRepositoryFallback']=True
        with self.assertRaises(ValueError):full_set.compose(self.plan,[self.old,changed])

if __name__=='__main__':unittest.main()
