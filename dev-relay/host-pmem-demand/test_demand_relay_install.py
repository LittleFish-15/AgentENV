import copy
import unittest
import demand_relay_install as installer


class IsolationTests(unittest.TestCase):
    def values(self):
        identity={'bootId':'fixture','uid':1204}
        old={'identity':identity,'node':'node-c','controlRepo':'owner/private-control','controlRepoId':1,
             'resultRepo':'owner/private-results','resultRepoId':2,'controlBranch':'main','resultBranch':'main'}
        profile={'node':'node-c','sessionId':installer.SESSION,'allowedOperations':['reviewed-python-v1'],
                 'allowedScopes':['workspace-files']}
        return old,profile,identity

    def test_separate_branch_does_not_change_full_mode_config(self):
        old,profile,current=self.values();before=copy.deepcopy(old)
        new=installer.independent_config(old,profile,current)
        self.assertEqual(old,before)
        self.assertEqual(new['controlBranch'],installer.BRANCH)
        self.assertEqual(new['resultBranch'],installer.BRANCH)
        self.assertNotIn('credentials',new)

    def test_changed_boot_and_foreign_node_rejected(self):
        old,profile,current=self.values()
        with self.assertRaises(RuntimeError):installer.independent_config(old,profile,dict(current,bootId='other'))
        profile['node']='node-d'
        with self.assertRaises(RuntimeError):installer.independent_config(old,profile,current)

    def test_source_nodes_are_not_build_targets(self):
        old,profile,current=self.values();old['node']=profile['node']='node-a'
        with self.assertRaises(RuntimeError):installer.independent_config(old,profile,current)

    def test_scope_widening_rejected(self):
        old,profile,current=self.values();profile['allowedScopes'].append('root')
        with self.assertRaises(RuntimeError):installer.independent_config(old,profile,current)


if __name__=='__main__':unittest.main()
