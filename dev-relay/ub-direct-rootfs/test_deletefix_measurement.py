"""Local composition/aggregation contracts with synthetic data, no target IO."""
import copy,importlib.util,sys,types,unittest
from pathlib import Path
HERE=Path(__file__).parent
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,HERE/file);value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
if sys.platform=='win32':sys.modules['fcntl']=types.ModuleType('fcntl')
admission=load('full_comparison_admission','full_comparison_admission_deletefix.py')
execution=load('full_local_comparison_body','deletefix_local_comparison_body.py')
composition=load('adapted_composition_tests','test_full_local_comparison.py')
original_harness=composition.Composition.harness
def harness(self,*args,**kwargs):
 result=original_harness(self,*args,**kwargs);result[0].lower_aliases=[];return result
composition.Composition.harness=harness
aggregation=load('full_pair_comparison_body','deletefix_comparison_aggregation_body.py')
load('native_group_replay','native_group_replay.py');load('scoped_comparison_sample','scoped_comparison_sample.py')
fixtures=load('test_deletefix_pair','test_deletefix_pair.py');fixtures.PIN=aggregation.EXIT_CONTROLLER_PIN
source=(HERE/'test_full_pair_comparison.py').read_text()
source=source.replace('import verify_actual_guest_pair as pair_gate','import verify_deletefix_pair as pair_gate')
source=source.replace('from test_verify_actual_guest_pair import fixture as pair_fixture','from test_deletefix_pair import fixture as pair_fixture')
source=source.replace('pair_gate.EXPECTED_CONTROLLER_SHA','subject.EXIT_CONTROLLER_PIN')
source=source.replace("pair['phaseReceipts']['a-written']['boundReplicas']","pair['historicalIsolation']['aWritten']['boundReplicas']")
aggregate_tests=types.ModuleType('adapted_aggregation_tests');aggregate_tests.__file__='<adapted-original-aggregation-tests>'
exec(compile(source,aggregate_tests.__file__,'exec'),aggregate_tests.__dict__)
views=load('comparison_lower_views','comparison_lower_views.py')
cohort=load('actual_comparison_cohort','actual_comparison_cohort_deletefix.py')
cohort_tests=load('adapted_cohort_tests','test_actual_comparison_cohort.py')
ready=load('D2_ready_tests','AB_deletefix_ub_guest_ready_v1.py')
cohort_tests.ENGINE=ready.module('cohort')
def make_cohort(self,api):
 template={'templateIndex':0,'templateId':'template','resources':{'cpu_count':2,'memory_mib':4096},
           'catalogSha256':'a'*64,'replaySha256':'b'*64,'rootfsLayers':[{'digest':'sha256:'+'c'*64,'size':1234}]}
 saved=[];permit=types.SimpleNamespace(check=lambda *a:None,begin_restore=lambda *a:None,persist_case=lambda *a:None)
 instance=cohort.ActualComparisonCohort(api,cohort_tests.ENGINE,None,None,None,Path('/home/jwk/agent/fixture'),
  'original',[template],{},lambda i,s:saved.append((i,copy.deepcopy(s))),lambda *a:None,permit=permit)
 instance.guard=lambda:None
 return instance,saved
cohort_tests.NativeCohortContracts.make=make_cohort

class Aliases(unittest.TestCase):
 def rows(self,same=True):
  return [{'path':'/original/lower','category':'rootfs-lower-original','identity':{'dev':1,'inode':10,'size':4096},'contentDigest':'sha256:'+'a'*64,'immutable':True},
          {'path':'/source/lower','category':'rootfs-lower-ub-source','identity':{'dev':1,'inode':10 if same else 11,'size':4096},'contentDigest':'sha256:'+'a'*64,'immutable':True}]
 def test_shared_inode_counted_once_per_phase(self):
  a,aliases_a=views.select_lower_views(self.rows(),'original');b,aliases_b=views.select_lower_views(self.rows(),'full')
  self.assertEqual(len(a),1);self.assertEqual(len(b),1);self.assertEqual(aliases_a,aliases_b)
  self.assertEqual(a[0]['category'],'rootfs-lower-original');self.assertEqual(b[0]['category'],'rootfs-lower-ub-source')
 def test_distinct_inodes_retained(self):
  rows,aliases=views.select_lower_views(self.rows(False),'full');self.assertEqual(len(rows),2);self.assertEqual(aliases,[])
 def test_conflicting_shared_identity_rejected(self):
  rows=self.rows();rows[1]['identity']['size']=8192
  with self.assertRaises(ValueError):views.select_lower_views(rows,'full')
 def test_alias_still_satisfies_both_lower_coverage_checks(self):
  instance=cohort.ActualComparisonCohort.__new__(cohort.ActualComparisonCohort)
  instance.templates=[{'rootfsLayers':[{'digest':'sha256:'+'a'*64,'size':4096}]}]
  instance.observe=lambda:(_ for _ in ()).throw(LookupError('coverage passed'))
  rows,_=views.select_lower_views(self.rows(),'full')
  with self.assertRaisesRegex(LookupError,'coverage passed'):instance.sampling_scope('a',rows,{}, {})

if __name__=='__main__':
 suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(composition),
                         unittest.defaultTestLoader.loadTestsFromModule(aggregate_tests),
                         unittest.defaultTestLoader.loadTestsFromModule(cohort_tests),
                         unittest.defaultTestLoader.loadTestsFromTestCase(Aliases)])
 result=unittest.TextTestRunner().run(suite)
 raise SystemExit(0 if result.wasSuccessful() else 1)
