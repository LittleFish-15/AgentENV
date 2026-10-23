import contextlib,hashlib,importlib.util,io,json,shutil,subprocess,sys,unittest,uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

H=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('native_round',H/'delivery/native_archive_round.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class NativeRoundEntryTests(unittest.TestCase):
 def test_memory_markdown_uses_recorded_phase_values_and_retains_missing(self):
  stats={'mean':2*1024**2,'max':3*1024**2,'count':2,'missing':1}
  report={'node':'node-a','jobs':[{'templateIndex':0,'slot':0,'sandboxId':'s0','replayStartedUnix':100,'replayFinishedUnix':102.5,
    'stepsCompleted':2,'expectedSteps':2,'failedCommands':1,'state':'REPLAY_COMPLETED'}],
    'measurementSummary':{'templateRows':[{'templateIndex':0,'phase':'both_replaying','metrics':{'actualGuestRamPssSumBytes':stats}},
      {'templateIndex':0,'phase':'after_replay','metrics':{'actualGuestRamPssSumBytes':dict(stats,mean=900*1024**2)}}],
      'hostObservations':{'providerPssBytes':stats}},'completedSample':{'host':{'memoryBytes':{'Cached':4*1024**2}}}}
  before=json.dumps(report,sort_keys=True)
  text='\n'.join(m.measurement_markdown([report],[]))
  self.assertIn('2.500',text);self.assertIn('2.000 / 3.000 / 2 / 1',text);self.assertIn('4.000',text)
  self.assertNotIn('900.000',text);self.assertIn('NA',text);self.assertIn('must not be summed',text)
  self.assertEqual(before,json.dumps(report,sort_keys=True))
 def test_memory_markdown_unknown_and_invalid_values_are_not_zero(self):
  report={'node':'node-a','jobs':[{'replayStartedUnix':5,'replayFinishedUnix':4}],
    'completedSample':{'host':{'memoryBytes':{'Cached':float('nan'),'Dirty':float('inf'),'Shmem':False}}}}
  text='\n'.join(m.measurement_markdown([report],[{'ownerId':'a'*32,'manifestIdentityConsistent':True,'ownerReportedCoverageBytes':128*1024**2}]))
  self.assertIn('| node-a | NA | NA | NA | NA |',text);self.assertIn('| 128.000 | NA |',text)
  self.assertNotIn('0.000',text);self.assertIn('global net saving remain NA',text)
 def complete_reports(self):
  return [{'node':node,'scenario':'dual-ab','replicaFormation':'restore-pair','status':'NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED',
    'workerExitCode':0,'jobs':[{'templateIndex':i,'slot':s,'sandboxId':node+'-'+str(i)+'-'+str(s),'state':'REPLAY_COMPLETED',
       'expectedSteps':2,'stepsCompleted':2,'failedCommands':1,'instanceId':'case-'+str(i),'replaySha256':'a'*64,
       'commandResults':[{'step':0,'returnCode':0},{'step':1,'returnCode':7}]} for i in range(4) for s in (0,1)]} for node in ('node-a','node-b')]
 def test_dual_missing_B_report_and_coordinator_error_cannot_pass_completion(self):
  m.scenario_paths('dual-ab');reports=self.complete_reports()
  self.assertFalse(m.validate_reports(reports[:1])['complete'])
  self.assertFalse(m.validate_reports(reports,{'type':'TimeoutError'})['complete'])
  self.assertTrue(m.validate_reports(reports)['complete'])
 def test_peer_exit_vector_difference_and_missing_actions_cannot_pass(self):
  m.scenario_paths('dual-ab');reports=self.complete_reports()
  reports[1]['jobs'][2]['commandResults'][1]['returnCode']=8
  self.assertFalse(m.validate_reports(reports)['nativePeerCommandResultsMatch'])
  reports=self.complete_reports();reports[1]['jobs'][2]['commandResults'].pop()
  self.assertFalse(m.validate_reports(reports)['complete'])
 def test_matching_nonzero_actions_are_preserved_and_not_called_all_success(self):
  m.scenario_paths('dual-ab');reports=self.complete_reports()
  self.assertTrue(m.validate_reports(reports)['complete'])
  reports[1]['jobs'][0]['failedCommands']=0
  self.assertFalse(m.validate_reports(reports)['complete'])
 def test_default_both_scenarios_do_not_access_hosts(self):
  for scenario,count in [('single-a',8),('dual-ab',16)]:
   run=subprocess.run([sys.executable,'-I','-B',m.__file__,'run-a','--scenario',scenario],capture_output=True,text=True)
   self.assertEqual(run.returncode,0,run.stderr);report=json.loads(run.stdout)
   self.assertEqual(report['status'],'PLAN_ONLY_NO_HOST_ACCESS_OR_CHANGES');self.assertEqual(report['guestCount'],count)
 def test_single_contact_guards_run_before_any_subprocess_or_file_read(self):
  m.scenario_paths('single-a')
  with patch.object(m.subprocess,'run') as run,patch.object(m,'safe') as safe:
   for action in (lambda:m.remote_command(['b-health']),m.transport_readiness,lambda:m.transfer(Path('x'),Path('y'))):
    with self.assertRaisesRegex(RuntimeError,'never contacts B'):action()
   run.assert_not_called();safe.assert_not_called()
 def test_runtime_unknown_cohort_cannot_produce_stop_plan(self):
  m.scenario_paths('dual-ab')
  state={'phase':'active','openRequests':[{'operation':'create'}],'sandboxIds':[],'outcomeUncertain':True,'fourPhase':'unrecognized'}
  with patch.object(Path,'exists',return_value=True),patch.object(m,'load',return_value=state),patch.object(m.subprocess,'run') as run:
   with self.assertRaisesRegex(RuntimeError,'Unknown native cohort phase'):m.stop_plan_local('node-a','restore-pair')
   run.assert_not_called()
 def test_submitted_provider_without_journal_is_never_assumed_not_created(self):
  m.scenario_paths('single-a')
  def exists(path):return path.name=='plan.json'
  with patch.object(Path,'exists',exists):
   with self.assertRaisesRegex(RuntimeError,'activation status unknown'):m.retire_local('node-a')
 def test_explicit_retire_refusal_is_preserved_without_long_poll_or_retry(self):
  root=(H.parent/('nrf-'+uuid.uuid4().hex[:12])).resolve();root.mkdir(mode=0o777)
  try:
   work=root/'generation-node-a/provider';work.mkdir(mode=0o777,parents=True);(root/'logs').mkdir(mode=0o777)
   (work/'owner.json').write_text(json.dumps({'state':'serving','ownerId':'a'*32,'manifestSha256':'sha256:'+'b'*64}))
   def run(command,**kwargs):kwargs['stdout'].write(b'{"state":"refused","reason":"active owned lease"}');return SimpleNamespace(returncode=1)
   with patch.object(m,'WORK',root),patch.object(m,'SCENARIO','single-a',create=True),patch.object(m,'load',side_effect=lambda p:json.loads(p.read_bytes())),patch.object(m.subprocess,'run',side_effect=run) as called,patch.object(m,'wait_until') as wait:
    with self.assertRaisesRegex(RuntimeError,'explicitly refused'):m.retire_local('node-a')
    self.assertEqual(called.call_count,1);wait.assert_not_called()
   self.assertTrue((root/'retire-node-a.json').exists())
  finally:
   assert root.resolve(strict=True).parent==H.parent.resolve(strict=True) and root.name.startswith('nrf-');shutil.rmtree(root)
 def test_cleanup_orders_runtime_before_peer_then_owner_without_resending(self):
  m.scenario_paths('dual-ab');events=[]
  def rpc(mode,**kw):
   events.append(mode);return {'stopped':True}
  with patch.object(m,'stop_plan_local',side_effect=lambda *a:events.append('stop-a') or {'stopped':True}),patch.object(m,'rpc',side_effect=rpc),patch.object(m,'rpc_long',side_effect=lambda *a,**k:events.append('retire-b') or {'state':'released'}),patch.object(m,'fetch_file',return_value=b'{}'),patch.object(Path,'open',return_value=io.BytesIO()),patch.object(m,'retire_local',side_effect=lambda n:events.append('retire-a') or {'state':'released'}),patch.object(m,'save'):
   result=m.cleanup_round(['node-a','node-b'],'restore-pair')
  self.assertEqual(events,['b-stop-plan','stop-a','retire-b','retire-a']);self.assertFalse(result['unknownPreserved'])
 def test_cleanup_unknown_peer_preserves_owner(self):
  m.scenario_paths('dual-ab')
  with patch.object(m,'rpc',side_effect=RuntimeError('B request uncertain')),patch.object(m,'retire_local') as retire,patch.object(m,'save'):
   report=m.cleanup_round(['node-a','node-b'],'restore-pair')
   self.assertTrue(report['unknownPreserved']);retire.assert_not_called()
 def test_report_counts_one_owner_generation_without_claiming_physical_savings(self):
  root=(H.parent/('nrr-'+uuid.uuid4().hex[:12])).resolve();root.mkdir(mode=0o777)
  try:
   reports=[{'node':node,'status':'NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED','workerExitCode':0,
             'completedSample':{'provider':{'available':True,'ownerId':'a'*32,'manifestSha256':'sha256:'+'b'*64,
                'sdkReportedBackingCoverageBytes':128*1024**2,'logicalRequestBudgetBytes':4*1024**2}}} for node in ('node-a','node-b')]
   with patch.object(m,'WORK',root),patch.object(m,'SCENARIO','dual-ab',create=True):
    value=m.emit_report(reports,{'unknownPreserved':False,'status':'released'})
   self.assertEqual(len(value['ubGenerations']),1);self.assertEqual(value['ubGenerations'][0]['ownerReportedCoverageBytes'],128*1024**2)
   self.assertIsNone(value['globalPhysicalNetSavingBytes']);self.assertFalse(value['completeCounterfactualAccepted'])
   self.assertFalse(value['memfileCrossNodeCowImplemented']);self.assertTrue((root/'comparison.md').exists())
  finally:
   assert root.resolve(strict=True).parent==H.parent.resolve(strict=True) and root.name.startswith('nrr-');shutil.rmtree(root)
 def exercise_workflow(self,scenario,fail_capture=False):
  root=(H.parent/('nre-'+uuid.uuid4().hex[:12])).resolve();root.mkdir(mode=0o777)
  events=[];reports=[];stack=contextlib.ExitStack()
  try:
   stack.enter_context(patch.object(m,'ROOT',root));m.scenario_paths(scenario)
   new=root/'build/return.json';new.parent.mkdir(mode=0o777);new.write_text('{}')
   stack.enter_context(patch.object(m,'NEW_BUILD',new));stack.enter_context(patch.object(m,'SELF',Path(m.__file__).resolve()))
   inputs=SimpleNamespace(image_selection=lambda p:({'version':1,'images':[]},4,128),preflight_a=lambda *a:({}, {}, {}, {}))
   stack.enter_context(patch.object(m,'packet_module',return_value=inputs));stack.enter_context(patch.object(m,'ordinary'))
   def load(path):return {'status':'FOUR_NATIVE_IMAGES_AND_BINARIES_PREPARED_NOT_DEPLOYED'}
   stack.enter_context(patch.object(m,'load',side_effect=load));stack.enter_context(patch.object(m,'sha',return_value='a'*64))
   stack.enter_context(patch.object(m,'read',return_value=b'/usr/bin/python3 -I -B - <<\'X\'\npass\nX\n'))
   class Steps:
    def __init__(self,node):m.WORK.mkdir(mode=0o777,parents=True);events.append('steps-'+node)
    def local(self,name,*args,**kw):events.append(name);return Path('log'),0
    def call(self,name,*args,**kw):events.append(name);return Path('log'),0
   stack.enter_context(patch.object(m,'Steps',Steps))
   stack.enter_context(patch.object(m,'install_tools'));stack.enter_context(patch.object(m,'install_components'))
   stack.enter_context(patch.object(m,'local_provider_prepare',side_effect=lambda *a:events.append('prepare-provider-a')))
   stack.enter_context(patch.object(m,'print_root',side_effect=lambda node,title,*a:events.append(node+':'+title)))
   stack.enter_context(patch.object(m,'wait_until',side_effect=lambda label,predicate,*a:predicate()))
   stack.enter_context(patch.object(m,'provider_state',return_value={'state':'serving'}))
   stack.enter_context(patch.object(m,'runtime_ready',return_value=True))
   stack.enter_context(patch.object(m,'prepare_runtime',side_effect=lambda *a:events.append('prepare-runtime-a')))
   def worker(node,mode,*a):
    events.append(mode+'-'+node)
    return {'status':('STOPPED' if fail_capture else 'FOUR_NATIVE_PARENTS_CAPTURED_OWNED_GUESTS_RELEASED') if mode=='parents' else 'NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED','workerExitCode':0}
   stack.enter_context(patch.object(m,'worker',side_effect=worker))
   for name in ('transport_readiness','bootstrap_b','transfer','rpc_long','rpc','fetch_file','dual_replay'):
    if scenario=='single-a':stack.enter_context(patch.object(m,name,side_effect=AssertionError('Single contacted B: '+name)))
   if scenario=='dual-ab':
    stack.enter_context(patch.object(m,'transport_readiness',side_effect=lambda:events.append('transport')))
    stack.enter_context(patch.object(m,'bootstrap_b',side_effect=lambda:events.append('bootstrap-b')))
    stack.enter_context(patch.object(m,'transfer',side_effect=lambda *a:events.append('transfer') or 'b'*64))
    stack.enter_context(patch.object(m,'rpc_long',side_effect=lambda mode,**kw:events.append(mode) or {}))
    stack.enter_context(patch.object(m,'rpc',return_value={'state':'serving','active':True}))
    stack.enter_context(patch.object(m,'fetch_file',return_value=b'/usr/bin/python3 -I -B - <<\'X\'\npass\nX\n'))
    stack.enter_context(patch.object(m,'dual_replay',side_effect=lambda *a:events.append('dual-replay') or [{'status':'NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED','workerExitCode':0}]*2))
   def cleanup(nodes,mode):events.append(('cleanup',tuple(nodes)));return {'status':'OWN_NATIVE_ROUND_QUIESCED_AND_UB_RELEASED','unknownPreserved':False}
   stack.enter_context(patch.object(m,'cleanup_round',side_effect=cleanup))
   def emit(values,cleanup,error):
    reports.append((values,cleanup,error));return {'status':'NATIVE_ROUND_PARTIAL_PRESERVED' if error else 'NATIVE_ROUND_MEASURED_AND_RELEASED'}
   stack.enter_context(patch.object(m,'emit_report',side_effect=emit));stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
   self.assertEqual(m.run_a('restore-pair'),1 if fail_capture else 0)
   self.assertEqual(events[-1],('cleanup',('node-a',) if scenario=='single-a' else ('node-a','node-b')))
   if scenario=='dual-ab':
    self.assertLess(events.index('node-b:START_NATIVE_PROVIDER'),events.index('parents-node-a'))
    if not fail_capture:self.assertLess(events.index('pack-a-native-snapshots'),events.index('b-prepare-runtime'))
   return reports
  finally:
   stack.close();assert root.resolve(strict=True).parent==H.parent.resolve(strict=True) and root.name.startswith('nre-');shutil.rmtree(root)
 def test_single_workflow_never_calls_B_and_always_cleans(self):self.exercise_workflow('single-a')
 def test_dual_has_B_mapping_before_capture_and_A_snapshot_before_B_start(self):self.exercise_workflow('dual-ab')
 def test_failed_capture_still_reaches_scoped_cleanup_and_partial_report(self):
  reports=self.exercise_workflow('dual-ab',True);self.assertIsNotNone(reports[0][2])

if __name__=='__main__':unittest.main()
