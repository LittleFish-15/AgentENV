"""Composition checks with synthetic adapters; no Runtime/SDK/Guest effects."""
import copy,types,unittest
from pathlib import Path
from unittest.mock import patch
import full_local_comparison_body as entry

class Composition(unittest.TestCase):
    def harness(self, status='LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED', phase='original'):
        events=[];saved={};instance=entry.Comparison.__new__(entry.Comparison)
        instance.args=types.SimpleNamespace(phase=phase,run_id='a'*32,peer_original=None)
        instance.node='a';instance.plan={'plan':'fixture'};instance.contexts={'original':{},'full':{}}
        instance.templates=[{}];instance.steps={0:[{'action':'true','delay':0}]};instance.files=[];instance.ledger={}
        instance.apis={'original':object(),'full':object()};instance.capacity=lambda *args:None
        instance.accepted={'bundleSha256':'b'*64};instance.ready=instance.ram=instance.sampler=None
        instance.runtime=types.SimpleNamespace(engine=None,index={},provider={'providerProcess':{}},replay=types.SimpleNamespace(shell_command=None))
        permit=types.SimpleNamespace(finish=lambda *args:events.append('finish'))
        registry=types.SimpleNamespace(state={'plan':instance.plan},begin=lambda *args:events.append('begin'),
            start_group=lambda *args: (events.append('reserve') or permit), close=lambda:events.append('close'))
        instance.journals=types.SimpleNamespace(RunJournal=lambda path:registry)
        cleanup={'ownedGuestsReleased':True,'released':[],'sharedUBObjectsRetired':False}
        group=types.SimpleNamespace(bindings={},cases={},owned=lambda sid:True)
        def restore(run):
            events.append('restore');return [{'templateIndex':0,'sandboxId':'g1'}]
        group.restore=restore
        group.release_after_completed_replay=lambda report:(events.append('cleanup') or cleanup)
        instance.adapter=types.SimpleNamespace(ActualComparisonCohort=lambda *args,**kwargs:group)
        instance.gates=types.SimpleNamespace(VERSIONS={'original':{'root':Path('/original')},'full':{'root':Path('/full')}}, input_signature=lambda templates:['fixture'])
        instance.continue_pair=types.SimpleNamespace(provider_status=lambda runtime:{'activeLeases':0,'activePayloadResponses':0,'payloadFailures':0})
        instance.idle_sample=lambda group:(events.append('idle-sample') or {})
        instance.replay=types.SimpleNamespace(NativeGroupReplay=lambda *args,**kwargs:types.SimpleNamespace(run=lambda:{
            'status':status,'completedCommands':1,'nonzeroCommands':0,'elapsedSeconds':1}))
        return instance,events,saved

    def test_original_phase_reserves_before_restore_and_releases_after_replay(self):
        instance,events,saved=self.harness()
        with patch.object(entry,'mkdir'),patch.object(entry,'save',side_effect=lambda path,value:saved.update({path.name:copy.deepcopy(value)})):
            receipt=instance.run()
        self.assertEqual(events,['begin','reserve','idle-sample','restore','cleanup','finish','close'])
        self.assertEqual(receipt['status'],'LOCAL_COMPARISON_PHASE_RELEASED')
        self.assertFalse(receipt['crossNodeSynchronizationVerified']);self.assertIsNone(receipt['netSavingsBytes'])

    def test_failed_replay_preserves_guests_and_blocks_completion(self):
        instance,events,saved=self.harness('LOCAL_REPLAY_FAILED_STATE_PRESERVED')
        with patch.object(entry,'mkdir'),patch.object(entry,'save',side_effect=lambda path,value:saved.update({path.name:copy.deepcopy(value)})):
            with self.assertRaisesRegex(RuntimeError,'Replay failed'):instance.run()
        self.assertNotIn('cleanup',events);self.assertNotIn('finish',events)
        self.assertEqual(saved['failure-original.json']['automaticCleanup'],False)

    def test_full_without_peer_completion_never_reserves_or_restores(self):
        instance,events,saved=self.harness(phase='full')
        with patch.object(entry,'mkdir'),patch.object(entry,'save'):
            with self.assertRaisesRegex(RuntimeError,'peer original'):instance.run()
        self.assertEqual(events,['close'])

    def test_idle_sampling_failure_is_before_first_guest_creation(self):
        instance,events,saved=self.harness()
        instance.idle_sample=lambda group:(_ for _ in ()).throw(RuntimeError('sample incomplete'))
        with patch.object(entry,'mkdir'),patch.object(entry,'save'):
            with self.assertRaisesRegex(RuntimeError,'sample incomplete'):instance.run()
        self.assertNotIn('restore',events);self.assertNotIn('cleanup',events)

if __name__=='__main__':unittest.main()
