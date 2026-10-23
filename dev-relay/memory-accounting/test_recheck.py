"""Original256 repeat gates; unchanged measurement payload and root restoration."""
import copy,importlib.util,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
NEW=load(HERE.parent/'cow4_memory_recheck256.py','repeat_packet')
FIXTURE=load(HERE/'test_pair.py','old_pair_fixtures')
def setup():
    p=HERE.parent/'cow4_memory_pair.py';base=load(p,'repeat_base_fixture');original={n:base.payload(n) for n in base.PAYLOADS}
    NEW.prepare(base,p.read_text(encoding='utf-8'),NEW.REPEAT_OWNER);return base,original
def root_source(base):
    patcher=base.module('repeat_patch_fixture',base.payload('patch_sources'))
    return patcher.root_source(FIXTURE.OLD[64].ROOT_SOURCE,base.payload('root256_extra'),base.payload('root_measure'),base.payload('root_pair'))
class Tests(unittest.TestCase):
    def test_measurement_payloads_and_previous_packet_are_unchanged(self):
        base,old=setup()
        for name in ('root_measure','root256_extra'):self.assertEqual(base.payload(name),old[name])
        self.assertTrue(base.payload('owner_extension').startswith(old['owner_extension']))
        self.assertEqual(__import__('hashlib').sha256((HERE.parent/'cow4_memory_pair.py').read_bytes()).hexdigest(),NEW.BASE_PACKET_SHA)
        self.assertEqual(base.STATE.name,'cow4-memory-256-recheck-controller-node-a.pending.json')

    def test_one_256_root_group_only(self):
        base,_=setup();source=root_source(base)
        case=FIXTURE.Tests(methodName='runTest');case.setUp()
        try:
            with patch.object(FIXTURE,'ROOT_SOURCE',source):result,seen,_=case.driver()
            self.assertEqual(seen,[256]);self.assertEqual(result['status'],'MEMORY_256_RECHECK_ROOT_RESTORED')
        finally:case.doCleanups()

    def test_256_literal_activation_and_restore_still_passes(self):
        base,_=setup();case=FIXTURE.Tests(methodName='runTest');case.setUp()
        try:
            with patch.object(FIXTURE,'ROOT_SOURCE',root_source(base)):case.lifecycle(256)
        finally:case.doCleanups()

    def test_new_stage_cannot_replace_previous_pending(self):
        base,_=setup();p=base.module('repeat_patch_fixture',base.payload('patch_sources'))
        text=(HERE.parent/'cow4_original_256_recheck.py').read_text(encoding='utf-8')
        source=p.stage_source(text,256,base.payload('owner_extension'));compile(source,'repeat-owner-stage','exec')
        self.assertIn("m.PENDING=m.ROOT/'relay/cow4-memory-recheck-256-node-a.pending.json'",source)
        with self.assertRaises(RuntimeError):p.stage_source(text,64,'')

    def test_previous_pair_gate_rejects_incomplete_release(self):
        base,_=setup();p=base.module('repeat_patch_fixture',base.payload('patch_sources'))
        source=p.stage_source((HERE.parent/'cow4_original_256_recheck.py').read_text(encoding='utf-8'),256,base.payload('owner_extension'))
        stage=base.module('repeat_stage_fixture',source,{'MODE':256,'MASTER':None,'PAIR_ID':'fixture'})
        flags=('original_configuration_restored','original_service_healthy','other_services_unchanged','observer_exit_confirmed','bound_guest_processes_exited','original_server_unchanged','original_server_bytes_and_metadata_restored')
        root=dict.fromkeys(flags,True);root['status']='COW4_ROOT_SESSION_RESTORED'
        common={'all_cohort_guests_released':True,'restore_outcome_uncertain':False,'replay_completed_guests':8,'root_session':root,'memory_accounting':{'coverage':{'required_accounting_complete':True}}}
        r0=dict(common,run_id='8701803e0ccd4278bc71bef829c4c85a',status='COW4_ORIGINAL_256_RECHECK_MEASURED_GUESTS_RELEASED_RESTORED')
        r1=dict(common,run_id='a2a2e2a1fb8d4344a6534975fdc5ce8b',status='COW4_IO64_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED')
        m=types.SimpleNamespace(ROOT=Path('/scope'),need=FIXTURE.require,B=types.SimpleNamespace(read_json=lambda p:r0 if '256' in p.name else r1))
        self.assertEqual(len(stage.repeat_previous(m)),2);r1['all_cohort_guests_released']=False
        with self.assertRaises(RuntimeError):stage.repeat_previous(m)

if __name__=='__main__':unittest.main(verbosity=2)
