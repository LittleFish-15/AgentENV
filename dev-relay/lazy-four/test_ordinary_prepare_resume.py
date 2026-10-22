"""Regressions for the actual ordinary-mode CLI failure and bounded continuation."""
import copy
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock


def module(name):
    spec=importlib.util.spec_from_file_location('resume_'+name,Path(__file__).with_name(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


m=module('lazy_four_rollout')
service=module('prepare_lazy_four_service')
REASON='Choose explicit v3 rootfs binding or --ordinary-only control; an unbound service cannot later be called UB-enabled'


def observed_stop():
    names=['pack-existing-four-snapshots','receive-snapshots-a','pack-binaries','prepare-runtime-a']
    prior={'node':'node-a','bootId':'boot','status':'PREPARING',
           'steps':[{'name':n,'state':'completed','exitCode':int(i==3)} for i,n in enumerate(names)]}
    failed={'status':'STOPPED_NATIVE_PREPARATION_NO_SERVICE_STARTED','errorType':'RuntimeError','reason':REASON,
            'SDK_called':False,'Guest_created':False,'services_changed':False}
    return prior,failed


class OrdinaryPreparation(unittest.TestCase):
    def test_old_missing_flag_reproduces_actual_cli_guard(self):
        args=['prepare_lazy_four_service.py','prepare','--node','node-a','--core-report','build.json','--tools-report','tools.json']
        output=io.StringIO()
        with mock.patch.object(service.sys,'argv',args),mock.patch.object(service,'prepare') as prepare,mock.patch('sys.stdout',output):
            self.assertEqual(service.main(),1)
        prepare.assert_not_called()
        self.assertIn(REASON,output.getvalue())

    def test_both_corrected_calls_reach_actual_cli_prepare(self):
        for node in ('node-a','node-b'):
            arguments=m.service_prepare_arguments(node,Path('build.json'),Path('tools.json'),Path('tools.ext4') if node=='node-b' else None)
            with mock.patch.object(service.sys,'argv',['prepare_lazy_four_service.py',*map(str,arguments)]),mock.patch.object(service,'prepare',return_value=0) as prepare:
                self.assertEqual(service.main(),0)
                args=prepare.call_args.args[0]
                self.assertTrue(args.ordinary_only)
                self.assertIsNone(args.rootfs_binding)
                self.assertEqual(args.node,node)

    def test_only_exact_known_prewrite_failure_is_accepted_without_mutation(self):
        prior,failed=observed_stop();before=copy.deepcopy((prior,failed))
        m.validate_ordinary_prepare_stop(prior,failed,'boot')
        self.assertEqual((prior,failed),before)
        for field in ('SDK_called','Guest_created','services_changed'):
            changed=copy.deepcopy(failed);changed[field]=True
            with self.assertRaises(RuntimeError):m.validate_ordinary_prepare_stop(prior,changed,'boot')
        changed=copy.deepcopy(failed);changed['reason']='some different installation failure'
        with self.assertRaises(RuntimeError):m.validate_ordinary_prepare_stop(prior,changed,'boot')

    def test_changed_boot_or_advanced_uncertain_journal_refused(self):
        prior,failed=observed_stop()
        with self.assertRaises(RuntimeError):m.validate_ordinary_prepare_stop(prior,failed,'new-boot')
        for change in ('extra','running','wrong-exit'):
            value=copy.deepcopy(prior)
            if change=='extra':value['steps'].append({'name':'seed-snapshots-a','state':'completed','exitCode':0})
            elif change=='running':value['steps'][-1]['state']='running'
            else:value['steps'][0]['exitCode']=1
            with self.assertRaises(RuntimeError):m.validate_ordinary_prepare_stop(value,failed,'boot')

    def test_resume_branches_past_all_three_completed_steps(self):
        steps=object()
        build={'status':'COORDINATED_CANDIDATE_BINARIES_BUILT_NOT_DEPLOYED',
               'release':{'coreCommit':m.CORE,'tree':m.CORE_TREE}}
        with (mock.patch.multiple(m,SELF=Path(m.__file__).resolve(),ordinary=mock.Mock(),load=mock.Mock(return_value=build),
                transport_readiness=mock.Mock(),download=mock.Mock(),resume_ordinary_prepare_steps=mock.Mock(return_value=steps),
                sha=mock.Mock(return_value='a'*64)),
              mock.patch.object(Path,'is_file',return_value=True),mock.patch('builtins.print'),
              mock.patch.object(m,'Steps') as constructor,mock.patch.object(m,'prepare_original_tools') as tools,
              mock.patch.object(m,'continue_after_archives',return_value='continued') as continuation):
            self.assertEqual(m.run_a(True),'continued')
            continuation.assert_called_once_with(steps,'a'*64,'a'*64,resumed=True)
            constructor.assert_not_called();tools.assert_not_called()

    def test_continuation_first_action_uses_new_log_and_ordinary_flag(self):
        class ReachedSeed(Exception):pass
        calls=[]
        class Steps:
            def local(self,*args):
                calls.append(args)
                if len(calls)==2:raise ReachedSeed()
        with self.assertRaises(ReachedSeed):m.continue_after_archives(Steps(),'b'*64,'c'*64,resumed=True)
        self.assertEqual(calls[0][0],'prepare-runtime-a-ordinary')
        self.assertIn('--ordinary-only',calls[0][2])
        self.assertEqual(calls[1][0],'seed-snapshots-a')
        self.assertFalse(any(c[0] in ('pack-existing-four-snapshots','receive-snapshots-a','pack-binaries') for c in calls))


if __name__=='__main__':unittest.main()
