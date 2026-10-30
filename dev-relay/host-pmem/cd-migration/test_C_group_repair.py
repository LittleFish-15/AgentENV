import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import json
HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
r=load('repair',HERE/'C_run_maintenance_v11.py')

class Tests(unittest.TestCase):
    def test_only_exact_inactive_four_is_a_recovery_candidate(self):
        original={'id':4,'uid':1204,'gid':1205,'pid':-1,'state':0}
        self.assertTrue(r.inactive_four(original))
        for key,value in [('id',0),('id',3),('uid',0),('gid',60001),('pid',42),('state',1)]:
            self.assertFalse(r.inactive_four({**original,key:value}))
    def test_changed_reconciliation_evidence_prevents_any_mutation(self):
        m=SimpleNamespace(write=Mock(),Demo=Mock())
        with patch.object(r,'read_root',return_value=b'{"changed":true}'):
            with self.assertRaisesRegex(RuntimeError,'evidence changed'):r.normal_recovery(m,Mock(),{})
        m.write.assert_not_called();m.Demo.assert_not_called()
    def test_unknown_existing_group_is_never_reused(self):
        m=SimpleNamespace(checked=Mock(),tool=Mock())
        with patch.object(r,'grp',SimpleNamespace(getgrnam=Mock(return_value=object()))):
            with self.assertRaisesRegex(RuntimeError,'already exists'):r.reserve_group(m,Mock(),{})
        m.checked.assert_not_called()
    def test_runtime_group_change_does_not_change_sdk_identity(self):
        m=load('fixed_v9',HERE/'C_run_maintenance_v9.py')
        launch=Mock();m.Demo.launch=launch;m.load_baseline=Mock()
        state={'protectedDevices':{}}
        with patch.object(m,'folder'),patch.object(m,'write'):
            r.configure_continuation(m,Mock(),state,60001)
        d=m.Demo({'units':{}},{},None)
        d.launch('original',[],['User=1204','Group=1205','SupplementaryGroups=985 36'])
        props=launch.call_args.args[-1]
        self.assertIn('Group=60001',props);self.assertIn('SupplementaryGroups=1205 985 36',props)
        d.launch('sdk',[],['User=1204','Group=1205','SupplementaryGroups=985'])
        self.assertEqual(launch.call_args.args[-1],['User=1204','Group=1205','SupplementaryGroups=985'])
    def test_continuation_unknown_state_is_not_reported_as_zero_guests(self):
        api=SimpleNamespace(atomic=Mock());state={'SDK_called':False,'Guest_created':False}
        current={'SDK_called':None,'Guest_created':None,'unknownCreate':{'attempt':0},'functionalSmokePassed':False,'netSavingsBytes':None}
        with patch.object(Path,'exists',return_value=True),patch.object(r,'read_root',return_value=json.dumps(current).encode()),patch.object(r.os,'chmod'):
            r.publish(api,state)
        report=api.atomic.call_args_list[0].args[1]
        self.assertIsNone(report['SDK_called']);self.assertIsNone(report['Guest_created'])

if __name__=='__main__':unittest.main()
