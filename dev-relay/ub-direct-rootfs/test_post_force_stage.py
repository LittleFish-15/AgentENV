"""Local recovery decision tests; no systemd, signals or remote operations."""
import copy, importlib.util, json, unittest
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('post_force', HERE / 'post_force_stage_body.py')
# fcntl is target-only. Loading function definitions on Windows needs a harmless
# module placeholder; no production lock operation is executed by these tests.
import sys, types
if sys.platform == 'win32': sys.modules['fcntl'] = types.ModuleType('fcntl')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Decisions(unittest.TestCase):
    def clean(self):
        return {'unit': {'MainPID': '0', 'ActiveState': 'inactive', 'Job': ''},
                'processes': [], 'devices': {k: None for k in m.DEVICES}, 'sysfsRemaining': []}

    def test_clean(self): self.assertTrue(m.old_drained(self.clean()))

    def test_actual_immediate_force_stop_is_not_release(self):
        v = self.clean(); v['unit'].update(MainPID='3966082', ActiveState='deactivating')
        v['devices']['ublkb12'] = {'major': 259, 'minor': 16, 'expectedIdentity': True}
        self.assertFalse(m.old_drained(v))

    def test_each_remaining_resource_blocks(self):
        changes = [('unit', {'MainPID': '0', 'ActiveState': 'deactivating'}),
                   ('unit', {'MainPID': '0', 'ActiveState': 'inactive', 'Job': '1'}),
                   ('processes', [{'pid':3966531,'startTicks':'80555408','state':'Z','inOldUnit':False}]),
                   ('processes', [{'pid':999,'startTicks':'1','state':'S','inOldUnit':True}]),
                   ('sysfsRemaining', ['/sys/class/block/ublkb12']),
                   ('devices', {'ublkb12': {'expectedIdentity':True}})]
        for key, value in changes:
            with self.subTest(key=key,value=value):
                v=self.clean();v[key]=value;self.assertFalse(m.old_drained(v))

    def test_reused_pid_not_old_identity(self):
        v=self.clean();v['processes']=[{'pid':3966082,'startTicks':'new','state':'S','inOldUnit':False}]
        self.assertTrue(m.old_drained(v))

    def test_reused_device_not_deleted(self):
        v=self.clean();v['devices']['ublkb12']={'expectedIdentity':False}
        self.assertFalse(m.old_drained(v)); self.assertIn('identity changed', m.remaining_reason(v))

    def test_uninterruptible_explained(self):
        v=self.clean();v['processes']=[{'pid':3966082,'startTicks':'80555317','state':'D','inOldUnit':True}]
        self.assertIn('uninterruptible',m.remaining_reason(v))

    def test_health_uses_actual_marker_format(self):
        report={'status':'DIRECT_GUEST_RUNTIME_HEALTHY_NO_GUEST_YET','Guest_created':False,'CLI_list_count':0}
        raw='BEGIN_DIRECT_GUEST_RUNTIME_REPORT\n'+json.dumps(report)+'\nEND_DIRECT_GUEST_RUNTIME_REPORT\n'
        self.assertEqual(m.health_report(raw),report)
        for bad in [raw+raw, raw.replace('HEALTHY_NO_GUEST_YET','FAILED'),raw.replace('"CLI_list_count": 0','"CLI_list_count": 1')]:
            with self.assertRaises(RuntimeError): m.health_report(bad)


if __name__=='__main__': unittest.main()
