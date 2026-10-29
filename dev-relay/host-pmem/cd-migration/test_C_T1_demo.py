import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import zlib

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('demo',HERE/'C_run_maintenance_v3.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def state(self):
        return {'runId':'a'*32,'units':{},'guests':{},'guestHistory':[],'unknownCreate':False,
                'guestProbes':[],'samples':[],'acl':[],'Guest_created':False}
    def demo(self,state=None):return m.Demo(state or self.state(),{},SimpleNamespace(atomic=Mock()))
    def test_unknown_create_is_retained_without_retry(self):
        d=self.demo();d.runtime=Mock();d.advise_sources=Mock();d.measure=Mock()
        d.cli=Mock(return_value=SimpleNamespace(returncode=1,stdout=b'',stderr=b'creation outcome unknown'))
        with self.assertRaisesRegex(RuntimeError,'not acknowledged'):d.pair('original')
        self.assertEqual(d.cli.call_count,1)
        self.assertEqual(d.state['unknownCreate'],{'variant':'original','attempt':0})
        self.assertIsNone(d.state['Guest_created'])
    def test_unknown_create_blocks_global_release_before_service_action(self):
        state=self.state();state['unknownCreate']={'variant':'dax','attempt':1}
        d=self.demo(state)
        with patch.object(m,'unit') as unit,patch.object(m,'checked') as command:
            with self.assertRaisesRegex(RuntimeError,'prohibit backing'):d.release()
            unit.assert_not_called();command.assert_not_called()
    def test_live_runtime_blocks_backing_release(self):
        state=self.state();state['units']={'dax':{'stopped':False}}
        with self.assertRaisesRegex(RuntimeError,'not exited'):self.demo(state).release()
    def test_foreign_process_is_not_stopped(self):
        state=self.state();state['units']={'sdk':{'name':'owned.service','pid':10,'ticks':'20','description':'owned'}}
        d=self.demo(state)
        with patch.object(m,'unit',return_value={'Description':'owned','ActiveState':'active','MainPID':'11'}), \
             patch.object(m,'checked') as command:
            with self.assertRaisesRegex(RuntimeError,'identity changed'):d.stop('sdk')
            command.assert_not_called()
    def test_old_sdk_owner_intent_blocks_new_allocation(self):
        d=self.demo()
        with patch.object(Path,'exists',return_value=True),patch.object(d,'launch') as launch:
            with self.assertRaisesRegex(RuntimeError,'never allocate again'):d.publish()
            launch.assert_not_called()
    def test_plan_no_side_effect_and_guest_timeout_not_extended(self):
        r=subprocess.run([sys.executable,'-X','utf8','-I','-B',str(HERE/'C_run_maintenance_v3.py')],capture_output=True,text=True,encoding='utf-8',check=True)
        row=json.loads(r.stdout)
        self.assertEqual(row['logicalUbRequestBytes'],1811939328)
        self.assertEqual(row['postMapCoverageGuardBytes'],4294967296)
        self.assertFalse(row['physicalHardQuota']);self.assertFalse(row['defaultChanges'])
        self.assertEqual((row['GuestCommandSeconds'],row['CLISeconds']),(300,330))
    def test_embedded_static_probe_exact_sha(self):
        raw=zlib.decompress(base64.b64decode(m.PROBE,validate=True))
        self.assertEqual(hashlib.sha256(raw).hexdigest(),m.PROBE_SHA)
        self.assertEqual(raw[:4],b'\x7fELF')
    def test_changed_acl_device_cannot_be_restored(self):
        state=self.state();state['acl']=[{'path':'/dev/obmm','rdev':1,'inode':2,'backup':'acl.txt'}]
        d=self.demo(state)
        with patch.object(Path,'stat',return_value=SimpleNamespace(st_rdev=999,st_ino=2)),patch.object(m,'checked') as command:
            with self.assertRaisesRegex(RuntimeError,'Device changed'):d.restore_acl()
            command.assert_not_called()
    def test_unknown_delete_does_not_remove_owned_guest_record(self):
        state=self.state();state['guests']={'original':['owned-id']}
        d=self.demo(state);d.cli=Mock(return_value=SimpleNamespace(returncode=1,stderr=b'lost ack'))
        with self.assertRaisesRegex(RuntimeError,'deletion not acknowledged'):d.close_pair('original')
        self.assertEqual(state['guests']['original'],['owned-id'])
    def test_refused_view_retirement_never_retires_sdk(self):
        state=self.state();state.update(viewLaunchAttempted=True,sdkLaunchAttempted=True)
        state['units']={'view':{'name':'view.service'},'sdk':{'name':'sdk.service'}}
        d=self.demo(state);d.bound=Mock();d.view=Mock(return_value={'state':'refused_preserve_resources'})
        with patch.object(m,'unit',return_value={'ActiveState':'active'}),patch.object(m,'checked') as command:
            with self.assertRaisesRegex(RuntimeError,'view release not confirmed'):d.release()
            command.assert_not_called()
        self.assertFalse(state.get('sdkRetiredConfirmed',False))
    def test_namespace_forwarding_guard_precedes_sysctl_write(self):
        text=(HERE/'C_run_maintenance_v3.py').read_text()
        guard=text.index('assert os.stat("/proc/self/ns/net")')
        mutation=text.index('Path("/proc/sys/net/ipv4/ip_forward").write_text')
        self.assertLess(guard,mutation)
        self.assertIn("'PrivateNetwork=yes'",text)
    def test_prepared_runtime_config_hashes_are_pinned_not_self_attested(self):
        receipt=json.loads((HERE/'C-T1-stage-receipt.private.json').read_bytes())
        self.assertEqual(m.CONFIG_PINS,{key:value['configSha256'] for key,value in receipt['plan']['variants'].items()})
        self.assertEqual(m.PLAN_SHA,hashlib.sha256((json.dumps(receipt['plan'],indent=2)+'\n').encode()).hexdigest())


if __name__=='__main__':unittest.main()
