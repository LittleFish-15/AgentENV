import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch,Mock
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('full_services',HERE/'AB_full_host_dax_services_v1.py')
m=importlib.util.module_from_spec(s)
with patch.dict(sys.modules,{k:types.SimpleNamespace() for k in ('fcntl','grp','pwd')}):s.loader.exec_module(m)


class Checks(unittest.TestCase):
    def test_embedded_source_exact(self):
        for key,path in {'api':HERE.parent/'github-relay-20261029/relay_runner.py',
                         'maintenance':HERE/'host_pmem_maintenance_v2.py','proxy':HERE/'hpab_proxy.py',
                         'sdk_lookup':HERE/'hpab_sdk_lookup.c','ublk_owner':HERE/'hpab_ublk_owner.c'}.items():
            self.assertEqual(m.source(key),path.read_bytes())

    def test_intent_prevents_duplicate_sdk(self):
        obj=m.Start.__new__(m.Start);obj.state={'steps':{'sdk':{'state':'intent'}}}
        fn=Mock(side_effect=AssertionError('must not reallocate'))
        with self.assertRaisesRegex(RuntimeError,'explicit reconciliation'):obj.once('sdk',fn)
        fn.assert_not_called()

    def test_confirmed_sdk_does_not_allocate_again(self):
        obj=m.Start.__new__(m.Start);obj.state={'steps':{'sdk':{'state':'done','result':{'allocation':'existing'}}}}
        fn=Mock();self.assertEqual(obj.once('sdk',fn),{'allocation':'existing'});fn.assert_not_called()

    def test_provider_key_order_preserved_through_private_event_envelope(self):
        manifest={'version':1,'ownerId':'a','mode':'pmem','readers':['b'],
                  'replicas':[{'objectName':'n','identity':{'objectId':'i','generation':'g','sha256':'d','bytes':4}}]}
        original=m.wire(manifest)
        transport=json.loads(json.dumps({'dataJson':original.decode()},sort_keys=True))
        self.assertEqual(m.wire(json.loads(transport['dataJson'])),original)
        self.assertNotEqual(m.wire(json.loads(json.dumps(manifest,sort_keys=True))),original)

    def test_missing_peer_blocks_maintenance_and_allocation(self):
        obj=m.Start.__new__(m.Start);obj.state={'steps':{}};obj.node='node-a'
        obj.export_code=Mock(return_value={});obj.compile_helpers=Mock(return_value={})
        obj.lookup_old=Mock(return_value={'allAbsent':True});obj.event=Mock()
        obj.peer_event=Mock(return_value=None);obj.maintenance=Mock();obj.permissions=Mock()
        obj.mark=Mock();obj.candidate_live=Mock()
        def once(label,fn):
            value=fn();obj.state['steps'][label]={'state':'done','result':value};return value
        obj.once=once
        with self.assertRaisesRegex(RuntimeError,'peer lookup'):obj.start()
        obj.maintenance.assert_not_called();obj.permissions.assert_not_called()

    def test_terminal_generation_never_restarts(self):
        obj=m.Start.__new__(m.Start);obj.state={'terminal':True};obj.export_code=Mock()
        with self.assertRaisesRegex(RuntimeError,'never restart'):obj.start()
        obj.export_code.assert_not_called()

    def test_peer_global_ack_required_even_without_import(self):
        obj=m.Start.__new__(m.Start);obj.node='node-b';obj.state={'units':{}};obj.peer_event=Mock(return_value=None)
        with self.assertRaisesRegex(RuntimeError,'A global release'):obj.restore()

    def test_sdk_query_source_has_no_allocation_mapping_or_delete(self):
        text=m.source('sdk_lookup').decode()
        for name in ('ubsmem_shmem_allocate(','ubsmem_shmem_map(','ubsmem_shmem_deallocate('):
            self.assertNotIn(name,text)
        self.assertIn('rc==UBSM_ERR_NOT_FOUND && intact',text)
        self.assertIn('fin=ubsmem_finalize()',text)

    def test_ublk_grant_requires_kernel_owner_and_correlated_completion(self):
        text=m.source('ublk_owner').decode()
        self.assertIn('info.owner_uid==1204 && info.owner_gid==1205',text)
        self.assertIn('UBLK_U_CMD_GET_DEV_INFO',text)
        self.assertIn('user_data==0x68706162',text)
        self.assertIn('alarm(1)',text)
        self.assertNotIn('chmod(',text);self.assertNotIn('chown(',text)

    def test_source_does_not_adopt_unknown_resources_or_target_ssh(self):
        text=(HERE/'AB_full_host_dax_services_v1.body.py').read_text()
        self.assertNotIn('rmmod --force',text);self.assertNotIn('drop_caches',text.split('"""',2)[-1])
        self.assertNotIn("tool('ssh')",text)
        self.assertIn("self.state.get('sdkRetirePending')",text)
        self.assertIn("self.state.get('viewRetirePending')",text)
        self.assertNotIn("['create'",text)

    def test_runtime_uses_root_prestart_in_private_network_not_host_toggle(self):
        text=(HERE/'AB_full_host_dax_services_v1.body.py').read_text()
        self.assertIn('ExecStartPre=+/usr/bin/python3',text)
        self.assertIn('PrivateNetwork=yes',text)
        self.assertIn('HostForwardingChanged',text)
        self.assertEqual(text.count("'BindReadOnlyPaths='"),1)

    def test_original_maintenance_verification_suite_not_replaced(self):
        text=m.source('maintenance').decode()
        self.assertIn('no_regions()',text)
        self.assertIn('check_module(src, params, 0)',text)
        self.assertIn('PropagatesStopTo',text)


if __name__=='__main__':unittest.main()
