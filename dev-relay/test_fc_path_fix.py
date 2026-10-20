import ast
import importlib.util
from pathlib import Path
import tomllib
import unittest
from unittest.mock import patch
import hashlib
import json

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fc_fix',HERE/'fix_original_fc_path.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Test(unittest.TestCase):
    RAW=b'home_path = "/home/jwk/agent/state"\n[firecracker]\nbinary_path = "/known/firecracker"\n[kernel]\nimage_path = "/known/kernel"\n'
    def test_changes_only_three_firecracker_settings(self):
        old=tomllib.loads(self.RAW.decode());new=tomllib.loads(m.updated_config(self.RAW).decode())
        for k in ('work_dir','serial_dir','log_level'): self.assertIn(k,new['firecracker'])
        self.assertEqual({k:v for k,v in new['firecracker'].items() if k not in ('work_dir','serial_dir','log_level')},old['firecracker'])
        del new['firecracker'];del old['firecracker'];self.assertEqual(new,old)
    def test_idempotent(self):
        first=m.updated_config(self.RAW);self.assertEqual(m.updated_config(first),first)
    def test_preserves_unknown_existing_custom_workdir(self):
        with self.assertRaisesRegex(RuntimeError,'preserved'):
            m.updated_config(self.RAW.replace(b'[firecracker]\n',b'[firecracker]\nwork_dir = "/different"\n'))
    def test_duplicate_section_rejected(self):
        with self.assertRaises(RuntimeError):m.updated_config(self.RAW+b'\n[firecracker]\n')
    def test_linux_path_budget(self):
        old='/home/jwk/agent/deployments/agentenv-ae9c626-baseline/state/firecracker-work/agentenv-fc-wIpjK3/firecracker.socket'
        new='/home/jwk/agent/r/fc-a-base/agentenv-fc-XXXXXX/firecracker.socket'
        self.assertEqual(len(old.encode()),114);self.assertLess(len(new.encode()),107)
    def test_reviewed_root_code_exact_unit_and_empty_inventory_gate(self):
        script=m.root_restart_text('a'*64,66497,'667294').split('\n',1)[1].rsplit('\n',1)[0]
        ast.parse(script)
        self.assertIn("'restart',unit",script)
        self.assertIn("json.loads(data)==[]",script)
        self.assertIn("jwk-aenv-ae9c626-node-a.service",script)
        self.assertNotIn('setcap',script);self.assertNotIn('setfacl',script)
        self.assertNotIn('node-b',script);self.assertNotIn('$',script)

    def run_verify(self, original=None, modified=None, bad_hash=False):
        original = original or {'MainPID':'2','start_ticks':'200'}
        modified = modified or {'MainPID':'3','start_ticks':'300'}
        config=m.updated_config(self.RAW)
        marker={'status':'A_ORIGINAL_FC_PATH_CONFIG_APPLIED_RESTART_REQUIRED','unit':m.UNIT,
                'new_config_sha256':'bad' if bad_hash else hashlib.sha256(config).hexdigest(),
                'original_process_before':{'MainPID':'1','start_ticks':'100'},
                'modified_process_before':{'MainPID':'3','start_ticks':'300'},
                'report_directory':'fixture','settings':{}}
        result={}
        with patch.object(m,'read',side_effect=lambda p: json.dumps(marker).encode() if p==m.MARKER else config), \
             patch.object(m,'state',side_effect=lambda unit=m.UNIT: original if unit==m.UNIT else modified), \
             patch.object(m,'health',return_value=204) as health, \
             patch.object(m,'empty_runtime') as inventory, patch.object(m.time,'sleep'):
            m.verify(result)
            self.assertEqual(health.call_count,6)
            inventory.assert_called_once()
        return result

    def test_verify_requires_actual_restart(self):
        with self.assertRaisesRegex(RuntimeError,'has not restarted'):
            self.run_verify(original={'MainPID':'1','start_ticks':'100'})

    def test_verify_rejects_changed_modified_runtime(self):
        with self.assertRaisesRegex(RuntimeError,'Modified runtime identity changed'):
            self.run_verify(modified={'MainPID':'4','start_ticks':'400'})

    def test_verify_rejects_changed_config(self):
        with self.assertRaisesRegex(RuntimeError,'Config changed'):
            self.run_verify(bad_hash=True)

    def test_verified_health_does_not_claim_guest_or_cow_success(self):
        result=self.run_verify()
        self.assertEqual(result['status'],'A_ORIGINAL_FC_PATH_RESTART_VERIFIED')
        self.assertFalse(result['Guest_or_CoW_tests_executed'])
        self.assertFalse(result['parent_create_retried'])
        self.assertFalse(result['pending_receipt_modified'])

if __name__=='__main__':unittest.main(verbosity=2)
