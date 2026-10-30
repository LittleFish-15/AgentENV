import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

P=Path(__file__).with_name('AB_reboot_readiness_v1.py')
s=importlib.util.spec_from_file_location('readiness',P)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)


class Checks(unittest.TestCase):
    def test_changed_machine_rejected_before_observation(self):
        class API:
            @staticmethod
            def identity():
                return {'hostname':'server1','machineId':'different','gid':1205,
                        'uid':1204,'architecture':'aarch64','bootId':'new'}
        config={'node':'node-a','sessionId':m.SESSION,
                'identity':dict(API.identity(),machineId='old')}
        with patch.object(m,'unit',side_effect=AssertionError('must not inspect')):
            with self.assertRaisesRegex(RuntimeError,'Physical node'):
                m.inspect(API,config)

    def test_private_state_projection_excludes_keys(self):
        value={'phase':'sdk_start_intent','ownerId':'known', 'api_key':'secret',
               'peerToken':'secret', 'arbitrary':{'payload':'secret'}}
        with patch.object(m,'file_info',return_value={'sha256':None}), \
             patch.object(m,'read',return_value=json.dumps(value).encode()):
            r=m.json_projection('/unused')
        self.assertEqual(r['summary'],{'phase':'sdk_start_intent','ownerId':'known'})
        self.assertNotIn('secret',json.dumps(r))

    def test_only_service_metadata_command(self):
        class Result:
            returncode=0
            stdout='LoadState=loaded\nActiveState=inactive\n'
        with patch.object(m.subprocess,'run',return_value=Result()) as run:
            row=m.unit('ubse.service')
        self.assertEqual(run.call_args.args[0][:2],['/usr/bin/systemctl','show'])
        self.assertEqual(row['properties']['ActiveState'],'inactive')
        self.assertEqual(run.call_args.kwargs['stdin'],m.subprocess.DEVNULL)

    def test_large_container_not_attested(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=P.parent) as tmp:
            p=Path(tmp)/'container.ext4'
            p.write_bytes(b'abc')
            row=m.file_info(p,False,[0])
        self.assertIsNone(row['sha256'])
        self.assertEqual(row['hashStatus'],'metadata_only')

    def test_no_mutation_or_sdk_execution_in_observer(self):
        import ast
        tree=ast.parse(P.read_text(encoding='utf-8'))
        commands=[n for n in ast.walk(tree) if isinstance(n,ast.Call)
                  and isinstance(n.func,ast.Attribute) and n.func.attr=='run']
        self.assertEqual(len(commands),1)
        self.assertNotIn('ctypes',P.read_text())
        self.assertNotIn('os.chmod',P.read_text())
        self.assertNotIn('os.kill',P.read_text())


if __name__=='__main__':unittest.main()
