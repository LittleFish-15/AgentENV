"""First-generation image preparation and map-only import; no SDK or Guest."""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import prebuilt, raw, service
import test_retained_publication as fixtures


class PrebuiltTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RetainedPublicationTests('test_default_plan_verifies_bytes_without_writing_or_opening_sdk')
        self.fixture.setUp(); self.root = self.fixture.root

    def tearDown(self):
        self.fixture.tearDown()

    def selection(self, count=4, shared=False):
        groups = []
        for index in range(count):
            config = self.root / f'config-{index}.json'
            config.write_text(json.dumps({'lowers': [{'digest': 'sha256:'+format(index, '064x'), 'size': 4096}]}))
            image = self.root / f'image-{index}.img'
            image.write_bytes(bytes([10 if shared else 10+index]) * (2*1024**2))
            groups.append({'sourceConfig': str(config), 'paths': [str(image)], 'filesystem': 'ext4'})
        selection = self.root / 'images.json'; selection.write_text(json.dumps({'version': 1, 'images': groups}))
        return selection, groups

    def args(self, budget=16*1024**2):
        f = self.fixture
        return f.runtime, f.out, f.adapter, f.adapter_sha, 'test', budget, 128*1024**2

    def transfer(self, plan):
        # Owner-local POSIX paths are metadata, never accessed by the importer.
        binding = json.loads(json.dumps(plan['binding']))
        for item in binding['bindings']: item['snapshotSources'] = ['/private/owner/image.img']*len(item['layers'])
        path = self.root / 'owner-bindings.json'; path.write_text(json.dumps(binding))
        manifest = self.root / 'owner-replicas.json'
        manifest.write_text(json.dumps({'version':1, 'ownerId':'d'*32, 'mode':'pmem', 'readers':['peer'],
            'replicas':[raw.shape(e['backing'], 'aenv_'+format(i,'032x')) for i,e in enumerate(plan['catalog']['objects'])]}))
        return path, service.identity_bytes(path), manifest, service.identity_bytes(manifest), 'peer'

    def test_four_prebuilt_groups_have_archive_sources_without_claiming_a_snapshot(self):
        selection, groups = self.selection()
        plan = prebuilt.plan_publish(selection, *self.args(), ['peer'])
        self.assertEqual(len(plan['binding']['bindings']), 4)
        self.assertEqual(plan['alignedLogicalBytes'], 16*1024**2)
        self.assertIn('not_guest_acceptance', plan['inputKind'])
        for item, group in zip(plan['binding']['bindings'], groups):
            self.assertEqual(item['version'], 3); self.assertEqual(item['snapshotSources'], group['paths'])
        self.assertFalse(self.fixture.out.exists())

    def test_shared_raw_content_is_one_allocation_but_separate_source_bindings(self):
        selection, _ = self.selection(shared=True)
        plan = prebuilt.plan_publish(selection, *self.args(4*1024**2), ['peer'])
        self.assertEqual(len(plan['catalog']['objects']), 1); self.assertEqual(len(plan['binding']['bindings']), 4)
        self.assertEqual(plan['alignedLogicalBytes'], 4*1024**2)

    def test_import_uses_pinned_catalog_and_exact_replicas_without_owner_paths(self):
        selection, _ = self.selection()
        plan = prebuilt.plan_publish(selection, *self.args(), ['peer'])
        transferred = self.transfer(plan)
        result = prebuilt.plan_import(*transferred, *self.args())
        self.assertEqual(result['config']['role'], 'import')
        for actual, expected in zip(result['binding']['bindings'], plan['binding']['bindings']):
            self.assertEqual(actual['layers'], expected['layers']); self.assertNotIn('snapshotSources', actual)
        self.assertNotIn('/private/owner', json.dumps(result))
        transferred[0].write_text('{}')
        with self.assertRaisesRegex(ValueError, 'SHA256'): prebuilt.plan_import(*transferred, *self.args())

    def test_incorrect_binding_schema_or_missing_replica_is_refused(self):
        selection, _ = self.selection(count=2)
        plan = prebuilt.plan_publish(selection, *self.args(), ['peer'])
        args = list(self.transfer(plan))
        value = json.loads(args[0].read_text()); value['bindings'][0]['version'] = 2; args[0].write_text(json.dumps(value))
        args[1] = service.identity_bytes(args[0])
        with self.assertRaisesRegex(ValueError, 'capture binding'): prebuilt.plan_import(*args, *self.args())
        args = list(self.transfer(plan)); value = json.loads(args[2].read_text()); value['replicas'].pop(); args[2].write_text(json.dumps(value)); args[3] = service.identity_bytes(args[2])
        with self.assertRaisesRegex(ValueError, 'missing'): prebuilt.plan_import(*args, *self.args())

    def test_combined_budget_bad_input_and_mutable_source_config_are_refused(self):
        selection, groups = self.selection(count=2)
        with self.assertRaisesRegex(ValueError, 'Combined'): prebuilt.plan_publish(selection, *self.args(4*1024**2), [])
        config = Path(groups[0]['sourceConfig']); value = json.loads(config.read_text()); value['upper'] = {'data':'mutable'}; config.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'mutable'): prebuilt.plan_publish(selection, *self.args(), [])
        selection.write_text(json.dumps({'version':1, 'images':[dict(groups[0], paths=['relative.img'])]}))
        with self.assertRaisesRegex(ValueError, 'absolute'): prebuilt.image_set(selection)
        self.assertFalse(self.fixture.out.exists())

    def test_cli_default_validates_without_write_or_sdk(self):
        selection, _ = self.selection(count=1); f = self.fixture
        runtime = self.root/'runtime.json'; runtime.write_text(json.dumps(f.runtime))
        args = ['provider','publish-prebuilt-set','--image-set',str(selection),'--device-runtime',str(runtime),
                '--output',str(f.out),'--adapter',str(f.adapter),'--adapter-sha256',f.adapter_sha,'--region','test',
                '--max-bytes',str(16*1024**2),'--coverage-bytes',str(128*1024**2)]
        with patch.object(sys,'argv',args), patch('aenv_ub_provider.retained.execute') as execute, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(service.main(),0); execute.assert_not_called()
        self.assertFalse(f.out.exists())

    def test_changed_raw_content_cannot_execute_a_previously_reviewed_plan(self):
        selection, groups = self.selection(count=1); f = self.fixture
        plan = prebuilt.plan_publish(selection, *self.args(), [])
        runtime = self.root/'runtime.json'; runtime.write_text(json.dumps(f.runtime))
        args = ['provider','publish-prebuilt-set','--image-set',str(selection),'--device-runtime',str(runtime),
                '--output',str(f.out),'--adapter',str(f.adapter),'--adapter-sha256',f.adapter_sha,'--region','test',
                '--max-bytes',str(16*1024**2),'--coverage-bytes',str(128*1024**2),
                '--expected-plan-sha256',service.identity(plan),'--run']
        Path(groups[0]['paths'][0]).write_bytes(b'z'*(2*1024**2))
        with patch.object(sys,'argv',args), patch('aenv_ub_provider.retained.execute') as execute:
            with self.assertRaisesRegex(ValueError,'plan changed'): service.main()
            execute.assert_not_called()
        self.assertFalse(f.out.exists())


if __name__ == '__main__': unittest.main()
