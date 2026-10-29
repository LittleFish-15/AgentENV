import hashlib
import base64
import importlib.util
import json
from pathlib import Path
import unittest
import uuid

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('inventory', HERE / 'AB_inventory_for_cd_v1.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)
kernel_spec = importlib.util.spec_from_file_location('kernel_materials', HERE / 'D_kernel_materials_readonly_v1.py')
kernel = importlib.util.module_from_spec(kernel_spec)
kernel_spec.loader.exec_module(kernel)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.root = HERE.parents[1] / 't' / ('bi-' + uuid.uuid4().hex[:8])
        self.root.mkdir(mode=0o755, parents=True)
        inventory.ROOT = self.root.resolve()

    def put(self, name, data):
        path = self.root / name
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_path_escape_rejected(self):
        with self.assertRaises(ValueError):
            inventory.safe(self.root / '..' / 'B_inventory_local_relay_v1.py')

    def test_missing_file_stays_missing(self):
        row = inventory.info(self.root / 'missing')
        self.assertFalse(row['present'])
        self.assertFalse(row['contentHashed'])

    def test_stat_only_does_not_claim_content_hash(self):
        path = self.put('layer', b'payload')
        row = inventory.info(path)
        self.assertEqual(row['bytes'], 7)
        self.assertFalse(row['contentHashed'])
        self.assertNotIn('sha256', row)

    def test_runtime_config_values_are_not_dumped(self):
        base = 'deployments/test-runtime'
        fc = self.put(base + '/deps/firecracker', b'ELF-placeholder')
        config = ('deps_path = ' + json.dumps(str(fc.parent)) + '\n[firecracker]\nbinary_path = '
                  + json.dumps(str(fc)) + '\n[private]\nkey="not-for-report"\n').encode()
        self.put(base + '/config/runtime.toml', config)
        row = inventory.runtime('test-runtime')
        self.assertNotIn('not-for-report', json.dumps(row))
        self.assertEqual(row['firecracker']['sha256'], hashlib.sha256(b'ELF-placeholder').hexdigest())

    def test_snapshot_reports_memory_dependency_without_claiming_full_closure(self):
        base = 'deployments/agentenv-lazy-four-32ce41c'
        repo = self.root / base / 'state/snapshot-store/repository'
        digest = 'sha256:' + hashlib.sha256(b'lower').hexdigest()
        layer = {'digest': digest, 'size': 5}
        record = {'id': inventory.TEMPLATE, 'committed': {'rootfs_layers': [{'Managed': layer}],
                    'memory_layers': [layer], 'runtime_versions': {}}}
        raw = json.dumps(record).encode()
        self.put(base + '/state/snapshot-store/repository/catalog/records/' + inventory.TEMPLATE + '.json', raw)
        self.put(base + '/state/snapshot-store/repository/managed-layers/' + digest.replace(':', '_') + '.overlaybd.commit', b'lower')
        seed = {'repository': str(repo), 'templates': [{'templateId': inventory.TEMPLATE,
                'catalogSha256': hashlib.sha256(raw).hexdigest(), 'rootfsLayers': [layer]}]}
        self.put(base + '/rootfs-inputs.json', json.dumps(seed).encode())
        row = inventory.snapshot()
        self.assertEqual(len(row['layers']['memory_layers']), 1)
        self.assertFalse(row['fullRecoveryClosureVerified'])
        self.assertFalse(row['artifacts']['vm_state.bin']['present'])

    def test_private_replay_is_validated_without_printing_contents(self):
        payload = b'PRIVATE_WORKLOAD_FIXTURE_NOT_FOR_OUTPUT'
        digest = hashlib.sha256(payload).hexdigest()
        selection = {'selected': [{'original': {'template_id': inventory.TEMPLATE},
                     'case': {'instance_id': 'case-fixture', 'replay_sha256': digest},
                     'replayBase64': base64.b64encode(payload).decode(), 'executedStepCount': 1}]}
        raw = json.dumps(selection).encode()
        self.put('input/selection.private.json', raw)
        manifest = json.dumps({'files': {'selection.private.json': {'sha256': hashlib.sha256(raw).hexdigest()}}}).encode()
        self.put('input/manifest.json', manifest)
        seed = {'inputDirectory': str(self.root / 'input'), 'sourceManifestSha256': hashlib.sha256(manifest).hexdigest()}
        selected = {'instanceId': 'case-fixture', 'replaySha256': digest}
        row = inventory.replay_inventory(seed, selected)
        self.assertTrue(row['replayIdentityVerified'])
        self.assertNotIn(payload.decode(), json.dumps(row))
        self.assertNotIn(selection['selected'][0]['replayBase64'], json.dumps(row))

    def test_kernel_disabled_distinguished_from_unknown(self):
        values = kernel.config_fields(b'CONFIG_MODULES=y\n# CONFIG_BLK_DEV_UBLK is not set\nCONFIG_LOCALVERSION="-org1028"\n')
        self.assertEqual(values['CONFIG_BLK_DEV_UBLK'], 'n')
        self.assertIsNone(values['CONFIG_FS_DAX'])

    def test_kernel_candidate_not_accepted_as_matching_runtime(self):
        self.put('kernel/Module.symvers', b'fixture')
        self.put('kernel/include/generated/utsrelease.h', b'#define UTS_RELEASE "fixture"\n')
        row = kernel.candidate(self.root / 'kernel')
        self.assertTrue(row['buildCandidate'])
        self.assertFalse(row['sourceCandidate'])
        self.assertFalse(row['matchesRunningKernelConfirmed'])

    def test_kernel_search_budget_cannot_claim_source_absent(self):
        self.put('nested/kernel/Module.symvers', b'fixture')
        row = kernel.search([self.root], max_dirs=1, seconds=2)
        self.assertTrue(row['budgetReached'])
        self.assertEqual(row['candidateTrees'], [])


if __name__ == '__main__':
    unittest.main()
