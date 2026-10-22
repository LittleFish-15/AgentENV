import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('four_contract', Path(__file__).with_name('four_contract.py'))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def fixture():
    history = {'validation': {'status': 'COW4_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED',
                              'all_cohort_guests_released': True}, 'jobs': []}
    inputs = {'cohort': {'cases': []}, 'replays': {}}
    build = {'cases': []}
    for i in range(4):
        raw = json.dumps({'trajectory': [{'action': 'printf fixture'}, {'action': 'submit'}]}).encode()
        pin = hashlib.sha256(raw).hexdigest()
        case = {'instance_id': 'fixture-' + str(i), 'replay_file': str(i) + '.json',
                'replay_sha256': pin, 'executable_steps': 1}
        inputs['cohort']['cases'].append(case)
        inputs['replays'][case['replay_file']] = base64.b64encode(raw).decode()
        original = {**case, 'state': 'READY', 'template_id': str(i), 'catalog_sha256': str(i) * 64,
                    'resources': {'memory_mib': 4096, 'cpu_count': 2, 'disk_size_mib': 65536}}
        build['cases'].append(original)
        for slot in (0, 1):
            history['jobs'].append({**case, 'index': 2 * i + slot, 'slot': slot, 'template_id': str(i),
                                    'catalog_sha256': str(i) * 64, 'state': 'REPLAY_COMPLETED',
                                    'steps_completed': 1, 'sandbox_id': str(i) + '-' + str(slot)})
    return history, inputs, build


class ContractTests(unittest.TestCase):
    def test_exact_eight_and_sixteen_not_half_sized_dual(self):
        selected = contract.select_four(*fixture())
        single = contract.scenario_jobs(selected, 'single-a')
        dual = contract.scenario_jobs(selected, 'dual-ab')
        self.assertEqual(len(single), 8)
        self.assertEqual(len(dual), 16)
        for node in ('node-a', 'node-b'):
            self.assertEqual(len([j for j in dual if j['node'] == node]), 8)

    def test_reference_cleanup_is_required(self):
        history, inputs, build = fixture()
        history['validation']['all_cohort_guests_released'] = False
        with self.assertRaises(ValueError):
            contract.select_four(history, inputs, build)

    def test_duplicate_slot_is_not_two_sandboxes(self):
        history, inputs, build = fixture()
        history['jobs'][1]['slot'] = 0
        with self.assertRaises(ValueError):
            contract.select_four(history, inputs, build)

    def test_changed_private_replay_refused(self):
        history, inputs, build = fixture()
        inputs['replays']['0.json'] = base64.b64encode(b'{}').decode()
        with self.assertRaises(ValueError):
            contract.select_four(history, inputs, build)

    def test_changed_catalog_refused(self):
        history, inputs, build = fixture()
        build['cases'][0]['catalog_sha256'] = 'b' * 64
        with self.assertRaises(ValueError):
            contract.select_four(history, inputs, build)

    def test_planning_count_may_include_terminal_marker(self):
        history, inputs, build = fixture()
        for case in inputs['cohort']['cases']:
            case['executable_steps'] = 2
        selected = contract.select_four(history, inputs, build)
        self.assertTrue(all(case['executedStepCount'] == 1 for case in selected))

    def test_original_source_prefix_does_not_include_capture_upper(self):
        layer = {'digest': 'sha256:' + 'a' * 64, 'size': 4096}
        original = {'template_id': 'test', 'resources': {'memory_mib': 4096}}
        record = {'id': 'test', 'resources': original['resources'],
                  'committed': {'rootfs_layers': [{'Managed': layer}, {'Managed': {'digest': 'sha256:' + 'b' * 64, 'size': 4096}}]}}
        value = contract.source_from_record(record, {'lowers': [layer], 'upper': {}}, original)
        self.assertEqual(value['captureOnlyLayerCount'], 1)
        self.assertEqual(value['sourceImage'], contract.source_identity([layer]))
        changed = copy.deepcopy(layer)
        changed['size'] += 4096
        with self.assertRaises(ValueError):
            contract.source_from_record(record, {'lowers': [changed]}, original)

    def test_mutable_source_refused(self):
        layer = {'digest': 'sha256:' + 'a' * 64, 'size': 4096}
        original = {'template_id': 'test', 'resources': {}}
        record = {'id': 'test', 'resources': {}, 'committed': {'rootfs_layers': [{'Managed': layer}] * 2}}
        with self.assertRaises(ValueError):
            contract.source_from_record(record, {'lowers': [layer], 'upper': {'data': '/mutable'}}, original)

    def test_historical_comparison_never_becomes_controlled_net_claim(self):
        history, inputs, build = fixture()
        selected = contract.select_four(history, inputs, build)
        reports = []
        for scenario, node in (('single-a', 'node-a'), ('dual-ab', 'node-a'), ('dual-ab', 'node-b')):
            jobs = [dict(j, sandboxId=str(i), state='REPLAY_COMPLETED')
                    for i, j in enumerate(contract.scenario_jobs(selected, scenario)) if j['node'] == node]
            reports.append({'scenario': scenario, 'node': node, 'jobs': jobs,
                            'ownedGuestsReleased': True, 'outcomeUncertain': False})
        result = contract.validate_comparison_scope(history, reports)
        self.assertIsNone(result['globalNetSavingBytes'])
        self.assertFalse(result['controlledABExperiment'])
        reports[2]['jobs'].pop()
        with self.assertRaises(ValueError):
            contract.validate_comparison_scope(history, reports)


if __name__ == '__main__':
    unittest.main()
