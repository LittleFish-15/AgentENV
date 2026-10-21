import copy
import importlib.util
from pathlib import Path
from unittest import mock
import unittest
import types

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


RAM, REPORT, DRIVER = (module(n) for n in ('ram_observer', 'cohort_report', 'native_cohort'))


def smaps(start='1000', end='3000', path='/dev/ublkb7', offset='00000000', perms='rw-p'):
    return f'{start}-{end} {perms} {offset} 00:00 1 {path}\nRss: 8 kB\nPss: 4 kB\nPrivate_Dirty: 0 kB\n'


def report(node, variant, value=100):
    metric = {'available': True, 'rss_bytes': 100, 'pss_bytes': 75}
    return {'node': node, 'variant': variant, 'sourceImage': 'same', 'workloadSha256': 'work',
            'bootId': 'boot-' + node, 'status': 'COHORT_FUNCTIONAL_PASS_SNAPSHOTS_RETAINED',
            'cohort': {'lifecyclePassed': True, 'phase': 'quiesced', 'outcomeUncertain': False,
                       'openRequests': [], 'sandboxIds': [],
                       'workloads': [{'passed': True, 'privateUpperIsolationPassed': True, 'result': {
                           'revision': 'public-pypika-v1', 'catalogSha256': 'catalog', 'sqlSha256': 'sql',
                           'queryCount': 2000, 'fileCount': 20, 'fileBytes': 1000, 'seconds': 3}} for _ in range(2)],
                       'samples': [{'phase': 'after_workload',
                                    'runtimeCharge': {'available': True, 'currentBytes': value},
                                    'ram': {'available': True, 'guests': [
                                        {'wholeProcess': dict(metric), 'guestRam': {'bytes': {'Pss': value}}}
                                        for _ in range(2)]}}]}}


def four():
    return [report(n, v, 100 if v == 'original' else 80)
            for n in ('node-a', 'node-b') for v in ('original', 'native')]


class RamTests(unittest.TestCase):
    def parse(self, text, regions, expected=8192):
        with mock.patch.object(RAM.os, 'sysconf', create=True, return_value=4096):
            return RAM.parse_guest_smaps(text, '/dev/ublkb7', expected, regions)

    def test_authoritative_interval_selects_real_mapping(self):
        result = self.parse(smaps(), [{'base_host_virt_addr': 4096, 'size': 8192, 'offset': 0}])
        self.assertEqual(result[0]['bytes']['Pss'], 4096)
        self.assertEqual(result[0]['mapping_kind'], 'snapshot_file_vma')

    def test_clipped_smaps_does_not_scale_or_assign_whole_vma_metrics(self):
        result = self.parse(smaps(), [{'base_host_virt_addr': 4096, 'size': 4096, 'offset': 0}], 4096)
        self.assertEqual(result[0]['bytes'], {})
        self.assertTrue(result[0]['smaps_metrics_omitted_due_to_clipping'])

    def test_anonymous_only_with_authoritative_address(self):
        result = self.parse(smaps(path=''), [{'base_host_virt_addr': 4096, 'size': 8192, 'offset': 0}])
        self.assertEqual(result[0]['mapping_kind'], 'anonymous_inside_guest_region')
        with self.assertRaises(RAM.BindingError):
            self.parse(smaps(path=''), None)

    def test_wrong_named_file_rejected(self):
        with self.assertRaises(RAM.BindingError):
            self.parse(smaps(path='/some/other/file'), [{'base_host_virt_addr': 4096, 'size': 8192, 'offset': 0}])

    def test_offset_mismatch_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'offset differs'):
            self.parse(smaps(offset='00001000'), [{'base_host_virt_addr': 4096, 'size': 8192, 'offset': 0}])

    def test_shared_ram_mapping_does_not_pass_private_validation(self):
        with self.assertRaisesRegex(RuntimeError, 'privately mapped'):
            self.parse(smaps(perms='rw-s'), [{'base_host_virt_addr': 4096, 'size': 8192, 'offset': 0}])

    def test_gap_in_authoritative_offset_coverage_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'offsets'):
            self.parse(smaps(), [{'base_host_virt_addr': 4096, 'size': 4096, 'offset': 4096}])


class ReportTests(unittest.TestCase):
    def test_partial_metric_positive_is_never_global_gain(self):
        result = REPORT.compare(four())
        self.assertEqual(result['nodes']['node-a']['runtimeCgroupChargeBytes']['reduction'], 20)
        self.assertIsNone(result['globalNetSavingBytes'])
        self.assertFalse(result['memfileCrossNodeCowAccepted'])
        self.assertFalse(result['rootfsCrossNodePhysicalSharingAcceptedByThisReport'])

    def test_negative_reduction_is_preserved(self):
        inputs = four()
        inputs[1]['cohort']['samples'][0]['runtimeCharge']['currentBytes'] = 150
        self.assertEqual(REPORT.compare(inputs)['nodes']['node-a']['runtimeCgroupChargeBytes']['reduction'], -50)

    def test_missing_ram_does_not_fill_zero(self):
        inputs = four()
        inputs[1]['cohort']['samples'][0]['ram']['available'] = False
        result = REPORT.compare(inputs)['nodes']['node-a']
        self.assertIsNone(result['actualGuestRamPssSumBytes']['native'])
        self.assertIsNone(result['actualGuestRamPssSumBytes']['reduction'])

    def test_clipped_pss_unavailable(self):
        inputs = four()
        inputs[1]['cohort']['samples'][0]['ram']['guests'][0]['guestRam']['bytes']['Pss'] = None
        self.assertIsNone(REPORT.compare(inputs)['nodes']['node-a']['actualGuestRamPssSumBytes']['native'])

    def test_mismatched_guest_contents_no_compare(self):
        inputs = four()
        inputs[1]['cohort']['workloads'][0]['result']['catalogSha256'] = 'different'
        result = REPORT.compare(inputs)
        self.assertFalse(result['matchedInputsAndGuestOutputs'])
        self.assertIsNone(result['nodes']['node-a']['guestWorkloadMeanSeconds']['reduction'])

    def test_failed_cleanup_prevents_comparison(self):
        inputs = four()
        inputs[1]['cohort']['sandboxIds'] = ['still-there']
        result = REPORT.compare(inputs)
        self.assertFalse(result['allFourFunctionalCohortsPassed'])
        self.assertIsNone(result['nodes']['node-a']['runtimeCgroupChargeBytes']['reduction'])

    def test_other_boot_no_paired_metric(self):
        inputs = four()
        inputs[1]['bootId'] = 'other-boot'
        result = REPORT.compare(inputs)
        self.assertFalse(result['nodes']['node-a']['comparablePublicWorkload'])
        self.assertIsNone(result['nodes']['node-a']['actualGuestRamPssSumBytes']['reduction'])

    def test_duplicate_node_rejected(self):
        inputs = four()
        inputs[-1] = copy.deepcopy(inputs[0])
        with self.assertRaisesRegex(ValueError, 'Repeated or missing'):
            REPORT.compare(inputs)

    def test_conditional_process_rss_pss_label(self):
        result = REPORT.conditional_process_sharing(four()[0])
        self.assertEqual(result['conditionalBytes'], 50)
        self.assertFalse(result['memfileAttributionEstablished'])
        self.assertFalse(result['externalSharersExcluded'])


class SnapshotTests(unittest.TestCase):
    def test_changed_runtime_cannot_recover_own_old_batch(self):
        api = types.SimpleNamespace(unit='own-unit', pid=100, ticks='200', config_sha='config')
        context = {'node': 'node-a', 'variant': 'native', 'unit': api.unit, 'runtimePid': api.pid,
                   'runtimeTicks': api.ticks, 'configSha256': api.config_sha, 'bootId': 'boot'}
        for field, value in [('runtimePid', 101), ('runtimeTicks', '201'), ('configSha256', 'changed')]:
            changed = dict(context)
            changed[field] = value
            with self.subTest(field=field), mock.patch.object(Path, 'read_text', return_value='boot'):
                with self.assertRaisesRegex(RuntimeError, 'Recovery boot, Runtime'):
                    DRIVER.recovery_context({'runtimeContext': changed}, api, 'node-a', 'native')

    def test_changed_boot_cannot_recover(self):
        api = types.SimpleNamespace(unit='own-unit', pid=100, ticks='200', config_sha='config')
        context = {'node': 'node-a', 'variant': 'native', 'unit': api.unit, 'runtimePid': api.pid,
                   'runtimeTicks': api.ticks, 'configSha256': api.config_sha, 'bootId': 'old-boot'}
        with mock.patch.object(Path, 'read_text', return_value='new-boot'):
            with self.assertRaisesRegex(RuntimeError, 'Recovery boot, Runtime'):
                DRIVER.recovery_context({'runtimeContext': context}, api, 'node-a', 'native')

    def test_missing_recovery_context_is_not_guessed(self):
        api = types.SimpleNamespace(unit='own-unit', pid=100, ticks='200', config_sha='config')
        with mock.patch.object(Path, 'read_text', return_value='boot'):
            with self.assertRaisesRegex(RuntimeError, 'Recovery boot, Runtime'):
                DRIVER.recovery_context({}, api, 'node-a', 'native')

    def test_native_snapshot_requires_binding_content(self):
        base = Path('/fixture')
        binding = {'layers': [{'sha256': 'sha256:' + 'a' * 64, 'bytes': 4096}]}
        native = {'version': 1, 'sourceImage': DRIVER.SOURCE, 'filesystem': 'ext4',
                  'layers': copy.deepcopy(binding['layers'])}
        def loader(path):
            return {'id': 'own'} if path.name == 'own.json' else {
                'nativeRootfs': native, 'memory': {'virtualSize': 512 * 1024**2}}
        with mock.patch.object(DRIVER, 'load', side_effect=loader), mock.patch.object(DRIVER, 'read', return_value=b'{}'):
            self.assertEqual(DRIVER.snapshot_evidence(base, 'own', 'native', binding)['nativeRootfs'], native)
            native['layers'][0]['bytes'] = 8192
            with self.assertRaisesRegex(RuntimeError, 'differs from live binding'):
                DRIVER.snapshot_evidence(base, 'own', 'native', binding)


if __name__ == '__main__':
    unittest.main()
