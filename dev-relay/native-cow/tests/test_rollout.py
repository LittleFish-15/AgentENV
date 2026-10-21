import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import subprocess
import sys
import types
import unittest
from unittest import mock
import uuid

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('rollout', HERE.parent / 'native_rollout.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
sync_spec = importlib.util.spec_from_file_location('pair_module', HERE.parent / 'cohort_sync.py')
SYNC = importlib.util.module_from_spec(sync_spec)
sync_spec.loader.exec_module(SYNC)


class Tests(unittest.TestCase):
    def test_failed_provider_is_terminal_before_service_poll(self):
        with mock.patch.object(m, 'ordinary'), mock.patch.object(m, 'load', return_value={'state': 'unresolved_preserved'}), \
                mock.patch.object(m.subprocess, 'run') as run:
            with self.assertRaises(m.TerminalReadinessFailure):
                m.ready('node-a')
        run.assert_not_called()

    def test_a_terminal_failure_does_not_wait_fifteen_minutes(self):
        with mock.patch.object(m, 'ready', side_effect=m.TerminalReadinessFailure('failed')), \
                mock.patch.object(m.time, 'sleep') as sleep:
            with self.assertRaises(m.TerminalReadinessFailure):
                m.wait_ready('node-a')
        sleep.assert_not_called()

    def test_loaded_unit_not_yet_executed_is_still_waiting(self):
        response = types.SimpleNamespace(returncode=0, stdout='LoadState=loaded\nActiveState=inactive\nExecMainCode=0\n')
        with mock.patch.object(m, 'ordinary'), mock.patch.object(m, 'load', return_value={'state': 'serving'}), \
                mock.patch.object(m.subprocess, 'run', return_value=response):
            with self.assertRaisesRegex(RuntimeError, 'not active yet') as caught:
                m.ready('node-a')
        self.assertNotIsInstance(caught.exception, m.TerminalReadinessFailure)

    def test_b_terminal_failure_does_not_wait_fifteen_minutes(self):
        response = types.SimpleNamespace(returncode=1, stdout=b'{"errorType":"TerminalReadinessFailure"}', stderr=b'')
        with mock.patch.object(m.subprocess, 'run', return_value=response), mock.patch.object(m.time, 'sleep') as sleep:
            with self.assertRaises(m.TerminalReadinessFailure):
                m.wait_ready('node-b')
        sleep.assert_not_called()

    def pair_fixture(self, early=False, release_failure=False):
        epoch = 'a' * 32
        events, saved, phase = [], [], {'measuring': False}
        readies = {node: {'node': node, 'variant': 'native', 'epoch': epoch,
                         'runId': ('b' if node == 'node-a' else 'c') * 32,
                         'sandboxIds': [node + '-1', node + '-2']} for node in SYNC.NODES}
        measurements = {node: {'node': node, 'epoch': epoch, 'readySha256': SYNC.digest(readies[node]),
                              'sampleSha256': 'd' * 64} for node in SYNC.NODES}
        def control(node, variant, value, operation, payload=None):
            self.assertEqual((variant, value), ('native', epoch))
            events.append((node, operation))
            if operation == 'status':
                return {'ready': readies[node], 'measured': measurements[node] if phase['measuring'] else None,
                        'abort': None, 'failed': None}
            if operation == 'measure' and node == 'node-a':
                phase['measuring'] = True
            if operation == 'release' and node == 'node-a' and release_failure:
                raise RuntimeError('A release delivery failed')
            return {'recorded': operation}
        class Future:
            def __init__(self, local):self.local = local
            def done(self):return self.local and early
            def result(self):return {'node': 'node-a'} if self.local else (Path('log'), 0)
        class Pool:
            def __init__(self, **kwargs):self.count = 0
            def __enter__(self):return self
            def __exit__(self, *args):return False
            def submit(self, fn, *args):
                self.count += 1
                return Future(self.count == 1)
        sync = types.SimpleNamespace(prepare=lambda n, v, e: control(n, v, e, 'prepare'),
                                     control=control, control_message=SYNC.control_message)
        steps = types.SimpleNamespace(call=lambda *a: None)
        with mock.patch.object(m, 'sync_module', return_value=sync), \
                mock.patch.object(m.uuid, 'uuid4', return_value=types.SimpleNamespace(hex=epoch)), \
                mock.patch.object(m.concurrent.futures, 'ThreadPoolExecutor', Pool), \
                mock.patch.object(m, 'remote_pair', side_effect=lambda v, e, o, p=None: control('node-b', v, e, o, p)), \
                mock.patch.object(m.time, 'sleep'), mock.patch.object(m, 'save', side_effect=lambda p, v: saved.append(copy.deepcopy(v))), \
                mock.patch.object(m, 'fetch_b', return_value='{"node":"node-b"}'):
            result = m.run_pair('native', steps)
        self.assertEqual(result, ({'node': 'node-a'}, {'node': 'node-b'}))
        return events, saved[-1]

    def test_pair_releases_only_after_both_samples(self):
        events, report = self.pair_fixture()
        self.assertEqual(report['status'], 'COORDINATED_POST_WORKLOAD_HOLD_RELEASED')
        self.assertEqual(events[-2:], [('node-b', 'release'), ('node-a', 'release')])
        self.assertLess(events.index(('node-a', 'measure')), events.index(('node-b', 'release')))
        self.assertEqual(set(report['measurements']), {'node-a', 'node-b'})

    def test_early_worker_exit_aborts_both_without_measure_or_release(self):
        events, report = self.pair_fixture(early=True)
        self.assertEqual(report['status'], 'PAIR_STOPPED_PRESERVE_COHORT_JOURNALS')
        self.assertEqual(events[-2:], [('node-a', 'abort'), ('node-b', 'abort')])
        self.assertFalse(any(op in ('measure', 'release') for node, op in events))

    def test_partial_release_is_not_reported_as_completed(self):
        events, report = self.pair_fixture(release_failure=True)
        self.assertEqual(report['status'], 'PAIR_STOPPED_PRESERVE_COHORT_JOURNALS')
        self.assertEqual(events[-2:], [('node-a', 'abort'), ('node-b', 'abort')])

    def directory(self):
        path = HERE / 't' / uuid.uuid4().hex[:8]
        path.mkdir(parents=True)
        return path

    def test_plan_never_initializes_target_or_download(self):
        result = subprocess.run([sys.executable, str(HERE.parent / 'native_rollout.py'), 'run-a'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['status'], 'PLAN_ONLY')

    def test_remote_command_has_fixed_host_and_quoted_args(self):
        args = ['b-fetch', '--file', 'x; touch /tmp/UNWANTED']
        command = m.remote_command(args)
        self.assertEqual(command[:-1], m.SSH)
        self.assertIn('-oStrictHostKeyChecking=yes', command)
        self.assertIn('-oBatchMode=yes', command)
        self.assertEqual(shlex.split(command[-1])[-4:], [*args, '--run'])

    def test_root_blocks_have_fail_stop_subshell(self):
        first = '/usr/bin/python3 -I -B - <<\'A\'\nprint("provider")\nA\n'
        second = '/usr/bin/python3 -I -B - <<\'B\'\nprint("runtime")\nB\n'
        rows = [b'BEGIN_REAL_PROVIDER_ROOT_BLOCK\n' + first.encode() + b'END_REAL_PROVIDER_ROOT_BLOCK',
                b'BEGIN_NATIVE_CONTROL_PLAN\n' + second.encode() + b'END_NATIVE_CONTROL_PLAN']
        with mock.patch.object(m, 'read', side_effect=rows):
            block = m.combined_root('node-a', [Path('a'), Path('b')])
        self.assertTrue(block.startswith('/usr/bin/bash -e <<'))
        self.assertLess(block.index('provider'), block.index('runtime'))

    def test_duplicate_or_wrong_root_block_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'exactly one'):
            m.root_block('BEGIN BEGIN END', 'BEGIN', 'END')
        with self.assertRaisesRegex(RuntimeError, 'prefix'):
            m.root_block('BEGIN\nrm arbitrary\nEND', 'BEGIN', 'END')

    def test_official_download_rejects_redirect(self):
        with self.assertRaisesRegex(RuntimeError, 'redirect'):
            m.OfficialOnly().redirect_request(None, None, 302, '', {}, 'https://other.example/script')

    def test_existing_helper_must_match_exact_content(self):
        directory = self.directory()
        path = directory / 'helper.py'
        path.write_bytes(b'keep')
        with mock.patch.object(m, 'safe', side_effect=lambda p, *a: p), mock.patch.object(m, 'read', return_value=b'keep'):
            m.install_bytes(path, b'keep', hashlib.sha256(b'keep').hexdigest())
            with self.assertRaisesRegex(RuntimeError, 'preserve it'):
                m.install_bytes(path, b'changed', hashlib.sha256(b'changed').hexdigest())
        self.assertEqual(path.read_bytes(), b'keep')

    def test_corrupt_download_never_written(self):
        directory = self.directory()
        with self.assertRaisesRegex(RuntimeError, 'hash differs'):
            m.install_bytes(directory / 'new.py', b'bad', 'a' * 64)
        self.assertFalse((directory / 'new.py').exists())

    def test_fresh_stage_journal_required(self):
        directory = self.directory()
        (directory / 'steps-node-a.json').write_text('{}')
        with mock.patch.object(m, 'WORK', directory), mock.patch.object(m, 'safe', side_effect=lambda p: p):
            with self.assertRaisesRegex(RuntimeError, 'Existing rollout'):
                m.Steps('node-a')

    def test_incomplete_baseline_stops_before_provider_start(self):
        self.workflow(False)

    def test_full_control_order_prepares_before_sdk_and_root_before_cohort(self):
        self.workflow(True)

    def workflow(self, success):
        directory = self.directory()
        work = directory / 'work'
        work.mkdir()
        events = []
        class Steps:
            def __init__(self, node):
                self.state = {}
                self.path = work / 'steps.json'
            def local(self, phase, entry, args=(), *rest):
                events.append(phase)
                return work / (phase + '.log'), 0
            def call(self, phase, command, *rest):
                events.append(phase)
                return work / (phase + '.log'), 0
        own = {'cohort': {'phase': 'quiesced' if success else 'needs_reconciliation',
                          'sandboxIds': [], 'openRequests': [], 'outcomeUncertain': False}}
        def fake_cohort(node, variant, *args):
            events.append(variant + '-' + node)
            return own
        def fetch(name):
            events.append('fetch-' + name)
            return json.dumps(own) if name.endswith('.json') else 'B ROOT BLOCK\n'
        def pair(variant, steps):
            events.append(variant + '-node-a')
            events.append('fetch-' + variant + '-node-b.json')
            return own, own
        entry = directory / 'native_rollout.py'
        with contextlib.ExitStack() as stack:
            for name, value in {'ROOT': directory, 'WORK': work, 'SELF': entry, '__file__': str(entry),
                                'PUBLIC_PINS': {'public.py': 'p'}, 'Steps': Steps}.items():
                stack.enter_context(mock.patch.object(m, name, value))
            stack.enter_context(mock.patch.object(m, 'ordinary'))
            stack.enter_context(mock.patch.object(m, 'download', side_effect=lambda: events.append('download')))
            stack.enter_context(mock.patch.object(m, 'load', return_value={'rootfsReady': True}))
            stack.enter_context(mock.patch.object(m, 'sha', return_value='a' * 64))
            stack.enter_context(mock.patch.object(m, 'transfer', side_effect=lambda *a: events.append('transfer') or 'a' * 64))
            stack.enter_context(mock.patch.object(m, 'cohort', side_effect=fake_cohort))
            stack.enter_context(mock.patch.object(m, 'run_pair', side_effect=pair))
            stack.enter_context(mock.patch.object(m, 'fetch_b', side_effect=fetch))
            stack.enter_context(mock.patch.object(m, 'wait_ready', side_effect=lambda node: events.append('ready-' + node)))
            stack.enter_context(mock.patch.object(m, 'combined_root', return_value='A ROOT BLOCK\n'))
            stack.enter_context(mock.patch.object(m, 'save'))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            if success:
                m.run_a()
            else:
                with self.assertRaisesRegex(RuntimeError, 'Original cohort did not confirm quiescence'):
                    m.run_a()
        self.assertLess(events.index('prepare-b'), events.index('legacy-sdk-handoff'))
        self.assertLess(events.index('seed-rootfs-a'), events.index('legacy-sdk-handoff'))
        self.assertLess(events.index('legacy-sdk-handoff'), events.index('original-node-a'))
        if success:
            self.assertLess(events.index('original-node-a'), events.index('provider-root-a'))
            self.assertLess(events.index('ready-node-a'), events.index('prepare-b-root'))
            self.assertLess(events.index('ready-node-b'), events.index('native-node-a'))
            self.assertLess(events.index('fetch-native-node-b.json'), events.index('comparison-report'))
        else:
            self.assertNotIn('provider-root-a', events)
            self.assertNotIn('native-node-a', events)


if __name__ == '__main__':
    unittest.main()
