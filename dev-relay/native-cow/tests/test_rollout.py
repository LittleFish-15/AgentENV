import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
from unittest import mock
import uuid

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('rollout', HERE.parent / 'native_rollout.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Tests(unittest.TestCase):
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
