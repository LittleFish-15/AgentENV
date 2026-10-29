import base64
import copy
import datetime as dt
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('relay', HERE / 'relay_runner.py')
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
NOW = 1800000000


def at(seconds):
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).isoformat()


class Results:
    def __init__(self):
        self.files = {}
        self.failures = 0

    def immutable_result(self, repo, repo_id, branch, path, raw):
        if self.failures:
            self.failures -= 1
            raise relay.Network()
        if path in self.files and self.files[path] != raw:
            raise relay.Stop('Existing result differs')
        self.files[path] = raw


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.root = (HERE.parents[1] / 't' / ('gr-' + uuid.uuid4().hex[:8])).resolve()
        self.root.mkdir(parents=True, mode=0o755)
        (self.root / 'jobs').mkdir(mode=0o755)
        self.identity = {'hostname': 'server1', 'uid': 1204, 'gid': 1205,
                         'machineId': 'fixture-machine', 'bootId': 'fixture-boot',
                         'kernel': 'fixture', 'architecture': 'aarch64'}
        self.config = {'protocol': relay.VERSION, 'node': 'node-a', 'sessionId': 'session-one',
                       'uid': 1204, 'gid': 1205, 'mode': 'manual', 'hostname': 'server1', 'machineId': 'fixture-machine',
                       'runnerSha256': 'fixture-runner', 'expiresAt': at(NOW + 3600),
                       'allowedOperations': ['identity-v1', 'retained-inventory-v1'],
                       'allowedScopes': ['readonly'],
                       'identity': self.identity, 'resultRepo': 'owner/private-results',
                       'resultRepoId': 2, 'resultBranch': 'main'}
        self.job = {'schema': 1, 'jobId': 'job-one', 'node': 'node-a', 'sessionId': 'session-one',
                    'kind': 'identity-v1', 'notBefore': at(NOW - 1), 'expiresAt': at(NOW + 1800)}
        self.results = Results()
        self.executions = 0

        def execute(argv, directory, seconds):
            self.executions += 1
            (directory / 'stdout.log').write_bytes(b'{"status":"fixture-read-only"}\n')
            (directory / 'stderr.log').write_bytes(b'')
            return {'returncode': 0, 'stopReason': None}
        self.execute = execute

        def mkdir(path):
            path.mkdir(parents=True, exist_ok=True, mode=0o755)
            return path
        self.mkdir = mkdir

    def runner(self, **extra):
        return relay.Runner(self.root, self.config, None, self.results,
                            execute=extra.pop('execute', self.execute), mkdir=self.mkdir, **extra)

    def test_duplicate_queue_does_not_repeat_operation(self):
        runner = self.runner()
        runner.run_job(self.job, self.identity, NOW)
        runner.run_job(self.job, self.identity, NOW)
        self.assertEqual(self.executions, 1)
        self.assertEqual(len(self.results.files), 1)

    def test_upload_failure_retries_only_result(self):
        self.results.failures = 1
        with self.assertRaises(relay.Network):
            self.runner().run_job(self.job, self.identity, NOW)
        state = relay.load(self.root / 'jobs/job-one/state.json')
        self.assertEqual(state['state'], 'upload_pending')
        self.runner().run_job(self.job, self.identity, NOW)
        self.assertEqual(self.executions, 1)
        self.assertEqual(relay.load(self.root / 'jobs/job-one/state.json')['state'], 'uploaded')

    def test_interrupted_operation_reports_unknown_and_never_replays(self):
        directory = self.mkdir(self.root / 'jobs/job-one')
        relay.atomic(directory / 'state.json', {'state': 'running', 'jobId': 'job-one',
            'jobSha256': relay.digest(relay.encoded(self.job)), 'startedAt': at(NOW - 20), 'identity': self.identity})
        with self.assertRaises(relay.Stop):
            self.runner().run_job(self.job, self.identity, NOW)
        self.assertEqual(self.executions, 0)
        value = json.loads(next(iter(self.results.files.values())))
        self.assertEqual(value['state'], 'unknown_after_interruption')
        self.assertFalse(value['resourceCleanupConfirmed'])

    def test_execution_exception_is_reported_without_sensitive_exception_text(self):
        def broken(*args):
            raise RuntimeError('sensitive-runtime-context')
        with self.assertRaises(relay.Stop):
            self.runner(execute=broken).run_job(self.job, self.identity, NOW)
        text = next(iter(self.results.files.values())).decode()
        self.assertNotIn('sensitive-runtime-context', text)
        self.assertIn('RuntimeError', text)

    def test_arbitrary_command_field_is_rejected(self):
        job = dict(self.job, command='arbitrary command')
        with self.assertRaises(relay.Stop):
            self.runner().run_job(job, self.identity, NOW)
        self.assertEqual(self.executions, 0)

    def test_wrong_node_session_and_operation_rejected(self):
        for key, value in (('node', 'node-d'), ('sessionId', 'other-session'), ('kind', 'root-shell')):
            with self.subTest(key=key), self.assertRaises(relay.Stop):
                self.runner().run_job(dict(self.job, **{key: value}), self.identity, NOW)
        self.assertEqual(self.executions, 0)

    def test_new_boot_rejected(self):
        with self.assertRaises(relay.Stop):
            self.runner().run_job(self.job, dict(self.identity, bootId='new-boot'), NOW)

    def test_expired_job_rejected(self):
        with self.assertRaises(relay.Stop):
            self.runner().run_job(dict(self.job, expiresAt=at(NOW - 1)), self.identity, NOW)

    def test_job_id_reuse_with_modified_payload_rejected(self):
        self.runner().run_job(self.job, self.identity, NOW)
        with self.assertRaises(relay.Stop):
            self.runner().run_job(dict(self.job, expiresAt=at(NOW + 1801)), self.identity, NOW)
        self.assertEqual(self.executions, 1)

    def test_source_digest_mismatch_never_spawns(self):
        class Public:
            def source(self, operation):
                return b'untrusted bytes'
        with self.assertRaises(relay.Stop):
            self.runner(public=Public()).run_job(dict(self.job, kind='retained-inventory-v1'), self.identity, NOW)
        self.assertEqual(self.executions, 0)
        self.assertFalse((self.root / 'jobs/job-one').exists())

    def test_c_node_cannot_execute_source_inventory(self):
        self.config['node'] = 'node-c'
        job = dict(self.job, node='node-c', kind='retained-inventory-v1')
        with self.assertRaises(relay.Stop):
            self.runner().run_job(job, self.identity, NOW)

    def test_tokens_are_redacted_from_uploaded_logs(self):
        secret = 'fixture-secret-token'
        def execute(argv, directory, seconds):
            (directory / 'stdout.log').write_bytes((secret + '\nAuthorization: Bearer hidden-value\ngithub_pat_FAKE_VALUE\n').encode())
            (directory / 'stderr.log').write_bytes(b'')
            return {'returncode': 0, 'stopReason': None}
        self.runner(execute=execute).run_job(self.job, self.identity, NOW, (secret,))
        result = json.loads(next(iter(self.results.files.values())))
        raw = gzip.decompress(base64.b64decode(result['logs']['stdout.log']['content']))
        for value in (secret, 'hidden-value', 'github_pat_FAKE_VALUE'):
            self.assertNotIn(value.encode(), raw)
        self.assertTrue(result['logs']['stdout.log']['redacted'])

    def test_profile_wrong_runner_or_machine_is_rejected(self):
        relay.validate_profile(self.config, self.identity, 'fixture-runner', NOW)
        with self.assertRaises(relay.Stop):
            relay.validate_profile(self.config, self.identity, 'other-runner', NOW)
        with self.assertRaises(relay.Stop):
            relay.validate_profile(self.config, dict(self.identity, machineId='other'), 'fixture-runner', NOW)

    def test_redirected_state_path_rejected_before_creation(self):
        with self.assertRaises(relay.Stop):
            relay.secure_dir(self.root / '..' / 'should-not-create')

    def test_auto_node_selection_requires_unique_bound_machine(self):
        row = {'node': 'node-a', 'uid': 1204, 'hostname': 'server1', 'machineId': 'fixture-machine'}
        session = {'protocol': relay.VERSION, 'nodes': [row]}
        self.assertEqual(relay.choose_node(session, self.identity), 'node-a')
        with self.assertRaises(relay.Stop):
            relay.choose_node(session, dict(self.identity, machineId='other-machine'))
        with self.assertRaises(relay.Stop):
            relay.choose_node({'protocol': relay.VERSION, 'nodes': [row, row]}, self.identity)

    def test_child_environment_does_not_inherit_tokens(self):
        class Child:
            returncode = 0
            def poll(self):
                return 0
        directory = self.mkdir(self.root / 'child-environment')
        with patch.dict(relay.os.environ, {'GITHUB_TOKEN': 'not-for-child', 'OTHER_SECRET': 'private'}), \
             patch.object(relay.subprocess, 'Popen', return_value=Child()) as spawn:
            relay.execute_bounded(['reviewed-program'], directory, 1)
        env = spawn.call_args.kwargs['env']
        self.assertNotIn('GITHUB_TOKEN', env)
        self.assertNotIn('OTHER_SECRET', env)

    def test_noninteractive_enrollment_never_prompts_for_secret(self):
        with patch.object(relay.sys.stdin, 'isatty', return_value=False), \
             patch.object(relay.getpass, 'getpass') as prompt:
            with self.assertRaises(relay.Stop):
                relay.prompt_tokens()
        prompt.assert_not_called()

    def manual_queue(self, ids):
        return {'schema': 1, 'mode': 'manual', 'roundId': 'round-one',
                'node': 'node-a', 'sessionId': 'session-one', 'jobIds': ids, 'stop': False}

    def test_manual_invocation_fetches_once_executes_once_and_returns(self):
        fetched = []
        def fetch(job_id):
            fetched.append(job_id)
            return self.job
        result = relay.manual_turn(self.runner(), self.manual_queue(['job-one']), fetch, self.identity, NOW)
        self.assertEqual(fetched, ['job-one'])
        self.assertEqual(self.executions, 1)
        self.assertEqual(result['state'], 'round_uploaded')
        self.assertTrue(result['nextStepRequiresUserInvocation'])

    def test_manual_invocation_does_not_execute_a_future_round(self):
        with self.assertRaises(relay.Stop):
            relay.manual_turn(self.runner(), self.manual_queue(['job-one', 'job-two']),
                              lambda job_id: self.job, self.identity, NOW)
        self.assertEqual(self.executions, 0)

    def test_repeating_manual_command_does_not_repeat_uploaded_task(self):
        queue = self.manual_queue(['job-one'])
        first = relay.manual_turn(self.runner(), queue, lambda x: self.job, self.identity, NOW)
        second = relay.manual_turn(self.runner(), queue, lambda x: self.job, self.identity, NOW)
        self.assertEqual(first['state'], 'round_uploaded')
        self.assertEqual(second['state'], 'already_uploaded')
        self.assertEqual(self.executions, 1)

    def test_next_manual_round_only_runs_after_next_invocation(self):
        relay.manual_turn(self.runner(), self.manual_queue(['job-one']), lambda x: self.job, self.identity, NOW)
        self.assertEqual(self.executions, 1)
        next_job = dict(self.job, jobId='job-two')
        queue = dict(self.manual_queue(['job-two']), roundId='round-two')
        result = relay.manual_turn(self.runner(), queue, lambda x: next_job, self.identity, NOW)
        self.assertEqual(result['roundId'], 'round-two')
        self.assertEqual(self.executions, 2)

    def test_empty_manual_round_returns_immediately_without_fetch(self):
        def forbidden(job_id):
            self.fail('Empty round must not fetch or wait for a job')
        result = relay.manual_turn(self.runner(), self.manual_queue([]), forbidden, self.identity, NOW)
        self.assertEqual(result['state'], 'no_task')
        self.assertEqual(self.executions, 0)

    def reviewed_job(self, raw):
        script = {'repo': relay.SOURCE_REPO, 'commit': 'a' * 40,
                  'path': 'dev-relay/example_readonly.py',
                  'blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                  'sha256': relay.digest(raw), 'bytes': len(raw), 'seconds': 30,
                  'scope': 'readonly', 'nodes': ['node-a']}
        self.config['allowedOperations'].append('reviewed-python-v1')
        return dict(self.job, kind='reviewed-python-v1', script=script, input={})

    def test_next_reviewed_script_can_be_selected_without_changing_client(self):
        raw = b'print("reviewed-read-only-fixture")\n'
        job = self.reviewed_job(raw)
        class Public:
            def source(self, descriptor):
                return raw
        self.runner(public=Public()).run_job(job, self.identity, NOW)
        self.assertEqual(self.executions, 1)
        result = json.loads(next(iter(self.results.files.values())))
        self.assertEqual(result['script']['sha256'], relay.digest(raw))

    def test_reviewed_script_cannot_change_repository_or_request_root_scope(self):
        job = self.reviewed_job(b'fixture')
        for field, value in (('repo', 'other/repository'), ('scope', 'root'), ('path', 'dev-relay/../outside.py')):
            changed = copy.deepcopy(job); changed['script'][field] = value
            with self.subTest(field=field), self.assertRaises(relay.Stop):
                self.runner().run_job(changed, self.identity, NOW)
        self.assertEqual(self.executions, 0)

    def test_reviewed_script_input_is_a_private_json_file_not_shell_arguments(self):
        raw = b'print("fixture")\n'
        job = self.reviewed_job(raw)
        job['input'] = {'message': 'text with ; symbols remains JSON data'}
        class Public:
            def source(self, descriptor):return raw
        seen = []
        def execute(argv, directory, seconds):
            seen.extend(argv)
            self.assertEqual(relay.load(directory / 'task-input.json'), job['input'])
            return self.execute(argv, directory, seconds)
        self.runner(public=Public(), execute=execute).run_job(job, self.identity, NOW)
        self.assertEqual(len(seen), 4)
        self.assertNotIn(job['input']['message'], seen)

    def test_reviewed_script_wrong_source_bytes_are_rejected(self):
        job = self.reviewed_job(b'approved-source')
        class Public:
            def source(self, descriptor):return b'other-source'
        with self.assertRaises(relay.Stop):
            self.runner(public=Public()).run_job(job, self.identity, NOW)
        self.assertEqual(self.executions, 0)


class ApiTests(unittest.TestCase):
    def test_public_results_repository_is_rejected_before_upload(self):
        class Client(relay.GitHub):
            def request(self, method, path, **kwargs):
                self.last_method = method
                return 200, {'private': False, 'full_name': 'owner/results', 'id': 2}, None
        client = Client('fixture')
        with self.assertRaises(relay.Stop):
            client.immutable_result('owner/results', 2, 'main', 'result.json', b'{}')
        self.assertEqual(client.last_method, 'GET')

    def test_existing_result_cannot_be_overwritten(self):
        class Client(relay.GitHub):
            def private_repo(self, *args):
                return {'id': 2}
            def contents(self, *args):
                return 200, b'existing', None
        with self.assertRaises(relay.Stop):
            Client().immutable_result('owner/results', 2, 'main', 'result.json', b'different')

    def test_lost_write_ack_is_reconciled_without_second_write(self):
        class Client(relay.GitHub):
            def __init__(self):
                self.raw = None; self.writes = 0
            def private_repo(self, *args):
                return {'id': 2}
            def contents(self, *args):
                return (404, None, None) if self.raw is None else (200, self.raw, None)
            def request(self, method, path, value=None, **kwargs):
                self.writes += 1
                self.raw = base64.b64decode(value['content'])
                raise relay.Network()
        client = Client()
        with self.assertRaises(relay.Network):
            client.immutable_result('owner/results', 2, 'main', 'result.json', b'fixed bytes')
        client.immutable_result('owner/results', 2, 'main', 'result.json', b'fixed bytes')
        self.assertEqual(client.writes, 1)

    def test_invalid_identifiers_and_repository_destinations(self):
        for value in ('../x', 'a/b', 'A', '', 'a' * 65):
            with self.subTest(value=value), self.assertRaises(relay.Stop):
                relay.identifier(value)
        with self.assertRaises(relay.Stop):
            relay.repo_name('https://other.example/steal')


if __name__ == '__main__':
    unittest.main()
