import ast, base64, copy, hashlib, importlib.util, io, json, time, types, unittest, uuid
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('four', HERE / 'A_dsec_four_v1.py')
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def input_fixture():
    images, cases, selected = [], [], []
    raw = json.dumps({'trajectory': [{'action': 'printf ok', 'delay_time': 0}, {'action': 'submit'}]}).encode()
    sha = hashlib.sha256(raw).hexdigest()
    for index in range(4):
        shared = {'instanceId': 'case'+str(index), 'templateIndex': index, 'sourceImage': 'sha256:'+str(index)*64,
                  'resources': {'cpu_count': 2, 'memory_mib': 4096}, 'replaySha256': sha,
                  'ociDirectory': '/home/jwk/agent/oci'+str(index), 'ociDigest': 'sha256:'+str(index)*64}
        cases.append(shared)
        images.append(dict(shared, ociReference='ocidir://'+shared['ociDirectory']+'@'+shared['ociDigest']))
        selected.append({'case': {'instance_id': shared['instanceId'], 'replay_sha256': sha},
                         'executedStepCount': 1, 'replayBase64': base64.b64encode(raw).decode()})
    receipt = {'status': 'FOUR_NATIVE_IMAGES_AND_BINARIES_PREPARED_NOT_DEPLOYED', 'coreCommit': 'origin32ce', 'cases': cases}
    seed = {'node': 'node-a', 'coreCommit': 'origin32ce', 'images': images}
    receipt_raw, selected_raw = json.dumps(receipt).encode(), json.dumps({'selected': selected}).encode()
    fake = types.SimpleNamespace(load=lambda p: seed,
                                 read=lambda p, limit: receipt_raw if p.name == 'return.json' else selected_raw)
    return fake, receipt_raw, seed, selected


def runtime_fixture():
    context = {'unit': m.UNIT, 'pid': 300, 'ticks': '777', 'configSha256': 'cfg', 'bootId': 'boot'}
    api = types.SimpleNamespace(pid=300, ticks='777', config_sha='cfg', port=18084)
    binding = {'catalogVersion': 1, 'bindings': [{'version': 5, 'lowerFilesystem': 'ext4'} for _ in range(4)]}
    binding_raw = json.dumps(binding).encode()
    proof = {'coreCommit': m.CORE, 'entrySha256': m.REPAIR_ENTRY_SHA, 'runtimeContext': context, 'serverSha256': 'server'}
    smoke = {'status': 'DSEC_REAL_TEMPLATE_RESTORE_PAIR_PASSED_GUESTS_RELEASED',
             'runtimeContext': context, 'coreCommit': m.CORE, 'ownedGuestsReleased': True, 'baseUnchanged': True}
    data = {'installation.json': {'commit': m.CORE, 'binaries': {'server': 'server'}},
            'activation-proof.json': proof, 'definition-native.json': {'apiPort': 18084,
                'rootfsBinding': {'path': 'binding', 'sha256': hashlib.sha256(binding_raw).hexdigest()}},
            'return.json': smoke}
    rt = types.SimpleNamespace(load=lambda p: data[p.name], Api=lambda *a: api,
        read=lambda p: binding_raw, digest_file=lambda p: 'server')
    return rt, data, api


class Four(unittest.TestCase):
    def test_all_embedded_helpers_parse_and_import_without_process(self):
        with patch.object(m.module('four_runtime').subprocess, 'run', side_effect=AssertionError('Unexpected external action')):
            for name in m.PAYLOAD:
                m.module(name)

    def test_input_selection_hashes_and_origin_remain_old_provenance(self):
        rt, raw, seed, _ = input_fixture()
        with patch.object(m, 'INPUT_RETURN_SHA', hashlib.sha256(raw).hexdigest()):
            result = m.input_contract(rt)
        self.assertEqual(result[0]['coreCommit'], 'origin32ce')
        self.assertEqual(len(result[1]), 4)

    def test_wrong_oci_not_reused(self):
        rt, raw, seed, _ = input_fixture();seed['images'][0]['ociReference'] = 'https://other'
        with patch.object(m, 'INPUT_RETURN_SHA', hashlib.sha256(raw).hexdigest()), self.assertRaisesRegex(RuntimeError, 'OCI'):
            m.input_contract(rt)

    def test_runtime_actual_lowerfilesystem_contract(self):
        rt, data, api = runtime_fixture()
        with patch.object(m, 'Path', return_value=types.SimpleNamespace(read_text=lambda: 'boot')):
            self.assertIs(m.runtime_contract(rt)[0], api)

    def test_old_unrepaired_runtime_not_accepted(self):
        rt, data, _ = runtime_fixture();data['installation.json']['commit'] = 'eb230'
        with self.assertRaisesRegex(RuntimeError, 'Repaired candidate'):
            m.runtime_contract(rt)

    def test_healthy_without_smoke_does_not_expand(self):
        rt, data, _ = runtime_fixture();data['return.json']['status'] = 'STOPPED'
        with patch.object(m, 'Path', return_value=types.SimpleNamespace(read_text=lambda: 'boot')), \
             self.assertRaisesRegex(RuntimeError, 'lifecycle must pass'):
            m.runtime_contract(rt)

    def test_reused_pid_or_config_rejects_smoke_receipt(self):
        rt, data, api = runtime_fixture();api.ticks = '778'
        with patch.object(m, 'Path', return_value=types.SimpleNamespace(read_text=lambda: 'boot')), \
             self.assertRaisesRegex(RuntimeError, 'Runtime changed'):
            m.runtime_contract(rt)

    def test_root_bootstrap_pins_complete_packet(self):
        text = m.root_bootstrap('a'*64, 'b'*64)
        source = text.split("<<'DSEC_FOUR_READONLY_ROOT'\n", 1)[1].split('\nDSEC_FOUR_READONLY_ROOT', 1)[0]
        ast.parse(source, feature_version=(3, 11))
        self.assertIn('a'*64, source);self.assertIn('b'*64, source)
        self.assertIn("os.geteuid()==0", source)

    def test_observer_request_binds_context_and_guest_bound(self):
        observer = m.module('dsec_root_observer')
        plan = {'observerRunId': 'a'*32, 'runtimeContext': {'pid': 300}}
        request = {'version': 1, **plan, 'runId': 'b'*32, 'phase': 'replay_window',
                   'sandboxIds': [str(uuid.uuid4())], 'jobs': [], 'monotonic': time.monotonic()}
        self.assertEqual(len(observer.request_contract(request, plan)), 1)
        request['sandboxIds'] *= 9
        with self.assertRaisesRegex(RuntimeError, 'Guest set'):
            observer.request_contract(request, plan)

    def test_observer_expired_request_cannot_run_indefinitely(self):
        observer = m.module('dsec_root_observer')
        plan = {'observerRunId': 'a'*32, 'runtimeContext': {'pid': 300}}
        request = {'version': 1, **plan, 'runId': 'b'*32, 'phase': 'replay_window',
                   'sandboxIds': [], 'jobs': [], 'monotonic': time.monotonic()-901}
        with self.assertRaisesRegex(RuntimeError, 'expired'):
            observer.request_contract(request, plan)

    def test_observer_rejects_arbitrary_output_name_before_io(self):
        observer = m.module('dsec_root_observer')
        with patch.object(observer.os, 'open') as opened, self.assertRaisesRegex(RuntimeError, 'outside observer'):
            observer.write_json_at(9, '/etc/unsafe', {})
        opened.assert_not_called()

    def test_one_cleanup_failure_still_cleans_other_owned_cases(self):
        lifecycle = m.module('four_lifecycle');calls = []
        def case(index):
            def recover():
                calls.append(index)
                if index == 0: raise RuntimeError('Unresolved first case')
            return types.SimpleNamespace(recover_owned=recover, state={'sandboxIds': [], 'openRequests': []})
        value = lifecycle.FourLifecycle(None, None, 'run', {}, None, None, None)
        value.cases = {i: case(i) for i in range(4)}
        result = value.cleanup()
        self.assertEqual(calls, [0, 1, 2, 3]);self.assertFalse(result['ownedGuestsReleased'])
        self.assertEqual(result['cleanupErrors'][0]['templateIndex'], 0)

    def test_guest300_cli330_semantics_unchanged(self):
        replay = m.module('four_replay')
        self.assertIn('timeout -s TERM -k 5 300', replay.shell_command('true', 'MARK'))
        raw = zlib.decompress(base64.b64decode(m.PAYLOAD['four_cohort']['z64'])).decode()
        self.assertIn('time.monotonic() + 330', raw)

    def test_four_clean_parents_then_eight_restores_real_journals(self):
        lifecycle = m.module('four_lifecycle');engine = m.module('cohort_engine')
        class Api:
            def __init__(self): self.guests = {};self.posts = [];self.maximum = 0
            def call(self, method, path, body=None, timeout=30):
                if method == 'GET' and path == '/v2/sandboxes?limit=1': return 200, list(self.guests.values())
                if method == 'POST':
                    self.posts.append(path)
                    if path.endswith('/snapshots'): return 201, {'snapshotID': str(uuid.uuid4())}
                    sid = str(uuid.uuid4());self.guests[sid] = {'sandboxID': sid, 'metadata': body['metadata']}
                    self.maximum = max(self.maximum, len(self.guests))
                    return 201, {'sandboxID': sid}
                sid = path.rsplit('/', 1)[1]
                if method == 'GET': return (200, self.guests[sid]) if sid in self.guests else (404, None)
                if method == 'DELETE': self.guests.pop(sid, None);return 204, None
                raise AssertionError((method, path))
        api = Api();saved = {}
        def create():
            return lifecycle.FourLifecycle(engine, api, uuid.uuid4().hex, {},
                lambda i, s: saved.update({i: copy.deepcopy(s)}), lambda _: None,
                lambda i, sid: {'snapshotId': sid, 'templateIndex': i})
        parents = create()
        templates = parents.prepare_parents([{'resources': {'memory_mib': 4096, 'cpu_count': 2},
                    'ociReference': 'fixture'+str(i), 'sourceImage': 'source'+str(i)} for i in range(4)])
        self.assertEqual(api.maximum, 1);self.assertTrue(parents.cleanup()['ownedGuestsReleased'])
        self.assertEqual(len(templates), 4)
        replay = create();jobs = replay.restore_pairs(templates)
        self.assertEqual(api.maximum, 8);self.assertEqual(len(jobs), 8)
        self.assertTrue(replay.cleanup()['ownedGuestsReleased']);self.assertFalse(api.guests)
        self.assertEqual(api.posts.count('/sandboxes-cold'), 4)
        self.assertEqual(api.posts.count('/v2/sandboxes'), 8)
        self.assertEqual(sum(len(c.state['snapshots']) for c in parents.cases.values()), 4)

    def test_root_observer_actual_loop_stops_on_owner_done_without_mutation(self):
        root = m.module('dsec_root_observer');writes = {};calls = []
        class Work:
            def __truediv__(self, name): return Path('/fixture')/name
            def resolve(self, strict=True): return self
            def stat(self): return types.SimpleNamespace(st_uid=1204)
        work = Work();context = {'pid': 300, 'ticks': '7'}
        raw_entry = b'local-fixture'
        plan = {'version': 1, 'entrySha256': hashlib.sha256(raw_entry).hexdigest(),
                'coreCommit': m.CORE, 'maxSeconds': 10800, 'maxGuests': 8,
                'runtimeContext': context, 'baseFiles': [], 'allowedLowers': [],
                'sourceSelectionSha256': 'selection', 'observerRunId': 'a'*32}
        raw_plan = json.dumps(plan).encode()
        request = {'version': 1, 'observerRunId': 'a'*32, 'runtimeContext': context,
                   'runId': 'b'*32, 'phase': 'owner_finished', 'sandboxIds': [], 'jobs': [],
                   'monotonic': time.monotonic()}
        rt = types.SimpleNamespace(read=lambda p: raw_plan, load=lambda p: request,
            ticks=lambda pid: '7', unit_fields=lambda u: {'User': 'jwk', 'Group': 'jwk', 'ActiveState': 'active', 'MainPID': '301'})
        observer = types.SimpleNamespace(pin_base_files=lambda p: [],
            host_observation=lambda: {}, cgroup_memory=lambda *a: {}, whole_process_metrics=lambda *a: {},
            collect_ram=lambda *a, **kw: calls.append('read_ram') or {'guests': []},
            base_file_cache=lambda p: {'residentPageBytes': 0})
        api = types.SimpleNamespace(pid=300, ticks='7', stable=lambda: calls.append('stable'))
        scope = {'module': lambda n: rt if n=='four_runtime' else observer, 'WORK': work, 'D': Path('/d'),
                 'CORE': m.CORE, '__file__': 'fixture', 'INPUTS': Path('/inputs'), 'PROVIDER': 'own.service',
                 'runtime_contract': lambda rt: (api, context, {}),
                 'input_contract': lambda rt: ({'images': []}, [], {}, 'selection')}
        class Journal(io.StringIO):
            def fileno(self): return 102
            def close(self): pass
        journal = Journal()
        with patch.object(root.Path, 'read_bytes', return_value=raw_entry), \
             patch.object(root.os, 'open', return_value=101), patch.object(root.os, 'fchown', create=True), \
             patch.object(root.os, 'O_DIRECTORY', 0, create=True), patch.object(root.os, 'O_NOFOLLOW', 0, create=True), \
             patch.object(root.os, 'O_CLOEXEC', 0, create=True), \
             patch.object(root.os, 'fdopen', return_value=journal), patch.object(root.os, 'fsync'), \
             patch.object(root.os, 'close'), patch.object(root.signal, 'signal'), patch.object(root.signal, 'SIGHUP', 1, create=True), \
             patch.object(root, 'write_json_at', side_effect=lambda fd,n,v: writes.update({n: copy.deepcopy(v)})):
            result = root.run(scope, hashlib.sha256(raw_plan).hexdigest())
        self.assertEqual(result, 0)
        self.assertEqual(writes['observer-return.json']['status'], 'READONLY_OBSERVER_OWNER_FINISHED')
        self.assertEqual(writes['observer-return.json']['sampleCount'], 1)
        self.assertEqual(calls, ['stable', 'read_ram'])
        self.assertEqual(len(journal.getvalue().splitlines()), 1)


import zlib
if __name__ == '__main__': unittest.main()
