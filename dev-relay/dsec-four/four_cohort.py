"""Native-only four-template lifecycle and recorded replay, 8 Guests per node."""
import argparse
import base64
import concurrent.futures
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path('/home/jwk/agent')
D = ROOT / 'deployments/agentenv-native-four-32ce41c'
CORE = '32ce41c0ac6436198860f888e07ef9793e58dc40'
TREE = '0e973a6e101c1a1c71b48bf70f2d910f48cd672f'
PINS = {'four_runtime': 'f4b31e6dbee970d757d8c5eaddd9b0d679c0ad6e512fffdc32c7a3115975f687', 'cohort_engine': '5d0cd8d4cf45b8301532517af832710c3928458f20c1cc64b0991500ddb1b89d', 'four_lifecycle': '6ee2afa816da54041220dfb0df100bdea60cd0f878f48d2aac9a2084437de245', 'ram_observer': '2aeeb8e9b4b875972bf8d6a41e98344c6709b7ccce472e25003b9ff09d16e112', 'four_replay': '780779b6d3f2c6ea2b7c4a6115d193b9d4116b654251149bac1cc5e0d004d20e', 'four_sync': 'caf26466eac628f58f7eaa17556caa4d155f6815b933456bef2a6f56944bdf83', 'four_metrics': 'd1a3e80825db2f62234a6b81f8141a9442b34cf6de10680ddb4b933d8c728a20'}
GIB = 1024**3


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def module(name):
    path = ROOT / (name + '.py')
    need(path.resolve(strict=True) == path and path.stat().st_uid == 1204 and path.stat().st_size <= 2 * 1024**2,
         'Unexpected helper source')
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == PINS[name], 'Pinned helper differs: ' + name)
    spec = importlib.util.spec_from_file_location('native_four_' + name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def host_observation():
    result = {'originalReplayActiveOperatorReport': False, 'wholeHostIdleEstablished': False}
    try:
        fields = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        result['memoryBytes'] = {k: int(fields[k].split()[0]) * 1024 for k in ('MemAvailable', 'Cached', 'Dirty', 'SwapFree')}
        result['loadAverage'] = Path('/proc/loadavg').read_text().strip()
        result['pressure'] = {name: Path('/proc/pressure', name).read_text() for name in ('cpu', 'memory', 'io')}
        result['available'] = True
    except OSError as error:
        result.update(available=False, errorType=type(error).__name__)
    return result


def capacity(kind, batch=False):
    limit = int(Path('/sys/module/ublk_drv/parameters/ublks_max').read_text())
    count = len([p for p in Path('/sys/class/ublk-char').iterdir() if re.fullmatch(r'ublkc\d+', p.name)])
    required = 14 if batch else (3 if kind == 'cold' else 4)
    need(0 < limit <= 4096 and count <= limit and limit - count >= required,
         'Insufficient ublk slots for the declared cohort; preserve existing devices')
    if batch:
        available = host_observation().get('memoryBytes', {}).get('MemAvailable')
        need(type(available) is int and available >= 48 * GIB, 'Need 32GiB Guest capacity plus16GiB headroom per node')
    need(shutil.disk_usage(ROOT).free >= 16 * GIB, 'Cohort disk reserve insufficient')
    return {'limit': limit, 'registered': count, 'requiredFree': required}


class FieldBatch:
    def __init__(self, args):
        self.args, self.node = args, args.node
        self.rt, self.engine = module('four_runtime'), module('cohort_engine')
        self.lifecycle_module = module('four_lifecycle')
        self.observer, self.replay, self.sync = module('ram_observer'), module('four_replay'), module('four_sync')
        self.metrics = module('four_metrics').Metrics()
        self.seed = self.rt.load(D / 'rootfs-inputs.json')
        need(self.seed.get('status') == 'FOUR_ROOTFS_INPUTS_SEEDED_NOT_GUEST_ACCEPTANCE'
             and self.seed['node'] == self.node and self.seed['coreCommit'] == CORE and self.seed['coreTree'] == TREE,
             'Four-image seed receipt differs')
        self.input_dir = Path(self.seed['inputDirectory'])
        manifest = self.rt.load(self.input_dir / 'manifest.json')
        selected = self.rt.read(self.input_dir / 'selection.private.json', 8 * 1024**2)
        need(hashlib.sha256(selected).hexdigest() == manifest['files']['selection.private.json']['sha256'], 'Private selection changed')
        self.selection = json.loads(selected)['selected']
        need(len(self.selection) == len(self.seed['images']) == 4, 'Exactly four cases required')
        for index, (case, image) in enumerate(zip(self.selection, self.seed['images'])):
            need(image['templateIndex'] == index and case['case']['instance_id'] == image['instanceId']
                 and case['case']['replay_sha256'] == image['replaySha256']
                 and image['resources']['cpu_count'] == 2 and image['resources']['memory_mib'] == 4096,
                 'Case/resource/replay identity differs')
        definition = self.rt.load(D / 'definition-native.json')
        binding_pin = definition.get('rootfsBinding', {})
        raw = self.rt.read(binding_pin['path'])
        need(hashlib.sha256(raw).hexdigest() == binding_pin['sha256'], 'Binding catalog changed')
        self.binding = json.loads(raw)
        need(self.binding.get('catalogVersion') == 1 and len(self.binding.get('bindings', [])) == 4,
             'Four native rootfs bindings required')
        for image, binding in zip(self.seed['images'], self.binding['bindings']):
            need(image['sourceImage'] == binding['sourceImage'] and binding['version'] == 3, 'Wrong native image binding')
        self.api = self.rt.Api(D, 'jwk-aenv-native-four-32ce41c-' + self.node + '.service', definition['apiPort'])
        installation = self.rt.load(D / 'installation.json')
        need(installation.get('runtimeSourceCommit', installation.get('commit')) == CORE and installation['node'] == self.node,
             'Installed Runtime source differs')
        for name in ('server', 'aenv'):
            need(self.rt.digest_file(D / 'bin' / name) == installation['binaries'][name], 'Installed executable differs')
        self.context = {'node': self.node, 'runtimePid': self.api.pid, 'runtimeTicks': self.api.ticks,
                        'configSha256': self.api.config_sha, 'unit': self.api.unit,
                        'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
        self.root = D / 'four-cohort'
        self.root.mkdir(mode=0o700, exist_ok=True)
        need(self.root.resolve(strict=True) == self.root and self.root.stat().st_uid == 1204, 'Journal directory differs')
        self.phase = args.mode if args.mode == 'parents' else args.scenario
        self.work = self.root / self.phase
        self.run_id = uuid.uuid4().hex
        self.states, self.jobs = {}, []
        self.state = {'samples': []}
        self.stop = threading.Event()
        self.mutex = threading.RLock()
        self.credentials = None
        self.lifecycle = None

    def persist_case(self, index, value):
        self.states[str(index)] = copy.deepcopy(value)
        self.rt.save(self.work / ('case-' + str(index) + '.json'), value)
        self.rt.save(self.work / 'state.json', {'runId': self.run_id, 'context': self.context, 'cases': self.states})
        self.aggregate()

    def aggregate(self):
        states = list(self.states.values())
        requests = [r for state in states for r in state['openRequests']]
        ids = [sid for state in states for sid in state['sandboxIds']]
        self.rt.save(D / 'cohort-state.json', {'version': 1,
            'phase': 'quiesced' if states and not requests and not ids and all(s['phase'] == 'quiesced' for s in states) else 'active',
            'openRequests': requests, 'sandboxIds': ids, 'outcomeUncertain': bool(requests),
            'fourRunId': self.run_id, 'fourPhase': self.phase})

    def snapshot(self, index, sid):
        repo = D / 'state/snapshot-store/repository'
        record_raw = self.rt.read(repo / 'catalog/records' / (sid + '.json'))
        record = json.loads(record_raw)
        saved = self.rt.load(repo / 'snapshots' / sid / 'firecracker-manifest.json')
        bound = self.binding['bindings'][index]
        expected = {'version': 1, 'sourceImage': bound['sourceImage'], 'filesystem': 'ext4',
                    'layers': [{'sha256': x['sha256'], 'bytes': x['bytes']} for x in bound['layers']]}
        need(record.get('id') == sid and saved.get('nativeRootfs') == expected
             and record.get('resources', {}).get('cpu_count') == 2
             and record.get('resources', {}).get('memory_mib') == 4096
             and saved.get('memory', {}).get('virtualSize') == 4096 * 1024**2,
             'Capture lacks exact portable native content or4GiB RAM')
        return {'snapshotId': sid, 'nativeRootfs': expected,
                'committedRecordSha256': hashlib.sha256(record_raw).hexdigest(),
                'crossNodeRamSharingAccepted': False}

    def record_hash(self, index, sid):
        path = D / 'state/snapshot-store/repository/catalog/records' / (sid + '.json')
        if not path.exists():
            return None
        raw = self.rt.read(path)
        need(json.loads(raw).get('id') == sid, 'Capture record ID differs')
        return hashlib.sha256(raw).hexdigest()

    def owned(self, sid):
        return self.lifecycle.owned(sid)

    def cancel_check(self):
        if self.args.mode == 'replay' and self.args.scenario == 'dual-ab':
            for stage, epoch in (('admission', self.args.admission_epoch), ('completed', self.args.completed_epoch)):
                need(isinstance(epoch, str) and re.fullmatch('[0-9a-f]{32}', epoch), 'Dual-node gate identity missing')
                path = self.sync.directory(self.node, stage, epoch)
                need(self.sync.optional(path / 'abort.json') is None, 'Dual-node coordinator cancelled this cohort')

    def capacity_kind(self, kind):
        self.cancel_check()
        return capacity(kind)

    def fresh(self):
        previous = self.rt.load(D / 'cohort-state.json')
        need(previous.get('phase') in ('prepared', 'quiesced') and previous.get('openRequests') == []
             and previous.get('sandboxIds') == [] and previous.get('outcomeUncertain') is False,
             'Previous lifecycle remains active or uncertain; no new phase permitted')
        need(not self.work.exists(), 'Previous phase journal preserved; no blind repeat')
        self.work.mkdir(mode=0o700)
        for name in ('commands', 'tmp', 'cli/aenv', 'cache'):
            (self.work / name).mkdir(mode=0o700, parents=True)
        self.lifecycle = self.lifecycle_module.FourLifecycle(self.engine, self.api, self.run_id, self.context,
            self.persist_case, self.capacity_kind, self.snapshot)

    def create_templates(self):
        self.fresh()
        try:
            templates = self.lifecycle.prepare_parents(self.seed['images'])
            need(self.api.call('GET', '/v2/sandboxes?limit=1') == (200, []), 'Parent phase inventory is not empty')
            value = {'status': 'FOUR_NATIVE_PARENTS_CAPTURED_OWNED_GUESTS_RELEASED',
                     'node': self.node, 'context': self.context, 'templates': templates,
                     'sourceImageIdentities': [i['sourceImage'] for i in self.seed['images']],
                     'oldVmStatesReused': False, 'memfileCrossNodeCowAccepted': False}
            self.rt.save(self.root / 'templates.json', value)
            return value
        finally:
            self.lifecycle.cleanup()

    def transport(self):
        self.credentials = self.work / 'cli/aenv/credentials'
        with self.credentials.open('x') as output:
            output.write('url = "http://127.0.0.1:' + str(self.api.port) + '"\napi_key = ' + json.dumps(self.api.key) + '\n')
        self.credentials.chmod(0o600)
        self.env = {'HOME': '/home/jwk', 'USER': 'jwk', 'LOGNAME': 'jwk', 'LANG': 'C.UTF-8',
                    'PATH': str(D / 'native/bin') + ':/usr/bin:/bin',
                    'LD_LIBRARY_PATH': str(D / 'native/lib') + ':' + str(D / 'native/fallback/lib'),
                    'XDG_CONFIG_HOME': str(self.work / 'cli'), 'XDG_CACHE_HOME': str(self.work / 'cache'),
                    'TMPDIR': str(self.work / 'tmp'), 'NO_PROXY': '127.0.0.1,localhost,::1'}

    def command(self, job, action, label):
        need(not self.stop.is_set(), 'Replay cancelled')
        self.api.stable()
        need(self.owned(job['sandboxId']) is not None, 'Scoped Guest vanished')
        marker = 'NATIVE_FOUR_END_' + uuid.uuid4().hex
        stem = self.work / 'commands' / (str(job['index']) + '-' + label)
        stdout, stderr = stem.with_suffix('.stdout'), stem.with_suffix('.stderr')
        began = time.time()
        with stdout.open('xb') as out, stderr.open('xb') as err:
            child = subprocess.Popen([str(D / 'bin/aenv'), 'exec', job['sandboxId'], '/bin/bash', '-c',
                                      self.replay.shell_command(action, marker)], stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=err, env=self.env)
            deadline = time.monotonic() + 330
            try:
                while child.poll() is None:
                    need(not self.stop.is_set() and time.monotonic() < deadline, 'Command cancelled or timed out')
                    need(stdout.stat().st_size + stderr.stat().st_size <= 16 * 1024**2, 'Command output budget exceeded')
                    time.sleep(0.2)
                need(child.returncode == 0 and stdout.stat().st_size + stderr.stat().st_size <= 16 * 1024**2,
                     'CLI transport failed or output budget exceeded')
            finally:
                if child.poll() is None:
                    child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(timeout=5)
        with stdout.open('rb') as source:
            source.seek(max(0, stdout.stat().st_size - 8192))
            tail = source.read().decode(errors='replace')
        matches = re.findall(r'(?m)^' + marker + r' ([0-9]+)\s*$', tail)
        need(len(matches) == 1, 'Guest exit marker absent')
        return {'startedUnix': began, 'finishedUnix': time.time(), 'returnCode': int(matches[0]),
                'stdout': str(stdout), 'stderr': str(stderr)}

    def replay_job(self, job):
        try:
            case = self.selection[job['templateIndex']]
            raw = base64.b64decode(case['replayBase64'], validate=True)
            need(hashlib.sha256(raw).hexdigest() == job['replaySha256'], 'Private replay changed')
            steps, _ = self.replay.steps_from(raw)
            need(len(steps) == case['executedStepCount'], 'Executable replay count differs')
            with self.mutex:
                job.update(state='REPLAYING', replayStartedUnix=time.time())
            for index, step in enumerate(steps):
                need(not self.stop.wait(step['delay']), 'Replay cancelled during recorded delay')
                result = self.command(job, step['action'], 'step-' + str(index))
                with (self.work / 'commands' / (str(job['index']) + '-events.jsonl')).open('a') as output:
                    output.write(json.dumps(dict(result, step=index, requestedDelaySeconds=step['delay'])) + '\n')
                need(result['returnCode'] not in (124, 137), 'Guest command timed out/killed')
                with self.mutex:
                    job['stepsCompleted'] += 1
                    job['failedCommands'] += int(result['returnCode'] != 0)
            with self.mutex:
                job.update(state='REPLAY_COMPLETED', replayFinishedUnix=time.time())
        except BaseException as error:
            self.stop.set()
            with self.mutex:
                job.update(state='REPLAY_FAILED', errorType=type(error).__name__)
            raise

    def sample(self, phase, ids):
        self.cancel_check()
        with self.mutex:
            before_states = [{k: j[k] for k in ('sandboxId', 'templateIndex', 'slot', 'state')} for j in self.jobs]
        for sid in ids:
            need(self.owned(sid) is not None, 'Guest missing during collection')
        value = self.rt.sample_node(self.api, self.observer, D, self.node, phase, ids)
        value.update(host=host_observation(), node=self.node, scenario=self.args.scenario, runId=self.run_id)
        with self.mutex:
            value['jobStatesAtCollectionStart'] = before_states
            value['jobStatesAtCollectionEnd'] = [{k: j[k] for k in ('sandboxId', 'templateIndex', 'slot', 'state')} for j in self.jobs]
        value['endNs'] = time.time_ns()
        path = self.work / 'samples.jsonl'
        need(not path.exists() or path.stat().st_size < 256 * 1024**2, 'Measurement log budget exceeded')
        with path.open('a') as output:
            output.write(json.dumps(value) + '\n')
        self.state['samples'] = [value]
        self.metrics.add(value, self.jobs)
        return value

    def isolation(self):
        # Post-measurement markers do not contaminate the replay sample window.
        paths = ['/tmp/native-four-' + self.run_id + '-' + str(j['index']) for j in self.jobs]
        for job, path in zip(self.jobs, paths):
            result = self.command(job, 'printf ' + self.run_id + ' > ' + path, 'isolation-write')
            need(result['returnCode'] == 0, 'Private upper write failed')
        for job, path in zip(self.jobs, paths):
            action = 'test "$(cat ' + path + ')" = ' + self.run_id
            action += ''.join(' && test ! -e ' + peer for peer in paths if peer != path)
            result = self.command(job, action, 'isolation-read')
            need(result['returnCode'] == 0, 'Guest upper isolation failed')
            job['privateUpperIsolationPassed'] = True

    def run_replay(self):
        need(self.args.scenario in ('single-a', 'dual-ab'), 'Explicit replay scenario required')
        need(self.args.scenario == 'dual-ab' or self.node == 'node-a', 'Single-node scenario runs only on A')
        templates = self.rt.load(self.root / 'templates.json')
        need(templates.get('context') == self.context and templates.get('status') ==
             'FOUR_NATIVE_PARENTS_CAPTURED_OWNED_GUESTS_RELEASED', 'Matching native parent preparation required')
        for index, template in enumerate(templates['templates']):
            need(self.snapshot(index, template['nativeTemplateId']) == template['snapshotEvidence'], 'Retained template changed')
        capacity('restore', batch=True)
        self.fresh()
        self.transport()
        report = {'status': 'NATIVE_FOUR_REPLAY_STARTING', 'scenario': self.args.scenario, 'node': self.node,
                  'context': self.context, 'coreCommit': CORE, 'runId': self.run_id,
                  'images': self.seed['images'], 'historicalReferenceOnly': True,
                  'nativeTemplates': templates['templates'],
                  'memfileCrossNodeCowAccepted': False, 'globalNetSavingBytes': None,
                  'rootfsHostAccessResidency': None, 'UBPhysicalChargedBytes': None,
                  'sampleFile': str(self.work / 'samples.jsonl'), 'jobs': self.jobs}
        try:
            self.jobs.extend(self.lifecycle.restore_pairs(templates['templates']))
            for index, job in enumerate(self.jobs):
                case = self.selection[job['templateIndex']]
                job.update(index=index, instanceId=case['case']['instance_id'], replaySha256=case['case']['replay_sha256'],
                           originalTemplateId=case['original']['template_id'], state='READY', stepsCompleted=0, failedCommands=0,
                           resources=case['original']['resources'])
                result = self.command(job, 'test "$(id -u)" = 0 && /agentenv/bin/busybox timeout -s TERM -k 1 5 /bin/bash -l -c true', 'admission')
                need(result['returnCode'] == 0, 'Guest admission probe failed')
            ids = [j['sandboxId'] for j in self.jobs]
            if self.args.scenario == 'dual-ab':
                need(self.args.admission_epoch and self.args.completed_epoch, 'Dual-node gates missing')
                report['admissionGate'] = self.sync.Fence(self.node, 'admission', self.args.admission_epoch, 1800)(self, ids)
                report['admissionSample'] = copy.deepcopy(self.state['samples'][-1])
            else:
                self.sample('before_replay', ids)
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(self.replay_job, job) for job in self.jobs]
                try:
                    deadline = time.monotonic() + 6600
                    while not all(future.done() for future in futures):
                        need(time.monotonic() < deadline and shutil.disk_usage(ROOT).free >= 8 * GIB, 'Replay time/disk budget reached')
                        self.sample('replay_window', ids)
                        if any(future.done() and future.exception() is not None for future in futures):
                            self.stop.set()
                        time.sleep(1)
                    for future in futures:
                        future.result()
                except BaseException:
                    self.stop.set()  # Cancel workers before the pool joins them.
                    raise
            if self.args.scenario == 'dual-ab':
                report['completedGate'] = self.sync.Fence(self.node, 'completed', self.args.completed_epoch, 1800)(self, ids)
            else:
                self.sample('after_replay', ids)
            report['completedSample'] = copy.deepcopy(self.state['samples'][-1])
            self.isolation()
            report['status'] = 'NATIVE_FOUR_REPLAY_COMPLETED_PENDING_CLEANUP'
        except BaseException as error:
            self.stop.set()
            report.update(status='STOPPED_NATIVE_FOUR_PRESERVE_JOURNAL', errorType=type(error).__name__,
                          reason=str(error).replace(self.api.key, '[REDACTED]')[:800])
        finally:
            report.update(self.lifecycle.cleanup())
            report['operationsByTemplate'] = {str(index): copy.deepcopy(case.state['operations'])
                                               for index, case in self.lifecycle.cases.items()}
            if self.credentials and self.credentials.exists():
                self.credentials.unlink()
            report['temporaryCredentialsRemoved'] = self.credentials is None or not self.credentials.exists()
            report['measurementSummary'] = self.metrics.result()
            if report['status'] == 'NATIVE_FOUR_REPLAY_COMPLETED_PENDING_CLEANUP' and report['ownedGuestsReleased']:
                report['status'] = 'NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED'
            self.rt.save(self.work / 'report.json', report)
        return report

    def cleanup_existing(self):
        saved = self.rt.load(self.work / 'state.json')
        need(saved['context'] == self.context, 'Recovery Runtime/boot/config differs')
        self.run_id, self.states = saved['runId'], saved['cases']
        self.lifecycle = self.lifecycle_module.FourLifecycle(self.engine, self.api, self.run_id, self.context,
            self.persist_case, capacity, self.snapshot, initial=self.states)
        result = self.lifecycle.cleanup()
        if self.args.release_captures:
            need(self.phase == 'parents', 'Capture release is scoped to parent journals')
            self.lifecycle.release_captures(self.record_hash)
            result['ownedCapturesReleased'] = True
        self.rt.save(self.work / ('recovery-' + uuid.uuid4().hex + '.json'), result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('parents', 'replay', 'cleanup'))
    parser.add_argument('--node', choices=('node-a', 'node-b'), required=True)
    parser.add_argument('--scenario', choices=('single-a', 'dual-ab', 'parents'))
    parser.add_argument('--admission-epoch')
    parser.add_argument('--completed-epoch')
    parser.add_argument('--release-captures', action='store_true')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'status': 'PLAN_ONLY', 'mode': args.mode, 'node': args.node, 'scenario': args.scenario})); return 0
    need(sys.platform == 'linux' and os.uname().machine == 'aarch64' and os.getuid() == os.geteuid() == 1204
         and socket.gethostname() == ('server1' if args.node == 'node-a' else 'agent1'), 'Use declared ordinary ARM64 node')
    need(args.mode == 'parents' or args.scenario, 'Explicit scenario required')
    os.umask(0o077)
    import fcntl
    lock = os.open(D / 'cohort.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    batch = None
    try:
        batch = FieldBatch(args)
        def interrupted(_signal, _frame):
            batch.stop.set()
            raise KeyboardInterrupt('Native four cohort termination requested')
        signal.signal(signal.SIGTERM, interrupted)
        if args.mode == 'parents':
            result = batch.create_templates()
        elif args.mode == 'replay':
            result = batch.run_replay()
        else:
            result = batch.cleanup_existing()
        print(json.dumps(result, indent=2))
        return 0 if result.get('status') in ('FOUR_NATIVE_PARENTS_CAPTURED_OWNED_GUESTS_RELEASED',
                                             'NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED') or (
            args.mode == 'cleanup' and result.get('ownedGuestsReleased') is True) else 1
    finally:
        os.close(lock)


if __name__ == '__main__':
    raise SystemExit(main())
