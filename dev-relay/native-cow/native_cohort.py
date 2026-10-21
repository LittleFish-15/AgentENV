"""One bounded original/native public-workload cohort on the declared node.

Default is plan only. No service restarts, device cleanup, SDK calls, cache
eviction, downloads, arbitrary host commands or repeat uncertain POSTs.
"""
import argparse
import concurrent.futures
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path('/home/jwk/agent')
CORE = '6cdac56ed70284e89693e7bda0470a43ad9bd0b5'
ORIGINAL = 'ae9c62693839ce7effa2b45df31c0039ae4f9fbc'
SOURCE = 'sha256:cf786498f77bf4ba6235156ab8540d0b9335e874e70b95efbeb53168e0dce68d'
MODULE_PINS = {'cohort_engine': '1be6d713340e631755d2f2c200c75822228feeaa3e4470312aa81296db214a83', 'ram_observer': '0b8ea355e4e0dd6ad8422968e63ff5dd9b640166cd29406096480589c6cc80af', 'public_workload': 'dfd483df3307a3a677dfc2bb1f4559b76aea3fb8ad4cc200832d572fb6a44490'}


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def read(path, limit=2 * 1024**2):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True) == path,
         'Input outside workspace or redirected')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 1204 and before.st_size <= limit,
             'Input ownership, type or size differs')
        value = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    need(len(value) == before.st_size and (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Input changed while reading')
    return value


def load(path):
    return json.loads(read(path))


def save(path, value):
    need(path.parent.resolve(strict=True) == path.parent and path.parent.stat().st_uid == 1204,
         'Output directory changed')
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temporary.open('xb') as stream:
        stream.write((json.dumps(value, indent=2) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def digest_file(path, limit=512 * 1024**2):
    path = Path(path)
    need(path.resolve(strict=True) == path and path.is_relative_to(ROOT), 'Binary path changed')
    with path.open('rb') as stream:
        meta = os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204 and 0 < meta.st_size <= limit,
             'Binary metadata differs')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        end = os.fstat(stream.fileno())
    need((meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns) ==
         (end.st_size, end.st_mtime_ns, end.st_ctime_ns), 'Binary changed')
    return digest


def module(name):
    path = Path(__file__).resolve().parent / (name + '.py')
    need(hashlib.sha256(read(path)).hexdigest() == MODULE_PINS.get(name), 'Pinned module differs: ' + name)
    spec = importlib.util.spec_from_file_location('cow_' + name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def unit_fields(unit):
    result = subprocess.run(['/usr/bin/systemctl', 'show', unit,
                             '--property=LoadState,ActiveState,MainPID,User,Group,ControlGroup'],
                            capture_output=True, text=True, timeout=10, check=True)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def ticks(pid):
    return Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()[19]


class Api:
    def __init__(self, base, unit, port):
        self.base, self.unit, self.port = base, unit, port
        self.key = read(base / 'config/api-key', 1024).decode().strip()
        need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+', self.key), 'Credential format differs; value withheld')
        fields = unit_fields(unit)
        need(fields.get('ActiveState') == 'active' and fields.get('User') == fields.get('Group') == 'jwk',
             'Declared Runtime is not active under the expected user')
        self.pid = int(fields['MainPID'])
        need(self.pid > 1, 'Invalid Runtime PID')
        self.ticks = ticks(self.pid)
        self.cgroup = fields['ControlGroup']
        self.config_sha = hashlib.sha256(read(base / 'config/runtime.toml')).hexdigest()

    def stable(self):
        need(int(unit_fields(self.unit)['MainPID']) == self.pid and ticks(self.pid) == self.ticks
             and hashlib.sha256(read(self.base / 'config/runtime.toml')).hexdigest() == self.config_sha,
             'Runtime/config changed; no further API request')

    def call(self, method, path, body=None, timeout=30):
        self.stable()
        allowed = path in ('/health', '/sandboxes-cold', '/v2/sandboxes', '/v2/sandboxes?limit=1')
        allowed = allowed or re.fullmatch(r'/sandboxes/[A-Za-z0-9_-]{1,128}(?:/snapshots|/fork)?', path)
        need(allowed and method in ('GET', 'POST', 'DELETE'), 'Route outside cohort scope')
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=timeout)
        try:
            connection.request(method, path, json.dumps(body).encode() if body is not None else None,
                               {'Content-Type': 'application/json', 'X-API-Key': self.key})
            response = connection.getresponse()
            raw = response.read(2 * 1024**2 + 1)
            need(len(raw) <= 2 * 1024**2 and not response.getheader('X-Next-Token'),
                 'Oversized or paginated reply; inventory uncertain')
            return response.status, json.loads(raw) if raw else None
        finally:
            connection.close()


def capacity(kind):
    maximum = int(Path('/sys/module/ublk_drv/parameters/ublks_max').read_text())
    devices = [p for p in Path('/sys/class/ublk-char').iterdir() if re.fullmatch(r'ublkc\d+', p.name)]
    need(0 < maximum <= 4096 and len(devices) <= maximum, 'Unexpected ublk capacity')
    # One rootfs for cold, rootfs+RAM for restore/Fork. Existing pool may reduce
    # demand, but is not treated as a reservation. Two slots stay as headroom.
    required = (1 if kind == 'cold' else 2) + 2
    need(maximum - len(devices) >= required, 'Insufficient ublk capacity for ' + kind + '; existing devices preserved')
    return {'limit': maximum, 'count': len(devices), 'requiredFree': required}


def cgroup_memory(group):
    try:
        need(isinstance(group, str) and group.startswith('/') and '..' not in group.split('/'), 'Invalid cgroup')
        directory = Path('/sys/fs/cgroup' + group)
        need(directory.resolve(strict=True) == directory, 'Redirected cgroup')
        current = int((directory / 'memory.current').read_text())
        fields = dict(line.split() for line in (directory / 'memory.stat').read_text().splitlines())
        return {'available': True, 'currentBytes': current,
                'statBytes': {k: int(fields[k]) for k in ('anon', 'file', 'kernel', 'shmem', 'slab') if k in fields},
                'scope': 'runtime_unit_charge_including_retained_pools_and_helpers',
                'UBProviderCostIncluded': False, 'componentValuesNotAdditive': True}
    except Exception as error:
        return {'available': False, 'errorType': type(error).__name__}


def snapshot_evidence(base, sid, variant, binding):
    repo = base / 'state/snapshot-store/repository'
    record = load(repo / 'catalog/records' / (sid + '.json'))
    manifest = load(repo / 'snapshots' / sid / 'firecracker-manifest.json')
    need(record.get('id') == sid, 'Committed capture identity mismatch')
    need(manifest.get('memory', {}).get('virtualSize') == 512 * 1024**2,
         'Capture RAM size differs from the fixed comparison cohort')
    native = manifest.get('nativeRootfs')
    if variant == 'native':
        need(isinstance(native, dict) and native.get('version') == 1
             and native.get('sourceImage') == SOURCE and native.get('filesystem') == 'ext4'
             and len(native.get('layers', [])) == 1, 'Portable native rootfs references absent from capture')
        need(native['layers'] == [{'sha256': layer['sha256'], 'bytes': layer['bytes']}
                                  for layer in binding['layers']], 'Captured content differs from live binding')
        serialized = json.dumps(native)
        need('socket' not in serialized and '/dev/' not in serialized and 'fd:' not in serialized,
             'Transient native resource persisted in capture')
    else:
        need(native is None, 'Original capture unexpectedly contains native pmem')
    return {'snapshotId': sid, 'nativeRootfs': native,
            'memoryVirtualBytes': manifest.get('memory', {}).get('virtualSize'),
            'committedRecordSha256': hashlib.sha256(read(repo / 'catalog/records' / (sid + '.json'))).hexdigest(),
            'snapshotsRetained': True, 'crossNodeSnapshotMigrationTested': False}


class Workload:
    def __init__(self, api, work, source):
        self.api, self.work, self.source = api, work, source
        for name in ('tmp', 'cache', 'cli-config/aenv'):
            (work / name).mkdir(parents=True, mode=0o700)
        self.credentials = work / 'cli-config/aenv/credentials'
        self.credentials.write_text('url = "http://127.0.0.1:' + str(api.port) + '"\napi_key = ' + json.dumps(api.key) + '\n')
        os.chmod(self.credentials, 0o600)
        self.env = {'HOME': '/home/jwk', 'USER': 'jwk', 'LOGNAME': 'jwk', 'LANG': 'C.UTF-8',
                    'PATH': str(api.base / 'native/bin') + ':/usr/bin:/bin',
                    'LD_LIBRARY_PATH': str(api.base / 'native/lib') + ':' + str(api.base / 'native/fallback/lib'),
                    'XDG_CONFIG_HOME': str(work / 'cli-config'), 'XDG_CACHE_HOME': str(work / 'cache'),
                    'TMPDIR': str(work / 'tmp'), 'NO_PROXY': '127.0.0.1,localhost,::1',
                    'no_proxy': '127.0.0.1,localhost,::1'}

    def command(self, sid, source, argv, label):
        self.api.stable()
        start = time.monotonic()
        stdout, stderr = self.work / (label + '.stdout.log'), self.work / (label + '.stderr.log')
        code = None
        try:
            with stdout.open('xb') as out, stderr.open('xb') as err:
                child = subprocess.run([str(self.api.base / 'bin/aenv'), 'exec', sid, 'python', '-c', source, *argv],
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=self.env, timeout=180)
                code = child.returncode
        except subprocess.TimeoutExpired:
            code = 'TIMEOUT'
        # Only public workload output is parsed; logs stay private/local and are
        # never included in published packets or a GitHub report.
        raw = read(stdout, 1024**2).decode(errors='replace')
        return code, raw, time.monotonic() - start

    def __call__(self, sids, run_id, sample):
        tokens = [hashlib.sha256((run_id + sid).encode()).hexdigest()[:32] for sid in sids]
        def one(index):
            code, output, elapsed = self.command(sids[index], self.source,
                                                 [tokens[index], json.dumps(tokens)], 'workload-' + str(index))
            matches = [line.removeprefix('COW_PUBLIC_RESULT=') for line in output.splitlines()
                       if line.startswith('COW_PUBLIC_RESULT=')]
            result = json.loads(matches[0]) if len(matches) == 1 else None
            return {'sandboxId': sids[index], 'exitCode': code, 'hostSeconds': elapsed,
                    'passed': code == 0 and isinstance(result, dict), 'result': result}
        rows = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(one, i) for i in range(2)]
            while not all(j.done() for j in jobs):
                sample([sids[i] for i, job in enumerate(jobs) if not job.done()])
                concurrent.futures.wait(jobs, timeout=2)
            rows = [j.result() for j in jobs]
        isolation = ('import json,sys; from pathlib import Path; own=sys.argv[1]; peers=json.loads(sys.argv[2]); '
                     'assert Path("/tmp/cow-private-"+own).read_text()==own; '
                     'assert all(not Path("/tmp/cow-private-"+p).exists() for p in peers if p!=own); '
                     'print("COW_PRIVATE_ISOLATION_OK")')
        for i, row in enumerate(rows):
            code, output, _ = self.command(sids[i], isolation, [tokens[i], json.dumps(tokens)], 'isolation-' + str(i))
            row['privateUpperIsolationPassed'] = code == 0 and 'COW_PRIVATE_ISOLATION_OK' in output
            row['passed'] = row['passed'] and row['privateUpperIsolationPassed']
        return rows

    def close(self):
        if self.credentials.exists():
            self.credentials.unlink()


def run(args):
    import fcntl
    need(sys.platform == 'linux' and os.geteuid() == 1204 and os.uname().machine == 'aarch64'
         and socket.gethostname() == ('server1' if args.node == 'node-a' else 'agent1'), 'Use declared node ordinary ARM64 user')
    os.umask(0o077)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Owned cohort termination requested')
    signal.signal(signal.SIGTERM, interrupted)
    engine, observer = module('cohort_engine'), module('ram_observer')
    workload_path = Path(__file__).resolve().parent / 'public_workload.py'
    workload_source = read(workload_path).decode()
    need(hashlib.sha256(workload_source.encode()).hexdigest() == MODULE_PINS['public_workload'], 'Workload source differs')
    native_base = ROOT / 'deployments/agentenv-native-6cdac56'
    seed = load(native_base / 'rootfs-inputs.json')
    need(seed.get('status') == 'ORIGINAL_ROOTFS_INPUTS_SEEDED_NOT_GUEST_ACCEPTANCE'
         and seed.get('coreCommit') == CORE and seed.get('node') == args.node and seed.get('sourceImage') == SOURCE,
         'Same-source input receipt missing or differs')
    image = seed['ociReference']
    need(isinstance(image, str) and image.startswith('ocidir:///home/jwk/agent/')
         and image.endswith('@sha256:039f1b18eb5c1bf56c074234e718af2f6156cbb729d638f05d1d8cf95dffe409'), 'Unexpected image reference')
    base = native_base if args.variant == 'native' else ROOT / 'deployments/agentenv-ae9c626-baseline'
    installation = load(base / 'installation.json')
    expected = CORE if args.variant == 'native' else ORIGINAL
    need(installation.get('runtimeSourceCommit', installation.get('commit')) == expected
         and installation.get('node') == args.node, 'Installed variant provenance differs')
    binding = None
    if args.variant == 'native':
        definition = load(base / 'definition-native.json')
        pin = definition.get('rootfsBinding')
        need(isinstance(pin, dict) and hashlib.sha256(read(pin['path'])).hexdigest() == pin['sha256'], 'Native binding differs')
        binding = load(pin['path'])
        need(binding.get('version') == 3 and binding.get('sourceImage') == SOURCE, 'Native v3 source differs')
        port = definition['apiPort']
        need(type(port) is int and 18082 <= port <= 18089, 'Native port differs')
        unit = 'jwk-aenv-native-6cdac56-' + args.node + '.service'
        journal_dir = base
    else:
        port = 18080
        unit = 'jwk-aenv-ae9c626-' + args.node + '.service'
        journal_dir = ROOT / 'r' / ('cohort-original-' + args.node + '-v1')
        journal_dir.mkdir(mode=0o700, exist_ok=True)
        need(journal_dir.resolve(strict=True) == journal_dir and journal_dir.stat().st_uid == 1204, 'Journal directory differs')
    shared_lock = ROOT / 'relay' / ('cow55-replay-' + args.node + '.lock')
    locks = []
    workload = None
    report = None
    try:
        # Original lock is the existing read/replay coordination lock; native
        # lock is also used by activation, rollback and base retirement.
        for path in ([shared_lock] if args.variant == 'original' else []) + [journal_dir / 'cohort.lock']:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            locks.append(fd)
            need(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_uid == 1204, 'Lock metadata differs')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state_path = journal_dir / 'cohort-state.json'
        state = load(state_path) if state_path.exists() else {
            'version': 1, 'phase': 'prepared', 'openRequests': [], 'sandboxIds': [], 'outcomeUncertain': False}
        need(engine.quiescent(state), 'Previous cohort unresolved; preserve it')
        need(args.attempt == 1 and not state.get('runId'), 'This entry runs one attempt; do not blindly repeat a previous cohort')
        api = Api(base, unit, port)
        need(api.call('GET', '/health')[0] == 204, 'Runtime health failed')
        disk = os.statvfs(ROOT)
        need(disk.f_bavail * disk.f_frsize >= 8 * 1024**3, 'Need 8GiB free workspace space for this capture/Fork cohort')
        work = ROOT / 'relay/reports' / ('cohort-' + args.node + '-' + args.variant + '-' + uuid.uuid4().hex[:12])
        work.mkdir(mode=0o700)
        evidence = {'node': args.node, 'variant': args.variant, 'sourceCommit': expected,
                    'sourceImage': SOURCE, 'workloadSha256': MODULE_PINS['public_workload'],
                    'runtimePid': api.pid, 'runtimeTicks': api.ticks, 'configSha256': api.config_sha,
                    'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    'binarySha256': {name: digest_file(base / 'bin' / name) for name in ('server', 'aenv')},
                    'reportDirectory': str(work), 'measurementScope': 'public_PyPika_not_private_replay',
                    'coldCacheClaimed': False, 'servicesChanged': False, 'SDKCalledByController': False,
                    'memfileCrossNodeCowImplemented': False, 'globalNetSavingBytes': None,
                    'rootfsHostAccessResidency': {'status': 'NA_NO_HOST_READ_OBSERVER_ATTACHED'},
                    'UBPhysicalChargedBytes': None, 'privateUpperResidentBytes': None}
        need(all(evidence['binarySha256'][name] == installation.get('binaries', {}).get(name)
                 for name in ('server', 'aenv')), 'Installed executable differs from its preparation receipt')
        workload = Workload(api, work, workload_source)
        def persist(value):
            save(state_path, value)
            save(work / 'report.json', {**evidence, 'cohort': value})
        def observe(phase, sids):
            start = time.time_ns()
            ram = observer.collect_ram(base, api.pid, api.ticks, sids)
            return {'phase': phase, 'startNs': start, 'endNs': time.time_ns(),
                    'ram': ram, 'runtimeCharge': cgroup_memory(api.cgroup)}
        cohort = engine.Cohort(api, state, persist, observe, workload, capacity,
                               lambda sid: snapshot_evidence(base, sid, args.variant, binding))
        result = cohort.run(image)
        report = {**evidence, 'cohort': result,
                  'status': 'COHORT_FUNCTIONAL_PASS_SNAPSHOTS_RETAINED' if result['lifecyclePassed']
                  and result['phase'] == 'quiesced' else 'STOPPED_COHORT_PRESERVE_JOURNAL'}
        save(work / 'report.json', report)
        print(json.dumps(report, indent=2), flush=True)
        return 0 if report['status'].startswith('COHORT_FUNCTIONAL_PASS') else 1
    finally:
        if workload is not None:
            workload.close()
        for fd in reversed(locks):
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', choices=('node-a', 'node-b'), required=True)
    parser.add_argument('--variant', choices=('original', 'native'), required=True)
    parser.add_argument('--attempt', type=int, default=1)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'status': 'PLAN_ONLY', 'node': args.node, 'variant': args.variant,
                          'coldParents': 1, 'captureCalls': 1, 'restoreCalls': 1, 'forkCalls': 1,
                          'workloadChildren': 2, 'snapshotsRetained': True,
                          'memfileCrossNodeCowImplemented': False}))
        return 0
    need(bool(MODULE_PINS), 'Unpublished draft; pinned modules required')
    return run(args)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'STOPPED_COHORT_PRESERVE_JOURNAL',
                          'errorType': type(error).__name__,
                          'reason': str(error)[:600] if isinstance(error, RuntimeError)
                          else 'Inspect preserved local journal; do not blindly repeat'}))
        raise SystemExit(1)
