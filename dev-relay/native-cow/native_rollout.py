"""User-run A coordinator: offline prepare, two root blocks, then comparison.

This public entry transfers private input only over the existing authenticated
A-to-B SSH connection. It never uploads inputs/reports to GitHub. No effects
without --run. Unknown or interrupted stage outcomes are preserved, not retried.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess
import sys
import time
import urllib.request

ROOT = Path('/home/jwk/agent')
WORK = ROOT / 'r/cow-rollout-v4'
DEPLOYMENT = ROOT / 'deployments/agentenv-native-6cdac56'
SELF = ROOT / 'native_rollout.py'
PUBLIC_COMMIT = '767cf12175dfdc0e9a3fa31e7e53d221307f0064'
PUBLIC_PINS = {'A_prepare_release_v4.py': 'f9c80889c21e041c1b28420889cb8acd4270eed33ebc6a442cf0114c272f4ece', 'prepare_native_service_v4.py': '0e128f48f0094d42281cb766347f87eb65d24ea558d832e72d10621c4722efd5', 'native_release_bundle.py': 'de2ebddf3d2599306b403dfef38e944669b3d2dab345502709bfb20cd6a53641', 'native_rootfs_inputs.py': '4c0c92a447efad6aa1110c9359ef7c768e416205a59a9413b1211ca08ae28947', 'native_provider_v4.py': '3ae0a58a4e51e056cecf61f7cd60a362ed82ac317c8c22e3a1262887c6bcfb36', 'legacy_provider_handoff.py': 'fe5c1819e0bf662d62cebf3a307f0204be89258086be1ec25c384c140a469c23', 'native_cohort.py': '5d14548e9953974f87c3bf17997dfedbaacf5d65b7a2e4b9fd3358d49f6cf346', 'cohort_engine.py': 'b0c3d818e45eebdcc909ee859fb63a002c10ac264eb9e2a87fb36babf782b45d', 'ram_observer.py': '0b8ea355e4e0dd6ad8422968e63ff5dd9b640166cd29406096480589c6cc80af', 'public_workload.py': 'dfd483df3307a3a677dfc2bb1f4559b76aea3fb8ad4cc200832d572fb6a44490', 'cohort_report.py': '3d2ac6bfb2eb6f75d1c4ca51a4c03d2d6ab4e2945eda87e63f656f116df52f15'}
PYTHON = '/usr/bin/python3'
SSH = ['/usr/bin/ssh', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
       '-oConnectTimeout=10', '-oServerAliveInterval=15', '-oServerAliveCountMax=4', 'jwk@agent1']
BUILD = ROOT / 'builds/native-release-v4/return.json'
TOOLS = ROOT / 'r/pm-a-v1/tools-runtime/return.json'


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def safe(path, existing=True):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=existing) == path,
         'Redirected or out-of-workspace path')
    if path.exists():
        need(path.stat().st_uid == 1204, 'Unexpected path owner')
    return path


def read(path, limit=2 * 1024**2):
    path = safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204 and 0 <= meta.st_size <= limit, 'Unexpected input file')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    need(len(data) == meta.st_size and (meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns) ==
         (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Input changed')
    return data


def load(path):
    return json.loads(read(path))


def sha(path):
    path = safe(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size <= 4 * 1024**3, 'File exceeds transfer budget')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    need((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Transfer source changed')
    return digest


def save(path, value):
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('xb') as stream:
        stream.write((json.dumps(value, indent=2) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def ordinary(node):
    need(os.name == 'posix' and os.getuid() == os.geteuid() == 1204
         and os.getgid() == os.getegid() == 1205 and os.uname().machine == 'aarch64'
         and socket.gethostname() == ('server1' if node == 'node-a' else 'agent1'),
         'Use the declared ordinary ARM64 node user')
    caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(caps[k].strip(), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), 'Capability-free coordinator required')
    os.umask(0o077)


def install_bytes(path, data, digest):
    need(hashlib.sha256(data).hexdigest() == digest, 'Published payload hash differs')
    safe(path, False)
    if path.exists():
        need(read(path, 8 * 1024**2) == data, 'Existing helper differs; preserve it')
        return
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class OfficialOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('Unexpected redirect while downloading pinned public source')


def download():
    need(PUBLIC_PINS, 'Unpublished rollout draft')
    client = urllib.request.build_opener(OfficialOnly())
    for name, pin in PUBLIC_PINS.items():
        need(re.fullmatch(r'[A-Za-z0-9_]+\.py', name), 'Invalid public file name')
        path = ROOT / name
        if path.exists():
            need(sha(path) == pin, 'Existing helper differs: ' + name)
            continue
        url = ('https://raw.githubusercontent.com/LittleFish-15/AgentENV/' + PUBLIC_COMMIT +
               '/dev-relay/native-cow/' + name)
        with client.open(url, timeout=60) as response:
            need(response.status == 200, 'Public download failed')
            data = response.read(8 * 1024**2 + 1)
        need(len(data) <= 8 * 1024**2, 'Public file too large')
        install_bytes(path, data, pin)


def remote_command(arguments):
    return SSH + [shlex.join([PYTHON, '-I', '-B', str(SELF), *arguments, '--run'])]


def transfer(path, destination):
    """Create one pinned B file via SSH stdin; no shell data interpolation."""
    path, destination = safe(path), Path(destination)
    need(destination.parent in (ROOT, WORK) and destination.name not in ('', '.', '..'), 'Transfer destination outside rollout')
    size, digest = path.stat().st_size, sha(path)
    script = r'''import hashlib,os,socket,stat,sys
from pathlib import Path
p=Path(DEST)
assert os.getuid()==os.geteuid()==1204 and socket.gethostname()=='agent1'
assert p.parent in (Path('/home/jwk/agent'),Path('/home/jwk/agent/r/cow-rollout-v4'))
assert p.parent.resolve(strict=True)==p.parent and p.parent.stat().st_uid==1204
assert not p.is_symlink() and not p.exists(),'Existing transfer destination preserved'
os.umask(0o077)
partial=p.with_name(p.name+'.partial')
h=hashlib.sha256();remaining=SIZE
with partial.open('xb') as out:
 while remaining:
  block=sys.stdin.buffer.read(min(1048576,remaining));assert block,'Truncated transfer'
  h.update(block);out.write(block);remaining-=len(block)
 assert not sys.stdin.buffer.read(1),'Excess transfer input'
 out.flush();os.fsync(out.fileno())
assert h.hexdigest()==SHA,'Transferred hash differs; partial retained'
assert not p.exists() and not p.is_symlink()
os.link(partial,p)
partial.unlink()
print('PINNED_TRANSFER_COMPLETE')
'''
    source = 'DEST=' + repr(str(destination)) + '\nSIZE=' + str(size) + '\nSHA=' + repr(digest) + '\n' + script
    # Remote code is literal and arguments are shell-quoted. File bytes travel
    # solely through stdin and are never evaluated as command text.
    with path.open('rb') as stream:
        result = subprocess.run(SSH + [shlex.join([PYTHON, '-I', '-B', '-c', source])],
                                stdin=stream, capture_output=True, timeout=1800)
    need(result.returncode == 0 and b'PINNED_TRANSFER_COMPLETE' in result.stdout,
         'Pinned transfer failed; preserve target partial and stage journal')
    return digest


class Steps:
    def __init__(self, node):
        self.node = node
        WORK.mkdir(mode=0o700, exist_ok=True)
        safe(WORK)
        (WORK / 'logs').mkdir(mode=0o700, exist_ok=True)
        self.path = WORK / ('steps-' + node + '.json')
        need(not self.path.exists(), 'Existing rollout journal preserved; do not restart from the beginning')
        self.state = {'revision': 'native-rollout-v1', 'node': node, 'steps': [], 'status': 'PREPARING',
                      'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
        save(self.path, self.state)

    def call(self, name, command, timeout=600, allow_failure=False):
        need(re.fullmatch('[a-z0-9-]+', name), 'Invalid phase name')
        row = {'name': name, 'state': 'running', 'startNs': time.time_ns()}
        self.state['steps'].append(row)
        save(self.path, self.state)
        log = WORK / 'logs' / (name + '.log')
        print('PHASE=' + name, flush=True)
        with log.open('xb') as stream:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT)
            start = last = time.monotonic()
            try:
                while child.poll() is None:
                    now = time.monotonic()
                    if now - last >= 30:
                        print('PROGRESS phase=' + name + ' elapsed_s=' + str(int(now - start)), flush=True)
                        last = now
                    if now - start > timeout:
                        child.terminate()
                        try:
                            child.wait(20)
                        except subprocess.TimeoutExpired:
                            # Only this owned launcher is reaped; remote/API
                            # side effects remain explicitly uncertain.
                            child.kill()
                            child.wait()
                        raise RuntimeError('Phase timed out; remote/API outcome may remain pending: ' + name)
                    time.sleep(1)
            except BaseException:
                if child.poll() is None:
                    child.terminate()
                raise
        row.update(state='completed', exitCode=child.returncode, finishNs=time.time_ns(), log=str(log))
        save(self.path, self.state)
        need(child.returncode == 0 or allow_failure, 'Phase failed; inspect full log and preserved journal: ' + name)
        return log, child.returncode

    def local(self, name, file, args=(), timeout=600, allow_failure=False):
        need(file in PUBLIC_PINS and sha(ROOT / file) == PUBLIC_PINS[file], 'Public executable changed')
        return self.call(name, [PYTHON, '-I', '-B', str(ROOT / file), *map(str, args)], timeout, allow_failure)


def root_block(text, begin, end):
    need(text.count(begin) == text.count(end) == 1, 'Expected exactly one reviewed root block')
    block = text.split(begin, 1)[1].split(end, 1)[0].strip() + '\n'
    need(block.startswith('/usr/bin/python3 -I -B - <<'), 'Unexpected root block prefix')
    return block


def combined_root(node, logs):
    provider, runtime = (read(path, 2 * 1024**2).decode() for path in logs)
    a = root_block(provider, 'BEGIN_REAL_PROVIDER_ROOT_BLOCK', 'END_REAL_PROVIDER_ROOT_BLOCK')
    b = root_block(runtime, 'BEGIN_NATIVE_CONTROL_PLAN', 'END_NATIVE_CONTROL_PLAN')
    marker = 'OWNED_COW_COORDINATED_ROOT_' + node.upper().replace('-', '_')
    need(marker not in a + b, 'Root delimiter collision')
    return "/usr/bin/bash -e <<'" + marker + "'\n" + a + b + marker + '\n'


def prepare_b(args):
    ordinary('node-b')
    for name, pin in PUBLIC_PINS.items():
        need(sha(ROOT / name) == pin, 'Transferred public helper differs')
    s = Steps('node-b')
    s.local('receive-release', 'native_release_bundle.py', ['receive', '--archive', WORK / 'release.tar',
            '--sha256', args.bundle_sha, '--destination', WORK / 'release', '--run'], 1800)
    s.local('receive-rootfs', 'native_rootfs_inputs.py', ['receive', '--archive', WORK / 'rootfs.tar',
            '--sha256', args.inputs_sha, '--destination', WORK / 'rootfs', '--run'], 1800)
    s.local('prepare-provider', 'native_provider_v4.py', ['prepare', '--node', 'node-b',
            '--build-report', WORK / 'release/build-receipt.json', '--owner-binding', WORK / 'binding-a.json',
            '--binding-sha256', args.binding_sha, '--run'])
    binding = ROOT / 'r/up-b-v4/binding/binding.json'
    s.local('prepare-runtime', 'prepare_native_service_v4.py', ['prepare', '--node', 'node-b',
            '--core-report', WORK / 'release/build-receipt.json', '--tools-report', WORK / 'release/tools-receipt.json',
            '--tools-image', WORK / 'release/tools.ext4', '--rootfs-binding', binding, '--binding-sha256', sha(binding)])
    s.local('seed-rootfs', 'native_rootfs_inputs.py', ['seed', '--input-directory', WORK / 'rootfs', '--node', 'node-b', '--run'], 1800)
    s.state['status'] = 'B_FILES_PREPARED_NO_SDK_NO_NEW_SERVICE'
    save(s.path, s.state)


def ready(node):
    import http.client
    ordinary(node)
    owner = load(ROOT / ('r/up-a-v4/provider/owner.json' if node == 'node-a' else 'r/up-b-v4/provider/owner.json'))
    need(owner.get('state') == 'serving', 'Provider not serving yet')
    unit = 'jwk-aenv-native-6cdac56-' + node + '.service'
    result = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState', '--value'],
                            capture_output=True, text=True, timeout=10)
    need(result.returncode == 0 and result.stdout.strip() == 'active', 'New Runtime not active yet')
    return {'status': 'NEW_PROVIDER_AND_RUNTIME_ACTIVE_NOT_GUEST_ACCEPTANCE', 'node': node}


def cohort(node, variant, s=None):
    ordinary(node)
    command = [PYTHON, '-I', '-B', str(ROOT / 'native_cohort.py'), '--node', node, '--variant', variant, '--run']
    name = variant + '-cohort-' + node
    if s is not None:
        log, code = s.call(name, command, 2100, True)
    else:
        log = WORK / 'logs' / (name + '.log')
        with log.open('xb') as stream:
            code = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=2100).returncode
    raw = read(log, 8 * 1024**2)
    report = json.loads(raw)
    # A preflight failure can occur before a report directory exists. Carry the
    # declared pair identity into the aggregate, without pretending it executed.
    report.setdefault('node', node)
    report.setdefault('variant', variant)
    report.setdefault('sourceImage', 'sha256:cf786498f77bf4ba6235156ab8540d0b9335e874e70b95efbeb53168e0dce68d')
    report.setdefault('workloadSha256', PUBLIC_PINS['public_workload.py'])
    save(WORK / (variant + '-' + node + '.json'), report)
    print(json.dumps({'status': 'COHORT_REPORT_RECORDED', 'exitCode': code, 'node': node, 'variant': variant}), flush=True)
    return report


def b_root(args):
    ordinary('node-b')
    # These phases have their own exact helper journals; never append to B's
    # completed preparation journal or rerun its earlier commands.
    commands = [
        ('import-manifest', 'native_provider_v4.py', ['import-manifest', '--node', 'node-b',
           '--manifest', WORK / 'owner-manifest.json', '--manifest-sha256', args.manifest_sha, '--run']),
        ('provider-root', 'native_provider_v4.py', ['start-plan', '--node', 'node-b', '--run']),
        ('runtime-root', 'prepare_native_service_v4.py', ['activation-plan', '--node', 'node-b'])]
    logs = []
    for name, entry, arguments in commands:
        need(sha(ROOT / entry) == PUBLIC_PINS[entry], 'Published helper changed')
        log = WORK / 'logs' / (name + '.log')
        with log.open('xb') as out:
            result = subprocess.run([PYTHON, '-I', '-B', str(ROOT / entry), *map(str, arguments)],
                                    stdout=out, stderr=subprocess.STDOUT, timeout=180)
        need(result.returncode == 0, 'B phase failed: ' + name)
        logs.append(log)
    text = combined_root('node-b', logs[-2:])
    with (WORK / 'root-node-b.txt').open('x') as stream:
        stream.write(text)


def fetch_b(name):
    need(name in ('root-node-b.txt', 'original-node-b.json', 'native-node-b.json'), 'Unexpected fetched file')
    result = subprocess.run(remote_command(['b-fetch', '--file', name]), capture_output=True, timeout=30)
    need(result.returncode == 0 and len(result.stdout) <= 8 * 1024**2, 'B bounded report fetch failed')
    value = json.loads(result.stdout)
    need(value.get('name') == name and isinstance(value.get('text'), str)
         and hashlib.sha256(value['text'].encode()).hexdigest() == value['sha256'], 'B result framing differs')
    with (WORK / name).open('x') as stream:
        stream.write(value['text'])
    return value['text']


def wait_ready(node):
    start = last = time.monotonic()
    while time.monotonic() - start < 900:
        try:
            if node == 'node-a':
                ready(node)
            else:
                r = subprocess.run(remote_command(['b-ready']), capture_output=True, timeout=30)
                need(r.returncode == 0, 'Waiting for B root activation')
            return
        except Exception:
            pass
        if time.monotonic() - last >= 30:
            print('WAITING_FOR_REVIEWED_ROOT_ACTIVATION node=' + node, flush=True)
            last = time.monotonic()
        time.sleep(3)
    raise RuntimeError('Root/provider readiness not observed within 15 minutes; journals preserved')


def run_a():
    ordinary('node-a')
    need(Path(__file__).resolve() == SELF, 'Place this entry at /home/jwk/agent/native_rollout.py')
    download()
    s = Steps('node-a')
    s.local('build-coordinated-release', 'A_prepare_release_v4.py', ['--run'], 10800)
    need(load(BUILD).get('rootfsReady') is True, 'Real executable rootfs preparation failed; binaries alone are insufficient')
    s.local('pack-rootfs-inputs', 'native_rootfs_inputs.py', ['pack', '--archive', WORK / 'rootfs.tar', '--run'], 1800)
    inputs_sha = sha(WORK / 'rootfs.tar')
    s.local('receive-rootfs-a', 'native_rootfs_inputs.py', ['receive', '--archive', WORK / 'rootfs.tar',
            '--sha256', inputs_sha, '--destination', WORK / 'rootfs', '--run'], 1800)
    s.local('pack-release', 'native_release_bundle.py', ['pack', '--build-report', BUILD, '--tools-report', TOOLS,
            '--archive', WORK / 'release.tar', '--run'], 1800)
    bundle_sha = sha(WORK / 'release.tar')
    # Create exactly this fresh rollout directory on B. No inventory scan or
    # deletion occurs. A stale directory means stop, not overwrite/reuse.
    code = "import os,socket;from pathlib import Path;assert os.geteuid()==1204 and socket.gethostname()=='agent1';p=Path('/home/jwk/agent/r/cow-rollout-v4');assert p.parent.resolve(strict=True)==p.parent and p.parent.stat().st_uid==1204;os.umask(0o077);p.mkdir(mode=0o700)"
    s.call('create-b-rollout-directory', SSH + [shlex.join([PYTHON, '-I', '-B', '-c', code])], 30)
    transfer(SELF, SELF)
    for name in PUBLIC_PINS:
        transfer(ROOT / name, ROOT / name)
    transfer(WORK / 'rootfs.tar', WORK / 'rootfs.tar')
    transfer(WORK / 'release.tar', WORK / 'release.tar')
    s.local('prepare-provider-a', 'native_provider_v4.py', ['prepare', '--node', 'node-a', '--build-report', BUILD,
            '--source-config', WORK / 'rootfs/source-config.json', '--run'], 1800)
    binding = ROOT / 'r/up-a-v4/binding/binding.json'
    binding_sha = transfer(binding, WORK / 'binding-a.json')
    s.call('prepare-b', remote_command(['b-prepare', '--bundle-sha', bundle_sha, '--inputs-sha', inputs_sha,
                                      '--binding-sha', binding_sha]), 3600)
    s.local('prepare-runtime-a', 'prepare_native_service_v4.py', ['prepare', '--node', 'node-a', '--core-report', BUILD,
            '--tools-report', TOOLS, '--rootfs-binding', binding, '--binding-sha256', sha(binding)])
    s.local('seed-rootfs-a', 'native_rootfs_inputs.py', ['seed', '--input-directory', WORK / 'rootfs', '--node', 'node-a', '--run'], 1800)
    s.local('legacy-sdk-handoff', 'legacy_provider_handoff.py', ['transition-a', '--run'], 1800)
    # Baseline precedes the new UB publication. Original services/configs are
    # never restarted. Two nodes run concurrently but have no atomic barrier.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        remote = pool.submit(s.call, 'original-cohort-b', remote_command(['b-cohort', '--variant', 'original']), 2400, True)
        original_a = cohort('node-a', 'original')
        remote.result()
    original_b = json.loads(fetch_b('original-node-b.json'))
    for result in (original_a, original_b):
        state = result.get('cohort')
        need(state is not None and state.get('phase') == 'quiesced' and state.get('openRequests') == []
             and state.get('sandboxIds') == [] and state.get('outcomeUncertain') is False,
             'Original cohort did not confirm quiescence; stop before new publication')
    pa, _ = s.local('provider-root-a', 'native_provider_v4.py', ['start-plan', '--node', 'node-a', '--run'])
    ra, _ = s.local('runtime-root-a', 'prepare_native_service_v4.py', ['activation-plan', '--node', 'node-a'])
    block = combined_root('node-a', [pa, ra])
    (WORK / 'root-node-a.txt').write_text(block)
    print('\nCOPY_FOLLOWING_BLOCK_ON_A_ROOT\n' + block + 'KEEP_THIS_ORDINARY_A_TERMINAL_OPEN\n', flush=True)
    wait_ready('node-a')
    s.call('runtime-health-a', [PYTHON, '-I', '-B', str(DEPLOYMENT / 'libexec/native_service.py'), 'health'], 120)
    manifest = ROOT / 'r/up-a-v4/provider/replicas.json'
    manifest_sha = transfer(manifest, WORK / 'owner-manifest.json')
    s.call('prepare-b-root', remote_command(['b-root', '--manifest-sha', manifest_sha]), 300)
    block = fetch_b('root-node-b.txt')
    print('\nCOPY_FOLLOWING_BLOCK_ON_B_ROOT\n' + block + 'KEEP_THIS_ORDINARY_A_TERMINAL_OPEN\n', flush=True)
    wait_ready('node-b')
    s.call('runtime-health-b', remote_command(['b-health']), 180)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        remote = pool.submit(s.call, 'native-cohort-b', remote_command(['b-cohort', '--variant', 'native']), 2400, True)
        cohort('node-a', 'native')
        remote.result()
    fetch_b('native-node-b.json')
    arguments = []
    for variant in ('original', 'native'):
        for node in ('node-a', 'node-b'):
            arguments.extend(['--report', WORK / (variant + '-' + node + '.json')])
    s.local('comparison-report', 'cohort_report.py', [*arguments, '--output', WORK / 'comparison'])
    s.state.update(status='ROLLOUT_AND_DESCRIPTIVE_COMPARISON_FINISHED_CHECK_REPORT_GAPS',
                   comparison=str(WORK / 'comparison'), snapshotsRetained=True,
                   memfileCrossNodeCowImplemented=False, globalNetSavingBytes=None)
    save(s.path, s.state)
    print(json.dumps(s.state, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('run-a', 'b-prepare', 'b-root', 'b-ready', 'b-health', 'b-cohort', 'b-fetch'))
    for name in ('bundle-sha', 'inputs-sha', 'binding-sha', 'manifest-sha'):
        parser.add_argument('--' + name)
    parser.add_argument('--variant', choices=('original', 'native'))
    parser.add_argument('--file')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'status': 'PLAN_ONLY', 'mode': args.mode, 'targetAccessed': False,
                          'humanRootBlocks': 2, 'memfileCrossNodeCowImplemented': False}))
        return
    for key in ('bundle_sha', 'inputs_sha', 'binding_sha', 'manifest_sha'):
        value = getattr(args, key)
        need(value is None or re.fullmatch('[0-9a-f]{64}', value), 'Invalid input hash')
    if args.mode == 'run-a':
        run_a()
        return
    ordinary('node-b')
    need(Path(__file__).resolve() == SELF, 'Unexpected transferred coordinator path')
    if args.mode == 'b-prepare':
        need(all((args.bundle_sha, args.inputs_sha, args.binding_sha)), 'Missing B input pins')
        prepare_b(args)
    elif args.mode == 'b-root':
        need(args.manifest_sha, 'Missing owner manifest pin')
        b_root(args)
    elif args.mode == 'b-ready':
        print(json.dumps(ready('node-b')))
    elif args.mode == 'b-health':
        subprocess.run([PYTHON, '-I', '-B', str(DEPLOYMENT / 'libexec/native_service.py'), 'health'], check=True, timeout=120)
    elif args.mode == 'b-cohort':
        need(args.variant, 'Missing cohort variant')
        cohort('node-b', args.variant)
    else:
        need(args.file in ('root-node-b.txt', 'original-node-b.json', 'native-node-b.json'), 'File outside public result contract')
        data = read(WORK / args.file, 8 * 1024**2)
        print(json.dumps({'name': args.file, 'text': data.decode(), 'sha256': hashlib.sha256(data).hexdigest()}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'STOPPED_ROLLOUT_PRESERVE_ALL_JOURNALS_AND_INPUTS',
                          'errorType': type(error).__name__, 'reason': str(error)[:1000]
                          if isinstance(error, RuntimeError) else 'Inspect full phase logs; do not restart from the beginning',
                          'workDirectory': str(WORK), 'memfileCrossNodeCowImplemented': False}), flush=True)
        raise SystemExit(1)
