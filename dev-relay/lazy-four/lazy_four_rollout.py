import argparse

import concurrent.futures

import hashlib

import importlib.util

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

import uuid

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
        need(stat.S_ISREG(before.st_mode) and before.st_size <= 64 * 1024**3 + 128 * 1024**2, 'File exceeds transfer budget')
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
    need(sys.version_info >= (3, 11) and os.name == 'posix' and os.getuid() == os.geteuid() == 1204
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
        path = HELPERS / name
        if path.exists():
            need(sha(path) == pin, 'Existing helper differs: ' + name)
            continue
        url = ('https://raw.githubusercontent.com/LittleFish-15/AgentENV/' + PUBLIC_COMMIT +
               '/dev-relay/lazy-four/' + name)
        with client.open(url, timeout=60) as response:
            need(response.status == 200, 'Public download failed')
            data = response.read(8 * 1024**2 + 1)
        need(len(data) <= 8 * 1024**2, 'Public file too large')
        install_bytes(path, data, pin)

def remote_command(arguments):
    return SSH + [shlex.join([PYTHON, '-I', '-B', str(SELF), *arguments, '--run'])]

def transport_readiness():
    # This is executed only by the user-run A entry, before any build/journal or
    # B filesystem preparation. No connectivity was established during authoring.
    code = ("import os,socket,sys; assert sys.version_info>=(3,11) and sys.platform=='linux'; "
            "assert os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205; "
            "assert socket.gethostname()=='agent1' and os.uname().machine=='aarch64'; "
            "print('B_COORDINATOR_TRANSPORT_READY')")
    result = subprocess.run(SSH + [shlex.join([PYTHON, '-I', '-B', '-c', code])],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    need(result.returncode == 0 and result.stdout.strip() == b'B_COORDINATOR_TRANSPORT_READY',
         'Existing authenticated A-to-B SSH/Python prerequisite unavailable; no build, SDK or service change attempted')

def transfer(path, destination):
    """Create one pinned B file via SSH stdin; no shell data interpolation."""
    path, destination = safe(path), Path(destination)
    need(destination.parent in (ROOT, WORK, HELPERS) and destination.name not in ('', '.', '..'), 'Transfer destination outside rollout')
    size, digest = path.stat().st_size, sha(path)
    script = r'''import hashlib,os,socket,stat,sys
from pathlib import Path
p=Path(DEST)
assert os.getuid()==os.geteuid()==1204 and socket.gethostname()=='agent1'
assert p.parent in (Path('/home/jwk/agent'),Path('/home/jwk/agent/r/lazy-four-rollout-v1'),Path('/home/jwk/agent/lazy-four'))
assert p.parent.resolve(strict=True)==p.parent and p.parent.stat().st_uid==1204
assert not p.is_symlink(),'Redirected transfer destination preserved'
if p.exists():
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as old:
  meta=os.fstat(old.fileno());assert stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1 and meta.st_size==SIZE
  assert hashlib.file_digest(old,'sha256').hexdigest()==SHA,'Existing transfer destination differs'
 h=hashlib.sha256();remaining=SIZE
 while remaining:
  part=sys.stdin.buffer.read(min(1048576,remaining));assert part
  h.update(part);remaining-=len(part)
 assert not sys.stdin.buffer.read(1) and h.hexdigest()==SHA
 print('PINNED_TRANSFER_COMPLETE');raise SystemExit(0)
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
        need(file in PUBLIC_PINS and sha(HELPERS / file) == PUBLIC_PINS[file], 'Public executable changed')
        return self.call(name, [PYTHON, '-I', '-B', str(HELPERS / file), *map(str, args)], timeout, allow_failure)

def sync_module():
    path = HELPERS / 'four_sync.py'
    need(sha(path) == PUBLIC_PINS.get('four_sync.py'), 'Pinned pair coordination module differs')
    spec = importlib.util.spec_from_file_location('owned_cohort_sync', path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

def remote_pair(variant, epoch, operation, payload=None):
    need(variant in ('admission', 'completed') and re.fullmatch('[0-9a-f]{32}', epoch), 'Invalid remote pair scope')
    args = ['b-pair', '--variant', variant, '--pair-epoch', epoch, '--operation', operation]
    if payload is not None:
        args.extend(['--payload', json.dumps(payload, sort_keys=True, separators=(',', ':'))])
    audit = {'variant': variant, 'epoch': epoch, 'operation': operation, 'startNs': time.time_ns()}
    try:
        result = subprocess.run(remote_command(args), capture_output=True, timeout=30)
        audit.update(exitCode=result.returncode, stdoutBytes=len(result.stdout), stderrBytes=len(result.stderr))
        if result.returncode:
            text = (result.stdout + result.stderr)[-8192:].decode(errors='replace')
            audit['errorTail'] = re.sub(r'e2b_[A-Za-z0-9._~-]+', '[REDACTED]', text)
    except Exception as error:
        audit.update(errorType=type(error).__name__, controlDeliveryUncertain=True)
        raise
    finally:
        audit['endNs'] = time.time_ns()
        with (WORK / 'logs' / ('pair-' + variant + '-' + epoch + '.rpc.jsonl')).open('a') as stream:
            stream.write(json.dumps(audit) + '\n')
    need(result.returncode == 0 and len(result.stdout) <= 65536, 'B pair control unavailable; preserve its cohort journal')
    return json.loads(result.stdout)

def worker(node, mode, scenario=None, admission=None, completed=None):
    ordinary(node)
    need(sha(HELPERS / 'lazy_four_cohort.py') == PUBLIC_PINS['lazy_four_cohort.py'], 'Cohort helper changed')
    need(mode == 'parents' or mode == 'replay' and scenario in ('off', 'lazy'), 'Unexpected worker mode')
    name = 'parents' if mode == 'parents' else scenario
    args = [PYTHON, '-I', '-B', str(HELPERS / 'lazy_four_cohort.py'), mode, '--node', node, '--run']
    if scenario:
        args += ['--scenario', scenario]
    if admission or completed:
        need(admission and completed, 'Both dual-node gates required')
        args += ['--admission-epoch', admission, '--completed-epoch', completed]
    log = WORK / 'logs' / (name + '-' + node + '.log')
    print('PHASE=' + name + '-' + node, flush=True)
    with log.open('xb') as output:
        child = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT, timeout=9000)
    raw = read(log, 8 * 1024**2)
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        report = {'status': 'WORKER_STOPPED_BEFORE_COMPLETE_REPORT', 'node': node, 'scenario': scenario,
                  'exitCode': child.returncode, 'fullLog': str(log), 'ownedGuestsReleased': False,
                  'outcomeUncertain': True, 'globalNetSavingBytes': None}
    report['workerExitCode'] = child.returncode
    save(WORK / (name + '-' + node + '.json'), report)
    return report

def run_dual(steps, scenario):
    sync = sync_module()
    epochs = {'admission': uuid.uuid4().hex, 'completed': uuid.uuid4().hex}
    for stage, epoch in epochs.items():
        sync.prepare('node-a', stage, epoch)
        remote_pair(stage, epoch, 'prepare')
    result = {'epochs': epochs, 'status': 'DUAL_LAZY_FOUR_STARTING'}
    released = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        local = pool.submit(worker, 'node-a', 'replay', scenario, epochs['admission'], epochs['completed'])
        remote = pool.submit(steps.call, scenario + '-worker-b', remote_command(['b-worker', '--worker-mode', 'replay',
            '--scenario', scenario, '--admission-epoch', epochs['admission'], '--completed-epoch', epochs['completed']]), 9300, True)
        try:
            for stage, epoch in epochs.items():
                measuring, stage_released = False, False
                deadline, last = time.monotonic() + 8100, time.monotonic()
                while time.monotonic() < deadline:
                    need(not local.done() and not remote.done(), 'A worker ended before both dual-node gates completed')
                    states = {'node-a': sync.control('node-a', stage, epoch, 'status'),
                              'node-b': remote_pair(stage, epoch, 'status')}
                    need(not any(value.get('failed') or value.get('abort') for value in states.values()), 'Dual-node gate failed')
                    if not measuring and all(value.get('ready') for value in states.values()):
                        readies = {node: value['ready'] for node, value in states.items()}
                        message = sync.control_message('measure', stage, epoch, readies)
                        remote_pair(stage, epoch, 'measure', message)
                        sync.control('node-a', stage, epoch, 'measure', message)
                        measuring = True
                    if measuring and all(value.get('measured') for value in states.values()):
                        measured = {node: value['measured'] for node, value in states.items()}
                        message = sync.control_message('release', stage, epoch, readies, measured)
                        remote_pair(stage, epoch, 'release', message)
                        sync.control('node-a', stage, epoch, 'release', message)
                        result[stage] = {'readies': readies, 'measurements': measured}
                        stage_released = True
                        break
                    if time.monotonic() - last >= 30:
                        print('DUAL_PROGRESS gate=' + stage, flush=True)
                        last = time.monotonic()
                    time.sleep(1)
                need(stage_released, 'Dual-node gate deadline exceeded')
            released = True
            result['status'] = 'BOTH_DUAL_GATES_RELEASED_PENDING_WORKER_CLEANUP'
        except BaseException as error:
            result.update(status='DUAL_STOPPED_PRESERVE_JOURNALS', errorType=type(error).__name__,
                          reason=str(error)[:500] if isinstance(error, RuntimeError) else 'Inspect node-local logs')
        finally:
            if not released:
                for stage, epoch in epochs.items():
                    for node in ('node-a', 'node-b'):
                        try:
                            if node == 'node-a':
                                sync.control(node, stage, epoch, 'abort')
                            else:
                                remote_pair(stage, epoch, 'abort')
                        except Exception as error:
                            result.setdefault('abortErrors', []).append({'node': node, 'stage': stage, 'type': type(error).__name__})
            save(WORK / (scenario + '-gates.json'), result)
        a = local.result()
        remote.result()
    b = json.loads(fetch_b(scenario + '-node-b.json'))
    need(released and all(value.get('status') == 'LAZY_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED'
                         and value.get('workerExitCode') == 0 for value in (a, b)), 'Dual replay or cleanup did not complete')
    return a, b

ROOT=Path('/home/jwk/agent')
HELPERS=ROOT/'lazy-four'
WORK=ROOT/'r/lazy-four-rollout-v1'
DEPLOYMENT=ROOT/'deployments/agentenv-lazy-four-32ce41c'
SELF=HELPERS/'lazy_four_rollout.py'
CORE='32ce41c0ac6436198860f888e07ef9793e58dc40'
CORE_TREE='0e973a6e101c1a1c71b48bf70f2d910f48cd672f'
PYTHON='/usr/bin/python3'
BUILD=ROOT/'builds/native-four-release-v1/return.json'
TOOLS=WORK/'ordinary-tools-receipt.json'
SSH = ['/usr/bin/ssh', '-F', '/dev/null', '-i', '/home/jwk/.ssh/agentenv-native-four/id_ed25519',
       '-oIdentitiesOnly=yes', '-oIdentityAgent=none', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
       '-oUserKnownHostsFile=/home/jwk/.ssh/agentenv-native-four/known_hosts',
       '-oGlobalKnownHostsFile=/dev/null', '-oUpdateHostKeys=no', '-oHostKeyAlgorithms=ssh-ed25519',
       '-oForwardAgent=no', '-oClearAllForwardings=yes', '-oRequestTTY=no',
       '-oConnectTimeout=10', '-oServerAliveInterval=15', '-oServerAliveCountMax=4', 'jwk@agent1']
PUBLIC_COMMIT='7d059b643c06fa64925840a8e1b7c87ef2c51976'
PUBLIC_PINS={'four_release_bundle.py': '3c9f0e696e84f0130ea205cca17955c68601466b82f40e716c40bb872c7dcb4e', 'four_contract.py': 'b4a7ddf8eaf0459652a1b10ffd3026d10af8a71106cc9a2598333ca724eb1667', 'four_replay.py': '780779b6d3f2c6ea2b7c4a6115d193b9d4116b654251149bac1cc5e0d004d20e', 'four_lifecycle.py': '6ee2afa816da54041220dfb0df100bdea60cd0f878f48d2aac9a2084437de245', 'cohort_engine.py': '5d0cd8d4cf45b8301532517af832710c3928458f20c1cc64b0991500ddb1b89d', 'four_metrics.py': 'd1a3e80825db2f62234a6b81f8141a9442b34cf6de10680ddb4b933d8c728a20', 'four_sync.py': '53288337dcf1de0fcb8874640d518241aafc4ab08301c4a27d6317b72db07dac', 'ram_observer.py': 'fb675b345713ef0faa1e2470e2b5b2588d3162c14176054640608519c30dcef7', 'four_runtime.py': 'd73dc91bcc714b60b9d2f35bb11df2d2590d6a27e90a94bf0aff0325fc3d5003', 'lazy_four_cohort.py': 'a59d4225f2499ddd42da4fd751f0ce9191b29b12ea0181691a98221f5b27a5c6', 'lazy_four_snapshots.py': '03d05a220f18317ceba84521b504635f81a6aa14c2416064a2401cf00846fad2', 'lazy_four_provider.py': 'e7fa6c44f456682bde059be722b310d1f0927dc46b8dc09d538ffa39dd118c77', 'lazy_four_handoff.py': 'e50b9230de25cd4e7d02034adacb920097db29ed1f6b33766a14bfa8c263de4d', 'lazy_four_transport.py': '8ecf7067a1ab1dd6eb302f1797fe4af3be3f4131148a103d9d34710cda212806', 'lazy_four_root.py': 'd249963d74545270713e6678e0143f01ce2ba7c38f9254aafc61c90cf22c6ade', 'lazy_four_root_client.py': '4cd0f7f0da7ff1505be8b7e81c8c437a85f1bcf140d965940f7a2d5e6223b213', 'lazy_four_report.py': 'c2a69a91b1d2c2712c776060d1b97afeb24ecad58c0e333a33529c765a81e5e1', 'prepare_lazy_four_service.py': '5015655787a4600fdd83c3b6db4fa47a417be6be36dd6dad920c23e68351d7f6'}

def provider_path(node):
    return ROOT/('r/lazy4-a-v1' if node=='node-a' else 'r/lazy4-b-v1')


def prepare_original_tools():
    base=ROOT/'deployments/agentenv-ae9c626-baseline'
    relative='deps/tools/0.1.1/tools.ext4'
    path=base/relative
    need(path.resolve(strict=True)==path and path.stat().st_uid==1204 and path.stat().st_size<=512*1024**2,
         'Original snapshot tools disk differs')
    before=path.stat();expected=sha(path);after=path.stat()
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Existing tools image changed during hashing')
    save(TOOLS,{'status':'EXISTING_SNAPSHOT_TOOLS_VERIFIED_NO_IMAGE_CHANGE','mode':'runtime','originalUnchanged':True,
        'lowerFilesystem':'ext4','toolsVersion':'0.1.1','imagePath':str(path),'image':{'sha256':expected},
        'scope':'same_tools_content_as_existing_ordinary_snapshots_no_native_tools_replacement'})


NATIVE_PREPARATION_LOCK=None


def wait_for_prior_preparation():
    # The user may still be running our older raw-export entry. Its outputs are
    # retained; wait for it to stop using CPU/disk before either formal round.
    import fcntl
    import stat
    global NATIVE_PREPARATION_LOCK
    path=ROOT/'relay/native-four-prepare.lock'
    need(path.resolve(strict=True)==path,'Retained preparation mutex missing or redirected')
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        meta=os.fstat(fd);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1,'Unexpected prior preparation mutex')
        deadline,last=time.monotonic()+3600,0
        while True:
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                need(time.monotonic()<deadline,'Prior preparation still active; preserve it, no formal replay started')
                if time.monotonic()-last>=30:
                    print('WAITING_FOR_EXISTING_PREPARATION_TO_FINISH_NO_RESTART',flush=True);last=time.monotonic()
                time.sleep(1)
        NATIVE_PREPARATION_LOCK=fd # Keep held through both rounds; process exit releases it.
    except BaseException:
        os.close(fd);raise


def root_scope(node):
    import stat
    ordinary(node)
    pins={str(DEPLOYMENT/name):row['sha256'] for name,row in load(DEPLOYMENT/'input-manifest.json').items()}
    for name in ('definition-native.json','config/runtime.toml','config/api-key','installation.json','rootfs-inputs.json',
                 'libexec/native_prepare.py','libexec/native_base.py','libexec/native_service.py'):
        pins[str(DEPLOYMENT/name)]=sha(DEPLOYMENT/name)
    session=provider_path(node)
    files=[session/'provider-entry.py',session/'libaenv-ub.so',session/'prepared.json',session/'plan.json']
    files+=list((session/'source/aenv_ub_provider').glob('*.py'))
    if node=='node-a':files+=[session/'config.json',session/'catalog.json']
    for path in files:pins[str(path)]=sha(path)
    for name in ('ram_observer.py','four_runtime.py'):
        pins[str(HELPERS/name)]=PUBLIC_PINS[name]
    old={}
    for unit in ('jwk-aenv-ae9c626-'+node+'.service','jwk-aenv-ub-b019f27-'+node+'.service',
                 'jwk-aenv-native-fe63038-'+node+'.service','ubsmd.service','ubse.service'):
        r=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,MainPID'],capture_output=True,text=True,timeout=10)
        f=dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
        need(r.returncode==0 or f.get('LoadState')=='not-found','Cannot inspect existing service')
        pid=int(f.get('MainPID','0'))
        tick=Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19] if pid>1 else None
        old[unit]=[f.get('LoadState'),f.get('ActiveState'),pid,tick]
    mailbox=WORK/'root-mailbox';mailbox.mkdir(mode=0o700)
    scope={'node':node,'nonce':uuid.uuid4().hex,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
           'pins':pins,'oldServices':old}
    save(WORK/'root-scope.json',scope)
    path=HELPERS/'lazy_four_root.py';pin=PUBLIC_PINS[path.name]
    code="""import hashlib,os,socket,stat,sys
from pathlib import Path
assert os.geteuid()==0 and socket.gethostname()==HOST,'Use declared node root terminal'
p=Path(SCRIPT);assert p.resolve(strict=True)==p and p.stat().st_uid==1204 and stat.S_ISREG(p.stat().st_mode)
raw=p.read_bytes();assert len(raw)<65536 and hashlib.sha256(raw).hexdigest()==SCRIPT_SHA,'Root supervisor changed'
sys.argv=[SCRIPT,'--scope',SCOPE,'--sha256',SCOPE_SHA]
exec(compile(raw,SCRIPT,'exec'),{'__name__':'__main__','__file__':SCRIPT})
"""
    constants={'HOST':'server1' if node=='node-a' else 'agent1','SCRIPT':str(path),'SCRIPT_SHA':pin,
               'SCOPE':str(WORK/'root-scope.json'),'SCOPE_SHA':sha(WORK/'root-scope.json')}
    block="/usr/bin/python3 -I -B - <<'LAZY_FOUR_SUPERVISE'\n"+''.join(k+'='+repr(v)+'\n' for k,v in constants.items())+code+'LAZY_FOUR_SUPERVISE\n'
    with (WORK/('root-'+node+'.txt')).open('x') as out:out.write(block)
    return block


def root_receipt(path):
    import stat
    need(path.resolve(strict=True)==path,'Redirected root receipt')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        m=os.fstat(fd);need(stat.S_ISREG(m.st_mode) and m.st_uid==0 and m.st_nlink in (1,2) and m.st_size<=65536,'Unexpected root receipt')
        return json.load(stream)


def local_root_command(operation):
    import importlib.util
    path=HELPERS/'lazy_four_root_client.py'
    need(sha(path)==PUBLIC_PINS[path.name],'Root client changed')
    spec=importlib.util.spec_from_file_location('lazy_root_client',path)
    client=importlib.util.module_from_spec(spec);spec.loader.exec_module(client)
    return client.request(operation)




def root_command(node,operation):
    if node=='node-a':return local_root_command(operation)
    result=subprocess.run(remote_command(['b-root-command','--root-operation',operation]),capture_output=True,timeout=270)
    need(result.returncode==0,'B root operation not confirmed; preserve request journal')
    return json.loads(result.stdout)


def wait_root(node):
    deadline,last=time.monotonic()+1800,time.monotonic()
    while time.monotonic()<deadline:
        if node=='node-a':
            path=WORK/'root-mailbox/ready.json'
            if path.exists():
                need(root_receipt(path)['nonce']==load(WORK/'root-scope.json')['nonce'],'Root nonce differs');return
        else:
            result=subprocess.run(remote_command(['b-root-ready']),capture_output=True,timeout=30)
            if result.returncode==0:return
        if time.monotonic()-last>=30:
            print('WAITING_FOR_ONE_ROOT_SUPERVISOR node='+node,flush=True);last=time.monotonic()
        time.sleep(2)
    raise RuntimeError('Root supervisor not ready; no service start requested')


def health(node):
    command=[PYTHON,'-I','-B',str(DEPLOYMENT/'libexec/native_service.py'),'health']
    if node=='node-a':
        with (WORK/'logs'/('health-'+uuid.uuid4().hex+'.log')).open('xb') as out:
            result=subprocess.run(command,stdout=out,stderr=subprocess.STDOUT,timeout=180)
    else:result=subprocess.run(remote_command(['b-health']),capture_output=True,timeout=200)
    need(result.returncode==0,'New Runtime health failed; inspect logs')


def wait_provider(node):
    deadline=time.monotonic()+300
    while time.monotonic()<deadline:
        if node=='node-a':
            path=provider_path(node)/'provider/owner.json'
            value=load(path) if path.exists() else {}
        else:
            result=subprocess.run(remote_command(['b-provider-state']),capture_output=True,timeout=30)
            need(result.returncode==0,'Cannot read B provider state')
            value=json.loads(result.stdout)
        if value.get('state')=='serving':return value
        need(value.get('state') not in ('unresolved_preserved','released'),'Provider failed; preserve SDK journal')
        time.sleep(1)
    raise RuntimeError('Provider not serving; no new SDK retry')


def prepare_b(args):
    ordinary('node-b');steps=Steps('node-b')
    steps.local('receive-binaries','four_release_bundle.py',['receive','--archive',WORK/'release.tar',
        '--sha256',args.bundle_sha,'--destination',WORK/'release','--run'],1800)
    steps.local('receive-snapshots','lazy_four_snapshots.py',['receive','--archive',WORK/'snapshots.tar',
        '--sha256',args.inputs_sha,'--directory',WORK/'snapshots','--run'],7200)
    steps.local('prepare-runtime','prepare_lazy_four_service.py',['prepare','--node','node-b',
        '--core-report',WORK/'release/build-receipt.json','--tools-report',WORK/'release/tools-receipt.json',
        '--tools-image',WORK/'release/tools.ext4'])
    steps.local('seed-snapshots','lazy_four_snapshots.py',['seed','--directory',WORK/'snapshots','--node','node-b','--run'],7200)
    steps.local('prepare-provider','lazy_four_provider.py',['prepare','--node','node-b','--owner-plan',WORK/'owner-plan.json',
        '--plan-sha256',args.plan_sha,'--run'],600)
    root_scope('node-b')
    steps.state['status']='ORDINARY_LAZY_B_PREPARED_NO_SDK_NO_SERVICE';save(steps.path,steps.state)


def fetch_b(name):
    need(name in ('root-node-b.txt','off-node-b.json','lazy-node-b.json'),'Unexpected fetched result')
    result=subprocess.run(remote_command(['b-fetch','--file',name]),capture_output=True,timeout=60)
    need(result.returncode==0 and len(result.stdout)<=16*1024**2,'B result unavailable')
    value=json.loads(result.stdout);raw=value['text'].encode()
    need(value['name']==name and hashlib.sha256(raw).hexdigest()==value['sha256'],'B result checksum differs')
    with (WORK/name).open('xb') as out:out.write(raw)
    return raw.decode()


def run_a():
    ordinary('node-a');need(Path(__file__).resolve()==SELF,'Use the isolated lazy-four coordinator')
    # Selection is saved before old raw exports begin. Reuse it even if those
    # unrelated exports are still running; do not restart or overwrite them.
    selection=ROOT/'builds/native-four-inputs-v1/selection.private.json'
    history=selection.parent/'historical-reference.private.json'
    need(selection.is_file() and history.is_file(),'Retained four-template selection is not ready')
    build=load(BUILD)
    need(build.get('status')=='COORDINATED_CANDIDATE_BINARIES_BUILT_NOT_DEPLOYED'
         and build['release']['coreCommit']==CORE and build['release']['tree']==CORE_TREE,
         'Wait for the existing coordinated binary build; do not rerun it')
    transport_readiness();download();steps=Steps('node-a')
    prepare_original_tools()
    steps.local('pack-existing-four-snapshots','lazy_four_snapshots.py',['pack','--repository',
        ROOT/'deployments/agentenv-ae9c626-baseline/state/snapshot-store/repository','--selection',selection,'--history',history,
        '--archive',WORK/'snapshots.tar','--run'],7200)
    snapshots_sha=sha(WORK/'snapshots.tar')
    steps.local('receive-snapshots-a','lazy_four_snapshots.py',['receive','--archive',WORK/'snapshots.tar',
        '--sha256',snapshots_sha,'--directory',WORK/'snapshots','--run'],7200)
    steps.local('pack-binaries','four_release_bundle.py',['pack','--build-report',BUILD,'--tools-report',TOOLS,
        '--archive',WORK/'release.tar','--run'],1800)
    bundle_sha=sha(WORK/'release.tar')
    steps.local('prepare-runtime-a','prepare_lazy_four_service.py',['prepare','--node','node-a',
        '--core-report',BUILD,'--tools-report',TOOLS])
    steps.local('seed-snapshots-a','lazy_four_snapshots.py',['seed','--directory',WORK/'snapshots','--node','node-a','--run'],7200)
    steps.local('prepare-lazy-provider-a','lazy_four_provider.py',['prepare','--node','node-a','--run'],3600)
    code="import os,socket;from pathlib import Path;assert os.getuid()==os.geteuid()==1204 and socket.gethostname()=='agent1';os.umask(0o077);r=Path('/home/jwk/agent');assert r.resolve(strict=True)==r and r.stat().st_uid==1204;p=r/'r/lazy-four-rollout-v1';assert p.parent.resolve(strict=True)==p.parent;p.mkdir(mode=0o700);h=r/'lazy-four';h.mkdir(mode=0o700,exist_ok=True);assert h.resolve(strict=True)==h and h.stat().st_uid==1204"
    steps.call('prepare-b-directories',SSH+[shlex.join([PYTHON,'-I','-B','-c',code])],30)
    transfer(SELF,SELF)
    for name in PUBLIC_PINS:transfer(HELPERS/name,HELPERS/name)
    transfer(WORK/'release.tar',WORK/'release.tar');transfer(WORK/'snapshots.tar',WORK/'snapshots.tar')
    plan_sha=transfer(provider_path('node-a')/'plan.json',WORK/'owner-plan.json')
    steps.call('prepare-b',remote_command(['b-prepare','--bundle-sha',bundle_sha,'--inputs-sha',snapshots_sha,'--plan-sha',plan_sha]),10800)
    # The same exact legacy transition fences B, retires only the old owned
    # disposable object, and confirms both shared SDK locks become available.
    steps.local('legacy-owned-handoff','lazy_four_handoff.py',['transition-a','--run'],1800)
    wait_for_prior_preparation()
    block_a=root_scope('node-a');block_b=fetch_b('root-node-b.txt')
    print('\nRUN_ON_A_ROOT_AND_KEEP_OPEN\n'+block_a+'\nRUN_ON_B_ROOT_AND_KEEP_OPEN\n'+block_b+
          '\nKEEP_THIS_A_JWK_TERMINAL_OPEN_FOR_BOTH_ROUNDS\n',flush=True)
    wait_root('node-a');wait_root('node-b')
    root_command('node-a','runtime-off');root_command('node-b','runtime-off')
    health('node-a');health('node-b')
    run_dual(steps,'off')
    root_command('node-b','runtime-stop');root_command('node-a','runtime-stop')
    root_command('node-a','provider-start');wait_provider('node-a')
    metadata_log=(WORK/'logs/metadata-transport.log').open('xb')
    transport=subprocess.Popen([PYTHON,'-I','-B',str(HELPERS/'lazy_four_transport.py'),'owner-a'],
                               stdin=subprocess.DEVNULL,stdout=metadata_log,stderr=subprocess.STDOUT,start_new_session=True)
    save(WORK/'metadata-transport.json',{'pid':transport.pid,
        'startTicks':Path('/proc',str(transport.pid),'stat').read_text().rsplit(')',1)[1].split()[19],
        'scriptSha256':PUBLIC_PINS['lazy_four_transport.py'],'scope':'owned_metadata_only_no_sdk'})
    providers_released=False
    try:
        manifest_sha=transfer(provider_path('node-a')/'provider/manifest.json',WORK/'owner-manifest.json')
        credential_sha=transfer(provider_path('node-a')/'provider/reader-lazy-four-b-v1.json',WORK/'reader-b.private.json')
        steps.call('configure-b-import',remote_command(['b-configure-import','--manifest-sha',manifest_sha,'--credential-sha',credential_sha]),120)
        root_command('node-b','provider-start');wait_provider('node-b')
        need(transport.poll() is None,'Metadata transport exited; preserve pool/pins')
        root_command('node-a','runtime-lazy');root_command('node-b','runtime-lazy')
        health('node-a');health('node-b')
        run_dual(steps,'lazy')
        steps.local('compare-matched-rounds','lazy_four_report.py',[
            '--report',WORK/'off-node-a.json','--report',WORK/'off-node-b.json',
            '--report',WORK/'lazy-node-a.json','--report',WORK/'lazy-node-b.json','--output',WORK/'comparison'],180)
        root_command('node-b','runtime-stop');root_command('node-a','runtime-stop')
        steps.call('retire-b-reader',remote_command(['b-retire']),180)
        steps.local('retire-a-pool','lazy_four_provider.py',['retire','--node','node-a','--run'],180)
        providers_released=True
        root_command('node-b','finish');root_command('node-a','finish')
        steps.state.update(status='TWO_NODE_OFF_LAZY_REAL_GUEST_COMPARISON_AND_RELEASE_COMPLETED',
            reportDirectory=str(WORK/'comparison'),guestsPerRound=16,actionsPerRound=764,
            memfileCrossNodeCowImplemented=False,globalPhysicalNetSavingBytes=None)
        save(steps.path,steps.state);print(json.dumps(steps.state,indent=2))
    finally:
        if providers_released:
            if transport.poll() is None:transport.terminate()
            try:transport.wait(timeout=20)
            except subprocess.TimeoutExpired:pass
        else:
            print('METADATA_TRANSPORT_PRESERVED_FOR_EXPLICIT_READER_RELEASE; see metadata-transport.json',flush=True)
        metadata_log.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('run-a','b-prepare','b-root-ready','b-root-command','b-health','b-provider-state',
        'b-configure-import','b-retire','b-worker','b-fetch','b-pair'))
    for name in ('bundle-sha','inputs-sha','plan-sha','manifest-sha','credential-sha','admission-epoch','completed-epoch','pair-epoch','payload','file','root-operation'):
        p.add_argument('--'+name)
    p.add_argument('--worker-mode',choices=('replay',));p.add_argument('--scenario',choices=('off','lazy'))
    p.add_argument('--variant',choices=('admission','completed'));p.add_argument('--operation',choices=('prepare','status','measure','release','abort'))
    p.add_argument('--run',action='store_true');a=p.parse_args()
    if not a.run:print('PLAN_ONLY_NO_TARGET_OPERATIONS');return
    if a.mode=='run-a':run_a();return
    ordinary('node-b');need(Path(__file__).resolve()==SELF,'Unexpected B coordinator')
    if a.mode=='b-prepare':prepare_b(a)
    elif a.mode=='b-root-ready':
        value=root_receipt(WORK/'root-mailbox/ready.json');need(value['nonce']==load(WORK/'root-scope.json')['nonce'],'Root nonce differs');print(json.dumps(value))
    elif a.mode=='b-root-command':print(json.dumps(local_root_command(a.root_operation)))
    elif a.mode=='b-health':subprocess.run([PYTHON,'-I','-B',str(DEPLOYMENT/'libexec/native_service.py'),'health'],check=True,timeout=180)
    elif a.mode=='b-provider-state':
        path=provider_path('node-b')/'provider/owner.json';print(json.dumps(load(path) if path.exists() else {}))
    elif a.mode=='b-configure-import':
        deadline=time.monotonic()+30
        while not (provider_path('node-b')/'metadata.sock').exists():
            need(time.monotonic()<deadline,'Metadata endpoint not ready');time.sleep(.25)
        subprocess.run([PYTHON,'-I','-B',str(HELPERS/'lazy_four_provider.py'),'configure-import','--node','node-b',
            '--manifest',str(WORK/'owner-manifest.json'),'--manifest-sha256',a.manifest_sha,
            '--credential',str(WORK/'reader-b.private.json'),'--credential-sha256',a.credential_sha,'--run'],check=True,timeout=60)
    elif a.mode=='b-retire':subprocess.run([PYTHON,'-I','-B',str(HELPERS/'lazy_four_provider.py'),'retire','--node','node-b','--run'],check=True,timeout=150)
    elif a.mode=='b-worker':
        value=worker('node-b','replay',a.scenario,a.admission_epoch,a.completed_epoch)
        need(value.get('workerExitCode')==0,'B replay failed; preserve journals')
    elif a.mode=='b-fetch':
        need(a.file in ('root-node-b.txt','off-node-b.json','lazy-node-b.json'),'Unexpected fetch')
        raw=read(WORK/a.file,16*1024**2);print(json.dumps({'name':a.file,'text':raw.decode(),'sha256':hashlib.sha256(raw).hexdigest()}))
    else:
        need(a.variant and a.pair_epoch and a.operation,'Pair fields missing')
        sync=sync_module()
        result=sync.prepare('node-b',a.variant,a.pair_epoch) if a.operation=='prepare' else sync.control('node-b',a.variant,a.pair_epoch,a.operation,
            json.loads(a.payload) if a.payload else None)
        print(json.dumps(result))

if __name__=="__main__":main()
