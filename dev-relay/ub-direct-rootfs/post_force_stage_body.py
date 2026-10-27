"""Continue only after the user's scoped A-unit force stop; preserve failed run."""
import argparse, base64, fcntl, hashlib, json, os, platform, select, signal
import stat, subprocess, time, types, uuid, zlib
from pathlib import Path

ROOT = Path('/home/jwk/agent')
OLD = ROOT / 'deployments/agentenv-direct-ub-guest-v1'
PAIR = OLD / 'acceptance/direct-pair-v1'
UNIT = 'jwk-aenv-direct-ub-guest-v1-node-a.service'
GROUP = '/system.slice/' + UNIT
BOOT = '58d0ee5f-f886-4eb6-93ea-a6328d14d139'
EXPECTED = {3966082: '80555317', 3966531: '80555408', 4070069: '84520448'}
DEVICES = {'ublkb12': ('block', 259, 16), 'ublkb13': ('block', 259, 17),
           'ublkc12': ('char', 242, 12), 'ublkc13': ('char', 242, 13)}


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def load_code(name, raw, pin, path):
    need(hashlib.sha256(raw).hexdigest() == pin, 'Code digest differs: ' + name)
    value = types.ModuleType(name); value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def process_row(pid):
    path = Path('/proc') / str(pid)
    try:
        before = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        groups = [line.split(':', 2)[2] for line in (path / 'cgroup').read_text().splitlines()]
        try: executable = os.readlink(path / 'exe')
        except FileNotFoundError: executable = None
        after = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        need(before[19] == after[19], 'Process identity changed during observation')
        try: wait_channel = (path / 'wchan').read_text().strip()
        except OSError: wait_channel = None
        return {'pid': pid, 'startTicks': after[19], 'state': after[0], 'waitChannel': wait_channel,
                'executable': executable, 'inOldUnit': any(x == GROUP or x.startswith(GROUP + '/') for x in groups)}
    except (FileNotFoundError, ProcessLookupError):
        return None


def snapshot():
    result = subprocess.run(['/usr/bin/systemctl', 'show', UNIT,
        '-p', 'MainPID', '-p', 'ControlGroup', '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState', '-p', 'Job'],
        capture_output=True, text=True, timeout=10)
    need(result.returncode == 0, 'Cannot query old unit')
    properties = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    need(all(k in properties for k in ('MainPID', 'LoadState', 'ActiveState')), 'Unit query incomplete')
    processes = []
    for path in Path('/proc').iterdir():
        if path.name.isdigit():
            row = process_row(int(path.name))
            if row and (row['inOldUnit'] or row['pid'] in EXPECTED): processes.append(row)
    devices = {}
    for name, (kind, major, minor) in DEVICES.items():
        path = Path('/dev') / name
        try:
            meta = path.lstat()
        except FileNotFoundError:
            devices[name] = None; continue
        right_type = stat.S_ISBLK(meta.st_mode) if kind == 'block' else stat.S_ISCHR(meta.st_mode)
        devices[name] = {'major': os.major(meta.st_rdev), 'minor': os.minor(meta.st_rdev),
                         'expectedIdentity': right_type and (os.major(meta.st_rdev), os.minor(meta.st_rdev)) == (major, minor)}
    sysfs = [str(p) for i in (12, 13) for p in (Path('/sys/class/ublk-char') / ('ublkc' + str(i)),
             Path('/sys/class/block') / ('ublkb' + str(i))) if p.exists() or p.is_symlink()]
    return {'unit': properties, 'processes': processes, 'devices': devices, 'sysfsRemaining': sysfs}


def old_drained(value):
    unit = value['unit']
    return (unit['MainPID'] == '0' and unit['ActiveState'] in ('inactive', 'failed') and not unit.get('Job')
            and not any(p['inOldUnit'] or EXPECTED.get(p['pid']) == p['startTicks'] for p in value['processes'])
            and all(x is None for x in value['devices'].values()) and not value['sysfsRemaining'])


def remaining_reason(value):
    if any(x and not x['expectedIdentity'] for x in value['devices'].values()):
        return 'Device identity changed; no device operation or deployment permitted'
    if any(p['state'] == 'D' for p in value['processes']):
        return 'Old unit has an uninterruptible process; repeated kill cannot confirm release'
    if any(x is not None for x in value['devices'].values()) or value['sysfsRemaining']:
        return 'Owned ublk devices remain; kernel deletion has not been confirmed'
    return 'Old unit/process exit has not been confirmed'


def health_report(text):
    begin = 'BEGIN_DIRECT_GUEST_RUNTIME_REPORT\n'
    end = '\nEND_DIRECT_GUEST_RUNTIME_REPORT'
    need(text.count(begin) == text.count(end) == 1, 'Health report framing differs')
    result = json.loads(text.split(begin, 1)[1].split(end, 1)[0])
    need(result.get('status') == 'DIRECT_GUEST_RUNTIME_HEALTHY_NO_GUEST_YET'
         and result.get('Guest_created') is False and result.get('CLI_list_count') == 0,
         'New service did not report healthy empty inventory')
    return result


def device_holders():
    """Bounded conventional FD evidence only; absence is not kernel quiescence."""
    result = {'matches': [], 'complete': True, 'scope': 'conventional process FDs; no proof of absent kernel references'}
    deadline = time.monotonic() + 15
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit(): continue
        if time.monotonic() >= deadline:
            result['complete'] = False; break
        try:
            before = process_row(int(proc.name)); hits = []
            if before is None: continue
            for fd in (proc / 'fd').iterdir():
                if time.monotonic() >= deadline:
                    result['complete'] = False; break
                try: meta = fd.stat()
                except FileNotFoundError: continue
                for name, (kind, major, minor) in DEVICES.items():
                    expected_type = stat.S_ISBLK(meta.st_mode) if kind == 'block' else stat.S_ISCHR(meta.st_mode)
                    if expected_type and (os.major(meta.st_rdev), os.minor(meta.st_rdev)) == (major, minor): hits.append(name)
            if hits:
                after = process_row(int(proc.name))
                result['matches'].append({'process': before, 'devices': sorted(set(hits)),
                    'identityStable': after is not None and after['startTicks'] == before['startTicks']})
        except (FileNotFoundError, ProcessLookupError): continue
        except PermissionError: result['complete'] = False
    return result


def write_report(directory, result):
    raw = (json.dumps(result, indent=2) + '\n').encode()
    temp = directory / ('report-' + uuid.uuid4().hex + '.tmp')
    with temp.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.replace(temp, directory / 'report.json')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--run', action='store_true')
    if not parser.parse_args().run:
        print(json.dumps({'status': 'PLAN_ONLY', 'node': 'a', 'actions': 'observe forced-stop completion; if fully drained stop exact old proxy, verify zero local UB leases, stage and activate already-built fixed daemon; no Guest or kernel deletion'})); return 0
    need(os.getuid() == os.geteuid() == 0 and platform.node() == 'server1', 'A/server1 root only')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT, 'Boot changed; old identities cannot be reused')
    os.umask(0o077)
    need(ROOT.resolve(strict=True) == ROOT and PAIR.resolve(strict=True) == PAIR and PAIR.stat().st_uid == 0, 'Old paths changed')
    deploy_raw = zlib.decompress(base64.b64decode(DEPLOY_Z64, validate=True))
    deploy_path = ROOT / 'AB_deploy_direct_deletefix_v2.py'
    deploy = load_code('post_force_deploy', deploy_raw, DEPLOY_SHA, deploy_path)
    controller_path = ROOT / 'actual_guest_pair_continue_v2.py'
    controller = load_code('post_force_controller', deploy.read(controller_path),
        '6c01a15e36a056b29a400e52f33f38981ff0abf3ca939185e6a4074dd9fda1fa', controller_path)
    lock = os.open(PAIR / 'run.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    output = None
    result = {'status': 'POST_FORCE_PREFLIGHT', 'node': 'a', 'oldPairLifecycleAccepted': False,
              'normalDeletePassed': False, 'oldJournalRewritten': False, 'sharedObjectsRetired': False,
              'kernelDeviceDeletionAttempted': False, 'GuestCreated': False, 'servicesChangeAttempted': False,
              'automaticRetry': False, 'signalIntents': []}
    try:
        meta = os.fstat(lock)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1, 'Old lock changed')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        docs = {n: controller.document(PAIR / n) for n in ('report.json', 'state.json', 'pair-phases.json')}
        origin = docs['report.json'][0]
        need(origin['node'] == 'a' and origin['pairRunId'] == 'ca0e30a36541483eaa26ff38ead95f8f', 'Wrong old run')
        need(origin['serverIdentity']['pid'] == 3966082 and origin['binding']['daemonIdentity']['pid'] == 3966531, 'Wrong old processes')
        life, phase = docs['state.json'][0], docs['pair-phases.json'][0]
        need(life['runId'] == origin['pairRunId'] and life['sandboxIds'] == [origin['sandboxId']]
             and life['outcomeUncertain'] is True and len(life['openRequests']) == 1
             and life['openRequests'][0]['kind'] == 'delete'
             and life['openRequests'][0]['route'] == '/sandboxes/' + origin['sandboxId']
             and phase['phase'] == 'a-written' and phase.get('pending', {}).get('phase') == 'release-a',
             'Old failed run differs; preserve it')
        definition = deploy.load(OLD / 'guest-definition.json')
        need(definition['node'] == 'a' and definition['apiPort'] == 18085, 'Old endpoint changed')
        provider = deploy.check_provider('a'); need(provider == origin['provider'], 'Provider identity/generation changed')
        runtime = types.SimpleNamespace(n='a', deploy=deploy)
        result['providerBefore'] = controller.provider_status(runtime)
        result['oldDocumentHashes'] = {n: row[1] for n, row in docs.items()}
        output = PAIR / ('post-force-' + uuid.uuid4().hex)
        output.mkdir(mode=0o700); result['outputDirectory'] = str(output)
        # Bounded observation, never another kill/restart/delete attempt.
        deadline = time.monotonic() + 30
        while True:
            result['oldResources'] = snapshot()
            if old_drained(result['oldResources']) or time.monotonic() >= deadline: break
            if any(x and not x['expectedIdentity'] for x in result['oldResources']['devices'].values()): break
            time.sleep(1)
        write_report(output, result)
        if not old_drained(result['oldResources']):
            result['remainingDeviceHolders'] = device_holders()
        need(old_drained(result['oldResources']), remaining_reason(result['oldResources']))
        result['oldProcessesAndDevicesGone'] = True
        need(deploy.check_provider('a') == provider, 'Provider changed during exit observation')
        result['providerAfterDrain'] = controller.provider_status(runtime)
        need(result['providerAfterDrain']['activeLeases'] == result['providerAfterDrain']['activePayloadResponses'] == 0,
             'Provider still retains local readers; no lease cleared or objects retired')
        new_runtime, new_fc, new_unit = deploy.location('a')
        need(all(not p.exists() and not p.is_symlink() for p in (deploy.D, new_runtime, new_fc)), 'Fixed deployment already exists; inspect its report instead of repeating')
        deploy.candidate_artifacts('a')
        m = deploy.make_module(definition)
        preserved = deploy.preserve_units(m, 'a')
        need(m.properties(new_unit).get('LoadState') == 'not-found', 'New unit already exists')
        # Old proxy runs outside the private-network unit. Use its exact receipt.
        proxy = deploy.load(ROOT / 'r/dg-a-v1/host-proxy.json')
        row = process_row(proxy['pid'])
        if row is not None:
            need(row['startTicks'] == str(proxy['start_ticks']), 'Old proxy PID reused; do not signal')
            old_m = deploy.make_module(definition); old_m.D = OLD; old_m.RUNTIME = ROOT / 'r/dg-a-v1'; old_m.UNIT = UNIT
            identity = old_m.process_identity(proxy['pid'])
            need(identity['uid'] == [1204] * 4 and old_m.owns_listener(proxy['pid']), 'Old proxy ownership/listener differs')
            ops = deploy.PidfdOps(); ops.self_check(); fd = ops.open(proxy['pid'])
            try:
                current = process_row(proxy['pid'])
                need(current is not None and all(current[k] == row[k] for k in ('pid','startTicks','executable','inOldUnit')),
                     'Proxy identity changed')
                result['signalIntents'].append({'pid': proxy['pid'], 'startTicks': row['startTicks'], 'signal': 'SIGTERM', 'role': 'old-host-proxy'})
                write_report(output, result); ops.send(fd, signal.SIGTERM)
                poll = select.poll(); poll.register(fd, select.POLLIN)
                need(bool(poll.poll(10000)), 'Old proxy exit unconfirmed')
            finally: os.close(fd)
        need(old_drained(snapshot()), 'Old resources changed before staging')
        need(deploy.check_provider('a') == provider, 'Provider changed before staging')
        after = controller.provider_status(runtime)
        need(after['activeLeases'] == after['activePayloadResponses'] == 0, 'Local readers remain')
        result['providerAfter'] = after
        need(all(controller.document(PAIR / n)[1] == row[1] for n, row in docs.items()), 'Old journal changed')
        if deploy_path.exists():
            meta = deploy_path.lstat()
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204 and meta.st_nlink == 1 and deploy.read(deploy_path) == deploy_raw, 'Staged deployment code differs')
        else:
            fd = os.open(deploy_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(deploy_raw); os.fchown(stream.fileno(), 1204, 1205); stream.flush(); os.fsync(stream.fileno())
        result['stageIntent'] = str(deploy.D); write_report(output, result)
        prepared = deploy.as_owner(['/usr/bin/python3', '-I', '-B', str(deploy_path), 'prepare', '--run'], 300)
        (output / 'prepare.log').write_text(prepared.stdout + prepared.stderr)
        need(prepared.returncode == 0, 'Fixed staging failed; preserve prepare.log')
        result['servicesChangeAttempted'] = True; result['activationIntent'] = new_unit; write_report(output, result)
        result['activation'] = deploy.activate()
        healthy = deploy.as_owner(['/usr/bin/python3', '-I', '-B', str(deploy_path), 'health', '--run'], 180)
        (output / 'health.log').write_text(healthy.stdout + healthy.stderr)
        need(healthy.returncode == 0, 'Fixed service health failed; preserve health.log')
        result['health'] = health_report(healthy.stdout)
        need(deploy.preserve_units(m, 'a') == preserved and deploy.check_provider('a') == provider, 'Retained services/provider changed')
        need(all(controller.document(PAIR / n)[1] == row[1] for n, row in docs.items()), 'Old journal changed during deployment')
        result.update(status='A_POST_FORCE_DELETEFIX_HEALTHY_NO_GUEST', ordinaryUserHealthPassed=True,
                      newDeployment=str(deploy.D), newDaemonSha256=deploy.BINARIES['uvm-ublk-daemon'])
        write_report(output, result)
    except Exception as error:
        result.update(status='STOPPED_POST_FORCE_PRESERVE_STATE', errorType=type(error).__name__, reason=str(error))
        if output: write_report(output, result)
    finally:
        os.close(lock)
    print('BEGIN_POST_FORCE_STAGE_REPORT'); print(json.dumps(result, indent=2)); print('END_POST_FORCE_STAGE_REPORT')
    return 0 if result['status'] == 'A_POST_FORCE_DELETEFIX_HEALTHY_NO_GUEST' else 1


if __name__ == '__main__':
    raise SystemExit(main())
