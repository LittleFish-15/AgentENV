"""Read-only diagnosis of the existing A release-a failure; never retry DELETE."""
import hashlib, json, os, platform, re, stat, sys, types
from pathlib import Path

ROOT = Path('/home/jwk/agent')
D = ROOT / 'deployments/agentenv-direct-ub-guest-v1'
WORK = D / 'acceptance/direct-pair-v1'
RUN = 'ca0e30a36541483eaa26ff38ead95f8f'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def scrub(value):
    text = str(value)
    text = re.sub(r'e2b_[A-Za-z0-9._~-]+', '[REDACTED_API_KEY]', text)
    text = re.sub(r'(?i)Bearer\s+\S+', 'Bearer [REDACTED]', text)
    text = re.sub(r'(?i)((?:authorization|password|api[_-]?key|access[_-]?token|secret)\s*[=:]\s*)(\S+)', r'\1[REDACTED]', text)
    return text[:1400]


def pinned_module(name, path, pin):
    need(path.resolve(strict=True) == path and path.is_relative_to(ROOT), 'Module redirected')
    raw = path.read_bytes()
    need(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == pin, 'Module digest differs')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def journal_summary(value):
    keys = ('version', 'phase', 'runId', 'sandboxIds', 'outcomeUncertain', 'pending', 'error')
    row = {key: value[key] for key in keys if key in value}
    if 'error' in row:
        row['error'] = {k: scrub(v) for k, v in row['error'].items() if k in ('type', 'reason')}
    for key in ('operations', 'openRequests'):
        if key in value:
            row[key] = [{k: item[k] for k in ('id', 'kind', 'route', 'startedNs', 'finishedNs',
                'httpStatus', 'responseHttpStatus', 'ack', 'reconciledBy') if k in item} for item in value[key]]
    return row


def exact_get(api, sid):
    # The failed DELETE is deliberately never repeated to obtain its lost reply.
    code, body = api.call('GET', '/sandboxes/' + sid, timeout=20)
    result = {'method': 'GET', 'httpStatus': code, 'originalDeleteHttpStatus': None}
    if isinstance(body, dict):
        result['fieldNames'] = sorted(body)
        result['sandboxID'] = body.get('sandboxID')
        result['batchMatches'] = isinstance(body.get('metadata'), dict) and body['metadata'].get('cow_batch') == RUN
        for key in ('state', 'status', 'code', 'message', 'reason', 'error'):
            if key in body and isinstance(body[key], (str, int, bool)):
                result[key] = scrub(body[key])
    return result


def proc_state(expected, same_boot):
    row = {'expected': expected, 'sameBootAsReady': same_boot}
    if not same_boot:
        return dict(row, state='incomparable_after_boot_change')
    proc = Path('/proc') / str(expected['pid'])
    try:
        before = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        row.update(state='present', actualStartTicks=before[19], processState=before[0])
        if before[19] != expected['startTicks']:
            return dict(row, identityMatches=False)
        row['actualExecutable'] = os.readlink(proc / 'exe')
        row['identityMatches'] = row['actualExecutable'] == expected['executable']
        row['stableDuringRead'] = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19] == before[19]
    except FileNotFoundError:
        row['state'] = 'absent_or_disappeared_during_read'
    except OSError as error:
        row.update(state='unavailable', errorType=type(error).__name__)
    return row


def log_tail(path, sid):
    row = {'path': str(path), 'tailBudgetBytes': 512 * 1024}
    try:
        need(path.resolve(strict=True) == path and path.is_relative_to(D / 'logs'), 'Log redirected')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            meta = os.fstat(stream.fileno())
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204, 'Log owner/type differs')
            start = max(0, meta.st_size - row['tailBudgetBytes'])
            stream.seek(start)
            raw = stream.read(meta.st_size - start)
        after = path.stat()
        need((meta.st_dev, meta.st_ino) == (after.st_dev, after.st_ino), 'Log rotated during read')
        lines = raw.decode('utf-8', 'replace').splitlines()
        if start and lines:
            lines = lines[1:]
        selected = [i for i, line in enumerate(lines) if sid in line or re.search(
            r'(?i)sandbox deletion|cleanup retry|delete required|failed to.*(?:delete|stop)|(?:error|warn).*ublk|permission denied|device.*busy', line)]
        indices = sorted({j for i in selected[-20:] for j in range(max(0, i - 1), min(len(lines), i + 2))})[-50:]
        row.update(state='read', sourceBytesAtRead=meta.st_size, tailStart=start,
                   tailSha256=hashlib.sha256(raw).hexdigest(), relevantLines=[scrub(lines[i]) for i in indices])
    except (OSError, ValueError) as error:
        row.update(state='unavailable', errorType=type(error).__name__)
    return row


def main():
    need(sys.platform == 'linux' and os.getuid() == os.geteuid() == 0 and platform.node() == 'server1', 'A/server1 root only')
    controller = pinned_module('pending_release_controller', ROOT / 'actual_guest_pair_continue_v2.py',
        '6c01a15e36a056b29a400e52f33f38981ff0abf3ca939185e6a4074dd9fda1fa')
    need(WORK.resolve(strict=True) == WORK and WORK.stat().st_uid == 0, 'Pair directory changed')
    import fcntl
    lock = os.open(WORK / 'run.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        meta = os.fstat(lock)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1, 'Pair lock changed')
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        docs = {name: controller.document(WORK / name) for name in ('report.json', 'state.json', 'pair-phases.json')}
        original, life, phases = [docs[name][0] for name in ('report.json', 'state.json', 'pair-phases.json')]
        sid = original['sandboxId']
        need(original['node'] == 'a' and original['pairRunId'] == life['runId'] == RUN
             and phases.get('pending', {}).get('phase') == 'release-a', 'Not the pending A release')
        need(re.fullmatch(r'[0-9a-f-]{36}', sid), 'Sandbox identity differs')
        result = {'status': 'PENDING_A_RELEASE_READ_ONLY_NOT_RECONCILED', 'node': 'a', 'sandboxId': sid,
            'lifecycleJournal': journal_summary(life), 'phaseJournal': journal_summary(phases),
            'sourceDocumentHashes': {name: row[1] for name, row in docs.items()},
            'originalDeleteHttpStatus': None, 'originalDeleteReplyPersistedByOldController': False,
            'DELETERequestsSent': 0, 'GuestCommandsRun': False, 'SDKCalled': False,
            'stateChanged': False, 'releaseAccepted': False, 'BContinuationAllowed': False}
        same_boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip() == original['provider']['providerProcess']['bootId']
        result['processes'] = {name: proc_state(value, same_boot) for name, value in (
            ('server', original['serverIdentity']), ('fc', original['binding']['fcIdentity']),
            ('daemon', original['binding']['daemonIdentity']))}
        device = Path(original['binding']['rootfsDevice'])
        need(re.fullmatch(r'/dev/ublkb[0-9]+', str(device)), 'Device path differs')
        try:
            dm = device.stat()
            result['device'] = {'path': str(device), 'present': True, 'isBlock': stat.S_ISBLK(dm.st_mode),
                'major': os.major(dm.st_rdev), 'minor': os.minor(dm.st_rdev),
                'matchesRecordedNumber': (os.major(dm.st_rdev), os.minor(dm.st_rdev)) ==
                (original['binding']['rootfsDeviceMajor'], original['binding']['rootfsDeviceMinor'])}
        except FileNotFoundError:
            result['device'] = {'path': str(device), 'present': False}
        try:
            ready = pinned_module('pending_release_ready', ROOT / 'AB_actual_ub_guest_ready_v1.py',
                '145ddd8b86c3cb8a1d1cb61278b01cbf0039668827a83e340e550f11e7c53c30')
            runtime = ready.ReadyRun()
            need(runtime.server == original['serverIdentity'] and runtime.provider == original['provider'], 'Live identity changed')
            result['currentExactSandboxGET'] = exact_get(runtime.api, sid)
            result['providerStatus'] = controller.provider_status(runtime)
            runtime.guard()
        except Exception as error:
            result['liveReadError'] = {'type': type(error).__name__, 'reason': scrub(error)}
        result['logs'] = [log_tail(D / 'logs' / name, sid) for name in ('server.log', 'ublk-daemon.log')]
        result['journalsUnchangedDuringRead'] = all(controller.document(WORK / name)[1] == row[1] for name, row in docs.items())
        print('BEGIN_PENDING_A_RELEASE_READ_ONLY')
        print(json.dumps(result, indent=2))
        print('END_PENDING_A_RELEASE_READ_ONLY')
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'STOPPED_RELEASE_READ_ONLY_PRESERVE_STATE',
                          'errorType': type(error).__name__, 'reason': scrub(error), 'stateChanged': False}))
        raise SystemExit(1)
