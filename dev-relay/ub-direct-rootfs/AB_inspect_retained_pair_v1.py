"""Inspect existing pair records only; never resume, reconcile or accept a run."""
import argparse
import hashlib
import json
import os
import platform
import re
import stat
import sys
import time
from pathlib import Path

ROOT = Path('/home/jwk/agent')
WORK = ROOT / 'deployments/agentenv-direct-ub-guest-v1/acceptance/direct-pair-v1'
RUN = 'ca0e30a36541483eaa26ff38ead95f8f'
PHASES = {'a': ('a-written', 'a-released'), 'b': ('peer-isolated', 'b-released')}
COMMANDS = {'a': ('a-private-write',), 'b': ('b-after-a-write', 'b-after-a-exit')}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def filenames(node):
    return ['report.json', 'ready-receipt.json', 'state.json', 'pair-phases.json',
            'command-intent.json', 'command-result.json',
            *[p + '-receipt.json' for p in PHASES[node]],
            *[c + suffix for c in COMMANDS[node] for suffix in ('-intent.json', '-result.json')]]


def stamp(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read_document(path):
    # Never follow even a broken final symlink; a missing file is only unknown.
    try:
        before_path = path.lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(before_path.st_mode) and path.resolve(strict=True) == path,
            'Receipt path/type changed')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and before.st_size <= 1024 * 1024 and stamp(before_path) == stamp(before),
                'Receipt owner/identity/size changed')
        raw = stream.read(1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
    require(stamp(before) == stamp(after) == stamp(path.lstat()) and len(raw) == before.st_size,
            'Receipt changed during read')
    value = json.loads(raw)
    require(isinstance(value, dict), 'Receipt is not an object')
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'stamp': stamp(after), 'value': value}


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f-]{8,64}', value) is not None


def summary(value):
    # No opaque response, token, command, output, environment or error text.
    result = {k: value[k] for k in ('status', 'phase', 'kind', 'node', 'label')
              if isinstance(value.get(k), str) and re.fullmatch(r'[A-Za-z0-9_-]{1,96}', value[k])}
    for k in ('runId', 'pairRunId', 'sandboxId', 'ownerId'):
        if identifier(value.get(k)):
            result[k] = value[k]
    for k in ('outcomeUncertain', 'timedOut', 'lifecyclePassed', 'captureReleaseComplete'):
        if type(value.get(k)) is bool:
            result[k] = value[k]
    for k in ('exitCode', 'returncode', 'guestTimeoutSeconds', 'cliTimeoutSeconds'):
        if type(value.get(k)) is int:
            result[k] = value[k]
    result['pendingFieldPresent'] = 'pending' in value
    result['errorFieldPresent'] = any(k in value for k in ('error', 'failure', 'captureReleaseError'))
    for k in ('sandboxIds', 'openRequests', 'operations', 'events'):
        if isinstance(value.get(k), list):
            result[k + 'Count'] = len(value[k])
    if isinstance(value.get('sandboxIds'), list):
        result['sandboxIds'] = [sid for sid in value['sandboxIds'] if identifier(sid)][:16]
    # A persisted empty list is not a fresh inventory or a release attestation.
    return result


def snapshot(work, node, reader=read_document):
    files = {name: reader(work / name) for name in filenames(node)}
    require(sum(row['bytes'] for row in files.values() if row) <= 4 * 1024 * 1024,
            'Combined receipt budget exceeded')
    # Compare both existence and bytes/stat again. Do not return a torn snapshot.
    for name, before in files.items():
        require(reader(work / name) == before, 'Receipt set changed; no snapshot returned')
    rows = {}
    identity_conflicts = []
    for name, row in files.items():
        if row is None:
            rows[name] = {'state': 'missing_unknown'}
            continue
        fields = summary(row['value'])
        rows[name] = {'state': 'recorded', 'sha256': row['sha256'], 'bytes': row['bytes'], 'fields': fields}
        value = row['value']
        if any(k in value and value[k] != RUN for k in ('runId', 'pairRunId')):
            identity_conflicts.append(name)
        if 'node' in value and value['node'] != node:
            identity_conflicts.append(name)
    return {'status': 'RETAINED_PAIR_RECORDS_INSPECTED_NOT_ACCEPTED', 'node': node,
            'expectedRunId': RUN, 'observedUnixNs': time.time_ns(), 'files': rows,
            'identityConflictFiles': sorted(set(identity_conflicts)),
            'currentGuestLiveness': None, 'currentBinaryIdentity': None,
            'releaseConfirmed': False, 'pairAccepted': False, 'resumeAuthorizedByInspection': False,
            'SDKCalled': False, 'APIRequestsMade': False, 'GuestCommandsRun': False,
            'stateChanged': False, 'netSavingsBytes': None,
            'scope': 'Historical JSON summaries only. Missing/empty records do not prove no resources. '
                     'No lifecycle or receipt-chain validation; use the existing complete verifier.'}


def inspect(node):
    require(sys.platform == 'linux' and os.getuid() == os.geteuid() == 0
            and platform.node() == {'a': 'server1', 'b': 'agent1'}[node], 'Wrong node or identity')
    require(WORK.resolve(strict=True) == WORK and WORK.stat().st_uid == 0,
            'Pair directory unavailable or changed; preserve unknown state')
    import fcntl
    fd = os.open(WORK / 'run.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1, 'Pair lock changed')
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        result = snapshot(WORK, node)
        require(stamp(os.fstat(fd)) == stamp((WORK / 'run.lock').lstat()), 'Pair lock replaced')
        return result
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', required=True, choices=('a', 'b'))
    parser.add_argument('--inspect', action='store_true')
    args = parser.parse_args()
    if not args.inspect:
        result = {'status': 'PLAN_ONLY', 'node': args.node, 'work': str(WORK),
                  'operation': 'Read existing fixed pair JSON records with shared nonblocking lock; print sanitized summary only',
                  'requires': 'root on declared node; no active exclusive pair controller; existing unredirected files',
                  'noActions': ['API', 'SDK', 'Guest commands', 'services', 'kernel', 'network', 'state writes', 'cleanup', 'retry']}
    else:
        try:
            result = inspect(args.node)
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
            result = {'status': 'STOPPED_PAIR_INSPECTION_PRESERVE_UNKNOWN', 'errorType': type(error).__name__,
                      'node': args.node, 'stateChanged': False, 'pairAccepted': False,
                      'reason': 'Missing/busy/changed/invalid records or identity. No cleanup or retry was attempted.'}
            print(json.dumps(result, indent=2))
            return 1
    print('BEGIN_RETAINED_PAIR_INSPECTION')
    print(json.dumps(result, indent=2))
    print('END_RETAINED_PAIR_INSPECTION')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
