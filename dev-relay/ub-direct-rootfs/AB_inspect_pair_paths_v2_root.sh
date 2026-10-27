#!/bin/sh
python3 -I -B - <<'UB_PAIR_PATH_STATE_V2'
"""Read fixed deployment/pair metadata to explain a missing inspector path."""
import hashlib
import json
import os
import platform
import stat
import sys
from pathlib import Path

DEPLOY = Path('/home/jwk/agent/deployments/agentenv-direct-ub-guest-v1')


def stamp(meta):
    return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def summary(value):
    if not isinstance(value, dict):
        raise ValueError('Expected JSON object')
    result = {}
    for key in ('version', 'phase', 'status', 'outcomeUncertain'):
        item = value.get(key)
        if type(item) in (bool, int) or isinstance(item, str) and len(item) <= 96:
            result[key] = item
    for key in ('sandboxIds', 'openRequests'):
        result[key + 'Count'] = len(value[key]) if isinstance(value.get(key), list) else None
    result['pendingFieldPresent'] = 'pending' in value
    result['errorFieldPresent'] = 'error' in value or 'failure' in value
    result['recordedQuiescent'] = (value.get('version') == 1
        and value.get('phase') in ('prepared', 'quiesced')
        and value.get('sandboxIds') == [] and value.get('openRequests') == []
        and value.get('outcomeUncertain') is False)
    return result


def inspect_path(path, kind, owner, read_json=False):
    row = {'path': str(path)}
    try:
        meta = path.lstat()
        row.update(state='present', uid=meta.st_uid, mode=oct(stat.S_IMODE(meta.st_mode)))
        valid_type = stat.S_ISDIR(meta.st_mode) if kind == 'directory' else stat.S_ISREG(meta.st_mode)
        if not valid_type or meta.st_uid != owner or path.resolve(strict=True) != path:
            row['state'] = 'unexpected_identity_or_type'
            return row
        if read_json:
            if meta.st_size > 1024 * 1024:
                raise ValueError('Oversized JSON')
            flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0)
            fd = os.open(path, flags)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if stamp(before) != stamp(meta):
                    raise ValueError('File replaced')
                raw = stream.read(1024 * 1024 + 1)
                after = os.fstat(stream.fileno())
            if len(raw) != meta.st_size or stamp(meta) != stamp(after) or stamp(meta) != stamp(path.lstat()):
                raise ValueError('File changed')
            row.update(sha256=hashlib.sha256(raw).hexdigest(), fields=summary(json.loads(raw)))
    except FileNotFoundError:
        row['state'] = 'missing'
    except (OSError, ValueError, RecursionError) as error:
        row.update(state='unavailable_or_changed', errorType=type(error).__name__)
    return row


def main():
    if sys.platform != 'linux' or os.getuid() != 0 or os.geteuid() != 0:
        raise SystemExit('Run on the declared Linux node as root; no action')
    node = {'server1': 'a', 'agent1': 'b'}.get(platform.node())
    if node is None:
        raise SystemExit('Unknown node; no action')
    work = DEPLOY / 'acceptance/direct-pair-v1'
    rows = [inspect_path(DEPLOY, 'directory', 1204),
            inspect_path(DEPLOY / 'guest-cohort-state.json', 'file', 1204, True),
            inspect_path(work.parent, 'directory', 0),
            inspect_path(work, 'directory', 0),
            inspect_path(work / 'run.lock', 'file', 0)]
    rows.extend(inspect_path(work / name, 'file', 0, True) for name in
                ('report.json', 'state.json', 'ready-receipt.json', 'pair-phases.json'))
    print('BEGIN_PAIR_PATH_STATE')
    print(json.dumps({'status': 'READ_ONLY_PAIR_PATH_STATE_NOT_ACCEPTANCE', 'node': node,
        'paths': rows, 'missingPaths': [r['path'] for r in rows if r['state'] == 'missing'],
        'crossFileSnapshotAtomic': False, 'currentGuestLiveness': None,
        'safeToCreateOrRetry': False, 'resourcesChanged': False, 'APIOrSDKCalled': False,
        'scope': 'Recorded metadata only; missing files or recorded quiescence do not prove current resources absent.'}, indent=2))
    print('END_PAIR_PATH_STATE')


if __name__ == '__main__':
    main()

UB_PAIR_PATH_STATE_V2
