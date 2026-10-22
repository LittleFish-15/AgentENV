"""A trusted two-node coordinator holds owned Guests during post-workload reads.

No remote execution, API mutation or SDK access in this module. Control files
are private, per-epoch and immutable. A hold is not an atomic hardware snapshot
and does not synchronize the start of workload instructions.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

ROOT = Path('/home/jwk/agent/r/lazy-four-rollout-v1')
NODES = ('node-a', 'node-b')


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def directory(node, variant, epoch):
    need(node in NODES and variant in ('admission', 'completed')
         and isinstance(epoch, str) and re.fullmatch('[0-9a-f]{32}', epoch), 'Invalid pair scope')
    return ROOT / ('hold-' + variant + '-' + epoch)


def secure_dir(path):
    need(path.resolve(strict=True) == path and path.is_dir()
         and path.stat().st_uid == 1204 and path.stat().st_mode & 0o077 == 0,
         'Pair directory must be private and owned')


def read_file(path):
    secure_dir(path.parent)
    need(path.resolve(strict=True) == path, 'Redirected pair file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 1204 and before.st_mode & 0o077 == 0
             and 0 < before.st_size <= 65536, 'Pair file metadata differs')
        if before.st_nlink != 1:
            # link() publication precedes removal of the temporary name. A
            # polling reader waits through that short two-link interval.
            raise FileNotFoundError('Pair record publication has not completed')
        raw = stream.read(65537)
        after = os.fstat(stream.fileno())
    need(len(raw) == before.st_size and (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Pair file changed')
    return json.loads(raw)


def optional(path):
    try:
        return read_file(path)
    except FileNotFoundError:
        return None


def put_once(path, value):
    secure_dir(path.parent)
    raw = canonical(value)
    need(0 < len(raw) <= 65536, 'Pair message too large')
    previous = optional(path)
    if previous is not None:
        need(canonical(previous) == raw, 'Existing pair message differs; preserve it')
        return
    # A receiver may observe the file before fsync; write to a unique temporary
    # inode then publish with link, which cannot replace another control record.
    temp = path.with_name(path.name + '.partial')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.link(temp, path)
    temp.unlink()
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare(node, variant, epoch):
    path = directory(node, variant, epoch)
    secure_dir(ROOT)
    path.mkdir(mode=0o700)
    put_once(path / 'seed.json', {'version': 1, 'node': node, 'variant': variant, 'epoch': epoch})


def seed(node, variant, epoch):
    path = directory(node, variant, epoch)
    need(read_file(path / 'seed.json') == {'version': 1, 'node': node, 'variant': variant, 'epoch': epoch},
         'Pair seed differs')
    return path


def valid_ready(value, node, variant, epoch):
    need(isinstance(value, dict) and set(value) == {'node', 'variant', 'epoch', 'runId', 'sandboxIds'}
         and value['node'] == node and value['variant'] == variant and value['epoch'] == epoch
         and re.fullmatch('[0-9a-f]{32}', value['runId']), 'Pair readiness identity differs')
    ids = value['sandboxIds']
    need(isinstance(ids, list) and len(ids) == 8 and len(set(ids)) == 8
         and all(isinstance(sid, str) and re.fullmatch('[A-Za-z0-9_-]{1,128}', sid) for sid in ids),
         'Expected exactly eight distinct scoped Guests')


def valid_measurement(value, ready):
    need(isinstance(value, dict) and set(value) == {'node', 'epoch', 'readySha256', 'sampleSha256'}
         and value['node'] == ready['node'] and value['epoch'] == ready['epoch']
         and value['readySha256'] == digest(ready)
         and isinstance(value['sampleSha256'], str) and re.fullmatch('[0-9a-f]{64}', value['sampleSha256']),
         'Pair measured receipt differs')


def control_message(operation, variant, epoch, readies, measurements=None):
    need(operation in ('measure', 'release') and isinstance(readies, dict) and set(readies) == set(NODES),
         'Both node readies required')
    for node in NODES:
        valid_ready(readies[node], node, variant, epoch)
    result = {'operation': operation, 'variant': variant, 'epoch': epoch, 'readies': readies}
    if operation == 'release':
        need(isinstance(measurements, dict) and set(measurements) == set(NODES), 'Both measured receipts required')
        for node in NODES:
            valid_measurement(measurements[node], readies[node])
        result['measurements'] = measurements
    return result


def control(node, variant, epoch, operation, payload=None):
    path = seed(node, variant, epoch)
    if operation == 'status':
        return {name: optional(path / (name + '.json')) for name in ('ready', 'measured', 'failed', 'abort')}
    if operation == 'abort':
        put_once(path / 'abort.json', {'epoch': epoch, 'reason': 'coordinator_stopped_pair'})
        return {'recorded': 'abort'}
    need(operation in ('measure', 'release') and isinstance(payload, dict), 'Unknown pair operation')
    expected = control_message(operation, variant, epoch, payload.get('readies'), payload.get('measurements'))
    need(payload == expected, 'Pair control content differs')
    own = read_file(path / 'ready.json')
    need(payload['readies'][node] == own, 'Control does not acknowledge this ready record')
    if operation == 'release':
        need(payload['measurements'][node] == read_file(path / 'measured.json'), 'Control does not acknowledge this measurement')
    put_once(path / (operation + '.json'), payload)
    return {'recorded': operation}


class Fence:
    def __init__(self, node, variant, epoch, timeout=600):
        self.node, self.variant, self.epoch = node, variant, epoch
        self.path = seed(node, variant, epoch)
        self.timeout = timeout

    def check(self):
        need(optional(self.path / 'abort.json') is None, 'Paired cohort was cancelled before a new mutation')

    def wait(self, name, cohort, ids):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            self.check()
            for sid in ids:
                need(cohort.owned(sid) is not None, 'A held Guest disappeared')
            value = optional(self.path / (name + '.json'))
            if value is not None:
                return value
            time.sleep(1)
        raise RuntimeError('Paired post-workload hold timed out; cleanup own Guests')

    def __call__(self, cohort, ids):
        try:
            self.check()
            ready = {'node': self.node, 'variant': self.variant, 'epoch': self.epoch,
                     'runId': cohort.run_id, 'sandboxIds': list(ids)}
            valid_ready(ready, self.node, self.variant, self.epoch)
            for sid in ids:
                need(cohort.owned(sid) is not None, 'Guest missing before pair readiness')
            put_once(self.path / 'ready.json', ready)
            measure = self.wait('measure', cohort, ids)
            need(measure == control_message('measure', self.variant, self.epoch, measure.get('readies'))
                 and measure['readies'][self.node] == ready, 'Unexpected measurement control')
            cohort.sample('before_replay' if self.variant == 'admission' else 'after_replay', ids)
            measured = {'node': self.node, 'epoch': self.epoch, 'readySha256': digest(ready),
                        'sampleSha256': digest(cohort.state['samples'][-1])}
            put_once(self.path / 'measured.json', measured)
            release = self.wait('release', cohort, ids)
            need(release == control_message('release', self.variant, self.epoch,
                                           release.get('readies'), release.get('measurements'))
                 and release['readies'][self.node] == ready
                 and release['measurements'][self.node] == measured, 'Unexpected pair release')
            return {'status': 'COORDINATED_EIGHT_GUEST_GATE_COMPLETED', 'epoch': self.epoch,
                    'node': self.node, 'readies': release['readies'], 'measurements': release['measurements'],
                    'atomicSnapshot': False, 'synchronizedWorkloadStart': False,
                    'authority': 'trusted_experiment_coordinator'}
        except BaseException as error:
            put_once(self.path / 'failed.json', {'epoch': self.epoch, 'node': self.node,
                                               'errorType': type(error).__name__})
            raise
