"""Persistent local comparison admission. No target access or remote transport.

One fixed journal directory must be shared by original/full controllers on a
node. An interrupted lock or unfinished generation requires explicit review;
neither a new run id nor an empty Runtime inventory clears it.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


class RunJournal:
    def __init__(self, directory):
        self.directory = Path(directory)
        need(self.directory.resolve(strict=True) == self.directory, 'Journal directory must be canonical')
        meta = self.directory.stat()
        need(stat.S_ISDIR(meta.st_mode), 'Journal directory missing')
        if os.name == 'posix':
            need(meta.st_uid == os.geteuid() and not meta.st_mode & 0o022, 'Journal ownership/mode differs')
        self.lock_path = self.directory / 'controller.lock'
        self.path = self.directory / 'run.json'
        self.mutex = threading.RLock()
        self.closed = False
        self.poisoned = False
        # O_EXCL also leaves an unambiguous crash marker after process exit.
        self.fd = os.open(self.lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                          getattr(os, 'O_NOFOLLOW', 0), 0o600)
        self.lock_identity = os.fstat(self.fd)
        try:
            os.write(self.fd, canonical({'pid': os.getpid(), 'automaticStaleRecovery': False}))
            os.fsync(self.fd)
            self.sync_directory()
            self.state = None
            if self.path.exists():
                need(self.path.resolve(strict=True) == self.path, 'Journal symlink refused')
                with self.path.open('rb') as stream:
                    before = os.fstat(stream.fileno())
                    need(stat.S_ISREG(before.st_mode) and before.st_size <= 4 * 1024**2,
                         'Journal type/size differs')
                    if os.name == 'posix':
                        need(before.st_uid == os.geteuid(), 'Journal owner differs')
                    self.state = json.load(stream)
                need(self.state.get('version') == 1, 'Unknown journal version')
        except BaseException:
            # Retain the lock on malformed/unreadable durable state as well.
            os.close(self.fd)
            self.closed = True
            raise

    def sync_directory(self):
        if os.name == 'posix':
            fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def save(self):
        need(not self.closed and not self.poisoned, 'Journal closed or failed')
        temporary = self.directory / 'run.next.json'
        try:
            raw = canonical(self.state)
            need(len(raw) <= 4 * 1024**2, 'Journal exceeds bounded state size')
            with temporary.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self.sync_directory()
        except BaseException:
            self.poisoned = True
            raise

    def begin(self, run_id, plan):
        with self.mutex:
            need(self.state is None, 'Prior run exists; no reset or implicit restart')
            need(re.fullmatch('[0-9a-f]{32}', run_id) is not None, 'Explicit run identity required')
            need(plan['node'] in ('a', 'b') and plan['variants'] == ['original', 'full'], 'Comparison order differs')
            need(len(plan['templates']) in (1, 4)
                 and re.fullmatch('[0-9a-f]{64}', plan['pairAcceptanceSha256']) is not None,
                 'Admission evidence missing')
            self.state = {'version': 1, 'runId': run_id, 'plan': copy.deepcopy(plan),
                          'planSha256': hashlib.sha256(canonical(plan)).hexdigest(),
                          'phase': 'admitted', 'groups': {}}
            self.save()

    def start_group(self, variant, context):
        with self.mutex:
            need(self.state and self.state['phase'] in ('admitted', 'between_groups'), 'Unfinished group blocks admission')
            expected = self.state['plan']['variants'][len(self.state['groups']):]
            need(expected and variant == expected[0], 'Group already attempted or out of order')
            self.state['groups'][variant] = {'context': copy.deepcopy(context), 'phase': 'reserved', 'cases': {}}
            self.state['phase'] = 'active'
            self.save()
            return GroupPermit(self, variant)

    def close(self):
        with self.mutex:
            if self.closed:
                return
            os.close(self.fd)
            self.closed = True
            if not self.poisoned:
                meta = self.lock_path.stat()
                need((meta.st_dev, meta.st_ino) == (self.lock_identity.st_dev, self.lock_identity.st_ino), 'Lock identity changed')
                self.lock_path.unlink()
                self.sync_directory()


class GroupPermit:
    def __init__(self, journal, variant):
        self.journal, self.variant = journal, variant

    @property
    def group(self):
        return self.journal.state['groups'][self.variant]

    def check(self, context, variant):
        need(not self.journal.closed and not self.journal.poisoned, 'Journal unavailable')
        need(variant == self.variant and context == self.group['context'], 'Runtime permit context differs')
        need(self.journal.state['phase'] == 'active' and self.group['phase'] != 'released', 'Group permit inactive')

    def begin_restore(self, run_id):
        with self.journal.mutex:
            self.check(self.group['context'], self.variant)
            need(run_id == self.journal.state['runId'] and self.group['phase'] == 'reserved', 'Restore already attempted')
            self.group['phase'] = 'restoring'
            self.journal.save()  # Before any API call, even inventory lookup.

    def persist_case(self, index, state):
        with self.journal.mutex:
            self.check(self.group['context'], self.variant)
            need(type(index) is int and 0 <= index < len(self.journal.state['plan']['templates']), 'Case scope differs')
            self.group['cases'][str(index)] = copy.deepcopy(state)
            self.journal.save()

    def finish(self, cleanup, provider_status=None):
        with self.journal.mutex:
            self.check(self.group['context'], self.variant)
            cases = self.group['cases']
            need(len(cases) == len(self.journal.state['plan']['templates']), 'Missing lifecycle journal')
            need(all(c['phase'] == 'quiesced' and not c['sandboxIds'] and not c['openRequests']
                     and not c.get('outcomeUncertain') for c in cases.values()), 'Unresolved lifecycle blocks next group')
            need(cleanup.get('ownedGuestsReleased') is True and cleanup.get('sharedUBObjectsRetired') is False,
                 'Explicit Guest cleanup with retained shared base required')
            need(len(cleanup['released']) == 2 * len(cases) and all(r['fcExitConfirmed'] for r in cleanup['released']),
                 'Actual Guest exit evidence missing')
            created = [sid for case in cases.values() for op in case.get('operations', [])
                       if op.get('kind') == 'create' and op.get('httpStatus') == 201
                       for sid in op.get('ack', {}).get('sandboxIds', [])]
            released = [row['sandboxId'] for row in cleanup['released']]
            need(len(created) == len(set(created)) == len(released) == len(set(released))
                 and set(created) == set(released), 'Cleanup differs from durable creation acknowledgments')
            if self.variant == 'full':
                need(all(r['requiredUBDeviceExitConfirmed'] for r in cleanup['released']), 'UB device exit unconfirmed')
                need(provider_status and provider_status['activeLeases'] == 0 and provider_status['activePayloadResponses'] == 0,
                     'Provider read permits/payloads not drained')
            self.group.update(phase='released', cleanup=copy.deepcopy(cleanup), providerStatus=copy.deepcopy(provider_status))
            self.journal.state['phase'] = 'completed' if len(self.journal.state['groups']) == 2 else 'between_groups'
            self.journal.save()
