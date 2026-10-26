"""Compose an existing SDK lease, Host pmem volume, private mount and DAX read.

This is the privileged local half of a coordinated experiment. It does not
start SDK owners, switch drivers or release UB objects. The caller must keep
both ordinary owners alive until exact local retirement and peer receipts.
"""
import os
from pathlib import Path
import stat

from . import host_pmem, host_pmem_lease, host_pmem_mount, host_pmem_guard
from .io import atomic_json


def prepare_work(path):
    work = Path(path)
    parent = work.parent
    info = parent.stat()
    if (os.getuid() != 0 or os.geteuid() != 0 or not work.is_absolute()
            or parent.resolve(strict=True) != parent or info.st_uid != 0
            or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022):
        raise ValueError('Session requires root and a root-owned private staging parent')
    work.mkdir(mode=0o700, exist_ok=False)
    (work / 'mount').mkdir(mode=0o700)
    return work


class MountedSession:
    def __init__(self, work, source, owner_uid, owner_pid, owner_ticks, publication):
        binding = host_pmem_guard.publication_binding(publication, source)
        self.work = prepare_work(work)
        self.record = {'version':1, 'phase':'prepared',
                       'publication':binding,
                       'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                       'source':dict(source), 'ownerUid':owner_uid, 'ownerPid':owner_pid,
                       'ownerStartTicks':owner_ticks, 'sharedBackingReleaseAuthorized':False}
        self.fd = None
        self.lease = self.mount = self.status = None
        self.persist()

    def persist(self):
        atomic_json(self.work / 'host-pmem-session.json', self.record)

    def update(self, key, value):
        self.record[key] = value
        self.persist()

    def start(self):
        if self.record['phase'] != 'prepared':
            raise RuntimeError('Session already attempted; no implicit restart')
        self.update('phase', 'starting')
        try:
            namespace = host_pmem_mount.private_namespace()
            self.update('namespace', list(namespace))
            self.fd = host_pmem.open_control()
            self.control = host_pmem.Control(self.fd)
            self.lease = host_pmem_lease.acquire(self.record['source'], self.record['ownerUid'],
                                                 self.record['ownerPid'], self.record['ownerStartTicks'])
            self.status = self.lease.attach(self.control, lambda value:self.update('volume', value))
            self.mount = host_pmem_mount.ReadonlyMount(namespace, self.status, self.work / 'mount',
                                                       lambda value:self.update('mount', value))
            self.mount.mount()
            self.update('phase', 'mounted_pending_file_verification')
        except BaseException as error:
            self.update('failure', {'phase':self.record['phase'], 'reason':str(error)})
            self.update('phase', 'stopped_preserve_resources')
            raise

    def export_release(self, path):
        return host_pmem_guard.write_release(path, self.record)

    def verify(self, filename, length, sha256):
        if self.record['phase'] not in ('mounted_pending_file_verification', 'local_read_verified'):
            raise RuntimeError('Session is not ready for DAX reads')
        if (not isinstance(filename, str) or not filename or filename in ('.','..')
                or '/' in filename or '\\' in filename or '\0' in filename):
            raise ValueError('Test file must be one explicit filename under the private mount')
        try:
            result = host_pmem.verify_dax_file(self.control, self.status,
                                               self.work / 'mount' / filename, length, sha256)
            self.update('verification', result)
            self.update('phase', 'local_read_verified')
            return result
        except BaseException as error:
            self.update('failure', {'phase':self.record['phase'], 'reason':str(error)})
            self.update('phase', 'stopped_preserve_resources')
            raise

    def retire(self):
        """Explicit local cleanup, usable after failed validation as well.

        Never close the native lease before unmount AND volume absence. A busy
        or uncertain resource leaves the owner retain requirement in effect.
        """
        if self.record['phase'] == 'local_resources_released':
            return dict(self.record)
        self.update('phase', 'retiring')
        try:
            if self.mount is not None and self.mount.state['phase'] != 'mount_absent':
                if self.mount.state['phase'] != 'new':
                    self.mount.unmount()
            if self.lease is not None:
                volume = self.lease.volume
                if volume is not None:
                    phase = volume.record['phase']
                    if phase in ('serving','retire_busy'):
                        volume.retire()
                    elif phase in ('destroy_intent','destroy_acknowledged','destroy_unconfirmed'):
                        volume.confirm_absent()
                    elif phase not in ('new','local_volume_absent'):
                        raise RuntimeError('Unconfirmed volume creation; preserve SDK anchors')
                self.lease.close()
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            self.update('phase', 'local_resources_released')
            return dict(self.record)
        except BaseException as error:
            self.update('failure', {'phase':'retiring', 'reason':str(error)})
            self.update('phase', 'retirement_stopped_preserve_resources')
            raise
