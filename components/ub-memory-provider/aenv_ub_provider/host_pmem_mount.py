"""Private-namespace ext4 read-only mount for the Host pmem test path.

No format, remount, force/lazy unmount or cached-file fallback. Module and SDK
lifecycle belong to the separately approved experiment coordinator.
"""
import ctypes
import os
from pathlib import Path
import re
import stat
import subprocess
import threading


def command(name, *args):
    for base in ('/usr/bin', '/bin', '/usr/sbin', '/sbin'):
        tool = Path(base) / name
        if tool.is_file():
            info = tool.resolve(strict=True).stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Unsafe system mount tool')
            result = subprocess.run([str(tool), *map(str, args)], capture_output=True,
                                    timeout=30, env={'PATH':'/usr/sbin:/sbin:/usr/bin:/bin',
                                                    'LANG':'C','LC_ALL':'C'})
            if result.returncode:
                raise RuntimeError(name + ' failed: ' + result.stderr.decode(errors='replace')[-2000:])
            return
    raise FileNotFoundError(name)


def namespace_identity():
    value = Path('/proc/self/ns/mnt').stat()
    return (value.st_dev, value.st_ino)


def private_namespace():
    if (os.getuid() != 0 or os.geteuid() != 0
            or threading.current_thread() is not threading.main_thread()
            or threading.active_count() != 1):
        raise RuntimeError('Private mount namespace requires single-threaded root helper')
    before = namespace_identity()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes, libc.unshare.restype = [ctypes.c_int], ctypes.c_int
    if libc.unshare(0x00020000) != 0:  # CLONE_NEWNS; no user/net namespace changes.
        raise OSError(ctypes.get_errno(), 'unshare mount namespace failed')
    after = namespace_identity()
    if before == after:
        raise RuntimeError('Mount namespace did not change')
    command('mount', '--make-rprivate', '/')
    lines = Path('/proc/self/mountinfo').read_text().splitlines()
    for line in lines:
        left = line.split(' - ', 1)[0].split()
        if any(item.startswith(('shared:', 'master:')) for item in left[6:]):
            raise RuntimeError('Mount propagation is not private')
    return after


def decode_mount_field(value):
    return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match.group(1), 8)), value)


def mounted_at(path):
    matches = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        fields, source = left.split(), right.split()
        if decode_mount_field(fields[4]) == str(path):
            matches.append({'id':int(fields[0]), 'device':fields[2], 'root':decode_mount_field(fields[3]),
                            'options':set(fields[5].split(',')), 'filesystem':source[0],
                            'source':decode_mount_field(source[1]), 'superOptions':set(source[2].split(','))})
    if len(matches) > 1:
        raise RuntimeError('Stacked mountpoints are not accepted')
    return matches[0] if matches else None


class ReadonlyMount:
    def __init__(self, namespace, volume, target, save):
        self.namespace, self.volume, self.target, self.save = namespace, volume, Path(target), save
        self.state = {'phase':'new', 'volumeUuid':volume.uuid, 'volumeId':volume.id,
                      'namespace':list(namespace), 'target':str(self.target)}
        self.mount_id = None

    def mark(self, phase, **values):
        self.state.update(phase=phase, **values)
        self.save(dict(self.state))

    def check_namespace(self):
        if namespace_identity() != self.namespace:
            raise RuntimeError('Mount namespace changed')

    def validate_mount(self, mounted):
        if (mounted is None or mounted['device'] != f'{self.volume.major}:{self.volume.minor}'
                or mounted['root'] != '/' or mounted['filesystem'] != 'ext4'
                or not {'ro','nodev','nosuid','noexec'}.issubset(mounted['options'])
                or 'ro' not in mounted['superOptions'] or 'dax=always' not in mounted['superOptions']):
            raise RuntimeError('Mount identity or readonly DAX options differ')

    def mount(self):
        self.check_namespace()
        if self.state['phase'] != 'new':
            raise RuntimeError('Mount already attempted; reconcile rather than retry')
        info = self.target.lstat()
        parent = self.target.parent
        parent_info = parent.stat()
        if (not self.target.is_absolute() or self.target.resolve(strict=True) != self.target
                or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077
                or parent.resolve(strict=True) != parent or parent_info.st_uid != 0
                or parent_info.st_mode & 0o022 or any(self.target.iterdir())
                or mounted_at(self.target) is not None):
            raise ValueError('Expected empty root-private mount directory')
        device = Path('/dev') / ('ubpmem_ro' + str(self.volume.id))
        metadata = device.lstat()
        if (not stat.S_ISBLK(metadata.st_mode)
                or metadata.st_rdev != os.makedev(self.volume.major, self.volume.minor)):
            raise ValueError('pmem block device identity differs')
        self.mark('mount_intent', device=str(device))
        try:
            command('mount', '-t', 'ext4', '-o', 'ro,noload,dax=always,nodev,nosuid,noexec', device, self.target)
            mounted = mounted_at(self.target)
            self.validate_mount(mounted)
            self.mount_id = mounted['id']
            self.mark('mounted', mountId=self.mount_id)
        except BaseException as error:
            self.mark('mount_unconfirmed', error=str(error))
            raise

    def unmount(self):
        self.check_namespace()
        if self.state['phase'] not in ('mounted', 'mount_unconfirmed', 'unmount_unconfirmed'):
            raise RuntimeError('No mount attempt to retire')
        mounted = mounted_at(self.target)
        if mounted is None:
            # Caller still must destroy the volume before closing SDK anchors.
            self.mark('mount_absent')
            return
        self.validate_mount(mounted)
        if self.mount_id is not None and mounted['id'] != self.mount_id:
            raise RuntimeError('Different mount appeared; preserve it')
        self.mount_id = mounted['id']
        self.mark('unmount_intent', mountId=self.mount_id)
        try:
            command('umount', '--', self.target)
            if mounted_at(self.target) is not None:
                raise RuntimeError('Unmount not confirmed')
            self.mark('mount_absent')
        except BaseException as error:
            self.mark('unmount_unconfirmed', error=str(error))
            raise
