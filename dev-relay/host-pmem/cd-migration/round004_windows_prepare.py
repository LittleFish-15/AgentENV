"""Prepare password-interactive SFTP staging and public host identity, no server changes."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import stat

HOME = Path('/home/jwk')
ROOT = HOME / 'agent'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def hostkeys():
    found = []
    for name in ('ssh_host_ed25519_key.pub', 'ssh_host_ecdsa_key.pub', 'ssh_host_rsa_key.pub'):
        path = Path('/etc/ssh') / name
        try:
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                 and info.st_size < 8192, 'Host public key metadata differs')
            parts = path.read_text().strip().split()
            need(len(parts) >= 2 and len(base64.b64decode(parts[1], validate=True)) < 4096, 'Invalid host public key')
            found.append(' '.join(parts[:2]))
        except FileNotFoundError:
            continue
    need(any(k.startswith('ssh-ed25519 ') for k in found), 'Missing public host identity')
    return found


def inspect_partial(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 1204 and not path.is_symlink(), 'Unexpected partial preserved')
    return {'path': str(path), 'bytes': info.st_size, 'mtimeNs': info.st_mtime_ns,
            'inode': info.st_ino, 'device': info.st_dev, 'removed': False}


def prepare(spec):
    result = {'node': spec['node'], 'hostPublicKeys': hostkeys(), 'SDK_called': False,
              'servicesChanged': False, 'moduleChanged': False, 'Guest_created': False}
    if spec['node'] == 'node-a':
        path = HOME / '.ssh/authorized_keys'
        need(path.resolve() == path and path.is_file(), 'Old export authorization missing or redirected; reconcile')
        info = path.lstat()
        need(info.st_uid == 1204 and hashlib.sha256(path.read_bytes()).hexdigest() == spec['oldAuthorizationSha256'],
             'Authorization changed; preserve unrelated keys')
        path.unlink()
        result.update(status='OLD_DIRECT_EXPORT_AUTHORIZATION_REVOKED_PUBLIC_HOST_ID_RETURNED',
                      directExportKeysRemoved=True)
    else:
        root = ROOT / 'cd-host-dax' / spec['sessionId']
        need(root.resolve() == root, 'Receiver directory redirected')
        marker = json.loads((root / 'receiver-identity.json').read_bytes())
        need(marker['node'] == spec['node'] and marker['machineId'] == spec['expectedIdentity']['machineId'],
             'Receiver marker differs')
        partials = list((root / 'incoming').glob('*.partial'))
        need(len(partials) <= 128, 'Partial list exceeds bound')
        result['preservedPartials'] = [inspect_partial(path) for path in partials]
        path = root / 'windows-incoming-v1'
        need(path.resolve() == path and not path.exists(), 'Previous staging exists; preserved')
        path.mkdir(mode=0o700)
        result.update(status='WINDOWS_SFTP_STAGING_READY_NOT_TRANSFERRED', stagingDirectory=str(path))
    return result


def main():
    need(platform.system() == 'Linux' and os.getuid() == os.geteuid() == 1204
         and os.getgid() == os.getegid() == 1205, 'Run as ordinary jwk')
    spec = json.loads(Path('task-input.json').read_bytes())
    current = {'hostname': platform.node(), 'uid': os.getuid(), 'gid': os.getgid(),
               'architecture': platform.machine(), 'kernel': platform.release(),
               'machineId': Path('/etc/machine-id').read_text().strip(),
               'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    need(current == spec['expectedIdentity'], 'Node boot identity changed')
    result = prepare(spec)
    result['identity'] = current
    print('BEGIN_WINDOWS_BRIDGE_PREPARATION')
    print(json.dumps(result, indent=2))
    print('END_WINDOWS_BRIDGE_PREPARATION')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'WINDOWS_BRIDGE_PREPARATION_STOPPED', 'reason': str(error)}))
        raise SystemExit(1)
