"""Read-only M/N deployment preflight for the pinned layered-demand build."""

import argparse
import fcntl
import hashlib
import json
import os
import stat
import struct
import subprocess
import uuid
from pathlib import Path


EXPECTED = {
    'agent1': {
        'attempt': '/root/agentenv-sp3/layered-baseline-build/attempt-aflp3z9b',
        'volume': '01a21fe3-9305-7e31-ac60-cb28b9532df5',
        'artifacts': {
            'server': ('target/release/server', 'a64852ff4dc991a72a6d7bb064c560b3c2cd3f31a6dfb117aa737b6c993c3cca'),
            'uvm-ublk-daemon': ('target/release/uvm-ublk-daemon', '5cde4369450526b930eb8c6967dcac497d19ac6ce70536946d8236b8566c61b7'),
            'agentenv-ub-provider': ('target/release/agentenv-ub-provider', 'bd5a833a67e27ece65eafead7ef4547941d06d4f10ee957d321ffd05981ee8c9'),
            'libaenv-ub.so': ('libaenv-ub.so', 'b729412a67e56d0c8545f07228930b5e4a01463f7acd6c3aa3813343a42332e7'),
        },
    },
    'agent2': {
        'attempt': '/root/agentenv-sp3/layered-baseline-build/attempt-_gun1gos',
        'volume': '01a21fe1-048a-7740-94a6-62f9e6927ecd',
        'artifacts': {
            'server': ('target/release/server', 'd8962860eb35749569fb21cfc3e7d15cd48a09c95d9d4bb82992ac281697d9fb'),
            'uvm-ublk-daemon': ('target/release/uvm-ublk-daemon', '18a1902501737ae71e90f5193768cadb61bf0876beab2f4a817152992d39b31c'),
            'agentenv-ub-provider': ('target/release/agentenv-ub-provider', '44f800cf1a50299a656561fd9a21a0ae7693ecff3f4ce56cd5705d988e68992e'),
            'libaenv-ub.so': ('libaenv-ub.so', 'b729412a67e56d0c8545f07228930b5e4a01463f7acd6c3aa3813343a42332e7'),
        },
    },
}
VOLUME_LAYOUT = struct.Struct('<II16sIIII7Q')
SYSTEM_PATHS = (
    '/usr/local/bin/aenv', '/usr/local/bin/server', '/usr/local/bin/uvm-ublk-daemon',
    '/usr/local/bin/agentenv-ub-provider', '/opt/aenv/libaenv-ub.so',
    '/etc/systemd/system/aenv-mn-titanic.service', '/usr/lib/systemd/system/aenv-mn-titanic.service',
    '/etc/aenv/ub/sdk.json', '/etc/aenv/ub/device.json',
)


def command(argv, timeout=15):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
        return {'exit': result.returncode,
                'stdout': result.stdout[:16000].decode('utf-8', 'replace'),
                'stderr': result.stderr[:4000].decode('utf-8', 'replace')}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'exit': None, 'error': type(error).__name__}


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def file_facts(path, expected_sha=None):
    path = Path(path)
    try:
        row = path.lstat()
    except FileNotFoundError:
        return {'path': str(path), 'present': False}
    result = {'path': str(path), 'present': True, 'regular': stat.S_ISREG(row.st_mode),
              'directory': stat.S_ISDIR(row.st_mode), 'symlink': stat.S_ISLNK(row.st_mode),
              'uid': row.st_uid, 'gid': row.st_gid, 'mode': oct(stat.S_IMODE(row.st_mode)),
              'bytes': row.st_size}
    if stat.S_ISREG(row.st_mode) and row.st_size <= 512 * 1024 * 1024:
        result['sha256'] = sha(path)
        with path.open('rb') as stream:
            header = stream.read(20)
        if header[:4] == b'\x7fELF' and len(header) >= 20:
            result['elfClass'] = header[4]
            result['elfData'] = header[5]
            result['elfMachine'] = int.from_bytes(header[18:20], 'little' if header[5] == 1 else 'big')
    if expected_sha:
        result['matchesBuildReceipt'] = result.get('sha256') == expected_sha
    return result


def volume_query(volume):
    try:
        fd = os.open('/dev/obmm_pmem', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        return {'status': 'query-unavailable', 'errno': error.errno}
    wire = bytearray(VOLUME_LAYOUT.size)
    struct.pack_into('<II16s', wire, 0, 1, 0, uuid.UUID(volume).bytes)
    try:
        try:
            fcntl.ioctl(fd, 0xc060b801, wire, True)
        except OSError as error:
            if error.errno == 2:
                return {'status': 'absent'}
            return {'status': 'query-error', 'errno': error.errno}
    finally:
        os.close(fd)
    names = ('version', 'reserved', 'uuid', 'id', 'state', 'major', 'minor', 'bytes',
             'openers', 'activeIo', 'blockReads', 'blockBytes', 'daxAccesses', 'daxSpanBytes')
    result = dict(zip(names, VOLUME_LAYOUT.unpack(wire)))
    if result['version'] != 1 or result['uuid'] != uuid.UUID(volume).bytes:
        return {'status': 'unexpected-reply'}
    result['uuid'] = volume
    result['status'] = 'present'
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', choices=('agent1', 'agent2'), required=True)
    parser.add_argument('--boot-id', required=True)
    parser.add_argument('--machine-id', required=True)
    args = parser.parse_args()
    expected = EXPECTED[args.node]
    if os.geteuid() != 0 or os.uname().nodename.split('.')[0] != args.node:
        raise RuntimeError('root privilege or node hostname differs')
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != args.boot_id:
        raise RuntimeError('boot identity differs')
    if Path('/etc/machine-id').read_text().strip() != args.machine_id:
        raise RuntimeError('machine identity differs')
    attempt = Path(expected['attempt'])
    attempt.lstat()
    artifacts = {name: file_facts(attempt / relative, digest)
                 for name, (relative, digest) in expected['artifacts'].items()}
    processes = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            exe = os.readlink(proc / 'exe')
            argv = (proc / 'cmdline').read_bytes().split(b'\0')
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        name = Path(exe).name
        if name in ('server', 'agentenv', 'uvm-ublk-daemon', 'firecracker') or 'agentenv-ub-provider' in exe:
            processes.append({'pid': int(proc.name), 'exe': exe,
                              'cmdline': [part.decode('utf-8', 'replace')[:256] for part in argv[:6]]})
    shmdevs = []
    for path in sorted(Path('/sys/devices/obmm').glob('obmm_shmdev*')):
        try:
            row = path.stat()
            shmdevs.append({'path': str(path), 'uid': row.st_uid, 'gid': row.st_gid,
                            'mode': oct(stat.S_IMODE(row.st_mode)), 'bytes': row.st_size})
        except FileNotFoundError:
            pass
    services = {}
    for unit in ('aenv-mn-titanic.service', 'ubse.service', 'ubsmd.service'):
        services[unit] = command(['/usr/bin/systemctl', 'show', unit,
                                  '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID'])
    result = {
        'status': 'MN_DEPLOYMENT_READ_ONLY_PREFLIGHT', 'node': args.node,
        'identity': {'bootId': args.boot_id, 'machineId': args.machine_id,
                     'kernel': os.uname().release, 'architecture': os.uname().machine},
        'pinnedBaseline': {'agentenvCommit': 'bffdc74bf9b2a11467ee25159099d03a19110f98',
                           'agentenvTree': '044b48e11c83c80d67b12caa5989a5729401294a',
                           'kernelCommit': 'bd8bc91e46e55418840e4cab751b19e5d08afc82',
                           'kernelTree': '93f12be0b395a48bb11daab438405c8ac53169e8'},
        'builtAttempt': str(attempt), 'builtArtifacts': artifacts,
        'oldVolume': expected['volume'], 'oldVolumeQuery': volume_query(expected['volume']),
        'processes': processes, 'services': services, 'obmmShmdevs': shmdevs,
        'knownInstallPaths': {path: file_facts(path) for path in SYSTEM_PATHS},
        'systemdUnits': command(['/usr/bin/systemctl', 'list-units', '--all', '--no-legend',
                                 '--no-pager', 'aenv*', 'agentenv*']),
        'actionsTaken': [],
    }
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
