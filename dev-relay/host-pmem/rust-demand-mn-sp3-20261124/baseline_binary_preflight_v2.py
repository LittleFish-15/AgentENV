"""Read-only verify cleanup completion and inventory artifacts for the pinned layered baseline."""

import argparse
import errno
import fcntl
import hashlib
import json
import os
import struct
import stat
import subprocess
import uuid
from pathlib import Path


AGENT_COMMIT = 'bffdc74bf9b2a11467ee25159099d03a19110f98'
AGENT_TREE = '044b48e11c83c80d67b12caa5989a5729401294a'
OBMM_COMMIT = 'bd8bc91e46e55418840e4cab751b19e5d08afc82'
ROOT = Path('/home/jwk/agent/sp3-mn')
PROVIDER_RUN = 'dabd65d32a1c5c3e91a994bbcbbb9e6f'
POOL = '01a21fe4-7e16-7442-b4e7-592d12958c40'
VOLUMES = {'agent1': '01a21fe3-9305-7e31-ac60-cb28b9532df5',
           'agent2': '01a21fe1-048a-7740-94a6-62f9e6927ecd'}
VOLUME_LAYOUT = struct.Struct('<II16sIIII7Q')


def command(argv, cwd='/'):
    try:
        result = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=20, check=False)
        return {'exit': result.returncode, 'stdout': result.stdout[:8192].decode('utf-8', 'replace'),
                'stderr': result.stderr[:4096].decode('utf-8', 'replace')}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'exit': None, 'error': type(error).__name__}


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def artifact(path):
    try:
        info = path.lstat()
        row = {'path': str(path), 'present': True, 'regular': stat.S_ISREG(info.st_mode),
               'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode)),
               'bytes': info.st_size}
        if row['regular'] and info.st_size <= 256 * 1024 * 1024:
            row['sha256'] = sha(path)
            row['elf'] = path.open('rb').read(20)[:6] == b'\x7fELF\x02\x01'
        return row
    except FileNotFoundError:
        return {'path': str(path), 'present': False}


def checkout(path):
    if not (path / '.git').exists():
        return {'path': str(path), 'present': False}
    return {'path': str(path), 'present': True,
            'head': command(['/usr/bin/git', 'rev-parse', 'HEAD'], str(path)),
            'tree': command(['/usr/bin/git', 'rev-parse', 'HEAD^{tree}'], str(path)),
            'status': command(['/usr/bin/git', 'status', '--porcelain', '--untracked-files=normal'], str(path))}


def exact_volume_query(volume):
    path = Path('/dev/obmm_pmem')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {'status': 'query-device-absent'}
    except OSError as error:
        return {'status': 'query-unavailable', 'errno': error.errno}
    wire = bytearray(VOLUME_LAYOUT.size)
    struct.pack_into('<II16s', wire, 0, 1, 0, uuid.UUID(volume).bytes)
    try:
        try:
            fcntl.ioctl(fd, 0xc060b801, wire, True)
        except OSError as error:
            if error.errno == errno.ENOENT:
                return {'status': 'absent'}
            return {'status': 'query-error', 'errno': error.errno}
    finally:
        os.close(fd)
    fields = ('version', 'reserved', 'uuid', 'id', 'state', 'major', 'minor', 'bytes',
              'openers', 'activeIo', 'blockReads', 'blockBytes', 'daxAccesses', 'daxSpanBytes')
    row = dict(zip(fields, VOLUME_LAYOUT.unpack(wire)))
    if row['version'] != 1 or row['reserved'] != 0 or row['uuid'] != uuid.UUID(volume).bytes:
        return {'status': 'unexpected-reply'}
    row['uuid'] = volume
    row['status'] = 'present'
    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', choices=('agent1', 'agent2'), required=True)
    parser.add_argument('--boot-id', required=True)
    parser.add_argument('--machine-id', required=True)
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    need = os.geteuid() == 0 and host == args.node
    need = need and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == args.boot_id
    need = need and Path('/etc/machine-id').read_text().strip() == args.machine_id
    if not need:
        raise RuntimeError('node identity differs from task binding')
    agent = checkout(ROOT / 'src/AgentENV')
    kernel = checkout(ROOT / 'src/kernel.partial')
    provider = ROOT / 'src/AgentENV/target/release/agentenv-ub-provider'
    server = ROOT / 'src/AgentENV/target/release/server'
    ublk = ROOT / 'src/AgentENV/target/release/uvm-ublk-daemon'
    old_objects = sorted(Path('/sys/devices/obmm').glob('obmm_shmdev*'))
    run_processes = []
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            exe = os.readlink(process / 'exe')
            argv = (process / 'cmdline').read_bytes().split(b'\0')
            if 'agentenv-ub-provider' in exe or Path(exe).name in ('server', 'uvm-ublk-daemon', 'firecracker'):
                run_processes.append({'pid': int(process.name), 'exe': exe,
                                      'cmdline': [part.decode('utf-8', 'replace')[:256] for part in argv[:5]]})
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    documents = {}
    for path in (ROOT / 'src/AgentENV/docs/src/internals/ub-rootfs-stable-demand.md',
                 ROOT / 'src/AgentENV/docs/src/getting-started/on-demand-loading.md'):
        documents[str(path)] = artifact(path)
    source_module = ROOT / 'src/kernel.partial/drivers/ub/obmm/obmm.ko'
    result = {
        'status': 'BASELINE_BINARY_PREFLIGHT_WITH_EXACT_VOLUME_READ_ONLY', 'node': host,
        'bootId': args.boot_id, 'machineId': args.machine_id,
        'agentenvBaseline': {'commit': AGENT_COMMIT, 'tree': AGENT_TREE},
        'obmmBaseline': {'commit': OBMM_COMMIT},
        'checkouts': {'AgentENV': agent, 'kernel.partial': kernel},
        'artifacts': {str(path): artifact(path) for path in
                      (server, ublk, provider, Path('/opt/aenv/libaenv-ub.so'),
                       source_module, Path('/lib/modules') / os.uname().release / 'extra/obmm.ko')},
        'module': {name: (Path('/sys/module/obmm') / name).read_text().strip()
                   for name in ('srcversion', 'parameters/pmem_ro_enable',
                                'parameters/pmem_demand_write_enable')
                   if (Path('/sys/module/obmm') / name).is_file()},
        'services': {name: command(['/usr/bin/systemctl', 'show', name, '-p', 'ActiveState', '-p', 'MainPID'])
                     for name in ('aenv-mn-titanic.service', 'ubse.service', 'ubsmd.service')},
        'processes': run_processes, 'oldRun': PROVIDER_RUN, 'oldPool': POOL,
        'oldVolume': VOLUMES[host], 'oldVolumeQuery': exact_volume_query(VOLUMES[host]),
        'shmdevs': [str(path) for path in old_objects],
        'documents': documents,
    }
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
