"""Reconcile the exact failed demand run before switching operators."""

import argparse
import errno
import fcntl
import json
import os
import stat
import struct
import uuid
from pathlib import Path


OBMM_DEVICE = Path('/dev/obmm_pmem')
PATCH_SRCVERSION = '29F10664C1EE59D7127F8C7'
VOLUME_LAYOUT = struct.Struct('<II16sIIII7Q')
SLOT_LAYOUT = struct.Struct('<II16sQII32s')
PROVIDER = 'agentenv-ub-provider'
ROOTS = tuple(map(Path, ('/root/aenv-pmem', '/etc/aenv/ub', '/var/lib/aenv-ub-sdk')))


def read_text(path, limit=128 * 1024):
    return read_bytes(path, limit).decode('utf-8', 'replace')


def read_bytes(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('expected a regular file')
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('file exceeds collection bound')
    return raw


def inspect_device(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'present': False}
    return {'present': True, 'character': stat.S_ISCHR(info.st_mode),
            'device': [os.major(info.st_rdev), os.minor(info.st_rdev)],
            'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode))}


def query_obmm(volume, segment):
    result = {}
    try:
        result['srcversion'] = read_text(Path('/sys/module/obmm/srcversion'), 128).strip()
        if result['srcversion'] != PATCH_SRCVERSION or os.uname().machine != 'aarch64':
            return {**result, 'query': 'unverified_abi'}
        fd = os.open(OBMM_DEVICE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        return {**result, 'query': 'unavailable', 'errno': error.errno}
    try:
        if not stat.S_ISCHR(os.fstat(fd).st_mode):
            return {**result, 'query': 'invalid_device_type'}
        for name, ident, opcode, layout, fields in (
            ('volume', volume, 0xc060b801, VOLUME_LAYOUT,
             ('version', 'reserved', 'uuid', 'id', 'state', 'major', 'minor', 'bytes',
              'openers', 'activeIo', 'blockReads', 'blockBytes', 'daxAccesses', 'daxSpanBytes')),
            ('segment', segment, 0xc048b80b, SLOT_LAYOUT,
             ('version', 'state', 'uuid', 'slotOffset', 'bytes', 'reserved', 'sha256')),
        ):
            wire = bytearray(layout.size)
            struct.pack_into('<II16s', wire, 0, 1, 0, ident.bytes)
            try:
                fcntl.ioctl(fd, opcode, wire, True)
            except OSError as error:
                result[name] = {'uuid': str(ident), 'errno': error.errno,
                                'status': 'absent' if error.errno == errno.ENOENT else 'query_failed'}
                continue
            row = dict(zip(fields, layout.unpack(wire)))
            if row['uuid'] != ident.bytes or row['version'] != 1 or row['reserved'] != 0:
                result[name] = {'uuid': str(ident), 'status': 'unexpected_reply'}
                continue
            row['uuid'] = str(ident)
            if 'sha256' in row:
                row['sha256'] = row['sha256'].hex()
            result[name] = {**row, 'status': 'present'}
    finally:
        os.close(fd)
    return result


def named_shmdevs(name):
    matches, unreadable = [], 0
    paths = sorted(Path('/sys/devices/obmm').glob('obmm_shmdev*'))
    for path in paths[:256]:
        try:
            size = int(read_text(path / 'priv_len', 32))
            raw = read_bytes(path / 'priv', 512)
            if 204 <= size <= len(raw) and raw[152:204].partition(b'\x00')[0] == name.encode('ascii'):
                matches.append({'name': path.name, 'type': read_text(path / 'type', 128).strip(),
                                'privBytes': size})
        except (OSError, ValueError):
            unreadable += 1
    return {'matches': matches, 'unreadable': unreadable, 'truncated': len(paths) > 256}


def nearby_files(roots):
    seen = set()
    for directory in roots:
        for folder, dirs, files in os.walk(directory, followlinks=False):
            here = Path(folder)
            if here in seen:
                dirs[:] = []
                continue
            seen.add(here)
            dirs[:] = sorted(name for name in dirs if not name.startswith('.')
                             and name not in ('evidence', 'view', 'target', 'registry'))
            if len(here.relative_to(directory).parts) >= 3:
                dirs[:] = []
            for name in sorted(files):
                yield here / name
            if len(seen) >= 128:
                return


def collect_runs(run):
    documents, sources = [], []
    for path in nearby_files(ROOTS):
        if path.suffix == '.ext4' and path.name == 'lowers.ext4' and not path.is_symlink():
            try:
                sources.append({'path': str(path), 'bytes': path.stat().st_size,
                                'manifestPresent': path.with_name('manifest.json').is_file()})
            except FileNotFoundError:
                pass
        if path.suffix != '.json' or path.is_symlink() or len(documents) >= 64:
            continue
        try:
            data = json.loads(read_bytes(path, 384 * 1024))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        if data.get('state') == 'metadata_ready' and isinstance(data.get('replicas'), list):
            generations = [entry.get('generation') for entry in data['replicas'] if isinstance(entry, dict)]
            documents.append({'path': str(path), 'indexState': data['state'], 'generations': generations})
            continue
        if not isinstance(data.get('run'), str):
            continue
        keys = ('run', 'node', 'phase', 'volume', 'closed', 'faulted', 'ready', 'released',
                'finalizeAcknowledged', 'initializeAcknowledged', 'bindings')
        row = {key: data[key] for key in keys if key in data}
        if 'device' in data and isinstance(data['device'], dict):
            row['device'] = {key: data['device'].get(key) for key in ('sourceImage', 'stateDir', 'index')}
        if data['run'] == run:
            row['poolIds'] = list(data['pools']) if isinstance(data.get('pools'), dict) else None
        documents.append({'path': str(path), **row})
    receipt = ROOTS[0] / 'evidence' / ('recovery-receipt-' + run[:8] + '.json')
    return {'documents': documents, 'outerImages': sources,
            'expectedRecoveryReceiptPresent': receipt.is_file()}


def inspect_processes(shmdevs):
    roles, references = [], []
    unreadable_refs = 0
    devices = {'/dev/' + item['name'] for item in shmdevs}
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            exe = os.readlink(process / 'exe')
            name = Path(exe).name
            if name.startswith((PROVIDER, 'uvm-ublk-daemon', 'firecracker')) or name in ('server', 'aenv'):
                row = {'pid': int(process.name), 'exe': exe, 'uid': process.stat().st_uid}
                if name.startswith(PROVIDER):
                    cmd = read_bytes(process / 'cmdline', 16 * 1024).split(b'\x00')
                    if len(cmd) >= 3 and cmd[1] in (b'sdk', b'root'):
                        row['role'] = cmd[1].decode()
                        try:
                            config = Path(os.fsdecode(cmd[2])).resolve(strict=True)
                            if config.suffix == '.json' and any(config.is_relative_to(root) for root in ROOTS):
                                from_config = json.loads(read_bytes(config, 256 * 1024))
                                row['run'] = from_config.get('run') if isinstance(from_config, dict) else None
                        except (OSError, ValueError, RuntimeError):
                            pass
                roles.append(row)
        except (OSError, ValueError):
            pass
        if not devices:
            continue
        try:
            fds = []
            for fd in (process / 'fd').iterdir():
                try:
                    target = os.readlink(fd)
                except FileNotFoundError:
                    continue
                if target in devices:
                    fds.append({'fd': fd.name, 'device': target})
            if fds:
                references.append({'pid': int(process.name), 'fds': fds})
        except FileNotFoundError:
            pass
        except OSError:
            unreadable_refs += 1
    return {'roles': roles, 'matchingShmdevFds': references, 'unreadableFdDirectories': unreadable_refs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volume', type=uuid.UUID, required=True)
    parser.add_argument('--segment', type=uuid.UUID, required=True)
    parser.add_argument('--run', type=uuid.UUID, required=True)
    parser.add_argument('--object', type=uuid.UUID, required=True)
    args = parser.parse_args()
    assert VOLUME_LAYOUT.size == 96 and SLOT_LAYOUT.size == 72
    shmdevs = named_shmdevs('aenv_' + args.object.hex)
    report = {'status': 'MN_TAKEOVER_READONLY', 'host': os.uname().nodename,
              'bootId': read_text(Path('/proc/sys/kernel/random/boot_id'), 128).strip(),
              'run': args.run.hex, 'obmm': query_obmm(args.volume, args.segment),
              'shmdevs': shmdevs, 'processes': inspect_processes(shmdevs['matches']),
              'state': collect_runs(args.run.hex), 'ublk': inspect_device(Path('/dev/ublk-control'))}
    print(json.dumps(report, separators=(',', ':'), ensure_ascii=True), flush=True)


if __name__ == '__main__':
    main()
