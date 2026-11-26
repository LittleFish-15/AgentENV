"""Inventory the pinned Titanic generation after both nodes reboot."""

import argparse
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import uuid
from pathlib import Path


WORK = Path('/home/jwk/agent/sp3-mn')
OLD_STORE = WORK / 'aenv-tit-d01/h/snapshot-store'
OWNER_STORE = WORK / 'mn-tcap-004/h/snapshot-store'
OWNER_IMAGE = Path('/root/aenv-pmem/mn-titanic-share-001-fprbb53_/lowers.ext4')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}
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
            if ident is None:
                continue
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


def command(*argv):
    try:
        result = subprocess.run(argv, env=ENV, capture_output=True, stdin=subprocess.DEVNULL,
                                timeout=12, check=False, text=True)
        return result.returncode, result.stdout[:8192]
    except (OSError, subprocess.TimeoutExpired):
        return None, ''


def document(path):
    try:
        return json.loads(read_bytes(path, 3 * 1024 * 1024))
    except FileNotFoundError:
        return {}


def file_fact(path, digest=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'path': str(path), 'present': False}
    result = {'path': str(path), 'present': True, 'bytes': info.st_size, 'uid': info.st_uid,
              'mode': oct(stat.S_IMODE(info.st_mode)), 'regular': stat.S_ISREG(info.st_mode)}
    if digest and result['regular']:
        sha = hashlib.sha256()
        with path.open('rb') as stream:
            for part in iter(lambda: stream.read(1024 * 1024), b''):
                sha.update(part)
        result['sha256'] = sha.hexdigest()
    return result


def modules():
    data = {name: inspect_device(Path('/dev') / name) for name in ('kvm', 'ublk-control', 'obmm_pmem')}
    for path in (Path('/sys/module/obmm/srcversion'), Path('/sys/module/obmm/parameters/pmem_ro_enable'),
                 Path('/sys/module/obmm/parameters/pmem_demand_write_enable')):
        data[path.name] = path.read_text().strip() if path.is_file() else None
    if data['srcversion'] != PATCH_SRCVERSION or not data['ublk-control']['present']:
        areas = (WORK, Path('/home/jwk/agent/incoming/rust-demand-sp3'), Path('/root/agentenv-mn-sp3'),
                 Path('/root/aenv-pmem'), Path('/lib/modules') / os.uname().release / 'extra')
        candidates = set()
        for area in areas:
            visited = 0
            for folder, children, files in os.walk(area, followlinks=False):
                path = Path(folder)
                visited += 1
                if visited >= 400:
                    break
                if len(path.relative_to(area).parts) >= 5:
                    children[:] = []
                else:
                    children[:] = sorted(child for child in children if not child.startswith('.')
                                         and child not in ('target', 'target-private-001', 'registry', 'deps', 'jobs',
                                                           'evidence', 'snapshot-store', 'benchmark-oci'))
                for leaf in ('obmm.ko', 'ublk_drv.ko'):
                    if leaf in files:
                        candidates.add(path / leaf)
        known = WORK / 'src/kernel.partial/drivers/ub/obmm/obmm.ko'
        if known.is_file():
            candidates.add(known)
        data['candidates'] = []
        for path in sorted(candidates)[:12]:
            item = file_fact(path, digest=True)
            if item['regular']:
                fields = {}
                for key in ('vermagic', 'srcversion', 'signer', 'depends'):
                    code, raw = command('/usr/sbin/modinfo', '-F', key, str(path))
                    fields[key] = raw.strip() if code == 0 else None
                data['candidates'].append({**item, **fields})
    return data


def old_generation(run):
    root = ROOTS[1] / ('relay-' + run)
    sdk = ROOTS[2] / ('relay-' + run)
    root_doc = document(root / 'device-state/root.json')
    sdk_doc = document(sdk / 'state/sdk.json')
    directory = document(sdk / ('directory-' + run + '.json'))
    for value in (root_doc, sdk_doc, directory):
        if value and value.get('run') != run:
            raise ValueError('Old generation journal identity differs')
    names = set()
    sdk_pools = {}
    for pool_id, record in sdk_doc.get('pools', {}).items():
        descriptor = record['descriptor']
        name = descriptor['objectName']
        if not re.fullmatch('aenv_[0-9a-f]{32}', name) or name != 'aenv_' + uuid.UUID(pool_id).hex:
            raise ValueError('Unexpected old SDK object identity')
        names.add(name)
        sdk_pools[pool_id] = {key: record.get(key) for key in ('phase', 'allocationOwner', 'coverageBytes')}
    results = {name: named_shmdevs(name) for name in sorted(names)}
    matches = [row for match in results.values() for row in match['matches']]
    mounts = [line for line in Path('/proc/self/mountinfo').read_text().splitlines()
              if str(root / 'mount') in line or '/dev/ubpmem_ro' in line]
    volume_id = root_doc.get('volume')
    segments = [item for group in root_doc.get('pool_segments', {}).values() for item in group]
    obmm = []
    if volume_id:
        # Query the actual retained volume even when its journal never recorded a pool segment.
        identifiers = [uuid.UUID(item) for item in segments] or [None]
        for segment in identifiers:
            obmm.append(query_obmm(uuid.UUID(volume_id), segment))
    return {'oldRun': run, 'rootPhase': root_doc.get('phase'), 'volume': volume_id, 'segments': segments,
            'sdkFinalized': sdk_doc.get('finalizeAcknowledged'), 'sdkPools': sdk_pools,
            'journalsPresent': {'root': bool(root_doc), 'sdk': bool(sdk_doc), 'directory': bool(directory)},
            'directory': {key: directory[key] for key in ('closed', 'released', 'faulted') if key in directory},
            'objects': results, 'liveRefs': inspect_processes(matches), 'mounts': mounts[:24], 'obmmQuery': obmm}


def assets(host, template):
    home = WORK / 'src/AgentENV/target/release'
    files = [home / 'server', home / 'uvm-ublk-daemon', Path('/opt/aenv/bin/agentenv-ub-provider-5ecfe105'),
             Path('/opt/aenv/libaenv-ub.so'), WORK / 'artifacts/deps/firecracker/firecracker',
             WORK / 'artifacts/deps/vmlinux-6.1.175-aarch64', Path('/etc/overlaybd/overlaybd.json')]
    repo = (OWNER_STORE if host == 'agent1' else OLD_STORE) / 'repository'
    record_path = repo / 'catalog/records' / (template + '.json')
    record = document(record_path)
    entry = record.get('committed') or {}
    lowers = len(entry.get('rootfs_layers', []))
    memory = []
    for layer in entry.get('memory_layers', []):
        if not re.fullmatch('sha256:[0-9a-f]{64}', layer['digest']):
            raise ValueError('Unexpected memory digest')
        stored = repo / 'managed-layers' / (layer['digest'].replace(':', '_') + '.overlaybd.commit')
        memory.append(file_fact(stored))
    snapshot = repo / 'snapshots' / template
    result = {'files': [file_fact(x, digest=True) for x in files], 'catalog': str(record_path),
              'catalogMatchesTemplate': record.get('id') == template, 'rootfsLayerCount': lowers,
              'memory': memory, 'markers': [file_fact(snapshot / name)
                                           for name in ('commit', 'vm_state.bin', 'firecracker-manifest.json')]}
    if host == 'agent1':
        result['sourceImage'] = file_fact(OWNER_IMAGE)
        result['sourceManifest'] = file_fact(OWNER_IMAGE.with_name('manifest.json'), digest=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old-run', required=True)
    parser.add_argument('--template', required=True)
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    if not (os.geteuid() == 0 and host in ('agent1', 'agent2') and
            re.fullmatch('[0-9a-f]{32}', args.old_run) and str(uuid.UUID(args.template)) == args.template):
        raise ValueError('Unexpected M/N identities')
    services = {}
    for unit in ('ubse.service', 'ubsmd.service', 'aenv-mn-titanic.service'):
        code, text = command('/usr/bin/systemctl', 'show', '-p', 'ActiveState', '-p', 'MainPID', unit)
        services[unit] = {'exitCode': code, **dict(line.split('=', 1) for line in text.splitlines() if '=' in line)}
    topo_code, topo = command('/usr/bin/ubsectl', 'display', 'topo', '-t', 'cpu')
    available = re.search(r'(?i)available links\s*:\s*(\d+)', topo)
    result = {'status': 'MN_TITANIC_REBOOT_PREFLIGHT', 'node': host, 'kernel': os.uname().release,
              'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'services': services, 'topology': {'exitCode': topo_code,
                  'namesFound': [node for node in ('agent1', 'agent2') if node in topo],
                  'availableLinks': int(available[1]) if available else None},
              'moduleAndDevices': modules(), 'previous': old_generation(args.old_run),
              'assets': assets(host, args.template)}
    print(json.dumps(result, separators=(',', ':'), sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
