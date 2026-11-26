"""Reconcile the one old Titanic SDK object and scoped reboot residue."""

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import traceback
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


POOL = '01a212b6-63a4-7b41-a7ff-b62c7ca77d58'
OBJECT = 'aenv_01a212b663a47b41a7ffb62c7ca77d58'
OLD_RUN = '6e3aa70745e948ba9af896dca2271151'
ADAPTER = Path('/opt/aenv/libaenv-ub.so')
ADAPTER_SHA = 'a5379bbd70fbd244de07c312076a9ece23ce38452682dfed31b60f6fe3912dbc'
NAMESPACE_FILES = (
    'agentenv-ns-01a2129a-ddf1-72b2-8714-856019513eda',
    'agentenv-ns-01a2129a-ddf2-74b1-b088-d8622c727e5a',
    'agentenv-ns-01a2129a-df11-75e1-afcc-41896e5072f3',
    'agentenv-ns-01a2129a-df72-7d80-8b2f-e56af84ce221',
    'agentenv-ns-01a2129a-dfd2-7bf3-b898-ec33f3059a2a',
)


def ensure_absent(state, host):
    info = state['obmmQuery']
    matches = state['objects'].get(OBJECT)
    if (not info or any(row.get('srcversion') != PATCH_SRCVERSION
                        or row.get('volume', {}).get('status') != 'absent'
                        or row.get('segment', {}).get('status') != 'absent' for row in info)
            or state['mounts'] or state['liveRefs']['roles']
            or not matches or matches['matches'] or matches['unreadable'] or matches['truncated']):
        raise ValueError('A live or unconfirmed reference to the old generation remains')
    if set(state['sdkPools']) != {POOL} or state['sdkPools'][POOL]['allocationOwner'] is not (host == 'agent1'):
        raise ValueError('SDK journal ownership differs from the pinned object')


def as_jwk(action):
    pid = os.fork()
    if pid == 0:
        try:
            os.initgroups('jwk', 1205)
            os.setgid(1205)
            os.setuid(1204)
            status = Path('/proc/self/status').read_text()
            if not all(re.search(r'^' + key + r':\s+0+$', status, re.M)
                       for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')):
                raise ValueError('SDK helper retained privileges')
            os.environ.clear()
            os.environ.update(ENV, HOME='/home/jwk', USER='jwk', LOGNAME='jwk')
            action()
        except Exception:
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if status:
        raise RuntimeError('Unprivileged recovery failed; preserve the original journals and receipt')


def deallocate():
    info = ADAPTER.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, 1204) or info.st_mode & 0o022
            or hashlib.sha256(read_bytes(ADAPTER, 512 * 1024)).hexdigest() != ADAPTER_SHA):
        raise ValueError('The adapter differs from the tested version')
    sdk_library = Path('/usr/lib64/libubsm_sdk.so')
    print(json.dumps({'event': 'SDK_ACCOUNT_PREFLIGHT', 'uid': os.getuid(),
                      'supplementaryGids': os.getgroups(), 'sdkReadable': os.access(sdk_library, os.R_OK)}),
          flush=True)
    if not os.access(sdk_library, os.R_OK):
        raise ValueError('Installed SDK is not readable with the tested jwk groups')
    record_path = WORK / ('sdk-retirement-' + OLD_RUN + '-002.jsonl')
    fd = os.open(record_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        def log(step, **values):
            row = {'event': step, 'run': OLD_RUN, 'object': OBJECT, **values}
            stream.write(json.dumps(row, sort_keys=True) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
            print(json.dumps(row, sort_keys=True), flush=True)

        adapter = ctypes.CDLL(str(ADAPTER), mode=os.RTLD_LOCAL | os.RTLD_NOW)
        for name in ('abi_version', 'configure_region', 'initialize', 'deallocate', 'finalize'):
            fn = getattr(adapter, 'aenv_ub_' + name)
            fn.argtypes = [ctypes.c_char_p] if name in ('configure_region', 'deallocate') else []
            fn.restype = ctypes.c_int
        if adapter.aenv_ub_abi_version() != 3 or adapter.aenv_ub_configure_region(b'default') != 0:
            raise ValueError('SDK adapter ABI or region differs')
        initialized = adapter.aenv_ub_initialize()
        if initialized != 0:
            log('SDK_INITIALIZE_FAILED', rc=initialized, finalizeRc=adapter.aenv_ub_finalize())
            raise RuntimeError('SDK initialization failed')
        deletion = None
        try:
            log('SDK_DEALLOCATE_INTENT')
            deletion = adapter.aenv_ub_deallocate(OBJECT.encode('ascii'))
            log('SDK_DEALLOCATE_RESULT', rc=deletion)
        finally:
            final = adapter.aenv_ub_finalize()
            log('SDK_FINALIZE_RESULT', rc=final)
        if deletion not in (0, 6020) or final != 0:
            raise RuntimeError('SDK deallocation or finalization requires reconciliation')


def clean_placeholder(path, socket):
    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return
    try:
        if Path(os.readlink('/proc/self/fd/' + str(directory))) != path.parent:
            raise ValueError('Stale directory has an unexpected link: ' + str(path.parent))
        try:
            info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        if socket:
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid not in (0, 1204):
                raise ValueError('Expected a known old socket: ' + str(path))
            table = Path('/proc/net/unix').read_text()
            if any(line.split()[-1:] == [str(path)] for line in table.splitlines()):
                raise ValueError('Socket is still open: ' + str(path))
        else:
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, 1204) or info.st_size != 0:
                raise ValueError('Expected an empty old namespace placeholder: ' + str(path))
            mounts = Path('/proc/self/mountinfo').read_text()
            if any(line.split()[4:5] == [str(path)] for line in mounts.splitlines()):
                raise ValueError('Namespace still has a mount: ' + str(path))
        os.unlink(path.name, dir_fd=directory)
    finally:
        os.close(directory)
    print(json.dumps({'event': 'EXACT_STALE_PATH_REMOVED', 'path': str(path)}), flush=True)


def retire_residue(host):
    if host == 'agent1':
        as_jwk(deallocate)
        ensure_absent(old_generation(OLD_RUN), host)
    state = ROOTS[1] / ('relay-' + OLD_RUN)
    sdk = ROOTS[2] / ('relay-' + OLD_RUN)
    for path in (state / 'rootctl/root.sock', state / 'broker/broker.sock', sdk / 'sdk.sock',
                 WORK / 'aenv-tit-d01/r/ublk-daemon.sock'):
        clean_placeholder(path, socket=True)
    if host == 'agent1':
        for name in NAMESPACE_FILES:
            clean_placeholder(WORK / 'mn-tcap-004/r/netns' / name, socket=False)
    print(json.dumps({'event': 'OLD_TITANIC_RESIDUE_RECONCILED', 'node': host, 'run': OLD_RUN}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--boot-id', required=True)
    parser.add_argument('--old-run', required=True)
    parser.add_argument('--template', required=True)
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    if not (os.geteuid() == 0 and host in ('agent1', 'agent2') and
            re.fullmatch('[0-9a-f]{32}', args.old_run) and str(uuid.UUID(args.template)) == args.template):
        raise ValueError('Unexpected M/N identities')
    if args.old_run != OLD_RUN or args.boot_id != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise ValueError('Old run or boot differs from the audited job')
    ensure_absent(old_generation(OLD_RUN), host)
    retire_residue(host)
    services = {}
    for unit in ('ubse.service', 'ubsmd.service', 'aenv-mn-titanic.service'):
        code, text = command('/usr/bin/systemctl', 'show', '-p', 'ActiveState', '-p', 'MainPID', unit)
        services[unit] = {'exitCode': code, **dict(line.split('=', 1) for line in text.splitlines() if '=' in line)}
    topo_code, topo = command('/usr/bin/ubsectl', 'display', 'topo', '-t', 'cpu')
    available = re.search(r'(?i)available links\s*:\s*(\d+)', topo)
    result = {'status': 'MN_TITANIC_OLD_RUN_CLEANUP', 'node': host, 'kernel': os.uname().release,
              'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'services': services, 'topology': {'exitCode': topo_code,
                  'namesFound': [node for node in ('agent1', 'agent2') if node in topo],
                  'availableLinks': int(available[1]) if available else None},
              'moduleAndDevices': modules(), 'previous': old_generation(args.old_run),
              'assets': assets(host, args.template)}
    print(json.dumps(result, separators=(',', ':'), sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
