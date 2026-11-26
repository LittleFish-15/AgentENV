"""Stage and start a fresh checked Titanic Provider generation after reboot."""

import argparse
import errno
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import struct
import stat
import subprocess
import time
import traceback
import uuid
from pathlib import Path


PROVIDER = Path('/opt/aenv/bin/agentenv-ub-provider-5ecfe105')
PROVIDER_SHA = '5ecfe105521b583e3e419bdf6da09258144a5a4e63834de6612b4bcf880647d8'
ROOT = Path('/etc/aenv/ub')
SDK = Path('/var/lib/aenv-ub-sdk')
HOST_WORK = Path('/home/jwk/agent/sp3-mn')
APP = HOST_WORK / 'aenv-tit-d03'
OWNER_SNAPSHOT_STORE = HOST_WORK / 'mn-tcap-004/h/snapshot-store'
IMPORTER_SNAPSHOT_STORE = HOST_WORK / 'aenv-tit-d01/h/snapshot-store'
OWNER_IMAGE = Path('/root/aenv-pmem/mn-titanic-share-001-fprbb53_/lowers.ext4')
BOOT_PATH = Path('/proc/sys/kernel/random/boot_id')
SRCVERSION = '29F10664C1EE59D7127F8C7'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C', 'LC_ALL': 'C'}
ROLE_ENV = {key: ENV[key] for key in ('PATH', 'LANG', 'LC_ALL')}
UID, GID = 1204, 1205
ROOTS = (Path('/root/aenv-pmem'), ROOT, SDK)
PROVIDER_PROG = 'agentenv-ub-provider'
OBMM_DEVICE = Path('/dev/obmm_pmem')
PATCH_SRCVERSION = SRCVERSION
VOLUME_LAYOUT = struct.Struct('<II16sIIII7Q')
SLOT_LAYOUT = struct.Struct('<II16sQII32s')


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def file_sha(path):
    state = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            state.update(block)
    return state.hexdigest()


def record_json(path, maximum=2 * 1024 * 1024):
    need(path.resolve(strict=True) == path and path.is_file() and path.stat().st_size <= maximum,
         'Unexpected staged JSON input: ' + str(path))
    return json.loads(path.read_bytes())


def direct_dir(path, allowed_owners):
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode) and
         info.st_uid in allowed_owners and not info.st_mode & 0o022, 'Unexpected directory: ' + str(path))


def newdir(path, uid, gid, mode):
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    path.chmod(mode)


def save(path, data, uid, gid, mode):
    with path.open('xb') as stream:
        os.fchown(stream.fileno(), uid, gid)
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def as_jwk(action):
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([])
            os.setgid(GID)
            os.setuid(UID)
            action()
        except BaseException:
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    need(status == 0, 'Private staging as jwk failed')


def create_app():
    APP.mkdir(mode=0o700)
    (APP / 'h').mkdir(mode=0o700)
    (APP / 'r').mkdir(mode=0o700)


def declared_lowers(record, template):
    need(record['id'] == template and record['alias'] == 'mn-titanic-verify-001', 'Snapshot identity differs')
    committed = record['committed']
    layers = [layer['Managed'] for layer in committed['rootfs_layers']]
    memory = committed['memory_layers']
    need(len(layers) == 10 and len(memory) == 1 and not committed['attached_drives']
         and sum(row['size'] for row in layers) == 1831881728, 'Expected original committed template layers')
    need(all(re.fullmatch(r'sha256:[a-f0-9]{64}', row['digest']) and row['size'] > 0 for row in layers + memory),
         'Invalid committed layer descriptor')
    lowers = [{'name': row['digest'].replace(':', '_') + '.overlaybd.commit',
               'digest': row['digest'], 'bytes': row['size']} for row in layers]
    return lowers, memory[0]


def json_file(path):
    need(path.resolve(strict=True) == path and path.is_file() and path.stat().st_size <= 2 * 1024 * 1024,
         'Unexpected configuration or journal file: ' + str(path))
    return json.loads(path.read_bytes())


def start(label, argv, home, logs):
    output = logs / (label + '.log')
    with output.open('xb') as stream:
        child = subprocess.Popen(argv, env={**ROLE_ENV, 'HOME': home}, cwd='/', stdin=subprocess.DEVNULL,
                                 stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
                                 close_fds=True)
    print(json.dumps({'event': 'role_dispatched', 'role': label, 'launcherPid': child.pid,
                      'log': str(output)}), flush=True)
    return child


def print_tail(label, path):
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - 4096))
        raw = stream.read(4096).decode('utf-8', 'replace')
    lines = [line for line in raw.splitlines()
             if not re.search(r'(?i)password|authorization|private.key|token', line)]
    print(json.dumps({'event': 'current_role_log', 'role': label, 'tail': lines[-20:]}), flush=True)


def start_provider(args, host):
    run = args.run
    root_dir = Path('/etc/aenv/ub') / ('relay-' + run)
    sdk_dir = Path('/var/lib/aenv-ub-sdk') / ('relay-' + run)
    root_cfg, sdk_cfg = root_dir / 'device-root.json', sdk_dir / 'device-sdk.json'
    root, sdk = json_file(root_cfg), json_file(sdk_cfg)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    for cfg in (root, sdk):
        need(cfg['run'] == run and cfg['node'] == host and cfg['manifestSha256'] == args.manifest_sha
             and cfg['device']['bootId'] == boot and cfg['device']['kernelRelease'] == os.uname().release,
             'Staged generation differs from the running node')
    need(root['device'] == sdk['device'] and root['rootSocket'] == sdk['rootSocket']
         and root['sdkSocket'] == sdk['sdkSocket'] and root['sdk'] == sdk['sdk'],
         'Provider roles have conflicting staged configuration')
    need(root['rootSocket'] == str(root_dir / 'rootctl/root.sock') and
         root['sdkSocket'] == str(sdk_dir / 'sdk.sock') and
         root['device']['brokerSocket'] == str(root_dir / 'broker/broker.sock') and
         root['device']['index'] == str(root_dir / 'index/stable-index.json') and
         root['device']['stateDir'] == str(root_dir / 'device-state') and
         root['sdk']['stateDir'] == str(sdk_dir / 'state'), 'Unexpected generation paths')
    fresh_paths = (root['rootSocket'], root['sdkSocket'], root['device']['brokerSocket'],
                   root['device']['index'], root_dir / 'device-state/root.json', sdk_dir / 'state')
    need(not any(os.path.lexists(path) for path in fresh_paths), 'Prior generation activity requires reconciliation')
    need(PROVIDER.resolve(strict=True) == PROVIDER and PROVIDER.is_file()
         and hashlib.sha256(PROVIDER.read_bytes()).hexdigest() == PROVIDER_SHA,
         'Provider build differs')
    for process in Path('/proc').iterdir():
        if process.name.isdecimal():
            try:
                executable = Path(os.readlink(process / 'exe')).name
            except OSError:
                continue
            need(not executable.startswith('agentenv-ub-provider'), 'A Provider process is already active')

    logs = root_dir / 'launch-evidence'
    logs.mkdir(mode=0o700)
    sdk_role = start('sdk', ['/usr/sbin/runuser', '-u', 'jwk', '--', str(PROVIDER),
                             'sdk', str(sdk_cfg)], '/home/jwk', logs)
    root_role = None
    try:
        socket_deadline = time.monotonic() + 15
        while time.monotonic() < socket_deadline:
            need(sdk_role.poll() is None, 'SDK exited before its socket appeared')
            try:
                if stat.S_ISSOCK((sdk_dir / 'sdk.sock').lstat().st_mode):
                    break
            except FileNotFoundError:
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError('SDK socket did not appear')
        root_role = start('root', [str(PROVIDER), 'root', str(root_cfg)], '/root', logs)
        deadline = time.monotonic() + 155
        while time.monotonic() < deadline:
            need(sdk_role.poll() is None and root_role.poll() is None, 'A Provider role exited during startup')
            index_path = root_dir / 'index/stable-index.json'
            if index_path.is_file():
                index = json_file(index_path)
                journal = json_file(root_dir / 'device-state/root.json')
                if journal.get('phase') == 'serving':
                    expected_lowers = [(row['digest'], row['bytes']) for row in root['device']['lowers']]
                    replicas = index['replicas']
                    actual_lowers = [(row['layerDigest'], row['fileBytes']) for row in replicas]
                    need(index['version'] == 3 and index['mode'] == 'host-dax-stable-demand'
                         and index['state'] == 'metadata_ready' and journal['run'] == run
                         and len(expected_lowers) == 10 and len(set(expected_lowers)) == 10
                         and actual_lowers == expected_lowers
                         and all(row['generation'] == run
                                 and row['manifestSha256'] == 'sha256:' + args.manifest_sha
                                 and row['brokerSocket'] == root['device']['brokerSocket']
                                 and row['stablePmem']['imageBytes'] == 2 ** 31
                                 and row['stablePmem']['loadBytes'] == 262144 for row in replicas),
                         'Published index differs from the committed Titanic lower identities')
                    print(json.dumps({'status': 'MN_PROVIDER_SERVING', 'node': host, 'run': run,
                                      'sdkLauncherPid': sdk_role.pid, 'rootPid': root_role.pid,
                                      'index': str(index_path), 'phase': journal['phase'],
                                      'replicas': len(replicas),
                                      'lowerBytes': sum(size for _, size in actual_lowers),
                                      'initialLocalBindings': len(journal['bindings'])}), flush=True)
                    return
            time.sleep(0.5)
        raise RuntimeError('Provider ready index did not appear before the observation deadline')
    except (OSError, RuntimeError, ValueError):
        print_tail('sdk', logs / 'sdk.log')
        if root_role is not None:
            print_tail('root', logs / 'root.log')
        raise


def engine():
    for unit in ('ubse.service', 'ubsmd.service'):
        result = subprocess.run(['/usr/bin/systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'MainPID'],
                                capture_output=True, text=True, env=ENV, check=True, timeout=10)
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        need(values['ActiveState'] == 'active' and int(values['MainPID']) > 0, unit + ' is not active')
        if unit == 'ubse.service':
            pid = int(values['MainPID'])
    return pid


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
            if name.startswith((PROVIDER_PROG, 'uvm-ublk-daemon', 'firecracker')) or name in ('server', 'aenv'):
                row = {'pid': int(process.name), 'exe': exe, 'uid': process.stat().st_uid}
                if name.startswith(PROVIDER_PROG):
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


def tls_material(files, role):
    paths = {kind: Path(files[kind]) for kind in ('ca', 'cert', 'key')}
    root_pki = ROOTS[1] / 'pki'
    if not all((path.is_relative_to(root_pki) or path.is_relative_to(ROOTS[2])) and path.resolve(strict=True) == path for path in paths.values()):
        raise ValueError('Unexpected TLS material path')
    facts = {}
    for kind, path in paths.items():
        info = path.lstat()
        facts[kind] = {'path': str(path), 'uid': info.st_uid, 'gid': info.st_gid,
                       'mode': oct(stat.S_IMODE(info.st_mode)), 'regular': stat.S_ISREG(info.st_mode)}
    private_rc, private_pub = command('/usr/bin/openssl', 'pkey', '-in', str(paths['key']),
                                       '-passin', 'pass:', '-pubout')
    public_rc, cert_pub = command('/usr/bin/openssl', 'x509', '-in', str(paths['cert']), '-pubkey', '-noout')
    verify_rc, _ = command('/usr/bin/openssl', 'verify', '-CAfile', str(paths['ca']),
                           '-purpose', 'ssl' + role, str(paths['cert']))
    cert = subprocess.run(['/usr/bin/openssl', 'x509', '-in', str(paths['cert']), '-outform', 'DER'],
                          env=ENV, capture_output=True, check=True, timeout=12)
    return {'files': facts, 'keyMatchesCert': private_rc == public_rc == 0 and bool(private_pub)
            and private_pub.strip() == cert_pub.strip(), 'certificateVerified': verify_rc == 0,
            'leafSha256': hashlib.sha256(cert.stdout).hexdigest()}


def retire_roles(configs):
    expected = {b'root': configs[0], b'sdk': configs[1]}
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        handle = None
        try:
            args = (path / 'cmdline').read_bytes().split(b'\x00')
            if len(args) < 3 or args[1] not in expected or args[2] != os.fsencode(expected[args[1]]):
                continue
            handle = os.pidfd_open(int(path.name))
            need((path / 'exe').resolve(strict=True) == PROVIDER and
                 (path / 'cmdline').read_bytes().split(b'\x00')[:3] == args[:3], 'Fixture PID changed')
            signal.pidfd_send_signal(handle, signal.SIGTERM)
            waiter = select.poll()
            waiter.register(handle, select.POLLIN)
            need(waiter.poll(15000), 'Fixture role did not exit: ' + path.name)
        except (FileNotFoundError, ProcessLookupError):
            continue
        finally:
            if handle is not None:
                os.close(handle)


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


def retire_incomplete(args, host):
    failed_root = ROOT / ('relay-' + args.failed_run)
    failed_sdk = SDK / ('relay-' + args.failed_run)
    root_cfg = failed_root / 'device-root.json'
    sdk_cfg = failed_sdk / 'device-sdk.json'
    root_state = record_json(failed_root / 'device-state/root.json')
    sdk_state = record_json(failed_sdk / 'state/sdk.json')
    wanted_phase = 'uncertain' if host == 'agent1' else 'preparing'
    need(root_state['run'] == args.failed_run and root_state['node'] == host
         and root_state['phase'] == wanted_phase and root_state['volume'] == args.failed_volume
         and not root_state['pools'] and not root_state['pool_segments'] and not root_state['bindings']
         and sdk_state['run'] == args.failed_run and not sdk_state['pools']
         and not (failed_root / 'index/stable-index.json').exists(), 'Failed generation has unconfirmed allocations')
    if host == 'agent1':
        directory = record_json(failed_sdk / ('directory-' + args.failed_run + '.json'))
        need(directory['run'] == args.failed_run and not directory['pools'] and not directory['units'],
             'Failed owner directory has an allocation')
    volume = uuid.UUID(args.failed_volume)
    state = query_obmm(volume, None)
    observed = state.get('volume', {})
    need(state.get('srcversion') == SRCVERSION, 'OBMM volume query unavailable')
    if host == 'agent1':
        need(observed.get('status') == 'present' and observed['state'] == 2
             and (observed['id'], observed['major'], observed['minor'], observed['bytes']) == (0, 259, 8, 2**32)
             and observed['openers'] == observed['activeIo'] == 0,
             'Failed owner volume differs from the read-only result')
    else:
        need(observed.get('status') == 'absent', 'Failed importer has a volume')
    before = inspect_processes([])['roles']
    expected_pid = 24341 if host == 'agent1' else 24330
    need(len(before) == 1 and before[0].get('pid') == expected_pid
         and before[0].get('role') == 'sdk' and before[0].get('run') == args.failed_run
         and before[0]['exe'] == str(PROVIDER), 'Failed generation SDK PID differs or an unrelated runtime is active')
    retire_roles((root_cfg, sdk_cfg))
    need(not inspect_processes([])['roles'], 'Failed SDK or another runtime is still active')
    need(query_obmm(volume, None).get('volume') == observed, 'Failed volume identity changed before retirement')
    if host == 'agent1':
        journal = bytearray(VOLUME_LAYOUT.size)
        struct.pack_into('<II16sI', journal, 0, 1, 0, volume.bytes, observed['id'])
        fd = os.open(OBMM_DEVICE, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            need(stat.S_ISCHR(os.fstat(fd).st_mode), 'Pinned OBMM device is invalid')
            fcntl.ioctl(fd, 0x4060b802, journal, True)
        finally:
            os.close(fd)
    need(query_obmm(volume, None).get('volume', {}).get('status') == 'absent',
         'Failed OBMM volume was not retired')
    for path in (failed_root / 'rootctl/root.sock', failed_root / 'broker/broker.sock', failed_sdk / 'sdk.sock'):
        clean_placeholder(path, socket=True)
    print(json.dumps({'status': 'MN_FAILED_TLS_RUN_RETIRED', 'node': host, 'run': args.failed_run,
                      'volumeAbsent': True, 'pools': 0, 'sdkPidStopped': expected_pid}), flush=True)


def install_private_client(seeds, new_root, host):
    root_tls = seeds[0]['tlsClient']['files']
    sdk_tls = seeds[1]['tlsClient']['files']
    client = tls_material(root_tls, 'client')
    peer = tls_material(sdk_tls, 'client')
    expected = {'agent1': '10c55e71d349a1d61d5178153a96931feb5846fdf36b0d8fe5ba56849772fd70',
                'agent2': '7cde769a9c75e6e59c2363eff6d47edac85053010184cce3a393d55bca5a548c'}
    need(all(row['keyMatchesCert'] and row['certificateVerified'] and row['leafSha256'] == expected[host]
             for row in (client, peer)), 'Client certificate or private key differs')
    if host == 'agent1':
        server = seeds[1]['tlsServer']
        proof = tls_material(server['files'], 'server')
        meta = proof['files']['key']
        need(proof['certificateVerified'] and proof['keyMatchesCert'] and meta['uid'] == UID
             and meta['mode'] == '0o600' and server['peerCertSha256'] == expected,
             'Owner SDK listener private key or certificate pins differ')
    original = Path(root_tls['key'])
    meta = client['files']['key']
    need(original == ROOT / 'pki' / (host + '.key') and meta['uid'] == 0 and meta['regular']
         and meta['mode'] in ('0o600', '0o640'), 'Root TLS key identity or permissions differ')
    protected = new_root / 'device-state/client.key'
    save(protected, read_bytes(original, 128 * 1024), 0, 0, 0o600)
    # The SDK retains its original client key path. Only the root role reads this copy.
    root_tls['key'] = str(protected)


def stage(args, host):
    owner = host == 'agent1'
    boot = BOOT_PATH.read_text().strip()
    need(boot == args.boot_id and os.uname().release == '6.6.0-145.3.34.165.oe2403sp3.aarch64',
         'Boot or kernel changed after the recovery receipt')
    need(Path('/sys/module/obmm/srcversion').read_text().strip() == SRCVERSION
         and Path('/dev/obmm_pmem').is_char_device(), 'Pinned OBMM is not available')
    params = Path('/sys/module/obmm/parameters')
    need(all((params / name).read_text().strip() in ('1', 'Y')
             for name in ('pmem_ro_enable', 'pmem_demand_write_enable')), 'OBMM mode differs')
    engine_pid = engine()
    old_root, old_sdk = ROOT / ('relay-' + args.old_run), SDK / ('relay-' + args.old_run)
    old_configs = (old_root / 'device-root.json', old_sdk / 'device-sdk.json')
    seeds = [record_json(path) for path in old_configs]
    for cfg in seeds:
        need(cfg['run'] == args.old_run and cfg['node'] == host and cfg['ownerNode'] == 'agent1'
             and cfg['manifestSha256'] == args.manifest_sha
             and (cfg['sdk']['uid'], cfg['sdk']['gid']) == (UID, GID) and cfg['device']['bootId'] != boot,
             'Archived seed configuration differs')
    raw = (OWNER_IMAGE.with_name('manifest.json') if owner else old_root / 'manifest.json').read_bytes()
    native = json.loads(raw)
    need(hashlib.sha256(raw).hexdigest() == args.manifest_file_sha and native['sha256'] == args.manifest_sha
         and native['document']['fileBytes'] == 2**31, 'Expected native manifest bytes differ')
    if owner:
        direct_dir(OWNER_IMAGE.parent, (0,))
        image = OWNER_IMAGE.stat()
        mtime_sec, mtime_ns = divmod(image.st_mtime_ns, 10**9)
        ctime_sec, ctime_ns = divmod(image.st_ctime_ns, 10**9)
        need(OWNER_IMAGE.resolve(strict=True) == OWNER_IMAGE and stat.S_ISREG(image.st_mode)
             and native['sourceIdentity'] == {'device': image.st_dev, 'inode': image.st_ino, 'bytes': image.st_size,
                 'mtimeSeconds': mtime_sec, 'mtimeNanos': mtime_ns,
                 'ctimeSeconds': ctime_sec, 'ctimeNanos': ctime_ns}, 'Owner image identity differs')

    store = OWNER_SNAPSHOT_STORE if owner else IMPORTER_SNAPSHOT_STORE
    repo = store / 'repository'
    lower, memory = declared_lowers(record_json(repo / 'catalog/records' / (args.template + '.json')), args.template)
    blob = repo / 'managed-layers' / (memory['digest'].replace(':', '_') + '.overlaybd.commit')
    snapshot = repo / 'snapshots' / args.template
    need(blob.resolve(strict=True) == blob and blob.stat().st_size == memory['size']
         and 'sha256:' + file_sha(blob) == memory['digest']
         and (snapshot / 'commit').read_bytes() == b'committed'
         and all((snapshot / name).is_file() for name in ('vm_state.bin', 'firecracker-manifest.json')),
         'Retained template or ordinary memory layer differs')
    new_root, new_sdk = ROOT / ('relay-' + args.run), SDK / ('relay-' + args.run)
    direct_dir(ROOT, (0,))
    direct_dir(SDK, (0, UID))
    direct_dir(HOST_WORK, (0, UID))
    need(not any(os.path.lexists(path) for path in (APP, new_root, new_sdk)), 'Fresh run paths already exist')
    as_jwk(create_app)
    home, runtime = APP / 'h', APP / 'r'
    newdir(new_root, 0, 0, 0o755)
    newdir(new_sdk, UID, GID, 0o700)
    reader_gid = seeds[0]['device']['readerGid']
    need(seeds[1]['device']['readerGid'] == reader_gid, 'Reader group differs')
    for leaf, group, mode in (('rootctl', GID, 0o750), ('broker', reader_gid, 0o750),
                              ('index', reader_gid, 0o750), ('device-state', 0, 0o700), ('mount', 0, 0o700)):
        newdir(new_root / leaf, 0, group, mode)
    install_private_client(seeds, new_root, host)
    local_manifest = new_root / 'manifest.json'
    save(local_manifest, raw, 0, 0, 0o644)
    root_cfg, sdk_cfg = new_root / 'device-root.json', new_sdk / 'device-sdk.json'
    for data, out, uid, gid in ((seeds[0], root_cfg, 0, 0), (seeds[1], sdk_cfg, UID, GID)):
        data.update(run=args.run, manifest=str(local_manifest), manifestSha256=args.manifest_sha,
                    rootSocket=str(new_root / 'rootctl/root.sock'), sdkSocket=str(new_sdk / 'sdk.sock'))
        data['sdk']['stateDir'] = str(new_sdk / 'state')
        data['device'].update(bootId=boot, enginePid=engine_pid, kernelRelease=os.uname().release,
                              moduleSrcversion=SRCVERSION, stateDir=str(new_root / 'device-state'),
                              mountDir=str(new_root / 'mount'), brokerSocket=str(new_root / 'broker/broker.sock'),
                              index=str(new_root / 'index/stable-index.json'),
                              sourceImage=str(OWNER_IMAGE) if owner else None, lowers=lower)
        save(out, (json.dumps(data, indent=2) + '\n').encode(), uid, gid, 0o600)
    subprocess.run([str(PROVIDER), 'validate', str(root_cfg)], env=ENV, check=True, timeout=16)
    subprocess.run(['/usr/sbin/runuser', '-u', 'jwk', '--', str(PROVIDER), 'validate', str(sdk_cfg)],
                   env=ENV, check=True, timeout=16)

    assets = HOST_WORK / 'relay-guest-assets-001/deps'
    inputs = HOST_WORK / 'artifacts/deps'
    cfg = (f'home_path = "{home}"\nruntime_path = "{runtime}"\ndeps_path = "{assets}"\n'
           'virtualization_mode = "kvm"\n[firecracker]\n'
           f'binary_path = "{inputs}/firecracker/firecracker"\ncgroup_pool_size = 1\n'
           f'[kernel]\nimage_path = "{inputs}/vmlinux-6.1.175-aarch64"\n'
           '[snapshot]\nrepository_backend = "posix_fs"\np2p_enabled = false\nrootfs_backing_mode = "ub_demand"\n'
           f'rootfs_demand_index = "{new_root}/index/stable-index.json"\n'
           f'[backend.posix_fs]\nsnapshot_store = "{store}"\n'
           '[pool.block]\nenabled = false\n[pool.network]\nmaintenance_enabled = false\n'
           '[pool.firecracker]\nenabled = false\n')
    as_jwk(lambda: save(APP / 'config.toml', cfg.encode(), UID, GID, 0o600))
    print(json.dumps({'status': 'MN_REBOOT_TITANIC_CONFIG_STAGED', 'node': host, 'run': args.run,
                      'enginePid': engine_pid, 'templateId': args.template, 'config': str(APP / 'config.toml')}),
          flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('old-run', 'run', 'boot-id', 'template', 'manifest-sha', 'manifest-file-sha', 'failed-run', 'failed-volume'):
        parser.add_argument('--' + option, required=True)
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    need(os.geteuid() == 0 and host in ('agent1', 'agent2')
         and re.fullmatch('[0-9a-f]{32}', args.run) and re.fullmatch('[0-9a-f]{32}', args.old_run)
         and args.run != args.old_run and str(uuid.UUID(args.template)) == args.template, 'Invalid M/N identity')
    need(PROVIDER.resolve(strict=True) == PROVIDER and file_sha(PROVIDER) == PROVIDER_SHA,
         'Retained Provider differs')
    os.umask(0o077)
    need(BOOT_PATH.read_text().strip() == args.boot_id and args.failed_run == 'b4c86da90e1a4b64bbce74b11612c163',
         'The failed rehearsal run or boot differs')
    retire_incomplete(args, host)
    stage(args, host)
    start_provider(args, host)
