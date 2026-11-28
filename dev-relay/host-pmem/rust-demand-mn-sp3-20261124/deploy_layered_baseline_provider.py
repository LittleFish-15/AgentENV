"""Install the pinned build-006 and start a fresh Titanic Provider generation."""

import argparse
import errno
import fcntl
import hashlib
import json
import os
import re
import shutil
import struct
import stat
import subprocess
import time
import traceback
import uuid
from pathlib import Path


INSTALL = Path('/opt/aenv-layered-006-012107ba')
PROVIDER = INSTALL / 'agentenv-ub-provider'
ROOT = Path('/etc/aenv/ub')
SDK = Path('/var/lib/aenv-ub-sdk')
HOST_WORK = Path('/home/jwk/agent/sp3-mn')
APP = HOST_WORK / 'aenv-layered-006-012107ba'
OWNER_SNAPSHOT_STORE = HOST_WORK / 'mn-tcap-004/h/snapshot-store'
IMPORTER_SNAPSHOT_STORE = HOST_WORK / 'aenv-tit-d01/h/snapshot-store'
OWNER_IMAGE = Path('/root/aenv-pmem/mn-titanic-share-001-fprbb53_/lowers.ext4')
BOOT_PATH = Path('/proc/sys/kernel/random/boot_id')
SRCVERSION = '29F10664C1EE59D7127F8C7'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C', 'LC_ALL': 'C'}
ROLE_ENV = {key: ENV[key] for key in ('PATH', 'LANG', 'LC_ALL')}
UID, GID = 1204, 1205
ROOTS = (Path('/root/aenv-pmem'), ROOT, SDK)
VOLUME_LAYOUT = struct.Struct('<II16sIIII7Q')


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
         and file_sha(PROVIDER) == EXPECTED[host]['artifacts'][PROVIDER.name][1],
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
POOL_OBJECT = 'aenv_01a21fe47e167442b4e7592d12958c40'
VOLUMES = {'agent1': '01a21fe3-9305-7e31-ac60-cb28b9532df5',
           'agent2': '01a21fe1-048a-7740-94a6-62f9e6927ecd'}
BOOTS = {'agent1': 'adca3a33-8bfd-4e89-b448-4f93385c68de',
         'agent2': '8b37b961-2b42-4c52-8aa7-8335cc52f52d'}
MACHINE_IDS = {'agent1': '498c7bb42c72427a8ce412b91776bc63',
               'agent2': '7579df430de64560b8d09b83baf1e2b0'}


def volume_query(volume):
    need(Path('/sys/module/obmm/srcversion').read_text().strip() == SRCVERSION,
         'loaded OBMM source version differs')
    ident = uuid.UUID(volume)
    wire = bytearray(VOLUME_LAYOUT.size)
    struct.pack_into('<II16s', wire, 0, 1, 0, ident.bytes)
    try:
        fd = os.open('/dev/obmm_pmem', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise RuntimeError('OBMM query device unavailable: ' + str(error.errno))
    try:
        try:
            fcntl.ioctl(fd, 0xc060b801, wire, True)
        except OSError as error:
            if error.errno == errno.ENOENT:
                return {'status': 'absent'}
            raise
    finally:
        os.close(fd)
    names = ('version', 'reserved', 'uuid', 'id', 'state', 'major', 'minor', 'bytes',
             'openers', 'activeIo', 'blockReads', 'blockBytes', 'daxAccesses', 'daxSpanBytes')
    row = dict(zip(names, VOLUME_LAYOUT.unpack(wire)))
    need(row['version'] == 1 and row['reserved'] == 0 and row['uuid'] == ident.bytes,
         'OBMM exact-volume reply differs')
    row['uuid'] = volume
    row['status'] = 'present'
    return row


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
        sdk_settings = data['sdk']
        adapter_fields = [key for key, value in sdk_settings.items()
                          if value == '/opt/aenv/libaenv-ub.so']
        need(len(adapter_fields) == 1, 'Archived SDK adapter setting differs')
        sdk_settings[adapter_fields[0]] = str(INSTALL / 'libaenv-ub.so')
        sdk_settings['stateDir'] = str(new_sdk / 'state')
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



def install_build(host):
    direct_dir(INSTALL.parent, (0,))
    expected = EXPECTED[host]
    attempt = Path(expected['attempt'])
    artifacts = expected['artifacts']
    for relative, digest in artifacts.values():
        path = attempt / relative
        info = path.lstat()
        need(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
             and info.st_uid == 0 and file_sha(path) == digest,
             'Build-006 artifact differs: ' + relative)
    newdir(INSTALL, 0, 0, 0o755)
    for name, (relative, digest) in artifacts.items():
        target = INSTALL / name
        with (attempt / relative).open('rb') as source, target.open('xb') as stream:
            shutil.copyfileobj(source, stream, 1024 * 1024)
            os.fchmod(stream.fileno(), 0o644 if name.endswith('.so') else 0o755)
            stream.flush()
            os.fsync(stream.fileno())
        need(file_sha(target) == digest, 'Installed artifact digest differs: ' + name)
    print(json.dumps({'event': 'MN_BUILD_006_INSTALLED', 'node': host,
                      'directory': str(INSTALL)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('node', 'machine-id', 'boot-id', 'old-run', 'run', 'template',
                   'manifest-sha', 'manifest-file-sha'):
        parser.add_argument('--' + option, required=True)
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    need(os.geteuid() == 0 and host == args.node and host in EXPECTED
         and args.machine_id == MACHINE_IDS[host] == Path('/etc/machine-id').read_text().strip()
         and args.boot_id == BOOTS[host] == BOOT_PATH.read_text().strip(),
         'Node, machine or boot identity differs')
    need(args.run == '012107bad2d64b4b8d7cfabaf56f4fe1' and args.old_run == '6e3aa70745e948ba9af896dca2271151'
         and str(uuid.UUID(args.template)) == args.template, 'Unexpected generation or template')
    for process in Path('/proc').iterdir():
        if process.name.isdecimal():
            try:
                name = Path(os.readlink(process / 'exe')).name.removesuffix(' (deleted)')
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            need(name != 'server' and not name.startswith(('agentenv-ub-provider',
                 'uvm-ublk-daemon', 'firecracker')), 'AENV runtime process already exists')
    unit = subprocess.run(['/usr/bin/systemctl', 'show', 'aenv-mn-titanic.service',
                           '-p', 'ActiveState', '-p', 'MainPID'], env=ENV, check=True,
                          capture_output=True, text=True, timeout=10)
    fields = dict(line.split('=', 1) for line in unit.stdout.splitlines() if '=' in line)
    need(fields.get('ActiveState') == 'inactive' and fields.get('MainPID') == '0',
         'AENV unit already exists in an active or pending state')
    need(volume_query(VOLUMES[host])['status'] == 'absent'
         and named_shmdevs(POOL_OBJECT) == {'matches': [], 'unreadable': 0, 'truncated': False},
         'Old dabd generation still has a volume or UB mapping')
    os.umask(0o077)
    install_build(host)
    stage(args, host)
    start_provider(args, host)


if __name__ == '__main__':
    main()
