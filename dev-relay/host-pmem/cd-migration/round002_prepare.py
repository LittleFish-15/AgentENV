"""Prepare selected immutable exports or a receiver; no network login, SDK, service or module changes."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import subprocess
import time
import tomllib
import types
import zlib

ROOT = Path('/home/jwk/agent')
HOME = Path('/home/jwk')
KERNEL_SOURCE_SHA = '4a8f65d3d9c62544019e0e19d15d8406d2bf9471515cd941292f3478269efdad'
KERNEL_SOURCE_Z64 = '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'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_id(value):
    need(isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', value), 'Invalid identifier')
    return value


def private_write(path, raw):
    need(not path.is_symlink(), 'Output redirected')
    if path.exists():
        need(path.is_file() and path.read_bytes() == raw, 'Existing output differs; preserved')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())


def private_dir(path, leaf=True):
    need(path.is_absolute() and path.is_relative_to(HOME) and path.resolve() == path, 'Private directory outside own home or redirected')
    path.mkdir(mode=0o700, exist_ok=True)
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 1204 and not stat.S_IMODE(s.st_mode) & (0o077 if leaf else 0o022),
         'Private directory owner/mode differs')
    return path


def source_path(value):
    p = Path(value)
    need(p.is_absolute() and '..' not in p.parts and p.is_relative_to(ROOT), 'Source path outside selected workspace')
    real = p.resolve(strict=True)
    need(real.is_relative_to(ROOT) and not any(x.lower() in ('.ssh', 'api-key', 'credentials', 'credentials.json') for x in real.parts),
         'Source resolves outside workspace or into credentials')
    return real


def file_facts(path, expected_bytes, expected_sha, hash_now=False):
    p = source_path(path)
    fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as f:
        a = os.fstat(f.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_uid in (0, 1204) and a.st_size == expected_bytes, 'Source type/owner/length differs')
        actual = None
        if hash_now:
            h = hashlib.sha256()
            for chunk in iter(lambda: f.read(1024**2), b''):
                h.update(chunk)
            actual = h.hexdigest()
        b = os.fstat(f.fileno())
    stable = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(stable(a) == stable(b) == stable(p.stat()), 'Source changed during preparation')
    if expected_sha is not None:
        need(re.fullmatch('[0-9a-f]{64}', expected_sha), 'Invalid expected content SHA')
        need(actual is None or actual == expected_sha, 'Source content differs from selected digest')
    need(actual is not None or expected_sha is not None, 'A content identity is required')
    return {'sourcePath': str(p), 'bytes': a.st_size, 'sha256': actual or expected_sha,
            'sourceIdentity': list(stable(a)),
            'hashEvidence': 'recomputed_now' if actual else 'expected_reference_not_recomputed_this_round'}


def relative_name(value):
    need(isinstance(value, str), 'Invalid receiver-relative name type')
    p = PurePosixPath(value)
    need('\\' not in value and ':' not in value and not p.is_absolute()
         and value and '..' not in p.parts and value == p.as_posix(), 'Invalid receiver-relative name')
    return value


def compile_export(spec, source_boot=None):
    need(isinstance(spec['files'], list) and 1 <= len(spec['files']) <= 128, 'Selected file count differs')
    need(type(spec['maxLogicalBytes']) is int and 0 < spec['maxLogicalBytes'] <= 8 * 1024**3, 'Export size bound differs')
    total = 0; rehashed = 0; placements = set(); objects = {}
    for selected in spec['files']:
        need(set(selected) == {'sourcePath', 'bytes', 'sha256', 'placements'}, 'Export selection fields differ')
        need(type(selected['bytes']) is int and selected['bytes'] > 0, 'Invalid selected file size')
        total += selected['bytes']; need(total <= spec['maxLogicalBytes'], 'Export logical bound exceeded')
        fresh = selected['sha256'] is None
        if fresh:
            need(selected['bytes'] <= 128 * 1024**2, 'Unknown large file needs a separately reviewed content identity')
            rehashed += selected['bytes']; need(rehashed <= 512 * 1024**2, 'Preparation read budget exceeded')
        fact = file_facts(selected['sourcePath'], selected['bytes'], selected['sha256'], fresh)
        key = fact['sha256']
        if key not in objects:
            objects[key] = dict(fact, placements=[])
        else:
            need(objects[key]['bytes'] == fact['bytes'], 'Conflicting content identity')
        for placement in selected['placements']:
            need(set(placement) == {'node', 'path', 'executable'} and placement['node'] in ('node-c', 'node-d')
                 and type(placement['executable']) is bool, 'Invalid placement')
            relative_name(placement['path'])
            marker = (placement['node'], placement['path'])
            need(marker not in placements, 'Duplicate receiver destination')
            placements.add(marker); objects[key]['placements'].append(placement)
    return {'version': 1, 'sessionId': safe_id(spec['sessionId']), 'sourceNode': 'node-a',
            'sourceBootId': source_boot or Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'objects': list(objects.values()), 'logicalSelectedBytes': total,
            'uniqueContentBytes': sum(x['bytes'] for x in objects.values()),
            'sourceBytesHashedThisRound': rehashed, 'allPayloadContentHashesVerified': False,
            'transferExecuted': False, 'sshAuthorizationChanged': False}


def configuration_hints(items):
    """Report key/type shape and selected filesystem paths; never serialize original values wholesale."""
    def shape(value, depth=0):
        if depth >= 6:
            return 'depth-bound'
        if isinstance(value, dict):
            return {key: shape(child, depth + 1) for key, child in value.items()}
        if isinstance(value, list):
            return {'type': 'array', 'length': len(value)}
        return type(value).__name__
    result = []
    fields = ('home_path', 'runtime_path', 'deps_path', 'firecracker.binary_path',
              'firecracker.work_dir', 'firecracker.serial_dir', 'backend.posix_fs.snapshot_store',
              'ublk.daemon_binary_path', 'ublk.daemon_log_path')
    for selected in items:
        p = source_path(selected['path']); before = p.stat()
        need(stat.S_ISREG(before.st_mode) and before.st_size <= 2 * 1024**2, 'Config type/size differs')
        raw = p.read_bytes(); after = p.stat()
        need((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
             and sha(raw) == selected['sha256'], 'Source config changed')
        value = tomllib.loads(raw.decode()); paths = {}
        for field in fields:
            child = value
            for key in field.split('.'):
                child = child.get(key) if isinstance(child, dict) else None
            if isinstance(child, str) and len(child) <= 512 and Path(child).is_absolute() and Path(child).is_relative_to(ROOT):
                paths[field] = child
        result.append({'source': str(p), 'sha256': sha(raw), 'keyTypeShape': shape(value),
                       'safePathReferences': paths, 'originalConfigIncludedInTransfer': False})
    return result


def tool(name):
    for base in ('/usr/bin', '/usr/sbin', '/bin', '/sbin'):
        p = Path(base) / name
        if p.is_file():
            s = p.resolve().stat()
            need(s.st_uid == 0 and not stat.S_IMODE(s.st_mode) & 0o022, 'System tool owner/mode differs')
            return str(p)
    raise RuntimeError('Missing system tool: ' + name)


def query(argv, limit=32768):
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        return {'exitCode': r.returncode, 'stdout': r.stdout[:limit].decode('utf-8', 'replace'),
                'stderr': r.stderr[:1024].decode('utf-8', 'replace'), 'truncated': len(r.stdout) > limit}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'errorType': type(error).__name__}


def ssh_source_metadata():
    result = {'addresses': [], 'hostPublicKeys': [], 'sshAuthorizationChanged': False}
    try:
        r = query([tool('ip'), '-j', '-4', 'address', 'show'])
        if r.get('exitCode') == 0:
            for interface in json.loads(r['stdout']):
                if interface['ifname'].startswith(('lo', 'veth', 'br', 'docker', 'cni', 'flannel', 'virbr')):
                    continue
                for addr in interface.get('addr_info', []):
                    if addr.get('family') == 'inet' and addr.get('scope') == 'global':
                        ipaddress.IPv4Address(addr['local'])
                        result['addresses'].append({'interface': interface['ifname'], 'address': addr['local']})
    except (OSError, ValueError, KeyError, RuntimeError):
        result['addressReadIncomplete'] = True
    for name in ('ssh_host_ed25519_key.pub', 'ssh_host_ecdsa_key.pub', 'ssh_host_rsa_key.pub'):
        p = Path('/etc/ssh') / name
        try:
            s = p.stat(); need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and not stat.S_IMODE(s.st_mode) & 0o022
                                and s.st_size <= 8192, 'Host public key metadata differs')
            key = p.read_text().strip().split()
            need(len(key) >= 2 and len(base64.b64decode(key[1], validate=True)) <= 4096, 'Invalid host public key')
            result['hostPublicKeys'].append({'path': str(p), 'key': key[0] + ' ' + key[1]})
        except (OSError, ValueError, RuntimeError):
            pass
    for name in ('.ssh', '.ssh/authorized_keys'):
        p = HOME / name
        try:
            s = p.lstat(); result[name] = {'exists': True, 'symlink': p.is_symlink(), 'uid': s.st_uid,
                                        'gid': s.st_gid, 'mode': oct(stat.S_IMODE(s.st_mode))}
        except OSError:
            result[name] = {'exists': False}
    try:
        result['localTcpListeners'] = query([tool('ss'), '-H', '-ltn'])
    except RuntimeError:
        result['localTcpListeners'] = {'unavailable': True}
    result['sshPortConfirmed'] = None
    return result


def public_key_text(path):
    raw = path.read_text().strip().split()
    need(len(raw) >= 2 and raw[0] == 'ssh-ed25519', 'Unexpected transfer public-key type')
    payload = base64.b64decode(raw[1], validate=True)
    need(payload[:4] == struct.pack('>I', 11) and payload[4:15] == b'ssh-ed25519'
         and payload[15:19] == struct.pack('>I', 32) and len(payload) == 51, 'Invalid transfer public key')
    return raw[0] + ' ' + raw[1]


def verify_key_files(key, pub, owner=1204):
    need(not key.is_symlink() and not pub.is_symlink(), 'Transfer key redirected')
    private = key.stat(); public = pub.stat()
    need(stat.S_ISREG(private.st_mode) and private.st_uid == owner and not stat.S_IMODE(private.st_mode) & 0o077,
         'Private key owner/mode differs')
    need(stat.S_ISREG(public.st_mode) and public.st_uid == owner, 'Public key owner differs')
    return public_key_text(pub)


def prepare_key(spec, generate=None):
    session = safe_id(spec['sessionId']); node = spec['node']
    need(node in ('node-c', 'node-d'), 'Receiver node differs')
    p = HOME
    for part in ('.local', 'state', 'agentenv-cd-transfer', session, node):
        p = private_dir(p / part, leaf=part not in ('.local', 'state'))
    marker = p / 'identity.json'
    binding = {'sessionId': session, 'node': node, 'machineId': spec['expectedIdentity']['machineId']}
    if marker.exists():
        need(json.loads(marker.read_bytes()) == binding, 'Existing transfer-key identity differs')
    else:
        need(not any(p.iterdir()), 'Unattributed transfer-key directory preserved')
        private_write(marker, canonical(binding))
    key = p / 'id_ed25519'; pub = p / 'id_ed25519.pub'
    if key.exists() or pub.exists():
        need(key.is_file() and pub.is_file() and not key.is_symlink() and not pub.is_symlink(), 'Partial/redirected key pair preserved')
    else:
        intent = p / 'keygen-intent.json'
        need(not intent.exists(), 'Prior key generation outcome unknown; do not repeat')
        private_write(intent, canonical({'attempted': True}))
        if generate:
            generate(key, pub)
        else:
            r = query([tool('ssh-keygen'), '-q', '-t', 'ed25519', '-N', '', '-f', str(key),
                       '-C', 'aenv-cd-transfer-' + session + '-' + node])
            need(r.get('exitCode') == 0, 'Transfer key generation failed; preserve state')
    key_text = verify_key_files(key, pub)
    return {'publicKey': key_text, 'publicKeySha256': sha(key_text.encode()),
            'privateKeyLocalPath': str(key), 'privateKeyContentReadOrUploaded': False,
            'sshAuthorizationChanged': False}


def kernel_materials(search_sources):
    raw = zlib.decompress(base64.b64decode(KERNEL_SOURCE_Z64, validate=True))
    need(sha(raw) == KERNEL_SOURCE_SHA, 'Bundled read-only kernel helper differs')
    module = types.ModuleType('pinned_kernel_metadata')
    exec(compile(raw, '<pinned-kernel-metadata>', 'exec'), module.__dict__)
    original_read = module.read
    def read_metadata_only(path, limit=2 * 1024**2):
        path = Path(path)
        if not (path.is_absolute() and path.resolve() == path and
                not any(part in ('.ssh', '.local', 'credentials', 'credentials.json') for part in path.parts)):
            raise ValueError('Kernel metadata path redirected or private')
        return original_read(path, limit)
    module.read = read_metadata_only
    original_candidate = module.candidate
    def release_candidate(path):
        row = original_candidate(path)
        if row:
            for field in ('include/generated/utsrelease.h', 'include/config/kernel.release'):
                if field in row:
                    text = row[field]
                    match = re.search(r'UTS_RELEASE\s+"([A-Za-z0-9._+\-]{1,128})"', text)
                    plain = re.fullmatch(r'[A-Za-z0-9._+\-]{1,128}', text)
                    row[field] = match.group(1) if match else text if plain else '<unrecognized-release-format>'
        return row
    module.candidate = release_candidate
    release = platform.release(); base = (Path('/lib/modules') / release).resolve()
    result = {'kernel': release, 'config': [module.config_info('/boot/config-' + release),
              module.config_info('/proc/config.gz')], 'standardTrees': {}, 'privilegedRootsNotSearched': ['/root']}
    for name in ('build', 'source'):
        p = base / name
        result['standardTrees'][name] = {'exists': p.exists(), 'resolved': str(p.resolve()),
                                        'candidate': module.candidate(p.resolve()) if p.is_dir() else None}
    result['ublk'] = {'controlPresent': Path('/dev/ublk-control').exists(),
                      'moduleSysfsPresent': Path('/sys/module/ublk_drv').exists(),
                      'controlSysfsPresent': Path('/sys/class/misc/ublk-control').exists()}
    for name in ('modules.builtin', 'modules.dep'):
        try:
            result['ublk'][name] = [line for line in module.read(base / name, 4 * 1024**2).decode().splitlines() if 'ublk' in line][:16]
        except (OSError, ValueError):
            result['ublk'][name] = None
    if search_sources:
        try:
            result['search'] = module.search(('/usr/src', '/home', '/opt', '/data', '/data1', '/workspace', '/build'),
                                             max_dirs=192, seconds=8)
            found = result['search']['candidateTrees']
            result['search']['candidateListTruncated'] = len(found) > 12
            result['search']['candidateTrees'] = found[:12]
        except (OSError, ValueError) as error:
            result['search'] = {'errorType': type(error).__name__, 'sourceAbsenceProven': False}
    return result


def receiver(spec):
    import grp
    need(spec['node'] in ('node-c', 'node-d'), 'Unexpected receiver role')
    base = private_dir(ROOT / 'cd-host-dax')
    target = private_dir(base / safe_id(spec['sessionId']))
    marker = target / 'receiver-identity.json'
    identity = {'node': spec['node'], 'sessionId': spec['sessionId'],
                'machineId': spec['expectedIdentity']['machineId']}
    if marker.exists():
        need(json.loads(marker.read_bytes()) == identity, 'Receiver identity differs')
    else:
        need(not any(target.iterdir()), 'Unattributed receiver contents preserved')
        private_write(marker, canonical(identity))
    for name in ('incoming', 'objects', 'artifacts', 'seed', 'inputs', 'images', 'logs'):
        private_dir(target / name)
    usage = shutil.disk_usage(target)
    need(type(spec['minimumFreeBytes']) is int and usage.free >= spec['minimumFreeBytes'], 'Insufficient receiver headroom')
    result = {'status': 'CD_RECEIVER_PREPARED_NO_TRANSFER_OR_DEPLOYMENT', 'node': spec['node'],
              'receiverRoot': str(target), 'diskFreeBytes': usage.free, 'minimumFreeBytes': spec['minimumFreeBytes'],
              'transferKey': prepare_key(spec), 'filesTransferred': False, 'servicesChanged': False,
              'moduleChanged': False, 'SDK_called': False, 'Guest_created': False}
    try:
        result['kernelMaterials'] = kernel_materials(spec['node'] == 'node-d')
    except Exception as error:
        result['kernelMaterials'] = {'errorType': type(error).__name__, 'sourceAbsenceProven': False}
    sdk = Path('/usr/lib64/libubsm_sdk.so')
    try:
        s = sdk.stat()
        result['sdkFilePermissions'] = {'uid': s.st_uid, 'gid': s.st_gid, 'group': grp.getgrgid(s.st_gid).gr_name,
                                        'mode': oct(stat.S_IMODE(s.st_mode)), 'readableByJwk': os.access(sdk, os.R_OK),
                                        'SDKLoaded': False}
    except (OSError, KeyError):
        result['sdkFilePermissions'] = None
    result['sdkHeaders'] = []
    for p in (Path('/usr/include/ubs_mem.h'), Path('/usr/include/ubs_mem/ubs_mem.h')):
        row = {'path': str(p), 'exists': p.is_file(), 'readable': os.access(p, os.R_OK)}
        if row['readable']:
            try:
                need(p.stat().st_size <= 256 * 1024, 'Header size differs')
                row['sha256'] = sha(p.read_bytes())
                row['package'] = query([tool('rpm'), '-qf', str(p)])
            except (OSError, RuntimeError) as error:
                row['errorType'] = type(error).__name__
        result['sdkHeaders'].append(row)
    for unit in ('ubse.service', 'ubsmd.service'):
        result[unit] = query([tool('systemctl'), 'show', unit, '--no-pager',
                              '--property=LoadState,ActiveState,SubState,MainPID,User,Group,Result'])
    return result


def main():
    need(platform.system() == 'Linux' and os.getuid() == os.geteuid() == 1204
         and os.getgid() == os.getegid() == 1205, 'Use ordinary jwk UID1204/GID1205')
    need(hasattr(os, 'O_NOFOLLOW'), 'Linux no-follow file opens are required')
    spec = json.loads(Path('task-input.json').read_bytes())
    expected = spec['expectedIdentity']
    current = {'hostname': platform.node(), 'uid': os.getuid(), 'gid': os.getgid(), 'kernel': platform.release(),
               'machineId': Path('/etc/machine-id').read_text().strip(),
               'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'architecture': platform.machine()}
    need(current == expected, 'Node/boot identity differs from the previous registered round')
    if spec['mode'] == 'source':
        need(spec['node'] == 'node-a' and platform.node() == 'server1', 'Selected source role differs')
        manifest = compile_export(spec)
        path = Path.cwd() / 'export-manifest.json'; private_write(path, canonical(manifest))
        result = {'status': 'SOURCE_EXPORT_MANIFEST_READY_NOT_AUTHORIZED_OR_TRANSFERRED', 'node': spec['node'],
                  'manifest': manifest, 'manifestPath': str(path), 'manifestSha256': sha(canonical(manifest)),
                  'sshSourceMetadata': ssh_source_metadata(), 'SDK_called': False, 'Guest_created': False,
                  'configurationHints': configuration_hints(spec['configurationTemplates']),
                  'servicesChanged': False, 'moduleChanged': False}
    else:
        need(spec['mode'] == 'receiver', 'Unsupported preparation mode')
        result = receiver(spec)
    result['identity'] = current
    print('BEGIN_CD_TRANSFER_PREPARATION')
    print(json.dumps(result, indent=2))
    print('END_CD_TRANSFER_PREPARATION')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'CD_TRANSFER_PREPARATION_STOPPED_PRESERVE_STATE',
                          'errorType': type(error).__name__, 'reason': str(error),
                          'SDK_called': False, 'servicesChanged': False, 'moduleChanged': False}))
        raise SystemExit(1)
