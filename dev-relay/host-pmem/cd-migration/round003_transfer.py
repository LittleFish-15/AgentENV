"""User-triggered selected-file migration; no SDK, Guest, module or service operations."""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time

HOME = Path('/home/jwk')
ROOT = HOME / 'agent'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_path(path, base, exists=True):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and path.is_relative_to(base)
         and path.resolve() == path, 'Path outside owned scope or redirected')
    if exists:
        s = path.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_uid in (0, 1204), 'File owner/type differs')
    return path


def private_dir(path):
    safe_path(path, HOME, False)
    path.mkdir(mode=0o700, exist_ok=True)
    s = path.stat()
    need(s.st_uid == 1204 and not stat.S_IMODE(s.st_mode) & 0o077, 'Private directory owner/mode differs')
    return path


def write_new(path, raw, mode=0o600):
    safe_path(path, HOME, False)
    if path.exists():
        need(path.read_bytes() == raw, 'Existing file differs; preserved')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def identity():
    return {'hostname': platform.node(), 'uid': os.getuid(), 'gid': os.getgid(),
            'kernel': platform.release(), 'architecture': platform.machine(),
            'machineId': Path('/etc/machine-id').read_text().strip(),
            'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def stable(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def validate_manifest(manifest):
    need(manifest['sourceNode'] == 'node-a' and 1 <= len(manifest['objects']) <= 128, 'Source manifest differs')
    seen = set(); total = 0
    for item in manifest['objects']:
        key = item['sha256']
        need(re.fullmatch('[0-9a-f]{64}', key) and key not in seen, 'Duplicate/invalid object')
        seen.add(key)
        need(type(item['bytes']) is int and 0 < item['bytes'] <= 4 * 1024**3, 'Object bound differs')
        total += item['bytes']
        safe_path(item['sourcePath'], ROOT, False)
        need(len(item['sourceIdentity']) == 5, 'Missing source identity')
        for place in item['placements']:
            p = PurePosixPath(place['path'])
            need(place['node'] in ('node-c', 'node-d') and not p.is_absolute() and '..' not in p.parts
                 and p.as_posix() == place['path'] and '\\' not in place['path'] and ':' not in place['path'], 'Invalid placement')
    need(total <= 8 * 1024**3, 'Total export bound exceeded')


def export_one(plan, node, command, out):
    need(time.time() < plan['expiresAtUnix'], 'Export grant expired')
    need(identity() == plan['sourceIdentity'], 'Source boot/identity changed')
    match = re.fullmatch(r'get ([0-9a-f]{64})', command)
    need(match is not None and node in ('node-c', 'node-d'), 'Only a selected object request is supported')
    matches = [x for x in plan['manifest']['objects'] if x['sha256'] == match.group(1)
               and any(p['node'] == node for p in x['placements'])]
    need(len(matches) == 1, 'Object not granted to this receiver')
    item = matches[0]
    path = safe_path(item['sourcePath'], ROOT)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        need(stable(os.fstat(source.fileno())) == item['sourceIdentity'], 'Source changed since inventory')
        count = 0
        for raw in iter(lambda: source.read(1024**2), b''):
            count += len(raw); need(count <= item['bytes'], 'Source grew')
            out.write(raw)
        out.flush()
        need(count == item['bytes'] and stable(os.fstat(source.fileno())) == item['sourceIdentity']
             and stable(path.stat()) == item['sourceIdentity'], 'Source changed while streaming')


def install(spec):
    validate_manifest(spec['manifest'])
    base = private_dir(ROOT / 'cd-export')
    target = private_dir(base / spec['sessionId'])
    script = target / 'export.py'; planfile = target / 'plan.json'
    plan = {'manifest': spec['manifest'], 'sourceIdentity': spec['expectedIdentity'],
            'expiresAtUnix': spec['expiresAtUnix']}
    raw = Path(__file__).read_bytes()
    write_new(script, raw)
    write_new(planfile, encoded(plan))
    lines = []
    for node in ('node-c', 'node-d'):
        key = spec['publicKeys'][node]
        need(re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+', key), 'Invalid receiver public key')
        base64.b64decode(key.split()[1], validate=True)
        command = '/usr/bin/python3 -I -B ' + str(script) + ' serve ' + str(planfile) + ' ' + sha(encoded(plan)) + ' ' + node
        need(re.fullmatch(r'[A-Za-z0-9_./ -]+', command), 'Unsafe forced-command representation')
        lines.append('restrict,command="' + command + '" ' + key + ' aenv-cd-' + spec['sessionId'] + '-' + node)
    authraw = ('\n'.join(lines) + '\n').encode()
    ssh = HOME / '.ssh'; s = ssh.lstat()
    need(not ssh.is_symlink() and s.st_uid == 1204 and not stat.S_IMODE(s.st_mode) & 0o077, 'SSH directory owner/mode differs')
    auth = ssh / 'authorized_keys'
    # First inventory found no authorized_keys. Never overwrite an unrelated existing one.
    write_new(auth, authraw)
    return {'status': 'SELECTED_EXPORT_READY_KEYS_RESTRICTED', 'exportRoot': str(target),
            'authorizedKeysSha256': sha(authraw), 'expiresAtUnix': spec['expiresAtUnix'],
            'allowedReceivers': ['node-c', 'node-d'], 'unrestrictedLoginGranted': False,
            'restoreCommand': '/usr/bin/python3 -I -B ' + str(script) + ' revoke ' + sha(authraw)}


def revoke(expected):
    auth = safe_path(HOME / '.ssh/authorized_keys', HOME)
    need(sha(auth.read_bytes()) == expected, 'Authorization changed; preserve it for reconciliation')
    auth.unlink()
    print('SELECTED_EXPORT_KEYS_REMOVED_OTHER_FILES_PRESERVED')


def verify_file(path, item):
    path = safe_path(path, HOME)
    need(path.stat().st_size == item['bytes'], 'Received length differs')
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024**2), b''):
            h.update(chunk)
    need(h.hexdigest() == item['sha256'], 'Received content SHA differs')


def ssh_command(spec, key, known, digest):
    need(re.fullmatch(r'[0-9.]+', spec['sourceAddress']) and 1 <= spec['sourcePort'] <= 65535, 'Invalid fixed endpoint')
    return ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', str(spec['sourcePort']),
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'HostKeyAlias=aenv-cd-source', '-o', 'HostKeyAlgorithms=ssh-ed25519',
            '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
            '-o', 'ClearAllForwardings=yes', '-o', 'RequestTTY=no', '-o', 'LogLevel=ERROR',
            '-i', str(key), 'jwk@' + spec['sourceAddress'], 'get ' + digest]


def receive_process(argv, partial, expected_bytes, seconds=600):
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    process = None; count = 0; errors = bytearray(); start = time.monotonic()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with os.fdopen(fd, 'wb') as stream, selectors.DefaultSelector() as selector:
            fd = None
            selector.register(process.stdout, selectors.EVENT_READ, 'data')
            selector.register(process.stderr, selectors.EVENT_READ, 'error')
            while selector.get_map():
                need(time.monotonic() - start < seconds, 'Selected transfer timed out; partial retained')
                for event, _ in selector.select(1):
                    raw = os.read(event.fileobj.fileno(), 1024**2)
                    if not raw:
                        selector.unregister(event.fileobj); continue
                    if event.data == 'data':
                        count += len(raw); need(count <= expected_bytes, 'Transfer exceeded selected object size')
                        stream.write(raw)
                    elif len(errors) < 2048:
                        errors.extend(raw[:2048 - len(errors)])
            code = process.wait(timeout=10)
            need(code == 0, 'SSH transfer failed (exit ' + str(code) + '): ' + errors.decode('utf-8', 'replace'))
            need(count == expected_bytes, 'Transfer ended before selected object completed')
            stream.flush(); os.fsync(stream.fileno())
    finally:
        if fd is not None:
            os.close(fd)
        if process is not None and process.poll() is None:
            process.kill(); process.wait(timeout=10)


def receive(spec):
    validate_manifest(spec['manifest'])
    target = safe_path(spec['receiverRoot'], ROOT, False)
    marker = json.loads((target / 'receiver-identity.json').read_bytes())
    need(marker == {'node': spec['node'], 'sessionId': spec['sessionId'],
                    'machineId': spec['expectedIdentity']['machineId']}, 'Receiver identity marker differs')
    key = safe_path(spec['keyPath'], HOME)
    need(key.stat().st_uid == 1204 and not stat.S_IMODE(key.stat().st_mode) & 0o077, 'Transfer key owner/mode differs')
    need((key.with_name(key.name + '.pub')).read_text().strip().split()[:2] == spec['publicKey'].split(), 'Transfer public key differs')
    known = target / 'source-known-hosts'
    need(re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+', spec['hostPublicKey']), 'Invalid pinned source host key')
    write_new(known, ('aenv-cd-source ' + spec['hostPublicKey'] + '\n').encode())
    selected = [x for x in spec['manifest']['objects'] if any(p['node'] == spec['node'] for p in x['placements'])]
    need(shutil.disk_usage(target).free >= sum(x['bytes'] for x in selected) + 1024**3, 'Insufficient transfer headroom')
    done = []
    for item in selected:
        obj = safe_path(target / 'objects' / item['sha256'], target, False)
        if obj.exists():
            verify_file(obj, item)
            need(obj.stat().st_uid == 1204 and not stat.S_IMODE(obj.stat().st_mode) & 0o222, 'Existing object is writable or unowned')
        else:
            partial = target / 'incoming' / (item['sha256'] + '.partial')
            need(not partial.exists(), 'Prior partial transfer preserved; reconciliation required')
            receive_process(ssh_command(spec, key, known, item['sha256']), partial, item['bytes'])
            verify_file(partial, item)
            os.chmod(partial, 0o500 if any(p['executable'] for p in item['placements']) else 0o400)
            os.link(partial, obj); partial.unlink()
        places = []
        for placement in item['placements']:
            if placement['node'] != spec['node']:
                continue
            dest = target / placement['path']
            safe_path(dest, target, False)
            current = target
            for part in dest.relative_to(target).parts[:-1]:
                current = private_dir(current / part)
            if dest.exists():
                need(dest.samefile(obj), 'Existing destination differs; preserved')
            else:
                os.link(obj, dest)
            places.append(str(dest))
        done.append({'sha256': item['sha256'], 'bytes': item['bytes'], 'placements': places})
        print('TRANSFER_OBJECT_VERIFIED ' + item['sha256'] + ' bytes=' + str(item['bytes']), flush=True)
    receipt = {'status': 'SELECTED_ARTIFACTS_TRANSFERRED_HASH_VERIFIED_NOT_DEPLOYED', 'node': spec['node'],
               'objects': done, 'uniqueTransferredBytes': sum(x['bytes'] for x in selected),
               'sourceIdentity': spec['sourceIdentity'], 'twoNodeUbAccepted': False}
    write_new(target / 'transfer-receipt.json', encoded(receipt))
    return receipt


def main():
    need(platform.system() == 'Linux' and os.getuid() == os.geteuid() == 1204
         and os.getgid() == os.getegid() == 1205, 'Use ordinary jwk UID1204/GID1205')
    if len(sys.argv) > 1 and sys.argv[1] == 'serve':
        need(len(sys.argv) == 5, 'Invalid export invocation')
        planfile = safe_path(sys.argv[2], ROOT / 'cd-export')
        raw = planfile.read_bytes(); need(sha(raw) == sys.argv[3], 'Export plan changed')
        export_one(json.loads(raw), sys.argv[4], os.environ.get('SSH_ORIGINAL_COMMAND', ''), sys.stdout.buffer)
        return
    if len(sys.argv) > 1 and sys.argv[1] == 'revoke':
        need(len(sys.argv) == 3, 'Invalid revoke invocation'); revoke(sys.argv[2]); return
    need(len(sys.argv) == 1, 'Unexpected command arguments')
    spec = json.loads(Path('task-input.json').read_bytes())
    need(identity() == spec['expectedIdentity'], 'Node/boot differs from registered preparation')
    need(spec['mode'] in ('install-source', 'receive'), 'Unsupported transfer mode')
    need(re.fullmatch('[a-z0-9-]{1,64}', spec['sessionId']), 'Invalid transfer session identifier')
    result = install(spec) if spec['mode'] == 'install-source' else receive(spec)
    result.update(SDK_called=False, Guest_created=False, moduleChanged=False, servicesChanged=False)
    print('BEGIN_SELECTED_TRANSFER_REPORT'); print(json.dumps(result, indent=2)); print('END_SELECTED_TRANSFER_REPORT')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'SELECTED_TRANSFER_STOPPED_PRESERVE_STATE', 'reason': str(error)}), file=sys.stderr)
        raise SystemExit(1)
