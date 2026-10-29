"""Independently verify C staging and place immutable artifacts. No SDK/service/module operations."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import subprocess

ROOT = Path('/home/jwk/agent')


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def stable(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def verify(path, item):
    need(path.resolve() == path and not path.is_symlink(), 'Staging path redirected')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 1204 and before.st_size == item['bytes'], 'Staging type/owner/length differs')
        h = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024**2), b''):
            h.update(chunk)
        need(h.hexdigest() == item['sha256'], 'C independent content SHA differs')
        need(stable(before) == stable(os.fstat(stream.fileno())) == stable(path.stat()), 'File changed during C verification')
    return before


def destination(value):
    p = PurePosixPath(value)
    need(isinstance(value, str) and p.parts and not p.is_absolute() and '..' not in p.parts
         and p.as_posix() == value and '\\' not in value and ':' not in value, 'Invalid relative artifact path')
    return p.parts


def directory(path):
    need(path.resolve() == path, 'Directory redirected')
    path.mkdir(mode=0o700, exist_ok=True)
    s = path.stat()
    need(s.st_uid == 1204 and not stat.S_IMODE(s.st_mode) & 0o077, 'Directory owner/mode differs')


def metadata(path):
    p = Path(path)
    try:
        s = p.stat()
        return {'path': path, 'uid': s.st_uid, 'gid': s.st_gid, 'mode': oct(stat.S_IMODE(s.st_mode)),
                'readable': os.access(p, os.R_OK), 'writable': os.access(p, os.W_OK)}
    except OSError:
        return {'path': path, 'presentOrAccessible': False}


def run(argv):
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        return {'exitCode': r.returncode, 'stdout': r.stdout[:16384].decode('utf-8', 'replace'),
                'stderr': r.stderr[:1024].decode('utf-8', 'replace'), 'truncated': len(r.stdout) > 16384}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {'errorType': type(e).__name__}


def main():
    need(platform.system() == 'Linux' and os.getuid() == os.geteuid() == 1204
         and os.getgid() == os.getegid() == 1205, 'Run as jwk')
    spec = json.loads(Path('task-input.json').read_bytes())
    current = {'hostname': platform.node(), 'uid': os.getuid(), 'gid': os.getgid(),
               'kernel': platform.release(), 'architecture': platform.machine(),
               'machineId': Path('/etc/machine-id').read_text().strip(),
               'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    need(current == spec['expectedIdentity'], 'C identity changed')
    root = ROOT / 'cd-host-dax' / spec['sessionId']
    staging = Path(spec['stagingDirectory'])
    need(root.resolve() == root and staging.resolve() == staging and staging.is_relative_to(root / 'windows-incoming-v1'),
         'Staging outside fixed receiver')
    selected = spec['objects']
    need(1 <= len(selected) <= 128 and sum(x['bytes'] for x in selected) <= 8 * 1024**3, 'Manifest bound differs')
    expected_names = {x['sha256'] for x in selected}
    need(len(expected_names) == len(selected) and {p.name for p in staging.iterdir()} == expected_names, 'Staging object inventory differs')
    verified = []
    for item in selected:
        need(len(item['sha256']) == 64 and all(c in '0123456789abcdef' for c in item['sha256']), 'Invalid SHA')
        verify(staging / item['sha256'], item)
        verified.append({'sha256': item['sha256'], 'bytes': item['bytes']})
    # Validate the complete inventory before making any deployment placement visible.
    for item in selected:
        source = staging / item['sha256']; obj = root / 'objects' / item['sha256']
        need(obj.resolve() == obj, 'Object path redirected')
        if obj.exists():
            need(obj.samefile(source), 'Existing object differs; preserved')
        else:
            os.link(source, obj)
        os.chmod(obj, 0o500 if any(p['executable'] for p in item['placements']) else 0o400)
        for place in item['placements']:
            need(place['node'] == 'node-c', 'Only C artifacts may be placed')
            parts = destination(place['path']); parent = root
            for part in parts[:-1]:
                parent = parent / part; directory(parent)
            dest = parent / parts[-1]
            need(dest.resolve() == dest, 'Artifact redirected')
            if dest.exists():
                need(dest.samefile(obj), 'Existing artifact differs; preserved')
            else:
                os.link(obj, dest)
    report = {'status': 'C_ARTIFACTS_INDEPENDENTLY_HASH_VERIFIED_PLACED_NOT_DEPLOYED',
              'identity': current, 'objects': verified, 'uniqueBytes': sum(x['bytes'] for x in selected),
              'workRoot': str(root), 'windowsRunId': spec['windowsRunId'], 'groups': os.getgroups(),
              'sdk': metadata('/usr/lib64/libubsm_sdk.so'), 'sdkHeader': metadata('/usr/include/ubs_mem.h'),
              'devices': [metadata(p) for p in ('/dev/obmm', '/dev/ublk-control', '/dev/kvm', '/dev/net/tun')],
              'module': {}, 'SDK_called': False, 'Guest_created': False, 'servicesChanged': False,
              'moduleChanged': False, 'hostDaxAccepted': False, 'cacheSavingsBytes': None}
    for key in ('refcnt', 'srcversion', 'taint'):
        try:
            report['module'][key] = (Path('/sys/module/obmm') / key).read_text().strip()
        except OSError:
            report['module'][key] = None
    params = Path('/sys/module/obmm/parameters')
    report['module']['pmem_ro_enable_present'] = (params / 'pmem_ro_enable').exists()
    report['services'] = run(['/usr/bin/systemctl', 'show', 'ubse.service', 'ubsmd.service', '--no-pager',
                              '--property=Id,MainPID,LoadState,ActiveState,SubState,User,Group,Result'])
    path = root / 'C-transfer-verified-v1.json'
    with path.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2); stream.flush(); os.fsync(stream.fileno())
    print('BEGIN_C_ARTIFACT_FINALIZE'); print(json.dumps(report, indent=2)); print('END_C_ARTIFACT_FINALIZE')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({'status': 'C_ARTIFACT_FINALIZE_STOPPED_PRESERVE_STATE', 'reason': str(e)}))
        raise SystemExit(1)
