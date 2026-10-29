"""Explicitly approved C/root read-only compatibility inspection; writes one restricted new receipt."""
import argparse
import base64
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess

REPORT_ROOT = Path('/var/lib/agentenv-c-rootfs-preflight-v1')
CANDIDATE = Path('/home/jwk/agent/cd-host-dax/relay-20261029-0d032371/artifacts/kernel/C-obmm-candidate.ko')
CANDIDATE_SHA = '59767d198966db908e662cfbe0f144b93d8fd20f01a39c917977aa9e8efd8a6a'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def read_regular(path, limit):
    path = Path(path)
    resolved = path.resolve(strict=True)
    with os.fdopen(os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'File type/size exceeds read-only inspection bound')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(key(before) == key(after) == key(resolved.stat()) and len(raw) == before.st_size, 'File changed during inspection')
    return raw, {'path': str(path), 'resolved': str(resolved), 'bytes': len(raw),
                 'sha256': hashlib.sha256(raw).hexdigest(), 'uid': before.st_uid,
                 'gid': before.st_gid, 'mode': oct(stat.S_IMODE(before.st_mode))}


def query(tool, args):
    for prefix in ('/usr/sbin', '/usr/bin', '/sbin', '/bin'):
        path = Path(prefix) / tool
        if path.is_file():
            s = path.resolve().stat()
            need(s.st_uid == 0 and not stat.S_IMODE(s.st_mode) & 0o022, 'System tool owner/mode differs')
            try:
                r = subprocess.run([str(path)] + args, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
                return {'exitCode': r.returncode, 'stdout': r.stdout[:32768].decode('utf-8', 'replace'),
                        'stderr': r.stderr[:2048].decode('utf-8', 'replace'), 'truncated': len(r.stdout) > 32768}
            except subprocess.TimeoutExpired:
                return {'error': 'Read-only query timed out'}
    return {'error': 'Missing read-only tool: ' + tool}


def inspect():
    raw, candidate = read_regular(CANDIDATE, 16 * 1024**2)
    need(candidate['sha256'] == CANDIDATE_SHA, 'Candidate binary SHA differs')
    sdk_raw, sdk = read_regular('/usr/lib64/libubsm_sdk.so', 16 * 1024**2)
    header_raw, header = read_regular('/usr/include/ubs_mem.h', 192 * 1024)
    header['contentBase64'] = base64.b64encode(header_raw).decode()
    current_module = query('modinfo', ['-n', 'obmm'])
    original = None
    if current_module.get('exitCode') == 0 and not current_module['truncated']:
        path = Path(current_module['stdout'].strip())
        need(path.is_absolute() and path.resolve().is_relative_to(Path('/usr/lib/modules')),
             'Original module is not inside installed kernel modules')
        _, original = read_regular(path, 32 * 1024**2)
    report = {'status': 'C_ROOT_COMPATIBILITY_INSPECTED_NO_SDK_OR_KERNEL_ACTION',
              'kernel': platform.release(), 'sdk': sdk, 'header': header, 'candidate': candidate,
              'candidateModinfo': query('modinfo', [str(CANDIDATE)]), 'originalModule': original,
              'sdkExports': query('nm', ['-D', '--defined-only', '/usr/lib64/libubsm_sdk.so']),
              'ubse': query('systemctl', ['show', 'ubse.service', 'ubsmd.service', '--no-pager',
                  '--property=Id,MainPID,ActiveState,SubState,User,Group,Result,FragmentPath']),
              'groups': {'jwk': query('id', ['jwk']), 'sdkGroup': grp.getgrgid(sdk['gid']).gr_name},
              'SDK_called': False, 'Guest_created': False, 'moduleChanged': False,
              'servicesChanged': False, 'permissionsChanged': False, 'kernelActionExecuted': False}
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--approval', required=True)
    p.add_argument('--machine-id', required=True)
    p.add_argument('--boot-id', required=True)
    args = p.parse_args()
    need(os.getuid() == os.geteuid() == 0 and platform.system() == 'Linux', 'Explicit C root execution required')
    need(args.approval == 'C_ROOT_READONLY_COMPATIBILITY_NO_KERNEL_CHANGE', 'Approval scope differs')
    need(Path('/etc/machine-id').read_text().strip() == args.machine_id
         and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == args.boot_id,
         'C machine/boot identity differs')
    need(platform.release() == '6.6.0-145.3.34.165.oe2403sp3.aarch64', 'Running kernel differs')
    report = inspect()
    report.update(machineId=args.machine_id, bootId=args.boot_id)
    need(REPORT_ROOT.resolve() == REPORT_ROOT and not REPORT_ROOT.exists(), 'Prior preflight preserved; do not repeat')
    REPORT_ROOT.mkdir(mode=0o750)
    os.chown(REPORT_ROOT, 0, 1205)
    os.chmod(REPORT_ROOT, 0o750)
    path = REPORT_ROOT / 'receipt.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, 'wb') as stream:
        os.fchown(stream.fileno(), 0, 1205); os.fchmod(stream.fileno(), 0o640)
        stream.write((json.dumps(report, indent=2) + '\n').encode()); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps({'status': report['status'], 'privateReceipt': str(path),
                      'SDK_called': False, 'kernelActionExecuted': False,
                      'servicesChanged': False, 'permissionsChanged': False}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({'status': 'C_ROOT_PREFLIGHT_STOPPED_PRESERVE_OUTPUTS', 'reason': str(e)}))
        raise SystemExit(1)
