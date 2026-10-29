"""Ordinary jwk reads only the approved root-created compatibility receipt into the private relay."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import zlib

REPORT = Path('/var/lib/agentenv-c-rootfs-preflight-v1/receipt.json')


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def pack(raw, row, expected):
    need(row['machineId'] == expected['machineId'] and row['bootId'] == expected['bootId']
         and row['kernel'] == expected['kernel'], 'Root receipt belongs to another machine/boot/kernel')
    need(row['status'] == 'C_ROOT_COMPATIBILITY_INSPECTED_NO_SDK_OR_KERNEL_ACTION'
         and all(row[k] is False for k in ('SDK_called', 'Guest_created', 'moduleChanged',
                                          'servicesChanged', 'permissionsChanged', 'kernelActionExecuted')),
         'Root receipt scope/status differs')
    header = base64.b64decode(row['header']['contentBase64'], validate=True)
    need(hashlib.sha256(header).hexdigest() == row['header']['sha256'], 'SDK header receipt SHA differs')
    encoded = base64.b64encode(zlib.compress(raw, 9)).decode()
    need(len(encoded) <= 180 * 1024, 'Private receipt exceeds bounded relay output; preserve local report')
    return {'status': 'C_ROOT_COMPATIBILITY_RECEIPT_COLLECTED_NO_DEPLOYMENT',
            'reportPath': str(REPORT), 'reportBytes': len(raw), 'reportSha256': hashlib.sha256(raw).hexdigest(),
            'encoding': 'zlib-base64', 'privateReport': encoded,
            'SDK_called': False, 'Guest_created': False, 'servicesChanged': False, 'moduleChanged': False}


def main():
    need(platform.system() == 'Linux' and os.getuid() == os.geteuid() == 1204
         and os.getgid() == os.getegid() == 1205, 'Run as ordinary jwk')
    expected = json.loads(Path('task-input.json').read_bytes())['expectedIdentity']
    current = {'hostname': platform.node(), 'uid': os.getuid(), 'gid': os.getgid(),
               'architecture': platform.machine(), 'kernel': platform.release(),
               'machineId': Path('/etc/machine-id').read_text().strip(),
               'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    need(current == expected, 'C identity differs')
    need(REPORT.resolve() == REPORT, 'Root report redirected')
    parent = REPORT.parent.stat()
    need(parent.st_uid == 0 and parent.st_gid == 1205 and not stat.S_IMODE(parent.st_mode) & 0o027,
         'Root report directory ownership/mode differs')
    fd = os.open(REPORT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_gid == 1205
             and stat.S_IMODE(before.st_mode) == 0o640 and before.st_size <= 512 * 1024,
             'Root report type/owner/mode/size differs')
        raw = stream.read(512 * 1024 + 1)
        after = os.fstat(stream.fileno())
        key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(key(before) == key(after) == key(REPORT.stat()) and len(raw) == before.st_size,
             'Root report changed during collection')
    print('BEGIN_C_ROOT_RECEIPT_COLLECTION')
    print(json.dumps(pack(raw, json.loads(raw), expected), indent=2))
    print('END_C_ROOT_RECEIPT_COLLECTION')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'C_ROOT_RECEIPT_COLLECTION_STOPPED', 'reason': str(error)}))
        raise SystemExit(1)
