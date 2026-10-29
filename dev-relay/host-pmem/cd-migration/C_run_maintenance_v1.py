"""Root-only driver for the separately approved C build/switch or explicit restore, with private receipt."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile
import urllib.request

PARENT = Path('/var/lib/agentenv-c-rootfs-preflight-v1')
STAGE = Path('/var/lib/agentenv-c-rootfs-maintenance-v1')
APPROVAL = 'C_NATIVE_ADAPTER_BUILD_OBMM_SWITCH_EXPLICIT_RESTORE'
COMMIT = 'b19bfd9def6c6fd5e56b45aaaeb1e7223f44bddb'
ENTRY_SHA = '90c9324730136472bdcaa9b3a4b155313cdadba7f14b79fadaade9beac625049'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def read_journal(path):
    if not path.exists():
        return None
    need(path.resolve() == path and path.stat().st_uid == 0 and path.stat().st_size <= 256 * 1024,
         'Private maintenance journal untrusted')
    return json.loads(path.read_bytes())


def write_receipt(path, row):
    raw = (json.dumps(row, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, 'wb') as stream:
        os.fchown(stream.fileno(), 0, 1205); os.fchmod(stream.fileno(), 0o640)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('activate', 'restore'))
    parser.add_argument('--approval', required=True)
    args = parser.parse_args()
    need(os.getuid() == os.geteuid() == 0 and args.approval == APPROVAL, 'Approved C root maintenance required')
    need(PARENT.resolve() == PARENT and PARENT.stat().st_uid == 0
         and not stat.S_IMODE(PARENT.stat().st_mode) & 0o022, 'Preflight directory untrusted')
    expected = read_journal(PARENT / 'receipt.json')
    need(expected['machineId'] == Path('/etc/machine-id').read_text().strip()
         and expected['bootId'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
         and expected['kernel'] == platform.release(), 'C machine/boot/kernel changed')
    receipt = PARENT / ('maintenance-' + args.action + '-v1.json')
    need(not receipt.exists(), 'Previous action receipt exists; preserve, do not retry')
    saved_driver = PARENT / 'C-run-maintenance-driver-v1.py'
    own = Path(__file__).read_bytes()
    if saved_driver.exists():
        need(saved_driver.read_bytes() == own and saved_driver.stat().st_uid == 0,
             'Existing recovery driver differs')
    else:
        fd = os.open(saved_driver, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(own); stream.flush(); os.fsync(stream.fileno())
    if args.action == 'activate':
        relative = 'dev-relay/host-pmem/cd-migration/C_prepare_and_switch_v1.py'
        url = 'https://' + 'api.github.com/repos/LittleFish-15/AgentENV/contents/' + relative + '?ref=' + COMMIT
        request = urllib.request.Request(url, headers={'User-Agent': 'AgentENV-C-Approved-Maintenance'})
        with urllib.request.urlopen(request, timeout=45) as response:
            item = json.loads(response.read(65536))
        need(item.get('type') == 'file' and item.get('path') == relative and item.get('encoding') == 'base64', 'Entry response differs')
        raw = base64.b64decode(''.join(item['content'].split()), validate=True)
        need(len(raw) == 20101 and hashlib.sha256(raw).hexdigest() == ENTRY_SHA, 'Fixed maintenance entry SHA differs')
        fd, name = tempfile.mkstemp(prefix='C-approved-maintenance-', suffix='.py', dir='/var/tmp')
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        entry = Path(name)
    else:
        entry = STAGE / 'entry.py'
        need(entry.resolve() == entry and entry.stat().st_uid == 0
             and hashlib.sha256(entry.read_bytes()).hexdigest() == ENTRY_SHA, 'Saved recovery entry differs')
    row = {'status': 'C_MAINTENANCE_ACTION_CAPTURED_NOT_UB_OR_GUEST_ACCEPTANCE', 'action': args.action,
           'machineId': expected['machineId'], 'bootId': expected['bootId'], 'kernel': expected['kernel'],
           'SDK_called': False, 'Guest_created': False, 'logicalUbAllocationBytes': 0,
           'actionExitCode': None, 'journal': None, 'nativeBuild': None}
    try:
        row['actionExitCode'] = subprocess.run([sys.executable, '-I', '-B', str(entry), args.action,
                                               '--approval', APPROVAL], stdin=subprocess.DEVNULL).returncode
    finally:
        row['journal'] = read_journal(STAGE / 'module/journal.json')
        row['nativeBuild'] = read_journal(STAGE / 'native-build.json')
        row['initialContext'] = read_journal(STAGE / 'initial-context.json')
        current = Path('/sys/module/obmm/srcversion')
        row['observedModuleSource'] = current.read_text().strip() if current.exists() else None
        write_receipt(receipt, row)
    print('C_MAINTENANCE_PRIVATE_RECEIPT_READY=' + str(receipt), flush=True)
    raise SystemExit(row['actionExitCode'] or 0)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({'status': 'C_MAINTENANCE_DRIVER_STOPPED_PRESERVE_STATE', 'reason': str(e)}))
        raise SystemExit(1)
