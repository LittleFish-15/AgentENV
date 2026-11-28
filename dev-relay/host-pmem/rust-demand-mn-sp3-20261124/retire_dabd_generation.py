"""Retire only the audited idle M/N generation dabd65d32a1c5c3e91a994bbcbbb9e6f."""

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import select
import signal
import stat
import struct
import subprocess
import uuid
from pathlib import Path


RUN = 'dabd65d32a1c5c3e91a994bbcbbb9e6f'
POOL = '01a21fe4-7e16-7442-b4e7-592d12958c40'
POOL_OBJECT = 'aenv_01a21fe47e167442b4e7592d12958c40'
VOLUMES = {'agent1': '01a21fe3-9305-7e31-ac60-cb28b9532df5',
           'agent2': '01a21fe1-048a-7740-94a6-62f9e6927ecd'}
BOOTS = {'agent1': 'adca3a33-8bfd-4e89-b448-4f93385c68de',
         'agent2': '8b37b961-2b42-4c52-8aa7-8335cc52f52d'}
MACHINE_IDS = {'agent1': '498c7bb42c72427a8ce412b91776bc63',
               'agent2': '7579df430de64560b8d09b83baf1e2b0'}
SRCVERSION = '29F10664C1EE59D7127F8C7'
ADAPTER = Path('/opt/aenv/libaenv-ub.so')
ADAPTER_SHA = 'a5379bbd70fbd244de07c312076a9ece23ce38452682dfed31b60f6fe3912dbc'
ROOT_STATE = Path('/etc/aenv/ub') / ('relay-' + RUN) / 'device-state/root.json'
SDK_ROOT = Path('/var/lib/aenv-ub-sdk') / ('relay-' + RUN)
SDK_STATE = SDK_ROOT / 'state/sdk.json'
VOLUME_LAYOUT = struct.Struct('<II16sIIII7Q')


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_journal(path):
    value = json.loads(path.read_text(encoding='utf-8'))
    need(isinstance(value, dict) and value.get('run') == RUN,
         'journal identity differs: ' + str(path))
    return value


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


def validate_volume(row):
    if row['status'] == 'absent':
        return
    need(row['state'] == 2 and row['bytes'] == 2**32,
         'exact old volume state or size differs')
    need(all(row[key] == 0 for key in ('openers', 'activeIo', 'blockReads', 'blockBytes',
                                       'daxAccesses', 'daxSpanBytes')),
         'exact old volume has live references or activity')


def process_inventory():
    rows = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            exe = os.readlink(proc / 'exe')
            argv = (proc / 'cmdline').read_bytes().split(b'\0')
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        name = Path(exe).name
        if name in ('server', 'uvm-ublk-daemon', 'firecracker') or 'agentenv-ub-provider' in exe:
            rows.append({'pid': int(proc.name), 'exe': exe,
                         'argv': [part.decode('utf-8', 'replace')[:256] for part in argv[:6]]})
    return rows


def validate_journals(node, volume):
    root = read_journal(ROOT_STATE)
    sdk = read_journal(SDK_STATE)
    need(root.get('volume') == volume, 'root journal volume differs')
    pools = sdk.get('pools', {})
    if node == 'agent1':
        need(set(pools) == {POOL}, 'M SDK journal pool set differs')
        row = pools[POOL]
        need(row.get('allocationOwner') is True and row.get('coverageBytes') == 128 * 1024 * 1024
             and row.get('phase') == 'READY', 'M SDK pool journal is not the audited owner state')
        directory = read_journal(SDK_ROOT / ('directory-' + RUN + '.json'))
        need(directory.get('closed') is True and directory.get('faulted') is True,
             'M SDK directory is no longer the audited closed/faulted state')
    else:
        need(not pools, 'N unexpectedly owns an SDK pool')
    return {'rootJournalRun': root['run'], 'volume': root['volume'],
            'sdkJournalRun': sdk['run'], 'sdkPoolIds': sorted(pools)}


def deallocate_owner_object():
    info = ADAPTER.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid in (0, 1204)
         and not info.st_mode & 0o022, 'SDK adapter metadata differs')
    digest = hashlib.sha256(ADAPTER.read_bytes()).hexdigest()
    need(digest == ADAPTER_SHA, 'SDK adapter digest differs from audited cleanup adapter')
    pid = os.fork()
    if pid == 0:
        try:
            os.initgroups('jwk', 1205)
            os.setgid(1205)
            os.setuid(1204)
            status = Path('/proc/self/status').read_text()
            need(all(re.search(r'^' + key + r':\s+0+$', status, re.M)
                     for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')),
                 'SDK caller retained capabilities')
            library = ctypes.CDLL(str(ADAPTER), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            signatures = {'aenv_ub_abi_version': [], 'aenv_ub_configure_region': [ctypes.c_char_p],
                          'aenv_ub_initialize': [], 'aenv_ub_deallocate': [ctypes.c_char_p],
                          'aenv_ub_finalize': []}
            for name, arguments in signatures.items():
                function = getattr(library, name)
                function.argtypes = arguments
                function.restype = ctypes.c_int
            need(library.aenv_ub_abi_version() == 3, 'SDK adapter ABI differs')
            need(library.aenv_ub_configure_region(b'default') == 0, 'SDK region configuration failed')
            need(library.aenv_ub_initialize() == 0, 'SDK initialize failed')
            result = library.aenv_ub_deallocate(POOL_OBJECT.encode('ascii'))
            final = library.aenv_ub_finalize()
            need(result in (0, 6020) and final == 0, 'exact owner-object deallocation failed')
            os._exit(0)
        except Exception:
            os._exit(1)
    handle = os.pidfd_open(pid)
    try:
        poller = select.poll()
        poller.register(handle, select.POLLIN)
        need(poller.poll(30000), 'SDK cleanup child did not exit')
        _, status = os.waitpid(pid, 0)
    finally:
        os.close(handle)
    need(status == 0, 'ordinary-user SDK deallocation failed')
    return {'object': POOL_OBJECT, 'adapterSha256': digest, 'sdkUid': 1204,
            'result': 'deallocated-or-already-absent'}


def destroy_exact_volume(volume, before):
    if before['status'] == 'absent':
        return {'before': before, 'after': before, 'action': 'already-absent'}
    validate_volume(before)
    ident = uuid.UUID(volume)
    wire = bytearray(VOLUME_LAYOUT.size)
    struct.pack_into('<II16sI', wire, 0, 1, 0, ident.bytes, before['id'])
    fd = os.open('/dev/obmm_pmem', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        fcntl.ioctl(fd, 0x4060b802, wire, True)
    finally:
        os.close(fd)
    after = volume_query(volume)
    need(after['status'] == 'absent', 'exact old volume remains after retirement')
    return {'before': before, 'after': after, 'action': 'retired-exact-uuid'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', choices=('agent1', 'agent2'), required=True)
    parser.add_argument('--boot-id', required=True)
    parser.add_argument('--machine-id', required=True)
    args = parser.parse_args()
    node = args.node
    volume = VOLUMES[node]
    need(os.geteuid() == 0 and os.uname().nodename.split('.')[0] == node,
         'root identity or hostname differs')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == args.boot_id == BOOTS[node],
         'boot identity differs')
    need(Path('/etc/machine-id').read_text().strip() == args.machine_id == MACHINE_IDS[node],
         'machine identity differs')
    need(Path('/sys/module/obmm/srcversion').read_text().strip() == SRCVERSION,
         'loaded OBMM source version differs')
    journal_facts = validate_journals(node, volume)
    processes = process_inventory()
    need(not processes, 'AENV consumer/provider/Firecracker process is active; cleanup stopped before mutation')
    unit = subprocess.run(['/usr/bin/systemctl', 'show', 'aenv-mn-titanic.service',
                           '-p', 'LoadState', '-p', 'ActiveState', '-p', 'MainPID'],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=15, check=False)
    unit_text = unit.stdout.decode('utf-8', 'replace')
    need(unit.returncode == 0 and 'ActiveState=active' not in unit_text and 'MainPID=0' in unit_text,
         'AENV unit is active or its state could not be verified')
    before = volume_query(volume)
    validate_volume(before)
    pool_result = None
    if node == 'agent1':
        pool_result = deallocate_owner_object()
    volume_result = destroy_exact_volume(volume, before)
    result = {'status': 'AUDITED_DABD_GENERATION_RETIRED', 'node': node, 'run': RUN,
              'journalFacts': journal_facts, 'liveAenvProcesses': processes,
              'serviceState': unit_text, 'poolCleanup': pool_result,
              'volumeCleanup': volume_result, 'journalsPreserved': True,
              'unknownShmdevsDeleted': False, 'sharedInstallFilesDeleted': False}
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(json.dumps({'status': 'AUDITED_DABD_GENERATION_CLEANUP_FAILED',
                          'reason': str(error)[:400]}, sort_keys=True), flush=True)
        raise SystemExit(1)
