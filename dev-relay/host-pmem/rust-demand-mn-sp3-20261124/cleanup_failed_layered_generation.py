"""Retire the audited failed M/N layered-demand generation without deleting evidence."""

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import stat
import struct
import time
import uuid
from pathlib import Path


RUN = 'dabd65d32a1c5c3e91a994bbcbbb9e6f'
PROVIDER = Path('/home/jwk/agent/sp3-mn/src/AgentENV/target/release/agentenv-ub-provider')
PROVIDER_SHA = '8624059e0f768341ca5f0f0217d4bb6398bef22c5e18836ff6c40a0f173e87f5'
SERVER = Path('/home/jwk/agent/sp3-mn/src/AgentENV/target/release/server')
SERVER_SHA = 'da57ec2c88e3c49748b6d32fd79a4b716b15a8496c34932b82e0f7fe45aff327'
UBLK = Path('/usr/local/lib/aenv/ublk/uvm-ublk-daemon')
ADAPTER = Path('/opt/aenv/libaenv-ub.so')
ADAPTER_SHA = 'a5379bbd70fbd244de07c312076a9ece23ce38452682dfed31b60f6fe3912dbc'
SRCVERSION = '29F10664C1EE59D7127F8C7'
POOL = '01a21fe4-7e16-7442-b4e7-592d12958c40'
OBJECT = 'aenv_' + uuid.UUID(POOL).hex
VOLUMES = {
    'agent1': '01a21fe3-9305-7e31-ac60-cb28b9532df5',
    'agent2': '01a21fe1-048a-7740-94a6-62f9e6927ecd',
}
BOOTS = {
    'agent1': 'adca3a33-8bfd-4e89-b448-4f93385c68de',
    'agent2': '8b37b961-2b42-4c52-8aa7-8335cc52f52d',
}
ROOT = Path('/etc/aenv/ub') / ('relay-' + RUN)
SDK = Path('/var/lib/aenv-ub-sdk') / ('relay-' + RUN)
OBMM = Path('/dev/obmm_pmem')
VOLUME_LAYOUT = struct.Struct('<II16sIIII7Q')


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def read_json(path):
    value = json.loads(path.read_text())
    need(isinstance(value, dict) and value.get('run') == RUN, 'journal identity differs: ' + str(path))
    return value


def volume_query(ident):
    need(Path('/sys/module/obmm/srcversion').read_text().strip() == SRCVERSION, 'OBMM source version differs')
    wire = bytearray(VOLUME_LAYOUT.size)
    struct.pack_into('<II16s', wire, 0, 1, 0, ident.bytes)
    fd = os.open(OBMM, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        try:
            fcntl.ioctl(fd, 0xc060b801, wire, True)
        except OSError as error:
            if error.errno == errno.ENOENT:
                return {'status': 'absent'}
            raise
    finally:
        os.close(fd)
    fields = ('version', 'reserved', 'uuid', 'id', 'state', 'major', 'minor', 'bytes',
              'openers', 'activeIo', 'blockReads', 'blockBytes', 'daxAccesses', 'daxSpanBytes')
    row = dict(zip(fields, VOLUME_LAYOUT.unpack(wire)))
    need(row['version'] == 1 and row['reserved'] == 0 and row['uuid'] == ident.bytes,
         'OBMM volume reply differs')
    row['uuid'] = str(ident)
    row['status'] = 'present'
    return row


def destroy_volume(ident, expected):
    observed = volume_query(ident)
    if observed['status'] == 'absent':
        return observed
    need(observed['state'] == 2 and observed['bytes'] == 2**32,
         'failed generation volume identity differs')
    need(observed['activeIo'] == 0 and observed['openers'] == 0,
         'failed generation volume still has readers')
    need({key: observed[key] for key in ('blockReads', 'blockBytes', 'daxAccesses', 'daxSpanBytes')} == expected,
         'failed generation acquired data after audit')
    wire = bytearray(VOLUME_LAYOUT.size)
    struct.pack_into('<II16sI', wire, 0, 1, 0, ident.bytes, observed['id'])
    fd = os.open(OBMM, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        fcntl.ioctl(fd, 0x4060b802, wire, True)
    finally:
        os.close(fd)
    need(volume_query(ident)['status'] == 'absent', 'OBMM volume retirement did not complete')
    return observed


def process_rows():
    rows = []
    for folder in Path('/proc').iterdir():
        if not folder.name.isdecimal():
            continue
        try:
            exe = Path(os.readlink(folder / 'exe'))
            argv = (folder / 'cmdline').read_bytes().split(b'\0')
            rows.append((int(folder.name), exe, argv))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return rows


def stop_pid(pid, exe, argv_prefix):
    folder = Path('/proc') / str(pid)
    handle = os.pidfd_open(pid)
    try:
        need(Path(os.readlink(folder / 'exe')) == exe, 'process executable changed')
        need((folder / 'cmdline').read_bytes().split(b'\0')[:len(argv_prefix)] == argv_prefix,
             'process command changed')
        signal.pidfd_send_signal(handle, signal.SIGTERM)
        waiter = select.poll()
        waiter.register(handle, select.POLLIN)
        need(waiter.poll(20000), 'process did not exit: ' + str(pid))
    finally:
        os.close(handle)


def stop_consumers_and_roles(host):
    rows = process_rows()
    need(not any(exe.name == 'firecracker' for _, exe, _ in rows), 'a Firecracker consumer is still active')
    root_cfg = ROOT / 'device-root.json'
    sdk_cfg = SDK / 'device-sdk.json'
    need(read_json(root_cfg)['node'] == host and read_json(sdk_cfg)['node'] == host,
         'provider configurations differ from this node')
    expected = {
        b'root': os.fsencode(root_cfg),
        b'sdk': os.fsencode(sdk_cfg),
    }
    selected = []
    for pid, exe, argv in rows:
        if exe == PROVIDER and len(argv) >= 3 and argv[1] in expected and argv[2] == expected[argv[1]]:
            selected.append((pid, exe, argv[:3]))
        elif host == 'agent1' and exe == SERVER:
            selected.append((pid, exe, argv[:1]))
        elif host == 'agent1' and exe == UBLK:
            selected.append((pid, exe, argv[:1]))
    provider_roles = {argv[1] for _, exe, argv in selected if exe == PROVIDER}
    need(provider_roles == {b'root', b'sdk'}, 'failed generation provider roles differ')
    for pid, exe, argv in sorted(selected, key=lambda row: (row[1] == PROVIDER and row[2][1] == b'sdk', row[0])):
        stop_pid(pid, exe, argv)
    remaining = process_rows()
    need(not any(exe == PROVIDER and len(argv) >= 3 and argv[2] in expected.values()
                 for _, exe, argv in remaining), 'failed generation provider survived')
    if host == 'agent1':
        need(not any(exe in (SERVER, UBLK) for _, exe, _ in remaining), 'old AENV consumer survived')
    return [pid for pid, _, _ in selected]


def deallocate_owner_object():
    need(sha(ADAPTER) == ADAPTER_SHA and not ADAPTER.stat().st_mode & 0o022,
         'SDK adapter differs from audited bytes')
    pid = os.fork()
    if pid == 0:
        try:
            os.initgroups('jwk', 1205)
            os.setgid(1205)
            os.setuid(1204)
            adapter = ctypes.CDLL(str(ADAPTER), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            for name in ('abi_version', 'configure_region', 'initialize', 'deallocate', 'finalize'):
                fn = getattr(adapter, 'aenv_ub_' + name)
                fn.argtypes = [ctypes.c_char_p] if name in ('configure_region', 'deallocate') else []
                fn.restype = ctypes.c_int
            need(adapter.aenv_ub_abi_version() == 3, 'adapter ABI differs')
            need(adapter.aenv_ub_configure_region(b'default') == 0, 'SDK region setup failed')
            need(adapter.aenv_ub_initialize() == 0, 'SDK initialize failed')
            result = adapter.aenv_ub_deallocate(OBJECT.encode())
            final = adapter.aenv_ub_finalize()
            need(result in (0, 6020) and final == 0, 'SDK deallocation failed')
        except Exception:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    need(status == 0, 'unprivileged SDK cleanup failed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', choices=('agent1', 'agent2'), required=True)
    parser.add_argument('--boot-id', required=True)
    args = parser.parse_args()
    need(os.geteuid() == 0 and os.uname().nodename.split('.')[0] == args.node, 'node identity differs')
    need(args.boot_id == BOOTS[args.node] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
         'boot identity differs')
    need(sha(PROVIDER) == PROVIDER_SHA and sha(SERVER) == SERVER_SHA, 'audited binary changed')
    root_state = read_json(ROOT / 'device-state/root.json')
    sdk_state = read_json(SDK / 'state/sdk.json')
    need(root_state['volume'] == VOLUMES[args.node], 'failed generation volume differs')
    if args.node == 'agent1':
        directory = read_json(SDK / ('directory-' + RUN + '.json'))
        need(directory.get('closed') is True and directory.get('faulted') is True,
             'owner directory is no longer the audited failed state')
        need(set(sdk_state.get('pools', {})) == {POOL}, 'owner pool set differs')
    else:
        need(not sdk_state.get('pools'), 'importer unexpectedly owns a pool')
    stopped = stop_consumers_and_roles(args.node)
    before = destroy_volume(uuid.UUID(VOLUMES[args.node]), {
        'blockReads': 0, 'blockBytes': 0, 'daxAccesses': 0, 'daxSpanBytes': 0,
    })
    if args.node == 'agent1':
        deallocate_owner_object()
    result = {
        'status': 'MN_FAILED_LAYERED_GENERATION_RETIRED', 'node': args.node, 'run': RUN,
        'stoppedPids': stopped, 'volume': VOLUMES[args.node], 'volumeBefore': before,
        'ownerObjectDeallocated': args.node == 'agent1', 'journalsPreserved': True,
        'ubseActive': os.system('/usr/bin/systemctl is-active --quiet ubse.service') == 0,
        'ubsmdActive': os.system('/usr/bin/systemctl is-active --quiet ubsmd.service') == 0,
    }
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
