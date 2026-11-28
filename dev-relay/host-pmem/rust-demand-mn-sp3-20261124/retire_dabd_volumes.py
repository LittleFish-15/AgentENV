"""Retire the exact idle OBMM volumes from the audited dabd generation."""

import argparse
import errno
import fcntl
import json
import os
import struct
import subprocess
import uuid
from pathlib import Path


RUN = 'dabd65d32a1c5c3e91a994bbcbbb9e6f'
VOLUMES = {'agent1': '01a21fe3-9305-7e31-ac60-cb28b9532df5',
           'agent2': '01a21fe1-048a-7740-94a6-62f9e6927ecd'}
BOOTS = {'agent1': 'adca3a33-8bfd-4e89-b448-4f93385c68de',
         'agent2': '8b37b961-2b42-4c52-8aa7-8335cc52f52d'}
MACHINE_IDS = {'agent1': '498c7bb42c72427a8ce412b91776bc63',
               'agent2': '7579df430de64560b8d09b83baf1e2b0'}
SRCVERSION = '29F10664C1EE59D7127F8C7'
VOLUME_IDS = {'agent1': 10, 'agent2': 9}
VOLUME_LAYOUT = struct.Struct('<II16sIIII7Q')


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


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
    need(not process_inventory(), 'AENV consumer or provider is running')
    unit = subprocess.run(['/usr/bin/systemctl', 'show', 'aenv-mn-titanic.service',
                           '-p', 'LoadState', '-p', 'ActiveState', '-p', 'MainPID'],
                          capture_output=True, text=True, timeout=15, check=True)
    fields = dict(line.split('=', 1) for line in unit.stdout.splitlines() if '=' in line)
    need(fields.get('ActiveState') == 'inactive' and fields.get('MainPID') == '0',
         'AENV unit is not confirmed inactive')
    before = volume_query(volume)
    need(before['status'] == 'absent' or before['id'] == VOLUME_IDS[node],
         'exact volume ID differs from the same-boot audit')
    result = destroy_exact_volume(volume, before)
    print(json.dumps({'status': 'DABD_EXACT_VOLUME_RETIRED', 'node': node,
                      'run': RUN, 'volume': volume, 'cleanup': result},
                     sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(json.dumps({'status': 'AUDITED_DABD_GENERATION_CLEANUP_FAILED',
                          'reason': str(error)[:400]}, sort_keys=True), flush=True)
        raise SystemExit(1)
