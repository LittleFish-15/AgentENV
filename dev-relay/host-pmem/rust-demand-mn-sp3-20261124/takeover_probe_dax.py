"""Read one known cold page through the production lower FD broker on M/N."""

import argparse
import array
import ctypes
import fcntl
import hashlib
import json
import os
import socket
import stat
import struct
import time
import uuid
from pathlib import Path


PAGE = 4096
LOWER_BYTES = 536870912
LOWER_SHA = 'sha256:42d2db6070a949f224fc2df0219d0bba969488dc57d1dba84aa39b45e65e4799'
PAGE_SHA = '6bd900c96e481ae146ac51e0145fe47fa2343bb07dc0409a0f5d5d3b13eb31d5'
PROVIDER = Path('/opt/aenv/bin/agentenv-ub-provider-5ecfe105')


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def document(path):
    with path.open('rb') as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    need(len(raw) <= 2 * 1024 * 1024, 'Oversized index or journal')
    return json.loads(raw)


def verify_fd(fd):
    info = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    need(stat.S_ISREG(info.st_mode) and info.st_size == LOWER_BYTES
         and flags & os.O_ACCMODE == os.O_RDONLY and not flags & getattr(os, 'O_PATH', 0),
         'Broker FD is not the expected read-only lower')
    status = ctypes.create_string_buffer(256)
    libc = ctypes.CDLL(None, use_errno=True)
    statx = libc.statx
    statx.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p)
    statx.restype = ctypes.c_int
    if statx(fd, b'', 0x1000, 0x201, status) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    mask, attributes = struct.unpack_from('<I4xQ', status.raw)
    size, attr_mask = struct.unpack_from('<Q8xQ', status.raw, 40)
    need(mask & 0x201 == 0x201 and size == LOWER_BYTES
         and attributes & attr_mask & 0x00200000
         and os.fstatvfs(fd).f_flag & os.ST_RDONLY, 'Returned lower is not on a read-only S_DAX mount')


def broker_read(replica):
    descriptors = array.array('i')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(8)
        client.connect(replica['brokerSocket'])
        _, uid, _ = struct.unpack('iII', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(uid == 0, 'Broker must run as root')
        payload = json.dumps(replica, ensure_ascii=True, separators=(',', ':')).encode()
        need(len(payload) <= 1024 * 1024, 'Oversized broker OPEN')
        client.sendall(b'AENVFD1\x00' + struct.pack('>I', len(payload)) + payload)
        marker, messages, flags, _ = client.recvmsg(1, socket.CMSG_SPACE(253 * descriptors.itemsize),
                                                    socket.MSG_CMSG_CLOEXEC)
        try:
            for level, kind, data in messages:
                if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                    descriptors.frombytes(data[:len(data) - len(data) % descriptors.itemsize])
            need(marker == b'\x01' and not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
                 and len(descriptors) == 1, 'Broker did not provide exactly one complete FD')
            fd = descriptors[0]
            verify_fd(fd)
            start = time.monotonic_ns()
            result = os.pread(fd, PAGE, 0)
            elapsed = time.monotonic_ns() - start
            need(len(result) == PAGE, 'Short DAX read')
            return {'readerUid': os.geteuid(), 'bytes': len(result), 'sha256': hashlib.sha256(result).hexdigest(),
                    'preadNs': elapsed, 'verifiedDaxFd': True}
        finally:
            for fd in descriptors:
                os.close(fd)


def read_as_reader(replica, uid, gid):
    read_end, write_end = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_end)
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            result = broker_read(replica)
            code = 0
        except (OSError, RuntimeError, ValueError) as error:
            result, code = {'readError': type(error).__name__, 'message': str(error)}, 1
        with os.fdopen(write_end, 'wb') as stream:
            stream.write(json.dumps(result).encode())
        os._exit(code)
    os.close(write_end)
    with os.fdopen(read_end, 'rb') as stream:
        raw = stream.read(4096)
    _, outcome = os.waitpid(child, 0)
    need(raw, 'Reader did not return a receipt')
    result = json.loads(raw)
    print(json.dumps({'event': 'dax_page_read', **result}), flush=True)
    need(os.WIFEXITED(outcome) and os.WEXITSTATUS(outcome) == 0 and result['sha256'] == PAGE_SHA,
         'Page read or fixed source digest validation failed')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=uuid.UUID, required=True)
    parser.add_argument('--root-pid', type=int, required=True)
    parser.add_argument('--manifest-sha', required=True)
    args = parser.parse_args()
    run = args.run.hex
    host = os.uname().nodename.split('.')[0]
    need(os.geteuid() == 0 and host in ('agent1', 'agent2'), 'Use the unified M/N root entry')
    root = Path('/etc/aenv/ub') / ('relay-' + run)
    config_path = root / 'device-root.json'
    proc = Path('/proc') / str(args.root_pid)
    need(proc.joinpath('exe').resolve(strict=True) == PROVIDER and
         proc.joinpath('cmdline').read_bytes().split(b'\x00')[1:3] == [b'root', os.fsencode(config_path)],
         'Expected Provider PID/generation is no longer active')
    cfg = document(config_path)
    need(cfg['run'] == run and cfg['node'] == host and cfg['manifestSha256'] == args.manifest_sha,
         'Root config does not match the scheduled run')
    idx = document(root / 'index/stable-index.json')
    need(idx['version'] == 3 and idx['state'] == 'metadata_ready' and len(idx['replicas']) == 1,
         'Expected single-lower ready index')
    replica = idx['replicas'][0]
    need(replica['generation'] == run and replica['layerDigest'] == LOWER_SHA
         and replica['fileBytes'] == LOWER_BYTES and replica['manifestSha256'] == 'sha256:' + args.manifest_sha
         and replica['brokerSocket'] == str(root / 'broker/broker.sock'), 'Index lower identity differs')
    layout = replica['stablePmem']
    extent = layout['extents'][0]
    need(extent['fileOffset'] == 0 and extent['bytes'] >= PAGE and extent['deviceOffset'] % PAGE == 0
         and layout['loadBytes'] == 262144, 'Unexpected page mapping')
    slot_index = extent['deviceOffset'] // layout['loadBytes']
    before = document(root / 'device-state/root.json')
    need(before['run'] == run and slot_index not in before['bindings'], 'Test page already bound on this node')
    owner = host == 'agent1'
    if owner:
        with Path('/root/aenv-pmem/aenv-template.ext4').open('rb') as original:
            need(hashlib.sha256(original.read(PAGE)).hexdigest() == PAGE_SHA, 'Original fixture page differs')
        directory = Path('/var/lib/aenv-ub-sdk') / ('relay-' + run) / ('directory-' + run + '.json')
        prior = document(directory)
        need(prior['run'] == run and not prior['closed'] and not prior['faulted']
             and set(prior['ready']) == {'agent1', 'agent2'} and str(slot_index) not in prior['units']
             and slot_index not in before['written'], 'Expected cold unit is already published or admission closed')
    print(json.dumps({'event': 'before_page_read', 'node': host, 'run': run, 'unit': slot_index,
                      'deviceOffset': extent['deviceOffset'], 'localBound': False,
                      'absentFromOwnerDirectory': True if owner else None}), flush=True)
    result = read_as_reader(replica, cfg['device']['readerUid'], cfg['device']['readerGid'])
    for _ in range(40):
        after = document(root / 'device-state/root.json')
        if slot_index in after['bindings']:
            break
        time.sleep(0.125)
    else:
        raise RuntimeError('Provider journal has no completed bind for the tested unit')
    entry = None
    if owner:
        current = document(directory)
        row = current['units'].get(str(slot_index))
        need(row and row['ready'] is True and slot_index in after['written'], 'Owner fill was not verified and published')
        entry = row['unit']
    else:
        need(slot_index not in after['written'], 'Importer unexpectedly wrote the unit')
    print(json.dumps({'status': 'MN_DAX_PAGE_VERIFIED', 'node': host, 'run': run, 'unit': slot_index,
                      'volume': after['volume'], 'poolSegments': after['pool_segments'], 'ownerUnit': entry,
                      'ownerWroteUnit': slot_index in after['written'], **result}), flush=True)


if __name__ == '__main__':
    main()
