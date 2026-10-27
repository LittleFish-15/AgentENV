"""Acquire existing SDK-owned region FDs for the privileged Host pmem reader.

The ordinary provider is unchanged. Its explicit retirement must remain gated
on the root volume journal, including after a root-helper crash. Disconnect is
never a substitute for a local-volume-absent receipt or peer release receipts.
"""
import array
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import threading

from . import contract, host_pmem


def process_ticks(pid):
    return (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19]


def receive_segments(stream, lengths):
    """Consume one bounded SCM_RIGHTS message and close every rejected FD."""
    fds = []
    try:
        data, ancillary, flags, _ = stream.recvmsg(
            1, socket.CMSG_SPACE(32 * array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
        unknown = False
        for level, kind, content in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                unknown = True
                continue
            values = array.array('i')
            size = values.itemsize
            values.frombytes(content[:len(content) - len(content) % size])
            fds.extend(values)
            unknown |= bool(len(content) % size)
        if (data != b'F' or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or unknown
                or not 1 <= len(fds) <= 32 or len(fds) != len(lengths)
                or len(set(fds)) != len(fds) or any(fd < 0 for fd in fds)):
            raise ValueError('Invalid/truncated native region FD handoff')
        return [host_pmem.Segment(fd, 0, length) for fd, length in zip(fds, lengths)]
    except BaseException:
        for fd in set(fds):
            if fd >= 0:
                os.close(fd)
        raise


class NativeLease:
    def __init__(self, stream, segments, source):
        self.stream, self.segments, self.source = stream, segments, source
        self.volume = None
        self.closed = False

    def attach(self, control, save):
        if self.closed or self.volume is not None:
            raise RuntimeError('Lease already closed or attach attempted')
        control.validate_segments(self.segments)
        ranges=[]
        logical=0
        for segment in self.segments:
            metadata=os.fstat(segment.fd)
            ranges.append({'rdev':metadata.st_rdev,'offset':segment.offset,
                           'bytes':segment.bytes,'logicalOffset':logical})
            logical+=segment.bytes
        def journal(record):
            save({**record, 'source': self.source, 'segments':ranges})
        # Keep this object even when CREATE or its reply fails. It is the guard
        # against closing the lease while a kernel volume might still exist.
        self.volume = host_pmem.LocalVolume(control, journal)
        return self.volume.create(self.segments)

    def close(self):
        if self.closed:
            return
        if self.volume is not None and self.volume.record['phase'] not in ('new', 'local_volume_absent'):
            raise RuntimeError('Volume may remain; retain region FDs and SDK lease')
        for segment in self.segments:
            os.close(segment.fd)
        self.stream.close()
        self.closed = True


def acquire(spec, owner_uid, owner_pid, owner_ticks):
    """Root-only single-thread bootstrap; SDK operations stay in the owner.

    Temporarily use the authorized ordinary owner's EUID for connect so the
    existing provider's same-UID authentication still applies. Restore root in
    finally, then independently bind peer PID/UID/start time before any handoff.
    Never load an ordinary-user SDK library inside this privileged process.
    """
    contract.validate_spec(spec)
    if (sys.platform != 'linux' or os.getuid() != 0 or os.geteuid() != 0
            or threading.current_thread() is not threading.main_thread()
            or threading.active_count() != 1):
        raise RuntimeError('Host pmem handoff requires a single-threaded root helper')
    if (type(owner_uid) is not int or owner_uid <= 0 or type(owner_pid) is not int
            or owner_pid <= 0 or not isinstance(owner_ticks, str) or not owner_ticks.isdecimal()):
        raise ValueError('Missing exact ordinary provider identity')
    path = Path(spec['socket'])
    parent = path.parent
    parent_stat, endpoint = parent.stat(), path.lstat()
    if (parent.resolve(strict=True) != parent or parent_stat.st_uid != owner_uid
            or parent_stat.st_mode & 0o077 or not stat.S_ISSOCK(endpoint.st_mode)
            or endpoint.st_uid != owner_uid or endpoint.st_mode & 0o077
            or process_ticks(owner_pid) != owner_ticks):
        raise ValueError('Provider path or process identity differs')
    stream = None
    segments = []
    try:
        try:
            os.seteuid(owner_uid)
            stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stream.settimeout(10)
            stream.connect(str(path))
        finally:
            os.seteuid(0)
        pid, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != owner_pid or uid != owner_uid or process_ticks(pid) != owner_ticks:
            raise PermissionError('Provider peer identity changed')
        request = {'version': 2, 'operation': 'acquire', 'privateCow': False,
                   **{key: spec[key] for key in ('objectId', 'generation', 'sha256', 'bytes')}}
        contract.send_json(stream, request)
        response = contract.receive_json(stream)
        keys = {'version', 'state', 'backing', 'privateCow', 'source', 'cacheMode', 'segmentLengths'}
        if (not isinstance(response, dict) or set(response) != keys
                or type(response['version']) is not int or response['version'] != 2
                or response['state'] != 'ready' or response['backing'] != spec
                or response['privateCow'] is not False or response['source'] != 'ub'
                or response['cacheMode'] != 'nc'):
            raise ValueError('Native source identity or protocol differs')
        lengths = response['segmentLengths']
        if (not isinstance(lengths, list) or not 1 <= len(lengths) <= 32
                or any(type(length) is not int or length <= 0 or length % contract.ALIGN for length in lengths)
                or sum(lengths) != spec['bytes']):
            raise ValueError('Native source segment coverage differs')
        segments = receive_segments(stream, lengths)
        host_pmem.Control(-1).validate_segments(segments)  # Validation only; no ioctl.
        stream.settimeout(None)
        return NativeLease(stream, segments, {'backing': dict(spec), 'ownerUid': owner_uid,
                           'ownerPid': owner_pid, 'ownerStartTicks': owner_ticks,
                           'crossNodePhysicalIdentityAccepted': False})
    except BaseException:
        for segment in segments:
            os.close(segment.fd)
        if stream is not None:
            stream.close()
        raise
