"""Serve existing immutable FS-DAX files; never create pmem or claim UB provenance.

The external volume owner must retain the publication on both nodes until all
consumers exit. File and socket leases cannot pin an unspecified UB allocator.
No SDK, mount, format, release, remount, or fallback-to-cached-file operation.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import signal
import stat
import struct
import threading
from . import contract as n
from .raw import RawProvider


def validate_fd(fd, length):
    import fcntl
    info = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    if (not stat.S_ISREG(info.st_mode) or info.st_size != length
            or flags & os.O_ACCMODE != os.O_RDONLY or flags & os.O_SYNC):
        raise ValueError('FS-DAX requires an exact-length readonly regular FD')
    libc = ctypes.CDLL(None, use_errno=True)
    statx = libc.statx
    statx.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                     ctypes.c_uint, ctypes.c_void_p]
    statx.restype = ctypes.c_int
    data = ctypes.create_string_buffer(256)
    if statx(fd, b'', 0x1000, 0x7ff, data) != 0:  # AT_EMPTY_PATH, BASIC_STATS
        raise OSError(ctypes.get_errno(), 'statx on FS-DAX FD failed')
    attributes = struct.unpack_from('=Q', data.raw, 8)[0]
    size = struct.unpack_from('=Q', data.raw, 40)[0]
    supported = struct.unpack_from('=Q', data.raw, 56)[0]
    if not supported & 0x200000 or not attributes & 0x200000 or size != length:
        raise ValueError('File does not have active S_DAX')
    if not os.fstatvfs(fd).f_flag & os.ST_RDONLY:
        raise ValueError('FS-DAX publication must be on a readonly mount')
    return {'device': info.st_dev, 'inode': info.st_ino, 'bytes': size,
            'activeDax': True, 'readonlyMount': True,
            'crossNodePhysicalIdentityAccepted': False}


class FsDaxProvider(RawProvider):
    def prepare_handoff(self, request):
        if (not isinstance(request, dict)
                or set(request) != {'version', 'operation', 'objectId', 'generation', 'sha256', 'bytes', 'privateCow'}
                or type(request['version']) is not int or request['version'] != 3
                or request['operation'] != 'acquire' or type(request['privateCow']) is not bool):
            raise ValueError('FS-DAX requires explicit protocol version 3')
        spec, segments = self.objects[request['objectId']]
        if (len(segments) != 1 or segments[0][1] != spec['bytes']
                or type(request['bytes']) is not int
                or any(request[k] != spec[k] for k in ('objectId', 'generation', 'sha256', 'bytes'))):
            raise ValueError('FS-DAX publication identity/layout differs')
        validate_fd(segments[0][0], spec['bytes'])
        return segments, {'version': 3, 'state': 'ready', 'backing': spec,
                          'privateCow': request['privateCow'], 'source': 'fs-dax',
                          'cacheMode': 'fs-dax'}


def open_catalog(catalog, socket_path, budget):
    if set(catalog) != {'version', 'objects'}:
        raise ValueError('Unexpected FS-DAX catalog fields')
    entries = n.validate_catalog(catalog, socket_path, budget)
    opened, observed = [], []
    try:
        for entry in entries:
            if set(entry) != {'path', 'backing'}:
                raise ValueError('FS-DAX catalog needs path and backing only')
            path = Path(entry['path'])
            if not path.is_absolute() or path.resolve(strict=True) != path:
                raise ValueError('FS-DAX path must be absolute without symlinks')
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
            opened.append((entry['backing'], [(fd, entry['backing']['bytes'])]))
            observed.append(validate_fd(fd, entry['backing']['bytes']))
        return opened, observed
    except BaseException:
        for _, segments in opened:
            os.close(segments[0][0])
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', required=True)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--max-bytes', required=True, type=int)
    args = parser.parse_args()
    n.linux_only()
    with open(args.catalog, 'rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('FS-DAX catalog exceeds 1MiB')
    entries, observed = open_catalog(json.loads(raw), args.socket, args.max_bytes)
    provider = FsDaxProvider(entries)
    stop = threading.Event()
    started = False
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    try:
        provider.start(args.socket)
        started = True
        print(json.dumps({'state': 'serving', 'source': 'fs-dax', 'files': observed,
                          'SDK_called': False, 'KVM_tested': False,
                          'externalPublicationMustRemainImmutableAndRetained': True}), flush=True)
        stop.wait()
    finally:
        if started:
            # Retire even if stdout disconnects or the main loop raises. Never
            # close source FDs while a handoff worker can still use their numbers.
            with provider.condition:
                provider.retiring = True
                provider.condition.wait_for(lambda: provider.active == 0)
            provider.stop()
        # These are local open-file references only; external bases stay intact.
        for _, segments in entries:
            os.close(segments[0][0])
    print(json.dumps({'state': 'local_provider_stopped',
                      'externalPublicationReleased': False}), flush=True)


if __name__ == '__main__':
    main()
