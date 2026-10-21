"""Public deterministic PyPika workload; unrelated to private replay inputs.

This source runs inside each owned Guest. File byte counts describe the actual
read payload, not Host lower-file offsets or physical page-cache residency.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time


def make_dax_observer():
    """Query effective S_DAX on the same open FD, not an advisory inode flag.

    Linux v6.1 UAPI stat.h fixes the 256-byte statx layout, attributes at 0x08,
    inode/size at 0x20/0x28, attributes mask at 0x38, and DAX at 0x00200000.
    fcntl.h defines AT_EMPTY_PATH=0x1000. No syscall number is guessed.
    """
    try:
        import ctypes
        import struct
        if sys.platform != 'linux':
            raise RuntimeError('Linux statx required')
        libc = ctypes.CDLL(None, use_errno=True)
        call = libc.statx
        call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p]
        call.restype = ctypes.c_int
    except (AttributeError, ImportError, OSError, RuntimeError) as error:
        return lambda fd, meta: None, {'available': False, 'errorType': type(error).__name__}

    def observe(fd, meta):
        buffer = ctypes.create_string_buffer(256)
        if call(fd, b'', 0x1000, 0x7ff, buffer) != 0:
            return None
        raw = buffer.raw
        mask = struct.unpack_from('=I', raw, 0)[0]
        attributes = struct.unpack_from('=Q', raw, 8)[0]
        inode, size = struct.unpack_from('=QQ', raw, 32)
        supported = struct.unpack_from('=Q', raw, 56)[0]
        if (mask & 0x300 != 0x300 or inode != meta.st_ino or size != meta.st_size
                or supported & 0x00200000 == 0):
            return None
        return bool(attributes & 0x00200000)
    return observe, {'available': True, 'method': 'statx_AT_EMPTY_PATH_same_read_FD',
                     'attribute': 'STATX_ATTR_DAX', 'advisoryInodeFlagUsed': False}


def read_observed(path, remaining, observe):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= remaining:
            raise RuntimeError('Public workload file exceeds the bounded read set')
        first = observe(stream.fileno(), before)
        data = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
        last = observe(stream.fileno(), after)
        if (len(data) != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise RuntimeError('Public workload file changed during reading')
        # A missing attribute mask or changed effective policy is unknown, not
        # proof of buffered I/O. Attribute queries bracket this actual read FD.
        dax = first if type(first) is bool and type(last) is bool and first == last else None
        return data, dax


def dax_summary(observations):
    result = {'files': len(observations), 'daxFiles': 0, 'nonDaxFiles': 0, 'unknownFiles': 0,
              'daxReadPayloadBytes': 0, 'nonDaxReadPayloadBytes': 0, 'unknownReadPayloadBytes': 0,
              'scope': 'effective_DAX_on_actual_read_FDs',
              'physicalSharedBytes': None, 'hostLowerAccessResidencyMeasured': False}
    for value, size in observations:
        if type(size) is not int or size < 0 or (value is not None and type(value) is not bool):
            raise ValueError('Invalid file DAX observation')
        label = 'unknown' if value is None else 'dax' if value else 'nonDax'
        result[label + 'Files'] += 1
        result[label + 'ReadPayloadBytes'] += size
    result['complete'] = bool(observations) and result['unknownFiles'] == 0
    result['allReadFilesDax'] = result['daxFiles'] == len(observations) if result['complete'] else None
    return result


def run(token, peers):
    assert len(token) == 32 and all(c in '0123456789abcdef' for c in token)
    assert len(peers) == 2 and token in peers and len(set(peers)) == 2
    target = Path('/tmp/cow-private-' + token)
    assert not target.exists()
    with target.open('x') as stream:
        stream.write(token)
        stream.flush()
        os.fsync(stream.fileno())
    # The host checks again after both workers finish, so sequential scheduling
    # cannot turn this into a false isolation pass.
    start = time.monotonic()
    root = Path('/pypika')
    paths = sorted(p for p in root.rglob('*.py') if p.is_file() and not p.is_symlink())
    assert 0 < len(paths) <= 4096
    catalog = hashlib.sha256()
    total = 0
    observe, adapter = make_dax_observer()
    observations = []
    for path in paths:
        assert path.resolve().is_relative_to(root)
        data, dax = read_observed(path, 32 * 1024**2 - total, observe)
        total += len(data)
        assert total <= 32 * 1024**2
        observations.append((dax, len(data)))
        catalog.update(json.dumps([str(path.relative_to(root)), len(data),
                                   hashlib.sha256(data).hexdigest()], separators=(',', ':')).encode() + b'\n')
    os.chdir(root)
    sys.path.insert(0, str(root))
    from pypika import Query, Table
    customers = Table('customers')
    result = hashlib.sha256()
    for i in range(2000):
        sql = str(Query.from_(customers).select(customers.id, customers.name)
                  .where(customers.id >= i).orderby(customers.name).limit(20))
        result.update(sql.encode() + b'\n')
    elapsed = time.monotonic() - start
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemTotal', 'MemAvailable', 'Cached', 'Buffers', 'Shmem', 'Slab'):
            memory[key] = int(value.split()[0]) * 1024
    return {'revision': 'public-pypika-v2', 'fileCount': len(paths), 'fileBytes': total,
            'catalogSha256': catalog.hexdigest(), 'sqlSha256': result.hexdigest(),
            'queryCount': 2000, 'seconds': elapsed, 'guestMemoryBytes': memory,
            'guestCacheIncludedInGuestRam': True,
            'fileDax': {**dax_summary(observations), 'adapter': adapter},
            'hostLowerAccessRangesMeasured': False,
            'privateToken': token}


if __name__ == '__main__':
    print('COW_PUBLIC_RESULT=' + json.dumps(run(sys.argv[1], json.loads(sys.argv[2])), sort_keys=True))
