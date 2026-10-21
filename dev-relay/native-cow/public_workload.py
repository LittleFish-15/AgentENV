"""Public deterministic PyPika workload; unrelated to private replay inputs.

This source runs inside each owned Guest. Reported file ranges are Guest path
reads only. They are NOT Host lower-file offsets or Host page-cache residency.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import time


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
    for path in paths:
        assert path.resolve().is_relative_to(root)
        data = path.read_bytes()
        total += len(data)
        assert total <= 32 * 1024**2
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
    return {'revision': 'public-pypika-v1', 'fileCount': len(paths), 'fileBytes': total,
            'catalogSha256': catalog.hexdigest(), 'sqlSha256': result.hexdigest(),
            'queryCount': 2000, 'seconds': elapsed, 'guestMemoryBytes': memory,
            'guestCacheIncludedInGuestRam': True,
            'hostLowerAccessRangesMeasured': False,
            'privateToken': token}


if __name__ == '__main__':
    print('COW_PUBLIC_RESULT=' + json.dumps(run(sys.argv[1], json.loads(sys.argv[2])), sort_keys=True))
