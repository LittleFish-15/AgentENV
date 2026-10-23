"""Separate memory-lower files, live memory block-device cache and helpers.

All operations are read-only. Device residency can overlap file-backed Guest
RAM; its natural Host accounting comparison is Buffers, not an extra Cached
charge. After Guest exit there is no attempt to reopen old device numbers.
"""
import hashlib, os, re, stat, struct
from pathlib import Path


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def memory_lower_inventory(rt, observer, deployment, templates):
    need(len(templates) == 4, 'Four committed parents required for memory lower inventory')
    repository = deployment / 'state/snapshot-store/repository'
    groups = {}
    for index, template in enumerate(templates):
        sid = template['nativeTemplateId']
        need(template['templateIndex'] == index and re.fullmatch('[0-9a-f-]{36}', sid), 'Unexpected parent identity')
        raw = rt.read(repository / 'catalog/records' / (sid + '.json'))
        need(hashlib.sha256(raw).hexdigest() == template['snapshotEvidence']['committedRecordSha256'],
             'Committed parent record changed before memory inventory')
        import json
        record = json.loads(raw)
        need(record['id'] == sid and record['resources']['memory_mib'] == 4096, 'Parent RAM contract differs')
        layers = record['committed']['memory_layers']
        need(isinstance(layers, list) and 0 < len(layers) <= 32, 'Unexpected committed memory layers')
        for layer in layers:
            digest, size = layer['digest'], layer['size']
            need(isinstance(digest, str) and re.fullmatch('sha256:[0-9a-f]{64}', digest) and
                 type(size) is int and 0 < size <= 8 * 1024**3, 'Memory layer digest/size differs')
            # Exact POSIX repository naming from layout.rs, no glob/host scan.
            path = repository / 'managed-layers' / (digest.replace(':', '_') + '.overlaybd.commit')
            meta = observer.owned_regular(path, 8 * 1024**3)
            need(meta.st_size == size, 'Committed memory file length changed')
            key = meta.st_dev, meta.st_ino
            row = {'path': str(path), 'dev': meta.st_dev, 'inode': meta.st_ino, 'size': size,
                   'mtimeNs': meta.st_mtime_ns, 'ctimeNs': meta.st_ctime_ns, 'uid': meta.st_uid,
                   'digest': digest, 'templateIndices': [index]}
            if key in groups:
                previous = groups[key]
                need(all(previous[k] == row[k] for k in row if k != 'templateIndices'), 'Aliased memory layer differs')
                if index not in previous['templateIndices']:
                    previous['templateIndices'].append(index)
            else:
                groups[key] = row
    need(0 < len(groups) <= 128 and sum(r['size'] for r in groups.values()) <= 32 * 1024**3,
         'Memory lower observation exceeds total budget')
    return sorted(groups.values(), key=lambda row: (row['dev'], row['inode']))


def bind_device(backend, smaps, expected_bytes):
    need(re.fullmatch('/dev/ublkb[0-9]+', backend) is not None, 'Memory device outside scoped ublk name')
    path = Path(backend)
    need(path.resolve(strict=True) == path, 'Memory device redirected')
    meta = path.stat()
    need(stat.S_ISBLK(meta.st_mode), 'Memory backing no longer a block device')
    headers = []
    for line in smaps.splitlines():
        match = re.fullmatch(r'([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+'
                            r'([0-9a-f]+):([0-9a-f]+)\s+(\d+)\s*(.*)', line)
        if match and match[8] == backend:
            need(int(match[7]) == meta.st_ino and int(match[5], 16) == os.major(meta.st_dev) and
                 int(match[6], 16) == os.minor(meta.st_dev), 'Mapped memory device inode differs from current node')
            need(match[3].endswith('p') and int(match[4], 16) + int(match[2], 16) - int(match[1], 16) <= expected_bytes,
                 'Mapped memory device range differs')
            headers.append(line)
    need(bool(headers), 'No actual file VMA identifies the live memory device')
    return {'available': True, 'path': backend, 'dev': meta.st_dev, 'inode': meta.st_ino,
            'rdev': meta.st_rdev, 'virtualBytes': expected_bytes, 'namedVmaCount': len(headers)}


def device_groups(guests):
    groups, missing = {}, []
    for guest in guests:
        row = guest.get('memoryDevice', {})
        if row.get('available') is not True:
            missing.append(guest['sandboxId'])
            continue
        key = row['dev'], row['inode'], row['rdev']
        entry = groups.setdefault(key, {'binding': row, 'guests': []})
        need(all(entry['binding'][k] == row[k] for k in ('path', 'virtualBytes')), 'Shared device contract differs')
        entry['guests'].append(guest)
    return groups, missing


def device_cache(guests, observer):
    result = {'available': False, 'devices': [], 'missingGuestBindings': [], 'uniqueResidentPageBytes': None,
              'scope': 'live_memory_block_device_pagecache_not_per_Guest_access',
              'compareWithHostBuffers': True, 'addToHostCachedOrGuestPss': False,
              'GuestExitMeansCacheIsZero': False, 'contentReadOrFaulted': False}
    groups, missing = device_groups(guests)
    result['missingGuestBindings'] = missing
    if not groups:
        result['reason'] = 'No live bound memory device; old device numbers are not queried'
        return result
    import fcntl
    for entry in groups.values():
        binding, users = entry['binding'], entry['guests']
        row = {'sandboxIds': [g['sandboxId'] for g in users], 'binding': binding, 'residentPageBytes': None}
        fd = None
        try:
            def check_guests():
                for guest in users:
                    need(observer.identity(guest['pid'])[1] == guest['startTicks'], 'Guest changed around device observation')
            def check(meta):
                need(stat.S_ISBLK(meta.st_mode) and (meta.st_dev, meta.st_ino, meta.st_rdev) ==
                     tuple(binding[k] for k in ('dev', 'inode', 'rdev')), 'Device replaced during observation')
            check_guests()
            path = Path(binding['path'])
            need(path.resolve(strict=True) == path, 'Redirected memory device')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            check(os.fstat(fd));check(path.stat())
            # Linux ARM64 uapi: BLKGETSIZE64 = _IOR(0x12, 114, size_t).
            size = struct.unpack('Q', fcntl.ioctl(fd, 0x80081272, bytes(8)))[0]
            need(size == binding['virtualBytes'] == 4096 * 1024**2, 'Memory device capacity differs from RAM contract')
            page = os.sysconf('SC_PAGESIZE')
            count = observer.resident_pages(fd, size, page, max_bytes=8 * 1024**3)
            check(os.fstat(fd));check(path.stat());check_guests()
            row.update(available=True, residentPageBytes=count * page)
        except (OSError, ValueError, RuntimeError) as error:
            row.update(available=False, errorType=type(error).__name__,
                       reason=str(error)[:300] if isinstance(error, RuntimeError) else 'Device cache observation unavailable')
        finally:
            if fd is not None:
                os.close(fd)
        result['devices'].append(row)
    if not missing and all(r.get('available') is True for r in result['devices']):
        result.update(available=True, uniqueResidentPageBytes=sum(r['residentPageBytes'] for r in result['devices']))
    return result


def service_processes(main_pid, ticks, guest_pids, observer):
    rows, queue, seen = [], [main_pid], set()
    try:
        need(observer.identity(main_pid)[1] == ticks, 'Runtime changed before service observation')
        while queue:
            pid = queue.pop()
            if pid in seen:
                continue
            seen.add(pid);need(len(seen) <= 128, 'Service tree exceeds bound')
            proc = Path('/proc') / str(pid)
            try:
                start = observer.identity(pid)[1]
                comm = observer.bounded_text(proc / 'comm', 128).strip()
                if pid == main_pid or comm == 'uvm-ublk-daemon':
                    need(pid not in guest_pids, 'Service and Guest scopes overlap')
                    rows.append({'role': 'runtime' if pid == main_pid else 'ublk_daemon', 'pid': pid,
                                 'startTicks': start, 'wholeProcess': observer.whole_process_metrics(pid, start)})
                tasks = list((proc / 'task').iterdir());need(len(tasks) <= 512, 'Service thread budget exceeded')
                for task in tasks:
                    try: children = observer.bounded_text(task / 'children', 8192).split()
                    except FileNotFoundError: continue
                    need(len(children) <= 128 and all(c.isdecimal() for c in children), 'Service children exceed scope')
                    for child in children:
                        try: parent = observer.identity(int(child))[0]
                        except (FileNotFoundError, ProcessLookupError): continue
                        if parent == pid: queue.append(int(child))
                need(observer.identity(pid)[1] == start, 'Service PID changed during tree scan')
            except (FileNotFoundError, ProcessLookupError):
                continue
        need(observer.identity(main_pid)[1] == ticks, 'Runtime changed after service observation')
        return {'available': bool(rows), 'processes': rows, 'visitedDescendants': len(seen),
                'scope': 'this_Runtime_and_its_ublk_daemons_only', 'includedInRuntimeCgroupCharge': True}
    except (OSError, ValueError, RuntimeError) as error:
        return {'available': False, 'processes': rows, 'errorType': type(error).__name__}
