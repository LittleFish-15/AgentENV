"""Authoritative FC RAM intervals; no memory-content or PFN export.

Derived from the already reviewed read-only collector. Private smaps mappings
describe local snapshot CoW; they do not establish cross-node physical sharing.
"""
import ctypes,http.client,json,os,re,socket,stat,struct
from pathlib import Path
def require(ok,message):
    if not ok: raise RuntimeError(message)

def identity(pid):
    s=(Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()
    return int(s[1]),s[19]

def find_firecrackers(main_pid,proc_root=Path('/proc')):
    queue=[main_pid];seen=set();found=[]
    while queue:
        pid=queue.pop()
        if pid in seen:continue
        seen.add(pid);require(len(seen)<=128,'Process tree exceeds bound')
        proc=proc_root/str(pid)
        try:
            ticks=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
            if (proc/'comm').read_text().strip()=='firecracker':found.append(pid)
            tasks=list((proc/'task').iterdir());require(len(tasks)<=512,'Thread count exceeds bound')
            for task in tasks:
                try:children=(task/'children').read_text().split()
                except FileNotFoundError:continue
                require(len(children)<=128,'Child count exceeds bound')
                for child in children:
                    require(child.isdecimal(),'Invalid child PID')
                    try:parent=(proc_root/child/'stat').read_text().rsplit(')',1)[1].split()[1]
                    except FileNotFoundError:continue
                    if int(parent)==pid:queue.append(int(child))
            require((proc/'stat').read_text().rsplit(')',1)[1].split()[19]==ticks,'Tree PID changed')
        except FileNotFoundError:continue
    return sorted(found)

def memory_backend(text):
    matches=[]
    for line in text.splitlines():
        if 'Put request on "/snapshot/load"' not in line: continue
        match=re.search(r'with body (".*")\.$',line)
        require(match is not None,'Unrecognized snapshot-load log syntax')
        body=json.loads(json.loads(match[1]))
        backend=body.get('mem_backend',{})
        require(backend.get('backend_type')=='File','Memory backend is not File')
        path=backend.get('backend_path','')
        require(re.fullmatch(r'/dev/ublkb[0-9]+',path),'Unexpected memory device')
        matches.append(path)
    require(len(matches)==1,'Expected exactly one snapshot load')
    return matches[0]

class BindingError(RuntimeError):
    def __init__(self,message,diagnostics):
        super().__init__(message);self.diagnostics=diagnostics

def guest_regions(cwd,pid):
    path=cwd/'firecracker.socket'
    require(path.resolve(strict=True)==path,'Redirected Firecracker socket')
    meta=path.stat()
    require(stat.S_ISSOCK(meta.st_mode) and meta.st_uid==1204,'Unexpected Firecracker socket metadata')
    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    connection=http.client.HTTPConnection('localhost',timeout=10)
    try:
        client.settimeout(10);client.connect(str(path))
        peer_pid,peer_uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        require(peer_pid==pid and peer_uid==1204,'Firecracker API socket peer identity differs')
        connection.sock=client
        connection.request('GET','/vm/guest-memory-regions')
        response=connection.getresponse();raw=response.read(1024**2+1)
        if response.status!=200:
            raise BindingError('Guest memory region API unavailable; no guessed anonymous ranges',
                               {'pid':pid,'guest_region_api_status':response.status})
        require(len(raw)<=1024**2,'Guest region API response too large')
        return json.loads(raw)
    finally:
        connection.close();client.close()

def parse_guest_smaps(text,device,expected_bytes,regions=None):
    maps=[];current=None
    for line in text.splitlines():
        match=re.match(r'^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$',line)
        if match:
            current=None
            current={'start':int(match[1],16),'end':int(match[2],16),
                     'offset':int(match[4],16),'permissions':match[3],'path':match[5],'bytes':{}}
            maps.append(current)
        elif current is not None:
            field=re.fullmatch(r'(\w+):\s+(\d+) kB',line)
            if field: current['bytes'][field[1]]=int(field[2])*1024
    exact=[m for m in maps if m['path']==device]
    diagnostic={'memory_device':device,'expected_guest_bytes':expected_bytes,
                'device_named_vma_bytes':sum(m['end']-m['start'] for m in exact),
                'device_named_vma_count':len(exact),
                'device_named_vmas_preview':[{k:v for k,v in m.items() if k!='bytes'} for m in exact[:16]],
                'all_vma_count':len(maps)}
    if regions is None:
        if not exact or diagnostic['device_named_vma_bytes']!=expected_bytes:
            raise BindingError('Guest memory VMA coverage differs from snapshot RAM; no size-only guess',diagnostic)
        require(all(m['permissions'].endswith('p') for m in exact),'Guest memory mapping is not private')
        return exact
    require(isinstance(regions,list) and 0<len(regions)<=32,'Unexpected Guest region API shape')
    intervals=[];page=os.sysconf('SC_PAGESIZE')
    for region in regions:
        start,size,offset=[region.get(k) for k in ('base_host_virt_addr','size','offset')]
        require(all(type(x) is int for x in (start,size,offset)) and start>0 and size>0 and offset>=0
                and start%page==size%page==offset%page==0,'Invalid Guest region addresses')
        intervals.append((start,start+size,offset))
    intervals.sort()
    require(all(a[1]<=b[0] for a,b in zip(intervals,intervals[1:])),'Overlapping Guest address regions')
    file_intervals=sorted((o,o+e-s) for s,e,o in intervals)
    require(file_intervals[0][0]==0 and file_intervals[-1][1]==expected_bytes
            and all(a[1]==b[0] for a,b in zip(file_intervals,file_intervals[1:])),
            'Guest API snapshot offsets do not cover expected RAM exactly')
    selected=[]
    for start,end,offset in intervals:
        cursor=start
        for m in maps:
            low=max(start,m['start']);high=min(end,m['end'])
            if low>=high:continue
            if low!=cursor:
                raise BindingError('Guest API region has unmapped/overlapping smaps coverage',diagnostic)
            require(m['permissions'].endswith('p'),'Guest API interval is not privately mapped')
            file_named=m['path']==device
            anonymous=m['path']=='' or m['path'].startswith('[anon:')
            if not(file_named or anonymous):
                raise BindingError('Unexpected file mapping inside authoritative Guest RAM interval',diagnostic)
            if file_named:
                require(m['offset']+low-m['start']==offset+low-start,'Memory backing file offset differs from Guest API')
            clipped=low!=m['start'] or high!=m['end']
            selected.append({'start':low,'end':high,'offset':m['offset']+low-m['start'],
                             'permissions':m['permissions'],'mapping_kind':'snapshot_file_vma' if file_named else 'anonymous_inside_guest_region',
                             'bytes':{} if clipped else m['bytes'],'smaps_metrics_omitted_due_to_clipping':clipped})
            cursor=high
        if cursor!=end:raise BindingError('Guest API region not fully covered by smaps',diagnostic)
    require(sum(m['end']-m['start'] for m in selected)==expected_bytes,'Guest range accounting differs')
    return selected

# Functions appended to the scoped RAM observer; no content-read sampling.


def owned_regular(path, limit):
    require(path.resolve(strict=True) == path, 'Redirected cache metadata path')
    meta = path.stat()
    require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204 and 0 <= meta.st_size <= limit,
            'Unexpected cache file metadata')
    return meta


def cache_path(value, config_dir, roots, allowed_files=()):
    require(isinstance(value, str) and value and '\x00' not in value, 'Missing cache file path')
    original = Path(value)
    original = original if original.is_absolute() else config_dir / original
    path = Path(os.path.abspath(original))
    require((any(path.is_relative_to(root) for root in roots) or path in allowed_files)
            and original.resolve(strict=True) == path, 'Cache file outside owned scope or redirected')
    return path


def upper_files(base, cwd, allowed_lowers=()):
    config_path = cwd / 'overlaybd/image.json'
    before = owned_regular(config_path, 2 * 1024**2)
    config = json.loads(config_path.read_text())
    after = owned_regular(config_path, 2 * 1024**2)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            'Rootfs config changed during cache binding')
    lowers = config.get('lowers')
    require(isinstance(lowers, list) and 0 < len(lowers) <= 128, 'Unexpected rootfs lower inventory')
    lower_ids = set()
    for row in lowers:
        require(isinstance(row, dict) and not row.get('ub'), 'Unsupported rootfs lower placement')
        path = cache_path(row.get('file'), config_path.parent, (cwd, base / 'state'), allowed_lowers)
        meta = owned_regular(path, 128 * 1024**3)
        lower_ids.add((meta.st_dev, meta.st_ino))
    upper = config.get('upper')
    require(isinstance(upper, dict), 'Rootfs writable upper absent')
    result = []
    for name in ('data', 'index'):
        path = cache_path(upper.get(name), config_path.parent, (cwd,))
        meta = owned_regular(path, 2 * 1024**3)
        require((meta.st_dev, meta.st_ino) not in lower_ids, 'Upper aliases a lower file')
        result.append({'kind': name, 'path': path, 'dev': meta.st_dev, 'inode': meta.st_ino})
    require(len({(r['dev'], r['inode']) for r in result}) == len(result), 'Upper data/index alias')
    return result, lower_ids


def resident_pages(fd, size, page, max_bytes=2 * 1024**3):
    require(type(size) is int and 0 <= size <= max_bytes <= 8 * 1024**3
            and type(page) is int and 4096 <= page <= 65536 and page & (page - 1) == 0,
            'Cache observation size/page bound differs')
    if size == 0:
        return 0
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    cached = 0
    for offset in range(0, size, 64 * 1024**2):
        length = min(64 * 1024**2, size - offset)
        # PROT_NONE + MAP_SHARED: query cache metadata without dereferencing or
        # faulting the content. No pread, page touching or cache eviction.
        address = libc.mmap(None, length, 0, 1, fd, offset)
        require(address not in (None, ctypes.c_void_p(-1).value), 'Cache observation mmap failed')
        try:
            vector = (ctypes.c_ubyte * ((length + page - 1) // page))()
            require(libc.mincore(address, length, vector) == 0, 'Cache residency query unavailable')
            cached += sum(bool(value & 1) for value in vector)
        finally:
            require(libc.munmap(address, length) == 0, 'Cache observation munmap failed')
    return cached


def upper_cache(base, cwd, allowed_lowers=()):
    result = {'available': False, 'files': [], 'scope': 'private_host_upper_file_cache',
              'contentReadOrFaulted': False, 'atomicSnapshot': False,
              'includedInRuntimeCgroupCharge': 'may_overlap_do_not_add_to_cgroup_total'}
    try:
        selected, lower_ids = upper_files(base, cwd, allowed_lowers)
        page = os.sysconf('SC_PAGESIZE')
        for row in selected:
            fd = os.open(row['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                before = os.fstat(fd)
                require(stat.S_ISREG(before.st_mode) and before.st_uid == 1204
                        and (before.st_dev, before.st_ino) == (row['dev'], row['inode']),
                        'Upper identity changed before cache sampling')
                count = resident_pages(fd, before.st_size, page)
                after = os.fstat(fd)
                require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                        'Writable upper changed during sampling; no stable charge attributed')
                result['files'].append({'kind': row['kind'], 'dev': row['dev'], 'inode': row['inode'],
                                        'logicalBytes': before.st_size, 'allocatedFileBytes': before.st_blocks * 512,
                                        'residentPageBytes': count * page})
            finally:
                os.close(fd)
        result.update(available=True, lowerFileIdentities=sorted(lower_ids),
                      residentPageBytes=sum(row['residentPageBytes'] for row in result['files']))
    except Exception as error:
        result.update(errorType=type(error).__name__, reason=str(error)[:400]
                      if isinstance(error, RuntimeError) else 'Scoped upper observation unavailable')
    return result


def aggregate_upper(guests):
    rows = [g.get('rootfsUpper', {}) for g in guests]
    if not rows or not all(row.get('available') is True for row in rows):
        return {'available': False, 'residentPageBytes': None, 'reason': 'Incomplete per-Guest upper observation'}
    upper_ids = [(f['dev'], f['inode']) for row in rows for f in row['files']]
    lower_ids = {tuple(identity) for row in rows for identity in row['lowerFileIdentities']}
    if len(set(upper_ids)) != len(upper_ids) or set(upper_ids) & lower_ids:
        return {'available': False, 'residentPageBytes': None, 'reason': 'Upper alias across Guests/lower files'}
    return {'available': True, 'residentPageBytes': sum(row['residentPageBytes'] for row in rows),
            'fileCount': len(upper_ids), 'allUpperFilesDistinct': True,
            'scope': 'private_host_upper_file_cache_only', 'hostLowerAccessResidencyMeasured': False,
            'addToRuntimeCgroupTotal': False}


# This file is appended to the pinned RAM/API/mincore parser at packaging time.
import time

PROC = Path('/proc')
MAX_TEXT = 4 * 1024**2
ROLLUP_FIELDS = ('Rss', 'Pss', 'Pss_Anon', 'Pss_File', 'Pss_Shmem',
                 'Private_Clean', 'Private_Dirty', 'Shared_Clean', 'Shared_Dirty', 'Swap')


def bounded_text(path, limit=MAX_TEXT):
    with Path(path).open(encoding='utf-8', errors='strict') as stream:
        text = stream.read(limit + 1)
    require(len(text) <= limit, 'Observation exceeds text budget')
    return text


def kb_fields(text, names):
    result = {}
    for name in names:
        matches = re.findall(r'^' + re.escape(name) + r':\s+(\d+) kB$', text, re.M)
        result[name] = int(matches[0]) * 1024 if len(matches) == 1 else None
    return result


def unavailable(error):
    return {'available': False, 'errorType': type(error).__name__,
            'reason': str(error)[:300] if isinstance(error, RuntimeError) else 'Observation unavailable'}


def maybe(call):
    try:
        return call(), None
    except (OSError, ValueError, RuntimeError) as error:
        return None, unavailable(error)


def whole_process_metrics(pid, ticks):
    """Keep each readable metric when optional rollup fields/PSI are absent."""
    result = {'scope': 'whole_process', 'available': False, 'atomicSnapshot': False,
              'rss_source': 'status.VmRSS', 'pss_source': 'smaps_rollup.Pss'}
    try:
        require(identity(pid)[1] == ticks, 'Process changed before observation')
        status, status_error = maybe(lambda: bounded_text(PROC / str(pid) / 'status', 65536))
        rollup, rollup_error = maybe(lambda: bounded_text(PROC / str(pid) / 'smaps_rollup', 65536))
        rss = kb_fields(status or '', ('VmRSS',))['VmRSS']
        values = kb_fields(rollup or '', ROLLUP_FIELDS)
        require(identity(pid)[1] == ticks, 'Process changed during observation')
        pss = values['Pss']
        result.update(available=rss is not None or pss is not None,
                      rss_bytes=rss, pss_bytes=pss, smaps_rollup_rss_bytes=values['Rss'],
                      rss_minus_pss_bytes=rss - pss if rss is not None and pss is not None else None,
                      rollupBytes=values, errors={'status': status_error, 'rollup': rollup_error})
    except (OSError, ValueError, RuntimeError) as error:
        result.update(unavailable(error))
    return result


def host_observation(proc=PROC):
    result = {'atomicSnapshot': False, 'wholeHostIdleEstablished': False,
              'startNs': time.time_ns(), 'errors': {}}
    text, error = maybe(lambda: bounded_text(proc / 'meminfo', 65536))
    result['memoryBytes'] = kb_fields(text or '', (
        'MemTotal', 'MemFree', 'MemAvailable', 'Cached', 'Buffers', 'Dirty', 'Writeback',
        'AnonPages', 'Mapped', 'Shmem', 'Slab', 'SReclaimable', 'SUnreclaim', 'PageTables',
        'KernelStack', 'SwapTotal', 'SwapFree'))
    result['errors']['meminfo'] = error
    result['pressure'] = {}
    for name in ('cpu', 'memory', 'io'):
        value, error = maybe(lambda n=name: bounded_text(proc / 'pressure' / n, 65536))
        result['pressure'][name] = value
        result['errors']['pressure.' + name] = error
    result['available'] = any(v is not None for v in result['memoryBytes'].values())
    result['endNs'] = time.time_ns()
    return result


def decode_mount(text):
    return re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), text)


def memory_cgroup_directory(cgroup_text, mountinfo_text):
    """Resolve the memory controller's real mount, including v1/hybrid roots."""
    memberships = []
    for line in cgroup_text.splitlines():
        parts = line.split(':', 2)
        require(len(parts) == 3, 'Invalid cgroup membership')
        controllers, group = parts[1], parts[2]
        require(group.startswith('/') and '..' not in group.split('/'), 'Invalid cgroup path')
        if 'memory' in controllers.split(','):
            memberships.append(('v1', group))
        elif parts[0] == '0' and controllers == '':
            memberships.append(('v2', group))
    # Hybrid systems may expose unified membership while memory remains in v1.
    selected = [m for m in memberships if m[0] == 'v1'] or [m for m in memberships if m[0] == 'v2']
    require(len(selected) == 1, 'Memory controller membership unavailable/ambiguous')
    version, group = selected[0]
    matches = []
    for line in mountinfo_text.splitlines():
        left, sep, right = line.partition(' - ')
        require(bool(sep), 'Invalid mountinfo line')
        fields, tail = left.split(), right.split()
        require(len(fields) >= 6 and len(tail) >= 3, 'Invalid mountinfo fields')
        kind = tail[0]
        if not ((version == 'v2' and kind == 'cgroup2') or
                (version == 'v1' and kind == 'cgroup' and 'memory' in tail[2].split(','))):
            continue
        root, mount = decode_mount(fields[3]), decode_mount(fields[4])
        require(root.startswith('/') and mount.startswith('/') and
                '..' not in root.split('/') and '..' not in mount.split('/'), 'Invalid controller mount')
        if group != root and not group.startswith(root.rstrip('/') + '/'):
            continue
        relative = group[len(root):].lstrip('/')
        matches.append((len(root), str(Path(mount) / relative)))
    require(bool(matches), 'Memory controller mount unavailable')
    deepest = max(n for n, _ in matches)
    paths = {p for n, p in matches if n == deepest}
    require(len(paths) == 1, 'Ambiguous memory controller mounts')
    return version, Path(paths.pop())


def cgroup_memory(pid, ticks):
    result = {'available': False, 'currentBytes': None, 'stat': None, 'pressure': None,
              'scope': 'process_memory_cgroup_charge_not_unique_physical_memory',
              'componentValuesNotAdditive': True, 'UBPhysicalChargeComplete': False, 'errors': {}}
    try:
        require(identity(pid)[1] == ticks, 'Process changed before cgroup observation')
        membership = bounded_text(PROC / str(pid) / 'cgroup', 65536)
        mountinfo = bounded_text(PROC / 'self/mountinfo', 1024**2)
        version, directory = memory_cgroup_directory(membership, mountinfo)
        require(directory.resolve(strict=True) == directory, 'Redirected memory cgroup')
        current_name = 'memory.current' if version == 'v2' else 'memory.usage_in_bytes'
        current, current_error = maybe(lambda: int(bounded_text(directory / current_name, 128)))
        text, stat_error = maybe(lambda: bounded_text(directory / 'memory.stat', 65536))
        fields = None
        if text is not None:
            def parse_stat():
                rows = [line.split() for line in text.splitlines()]
                require(all(len(r) == 2 for r in rows), 'Malformed memory.stat')
                require(len({r[0] for r in rows}) == len(rows), 'Duplicate memory.stat fields')
                return {key: int(value) for key, value in rows}
            fields, stat_error = maybe(parse_stat)
        pressure, psi_error = maybe(lambda: bounded_text(directory / 'memory.pressure', 65536))
        require(identity(pid)[1] == ticks and bounded_text(PROC / str(pid) / 'cgroup', 65536) == membership,
                'Process/cgroup changed during observation')
        result.update(available=current is not None or fields is not None, version=version,
                      directory=str(directory), currentBytes=current, stat=fields, pressure=pressure,
                      statUnits='kernel-defined; includes both byte quantities and event counters',
                      errors={'current': current_error, 'stat': stat_error, 'pressure': psi_error})
    except (OSError, ValueError, RuntimeError) as error:
        result.update(unavailable(error))
    return result


def pmem_mappings(smaps, pinned_files):
    """Recognize whole, shared RO VMAs by pinned dev/inode; never infer RAM/access."""
    expected = {(row['dev'], row['inode']): row for row in pinned_files}
    require(len(expected) == len(pinned_files), 'Duplicate pinned PMEM inode')
    found = []
    current = None
    for line in smaps.splitlines():
        match = re.fullmatch(r'([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+'
                             r'([0-9a-f]+):([0-9a-f]+)\s+(\d+)\s*(.*)', line)
        if match:
            current = None
            # Compare major/minor explicitly; no assumptions about dev_t encoding.
            candidates = [row for (dev, inode), row in expected.items()
                          if inode == int(match[7]) and os.major(dev) == int(match[5], 16)
                          and os.minor(dev) == int(match[6], 16)]
            if not candidates:
                continue
            require(len(candidates) == 1, 'Ambiguous PMEM file identity')
            row = candidates[0]
            start, end, offset = int(match[1], 16), int(match[2], 16), int(match[4], 16)
            require(match[3] == 'r--s' and start < end and offset + end - start <= row['size'],
                    'PMEM mapping permissions/range differs from readonly base')
            require(match[8] == str(row['path']), 'PMEM mapping pathname changed/deleted')
            current = {'dev': row['dev'], 'inode': row['inode'], 'offset': offset,
                       'virtualBytes': end - start, 'bytes': {}, 'path': str(row['path'])}
            found.append(current)
        elif current is not None:
            value = re.fullmatch(r'(\w+):\s+(\d+) kB', line)
            if value:
                current['bytes'][value[1]] = int(value[2]) * 1024
    metrics = {key: sum(row['bytes'][key] for row in found)
               if found and all(key in row['bytes'] for row in found) else None for key in ROLLUP_FIELDS}
    return {'available': bool(found), 'scope': 'identified_readonly_pmem_host_file_vmas',
            'mappings': found, 'bytes': metrics, 'actualAccessSetMeasured': False,
            'accessResidentIntersectionBytes': None, 'uniquePhysicalBytes': None,
            'overlapsHostFilePagecache': True, 'includedInWholeProcessPss': True}


def pin_base_files(paths, owner=1204):
    """Call after input manifests were verified. No content read/rehash here."""
    require(0 < len(paths) <= 8, 'PMEM base inventory exceeds bound')
    rows = []
    for path in map(Path, paths):
        require(path.is_absolute() and path.resolve(strict=True) == path, 'Redirected PMEM base')
        meta = path.stat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == owner and 0 < meta.st_size <= 8 * 1024**3,
                'Unexpected PMEM base metadata')
        rows.append({'path': str(path), 'dev': meta.st_dev, 'inode': meta.st_ino, 'size': meta.st_size,
                     'mtimeNs': meta.st_mtime_ns, 'ctimeNs': meta.st_ctime_ns, 'uid': owner})
    require(len({(r['dev'], r['inode']) for r in rows}) == len(rows), 'Duplicate PMEM base inventory')
    return rows


def base_file_cache(pinned_files):
    result = {'available': False, 'files': [], 'residentPageBytes': None,
              'scope': 'whole_immutable_host_pmem_files_not_actual_access_set',
              'contentReadOrFaulted': False, 'atomicSnapshot': False,
              'globalPhysicalSavingBytes': None, 'startNs': time.time_ns()}
    for row in pinned_files:
        item = {'path': row['path'], 'dev': row['dev'], 'inode': row['inode'],
                'logicalBytes': row['size'], 'residentPageBytes': None}
        fd = None
        try:
            path = Path(row['path'])
            require(path.resolve(strict=True) == path, 'Redirected PMEM base')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            def check(meta):
                require(stat.S_ISREG(meta.st_mode) and
                        (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns, meta.st_uid) ==
                        tuple(row[k] for k in ('dev', 'inode', 'size', 'mtimeNs', 'ctimeNs', 'uid')),
                        'PMEM file identity/content metadata changed')
            check(os.fstat(fd))
            page = os.sysconf('SC_PAGESIZE')
            count = resident_pages(fd, row['size'], page, max_bytes=8 * 1024**3)
            check(os.fstat(fd));check(path.stat())
            item.update(available=True, residentPageBytes=count * page)
        except (OSError, ValueError, RuntimeError) as error:
            item.update(unavailable(error))
        finally:
            if fd is not None:
                os.close(fd)
        result['files'].append(item)
    keys = [(r['dev'], r['inode']) for r in pinned_files]
    if keys and len(set(keys)) == len(keys) and all(r.get('available') for r in result['files']):
        result.update(available=True, residentPageBytes=sum(r['residentPageBytes'] for r in result['files']))
    result['endNs'] = time.time_ns()
    return result


def sum_vma_metrics(maps):
    return {name: sum(m['bytes'][name] for m in maps)
            if maps and all(name in m['bytes'] for m in maps) else None for name in ROLLUP_FIELDS}


def collect_ram(base, runtime_pid, runtime_ticks, sids, *, expected_bytes, pinned_files=(), allowed_lowers=()):
    """expected_bytes is an exact SID -> snapshot virtual RAM size contract."""
    result = {'available': False, 'guests': [], 'atomicSnapshot': False,
              'scope': 'actual_guest_ram_vmas_and_separately_identified_pmem',
              'crossNodeMemfileCowAccepted': False, 'rawPFNsExported': False,
              'startNs': time.time_ns()}
    try:
        require(len(sids) == len(set(sids)) <= 8 and set(expected_bytes) == set(sids), 'Guest RAM contracts differ')
        require(all(type(n) is int and 0 < n <= 32 * 1024**3 for n in expected_bytes.values()),
                'Guest RAM size outside bounded contract')
        require(identity(runtime_pid)[1] == runtime_ticks, 'Runtime identity changed')
        found = {}
        for pid in find_firecrackers(runtime_pid):
            proc = PROC / str(pid)
            stderr = Path(os.readlink(proc / 'fd/2'))
            if stderr.name != 'firecracker-stderr.log' or stderr.parent.parent != base / 'logs/firecracker':
                continue
            sid = stderr.parent.name
            if sid not in sids:
                continue
            require(sid not in found, 'Multiple Firecrackers for one Guest')
            ticks = identity(pid)[1]
            status = bounded_text(proc / 'status', 65536)
            require(re.search(r'^Uid:\s+1204\s+1204\s+1204\s+1204$', status, re.M), 'Unexpected Guest UID')
            cwd = (proc / 'cwd').resolve(strict=True)
            require(cwd.is_relative_to(Path('/home/jwk/agent/r')) and cwd.name.startswith('agentenv-fc-'),
                    'Unexpected FC working directory')
            row = {'sandboxId': sid, 'pid': pid, 'startTicks': ticks,
                   'wholeProcess': whole_process_metrics(pid, ticks)}
            smaps, error = maybe(lambda: bounded_text(proc / 'smaps'))
            row['smapsError'] = error
            if smaps is not None:
                try:
                    log = stderr.parent / 'firecracker.log'
                    owned_regular(log, 16 * 1024**2)
                    backend = memory_backend(bounded_text(log, 16 * 1024**2))
                    maps = parse_guest_smaps(smaps, backend, expected_bytes[sid], guest_regions(cwd, pid))
                    row['guestRam'] = {'available': True, 'bytes': sum_vma_metrics(maps),
                        'vmaCount': len(maps), 'virtualBytes': sum(m['end'] - m['start'] for m in maps),
                        'binding': 'PEERCRED_FC_API_INTERSECT_SMAPS',
                        'clippedVmas': sum(bool(m.get('smaps_metrics_omitted_due_to_clipping')) for m in maps)}
                except (OSError, ValueError, RuntimeError) as error:
                    row['guestRam'] = unavailable(error)
                try:
                    row['pmem'] = pmem_mappings(smaps, pinned_files)
                except (OSError, ValueError, RuntimeError) as error:
                    row['pmem'] = unavailable(error)
            else:
                row['guestRam'] = row['pmem'] = {'available': False, 'reason': 'smaps unavailable'}
            row['rootfsUpper'] = upper_cache(base, cwd, allowed_lowers)
            require(identity(pid)[1] == ticks, 'Guest changed during observation')
            found[sid] = row
        require(identity(runtime_pid)[1] == runtime_ticks, 'Runtime changed during observation')
        guests = [found.get(sid, {'sandboxId': sid, 'available': False,
                  'reason': 'Scoped Firecracker process not observed'}) for sid in sids]
        result.update(available=bool(sids) and set(found) == set(sids), guests=guests,
                      completeGuestRam=bool(sids) and all(g.get('guestRam', {}).get('available') for g in guests),
                      privateUpper=aggregate_upper(guests))
    except (OSError, ValueError, RuntimeError) as error:
        result.update(unavailable(error))
    result['endNs'] = time.time_ns()
    return result
