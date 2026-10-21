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

def whole_process_metrics(pid,ticks):
    """Match colleague RSS=status.VmRSS, PSS=smaps_rollup.Pss; never fill missing with zero."""
    result={'scope':'whole_firecracker_process','available':False,
            'rss_source':'/proc/PID/status:VmRSS','pss_source':'/proc/PID/smaps_rollup:Pss',
            'atomic_snapshot':False}
    try:
        require(identity(pid)[1]==ticks,'Process changed before process-metric read')
        def bounded(name):
            with (Path('/proc')/str(pid)/name).open() as stream:data=stream.read(65537)
            require(len(data)<=65536,'Process metric input too large');return data
        status=bounded('status');rollup=bounded('smaps_rollup')
        def kb(text,key):
            match=re.search(r'^'+key+r':\s+(\d+) kB$',text,re.M)
            require(match is not None,'Missing process metric: '+key);return int(match[1])*1024
        rss=kb(status,'VmRSS');pss=kb(rollup,'Pss')
        require(identity(pid)[1]==ticks,'Process changed during process-metric read')
        result.update(available=True,rss_bytes=rss,pss_bytes=pss,rss_minus_pss_bytes=rss-pss,
                      smaps_rollup_rss_bytes=kb(rollup,'Rss'))
    except Exception as e:
        result.update(error_type=type(e).__name__,reason=str(e) if isinstance(e,RuntimeError) else 'Process metric unavailable')
    return result

# Functions appended to the scoped RAM observer; no content-read sampling.


def owned_regular(path, limit):
    require(path.resolve(strict=True) == path, 'Redirected cache metadata path')
    meta = path.stat()
    require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204 and 0 <= meta.st_size <= limit,
            'Unexpected cache file metadata')
    return meta


def cache_path(value, config_dir, roots):
    require(isinstance(value, str) and value and '\x00' not in value, 'Missing cache file path')
    original = Path(value)
    original = original if original.is_absolute() else config_dir / original
    path = Path(os.path.abspath(original))
    require(any(path.is_relative_to(root) for root in roots)
            and original.resolve(strict=True) == path, 'Cache file outside owned scope or redirected')
    return path


def upper_files(base, cwd):
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
        path = cache_path(row.get('file'), config_path.parent, (cwd, base / 'state'))
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


def resident_pages(fd, size, page):
    require(type(size) is int and 0 <= size <= 2 * 1024**3
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


def upper_cache(base, cwd):
    result = {'available': False, 'files': [], 'scope': 'private_host_upper_file_cache',
              'contentReadOrFaulted': False, 'atomicSnapshot': False,
              'includedInRuntimeCgroupCharge': 'may_overlap_do_not_add_to_cgroup_total'}
    try:
        selected, lower_ids = upper_files(base, cwd)
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


def collect_ram(base, runtime_pid, runtime_ticks, sids):
    result = {'available': False, 'scope': 'actual_guest_ram_vmas',
              'guests': [], 'crossNodeMemfileCowAccepted': False,
              'rawPFNsExported': False, 'atomicSnapshot': False}
    try:
        require(identity(runtime_pid)[1] == runtime_ticks, 'Runtime identity changed')
        found = {}
        for pid in find_firecrackers(runtime_pid):
            proc = Path('/proc') / str(pid)
            stderr = Path(os.readlink(proc / 'fd/2'))
            if stderr.name != 'firecracker-stderr.log' or stderr.parent.parent != base / 'logs/firecracker':
                continue
            sid = stderr.parent.name
            if sid not in sids:continue
            require(sid not in found, 'Multiple Firecrackers for one Guest')
            ticks = identity(pid)[1]
            status = (proc / 'status').read_text()
            require(re.search(r'^Uid:\s+1204\s+1204\s+1204\s+1204$', status, re.M), 'Unexpected Guest UID')
            cwd = (proc / 'cwd').resolve(strict=True)
            require(cwd.is_relative_to(Path('/home/jwk/agent/r'))
                    and cwd.name.startswith('agentenv-fc-'), 'Unexpected FC working directory')
            log = stderr.parent / 'firecracker.log'
            require(log.resolve(strict=True) == log and log.stat().st_uid == 1204
                    and log.stat().st_size <= 16 * 1024**2, 'Unexpected own Guest log')
            backend = memory_backend(log.read_text())
            with (proc / 'smaps').open() as stream:smaps = stream.read(4 * 1024**2 + 1)
            require(len(smaps) <= 4 * 1024**2, 'Guest smaps exceeds observation bound')
            maps = parse_guest_smaps(smaps, backend, 512 * 1024**2,
                                     guest_regions(cwd, pid))
            metrics = {}
            for name in ('Rss', 'Pss', 'Private_Clean', 'Private_Dirty', 'Shared_Clean', 'Shared_Dirty', 'Swap'):
                values = [m['bytes'].get(name) for m in maps]
                metrics[name] = sum(values) if all(x is not None for x in values) else None
            require(identity(pid)[1] == ticks, 'Guest changed during sampling')
            found[sid] = {'sandboxId': sid, 'pid': pid, 'startTicks': ticks,
                          'wholeProcess': whole_process_metrics(pid, ticks),
                          'rootfsUpper': upper_cache(base, cwd),
                          'guestRam': {'bytes': metrics, 'vmaCount': len(maps),
                                       'virtualBytes': sum(m['end'] - m['start'] for m in maps),
                                       'binding': 'PEERCRED_FC_API_INTERSECT_SMAPS',
                                       'clippedVmas': sum(bool(m.get('smaps_metrics_omitted_due_to_clipping')) for m in maps)}}
            require(identity(pid)[1] == ticks, 'Guest changed during upper sampling')
        require(set(found) == set(sids), 'Not every scoped Guest was bound')
        require(identity(runtime_pid)[1] == runtime_ticks, 'Runtime changed during sample')
        guests = [found[sid] for sid in sids]
        result.update(available=True, guests=guests, privateUpper=aggregate_upper(guests))
    except Exception as error:
        result.update(errorType=type(error).__name__, reason=str(error)[:400]
                      if isinstance(error, RuntimeError) else 'Read-only proc/API observation unavailable')
    return result
