"""Scoped cold-cache validation and full-file mincore accounting.

No global cache drop, no data reads of lower files, no claim that a 256KiB
aggregation cell is a kernel folio. Inject ACCOUNTING before use.
"""
import base64, ctypes, json, os, stat, subprocess, tempfile, time, zlib
from pathlib import Path

PAGE=4096
CELL=262144


def need(ok, why):
    if not ok: raise RuntimeError(why)


def host_memory():
    return {k:int(v.split()[0])*1024 for k,v in
            (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
            if k in ('Cached','Buffers','Shmem','Dirty','Writeback','MemAvailable')}


def checked_fd(key, info):
    p=Path(info['path']);need(p.resolve(strict=True)==p,'Redirected lower')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid(), 'File owner authorization missing')
        need((s.st_dev,s.st_ino)==key and s.st_size==info['file_bytes'], 'Lower identity changed')
        return fd,s
    except BaseException:
        os.close(fd);raise


def vector(fd, size):
    need(os.sysconf('SC_PAGESIZE')==PAGE,'Target base page size is not 4KiB')
    lib=ctypes.CDLL(None,use_errno=True)
    lib.mmap.restype=ctypes.c_void_p
    lib.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
    lib.mincore.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
    lib.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    out=bytearray()
    for offset in range(0,size,4*1024**2):
        length=min(4*1024**2,size-offset);n=(length+PAGE-1)//PAGE
        address=lib.mmap(None,length,1,1,fd,offset)
        need(address not in (None,ctypes.c_void_p(-1).value),'mincore mapping failed')
        try:
            bits=(ctypes.c_ubyte*n)()
            need(lib.mincore(address,length,bits)==0,'mincore query failed')
            out.extend(b&1 for b in bits)
        finally:need(lib.munmap(address,length)==0,'mincore unmap failed')
    return out


def vector_counts(bits):
    cells=[bits[i:i+CELL//PAGE] for i in range(0,len(bits),CELL//PAGE)]
    return {'resident_4k_pages':sum(bits), 'resident_bytes':sum(bits)*PAGE,
            'cells_256k_any_resident':sum(any(c) for c in cells),
            'cells_256k_fully_resident':sum(all(c) for c in cells),
            'cells_256k_partly_resident':sum(any(c) and not all(c) for c in cells),
            'resident_bytes_summed_inside_256k_cells':sum(sum(c)*PAGE for c in cells),
            'any_resident_cell_capacity_upper_bound_bytes':sum(len(c)*PAGE for c in cells if any(c))}


def scan(files, requested):
    began=time.monotonic_ns();before=host_memory();rows=[];resident=set()
    groups={}
    for dev,ino,index in requested:groups.setdefault((dev,ino),set()).add(index)
    need(set(groups)<=set(files),'Requested pages outside scoped files')
    for key,info in sorted(files.items()):
        fd,s=checked_fd(key,info)
        try:
            start=time.monotonic_ns();bits=vector(fd,s.st_size);end=time.monotonic_ns()
            after=os.fstat(fd)
            need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'Lower changed during scan')
            for index in groups.get(key,()):
                need(0<=index<len(bits),'Access outside lower')
                if bits[index]:resident.add((key[0],key[1],index))
            rows.append(dict(info,**vector_counts(bits),
                started_monotonic_ns=start,finished_monotonic_ns=end,
                residency_vector_zlib_base64=base64.b64encode(zlib.compress(bytes(bits))).decode(),
                vector_encoding='one byte 0/1 per host base page, zlib then base64'))
        finally:os.close(fd)
    probe={'started_monotonic_ns':began,'finished_monotonic_ns':time.monotonic_ns(),
           'host_memory_before':before,'host_memory_after':host_memory(),
           'queried_pages':sum((r['file_bytes']+PAGE-1)//PAGE for r in rows),'queried_files':len(rows),
           'file_owner_authorization_verified':True,'data_read_or_touched':False,'atomic_snapshot':False,
           'whole_lower_files':rows,'whole_lower_resident_bytes':sum(r['resident_bytes'] for r in rows),
           'accessed_resident_bytes':len(resident)*PAGE,
           'resident_outside_observed_access_bytes':sum(r['resident_bytes'] for r in rows)-len(resident)*PAGE,
           'outside_access_is_not_automatically_readahead':True}
    return resident,probe


def evict(files):
    """One advisory eviction pass. No fsync of lower or global sync/drop_caches."""
    for key,info in sorted(files.items()):
        fd,_=checked_fd(key,info)
        try:os.posix_fadvise(fd,0,0,os.POSIX_FADV_DONTNEED)
        finally:os.close(fd)


def cold_checkpoint(files, output, label):
    _,before=scan(files,set());evict(files);_,after=scan(files,set())
    report={'label':label,'method':'POSIX_FADV_DONTNEED once per verified immutable lower inode',
            'before':before,'after':after,'global_cache_dropped':False,
            'zero_resident_at_each_file_observation':after['whole_lower_resident_bytes']==0,
            'globally_atomic_cold_state_claimed':False,
            'guest_or_daemon_userspace_buffers_flushed':False}
    Path(output).write_text(json.dumps(report),encoding='utf-8')
    need(report['zero_resident_at_each_file_observation'],
         'Scoped lower cache eviction left resident pages; saved evidence, no cold replay claim')
    return report


def coarse_comparison(a,b,resident,files):
    ar=a&resident;br=b&resident
    aa={(d,i,p//64) for d,i,p in ar};bb={(d,i,p//64) for d,i,p in br}
    def capacity(cells):
        return sum(min(64,(files[(d,i)]['file_bytes']+PAGE-1)//PAGE-c*64)*PAGE for d,i,c in cells)
    return {'coarse_256k_common_cell_capacity_upper_bound_bytes':capacity(aa&bb),
            'coarse_256k_union_cell_capacity_upper_bound_bytes':capacity(aa|bb),
            'coarse_cells_are_not_measured_kernel_folios':True}


def enrich(frame, files, sets, resident):
    bykey={(r['dev'],r['inode']):r for r in frame['residency_probe']['whole_lower_files']}
    for row in frame['templates']:
        s1,s2=row['sandbox_ids'];keys=TEMPLATE_KEYS[row['template_id']]
        full=sum(bykey[k]['resident_bytes'] for k in keys)
        row.update(whole_lower_host_pagecache_bytes=full,
            whole_lower_residency_fraction=full/row['lower_page_span_bytes'],
            lower_resident_outside_pair_observed_access_bytes=full-row['accessed_resident_union_bytes'],
            **coarse_comparison(sets[s1],sets[s2],resident,files))
        need(full>=row['accessed_resident_union_bytes'],'Accessed resident union exceeds full lower cache')
    return frame


TEMPLATE_KEYS={}


def independent_check(files, output):
    rows=[]
    for key,info in sorted(files.items()):
        fd,s=checked_fd(key,info)
        try:
            before=sum(vector(fd,s.st_size))*PAGE
            row=dict(info,mincore_before_bytes=before)
            try:
                r=subprocess.run(['fincore','--bytes','--noheadings','--output','RES',info['path']],capture_output=True,text=True,timeout=5)
                row['fincore_returncode']=r.returncode
                row['fincore_resident_bytes']=int(r.stdout.strip()) if r.returncode==0 else None
            except (OSError,ValueError,subprocess.TimeoutExpired) as e:
                row['fincore_unavailable']=type(e).__name__
            after=sum(vector(fd,s.st_size))*PAGE;row['mincore_after_bytes']=after
            row['three_sequential_observations_agree']=before==after==row.get('fincore_resident_bytes')
            row['simultaneous_atomic_comparison']=False
            rows.append(row)
        finally:os.close(fd)
    result={'files':rows,'fincore_available_files':sum(r.get('fincore_resident_bytes') is not None for r in rows),
            'agreeing_files':sum(r['three_sequential_observations_agree'] for r in rows),
            'different_client_same_mincore_kernel_interface':True,'difference_is_reported_not_hidden':True}
    Path(output).write_text(json.dumps(result),encoding='utf-8')
    return {'file':str(output),'files':len(rows),'available_files':result['fincore_available_files'],'agreeing_files':result['agreeing_files']}


def environment(files):
    devices={}
    for dev,_ in files:
        key=str(os.major(dev))+':'+str(os.minor(dev))
        if key in devices:continue
        root=Path('/sys/dev/block')/key;targets=[root]
        if root.exists():targets+=list((root/'slaves').glob('*'))
        observations=[]
        for target in targets:
            row={'sysfs_device':str(target)}
            for name in ('read_ahead_kb','logical_block_size','physical_block_size','minimum_io_size','optimal_io_size','max_sectors_kb'):
                try:row[name]=(target/'queue'/name).read_text().strip()
                except OSError:row[name]=None
            observations.append(row)
        devices[key]=observations
    return {'kernel_release':os.uname().release,'host_base_page_bytes':os.sysconf('SC_PAGESIZE'),
            'aggregation_cell_bytes':CELL,'block_queue_metadata':devices,
            'kernel_folio_size_measured':False,'queue_or_readahead_size_is_not_base_page_size':True}


def calibrate(work):
    """Owned 8MiB fixture, normal/random read hints; no lower data touched."""
    out=[];path=Path(work)/'cold-cache-fixture.bin';created=False
    try:
        with path.open('xb') as f:
            created=True
            for _ in range(8):f.write(bytes(1024**2))
            f.flush();os.fsync(f.fileno())
        s=path.stat();files={(s.st_dev,s.st_ino):dict(path=str(path),dev=s.st_dev,inode=s.st_ino,file_bytes=s.st_size)}
        for label,hint in [('normal',os.POSIX_FADV_NORMAL),('random',os.POSIX_FADV_RANDOM)]:
            cold_checkpoint(files,Path(work)/('fixture-'+label+'-cold.json'),label)
            fd,_=checked_fd(next(iter(files)),next(iter(files.values())))
            try:
                os.posix_fadvise(fd,0,0,hint)
                need(len(os.pread(fd,PAGE,0))==PAGE,'Fixture read failed')
                bits=vector(fd,s.st_size);need(bits[0]==1,'Demanded fixture page not resident')
                row=dict(mode=label,requested_bytes=PAGE,**vector_counts(bits))
                # An independent util-linux client, if installed, queries the same
                # inode later. Differences are recorded, not forced to equality.
                try:
                    p=subprocess.run(['fincore','--bytes','--noheadings','--output','RES',str(path)],capture_output=True,text=True,timeout=10)
                    row['fincore']={'returncode':p.returncode,'resident_bytes':int(p.stdout.strip()) if p.returncode==0 else None}
                except (OSError,ValueError,subprocess.TimeoutExpired) as e:row['fincore']={'unavailable':type(e).__name__}
                out.append(row)
            finally:os.close(fd)
    finally:
        if created:path.unlink()
    result={'status':'OWNED_FIXTURE_COLD_AND_DEMAND_PAGE_VERIFIED','samples':out,
            'fixture_removed':True,'target_kernel_large_folios_proven':False}
    (Path(work)/'cold-calibration.json').write_text(json.dumps(result),encoding='utf-8')
    return result
