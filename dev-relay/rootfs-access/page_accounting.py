"""Account attributed buffered lower-page reads; never infer them from file size."""
import ctypes, json, os, stat, time
from pathlib import Path

def need(ok,why):
    if not ok:raise ValueError(why)

def pages(offset,length,page_bytes):
    need(type(offset) is int and offset>=0 and type(length) is int and length>0,'Invalid successful read range')
    need(type(page_bytes) is int and page_bytes>0,'Invalid page size')
    return range(offset//page_bytes,(offset+length-1)//page_bytes+1)

def read_sets(stream,status,bindings,windows,files,patch_sha,page_bytes=4096):
    """bindings: source image.json -> template/sandbox/lower/upper inode sets.

    files is keyed by (dev,inode), with the immutable lower's path and size.
    Only a complete prefix attested by a post-window status is consumed.
    """
    need(windows and all(type(v[0]) is int and type(v[1]) is int and 0<v[0]<v[1] for v in windows.values()),'Invalid workload windows')
    need({v['sandbox_id'] for v in bindings.values()}==set(windows),'Bindings/window scopes differ')
    need(status['dropped_records']==status['errors']==status['unsupported_context_calls']==0,'Observer reports incomplete evidence')
    need(status['mono_ns']>=max(v[1] for v in windows.values()),'Status predates observation window end')
    header=json.loads(next(stream));need(header['kind']=='header' and header['version']==1 and header['pid']==status['pid'],'Trace/header identity differs')
    need(header['clock']=='CLOCK_MONOTONIC' and header['build_patch_sha256']==patch_sha,'Trace build/clock differs')
    count=status['records_written'];need(type(count) is int and 0<=count<=1000000,'Record budget exceeded')
    observed={sid:set() for sid in windows};audit={'records_checked':0,'outside_window':0,'boundary_crossing':0,'direct_lower_reads':0,'upper_reads':0,'unknown_sources_outside_window':0}
    low=min(v[0] for v in windows.values());high=max(v[1] for v in windows.values())
    for seq in range(count):
        line=next(stream);need(len(line)<=32768,'Oversized trace row');row=json.loads(line)
        need(row['kind']=='read' and row['seq']==seq and 0<row['start_ns']<=row['end_ns'],'Trace sequence/time invalid')
        need(type(row['direct_io']) is bool and type(row['allowed_lower']) is bool,'Invalid read flags')
        audit['records_checked']+=1
        source=bindings.get(row['source'])
        if source is None:
            need(row['end_ns']<low or row['start_ns']>high,'Unbound source read during workload')
            audit['unknown_sources_outside_window']+=1;continue
        sid=source['sandbox_id'];start,end=windows[sid]
        if row['end_ns']<start or row['start_ns']>end:audit['outside_window']+=1;continue
        if row['start_ns']<start or row['end_ns']>end:audit['boundary_crossing']+=1;continue
        key=(row['dev'],row['inode'])
        if key in source['upper_keys']:audit['upper_reads']+=1;continue
        need(key in source['lower_keys'] and key in files and row['allowed_lower'] is True,'Read is not bound to a verified lower or upper')
        need(row['file_bytes']==files[key]['file_bytes'] and row['offset']+row['bytes']<=row['file_bytes'],'Lower changed or range invalid')
        if row['direct_io']:audit['direct_lower_reads']+=1;continue
        for page in pages(row['offset'],row['bytes'],page_bytes):observed[sid].add((key[0],key[1],page))
    # Caller must preserve the raw log/status; later records are outside this checkpoint.
    need(audit['boundary_crossing']==0,'A read crossed a workload boundary; complete-window claim requires review')
    return observed,audit

def pair_statistics(a,b,resident,page_bytes=4096):
    a=set(a);b=set(b);resident=set(resident)
    ar=a&resident;br=b&resident;common=ar&br;union=ar|br;refs=len(ar)+len(br)
    return {'sandbox1_accessed_lower_bytes':len(a)*page_bytes,'sandbox2_accessed_lower_bytes':len(b)*page_bytes,
        'both_accessed_lower_bytes':len(a&b)*page_bytes,
        'sandbox1_accessed_and_resident_bytes':len(ar)*page_bytes,'sandbox2_accessed_and_resident_bytes':len(br)*page_bytes,
        'shared_accessed_host_pagecache_bytes':len(common)*page_bytes,'accessed_resident_union_bytes':len(union)*page_bytes,
        'shared_pool_fraction':len(common)/len(union) if union else None,
        'duplicate_avoidance_fraction':len(common)/refs if refs else None,
        'shared_participation_fraction':2*len(common)/refs if refs else None,
        'zero_observed_buffered_reads':not(a or b),'file_size_used_as_access_count':False}

def resident_accessed_pages(files,requested):
    """Probe only accessed pages, as the actual file owner, without touching data."""
    need(os.name=='posix' and os.getuid()==os.geteuid(),'Ordinary same-UID sampler required')
    page=os.sysconf('SC_PAGESIZE');need(page==4096,'Expected observed 4KiB page size')
    libc=ctypes.CDLL(None,use_errno=True);libc.mmap.restype=ctypes.c_void_p
    libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
    libc.mincore.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
    libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    grouped={};resident=set();began=time.monotonic_ns()
    for dev,ino,index in requested:grouped.setdefault((dev,ino),set()).add(index)
    for key,indexes in grouped.items():
        info=files[key];path=Path(info['path']);need(path.resolve(strict=True)==path,'Redirected lower')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid(),'mincore owner authorization is not established')
            need((before.st_dev,before.st_ino)==key and before.st_size==info['file_bytes'],'Lower identity differs')
            ordered=sorted(indexes);groups=[]
            for index in ordered:
                need(0<=index*page<before.st_size,'Requested page outside lower')
                if groups and index==groups[-1][-1]+1 and len(groups[-1])<1024:groups[-1].append(index)
                else:groups.append([index])
            for group in groups:
                offset=group[0]*page;length=min(len(group)*page,before.st_size-offset)
                address=libc.mmap(None,length,1,1,fd,offset)
                need(address not in (None,ctypes.c_void_p(-1).value),'mmap failed')
                try:
                    bits=(ctypes.c_ubyte*len(group))();need(libc.mincore(address,length,bits)==0,'mincore failed')
                    resident.update((key[0],key[1],i) for i,bit in zip(group,bits) if bit&1)
                finally:need(libc.munmap(address,length)==0,'munmap failed')
            after=os.fstat(fd);need((after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)==(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns),'Lower changed while sampling')
        finally:os.close(fd)
    return resident,{'started_monotonic_ns':began,'finished_monotonic_ns':time.monotonic_ns(),
        'queried_pages':len(requested),'queried_files':len(grouped),'file_owner_authorization_verified':True,
        'data_read_or_touched':False,'atomic_snapshot':False}
