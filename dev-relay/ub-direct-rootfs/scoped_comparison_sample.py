"""Read-only, bounded memory samples for explicitly identified experiment inputs.

No SDK, cache eviction, service action or Guest command. Ordinary file cache,
block-device cache and process PSS overlap; this module never adds them into a
physical total. A caller must validate cohort ownership before supplying scope.
"""
import ctypes,errno,hashlib,json,os,re,stat,time
from pathlib import Path

def need(ok,why):
    if not ok:raise ValueError(why)

def kib_fields(text):
    result={}
    for line in text.splitlines():
        match=re.fullmatch(r'([A-Za-z_]+):\s+(\d+) kB',line.strip())
        if match:result[match[1]]=int(match[2])*1024
    return result

def identity(pid):
    need(type(pid) is int and pid>1,'Invalid PID')
    proc=Path('/proc')/str(pid)
    ticks=proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]
    status=proc.joinpath('status').read_text()
    uid=re.search(r'(?m)^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$',status)
    need(uid is not None,'Process UID unavailable')
    return {'pid':pid,'startTicks':ticks,'uids':[int(x) for x in uid.groups()]}

def process_sample(row):
    before=identity(row['pid'])
    need(before['startTicks']==row['startTicks'] and before['uids']==[row['uid']]*4,'Process identity changed')
    proc=Path('/proc')/str(row['pid']);meta=os.stat(proc/'exe')
    need(os.readlink(proc/'exe')==row['executable'] and (meta.st_dev,meta.st_ino)==(row['exeDev'],row['exeInode']),
         'Process executable identity changed')
    begin=time.monotonic_ns();rollup=kib_fields((proc/'smaps_rollup').read_text())
    need(identity(row['pid'])==before,'Process changed during sampling')
    need('Rss' in rollup and 'Pss' in rollup,'Required process RSS/PSS missing')
    return {'role':row['role'],**before,'beginNs':begin,'endNs':time.monotonic_ns(),
            'metricsBytes':{key:rollup.get(key) for key in ('Rss','Pss','Pss_Anon','Pss_File','Pss_Shmem',
                'Private_Clean','Private_Dirty','Shared_Clean','Shared_Dirty','Anonymous','Swap','SwapPss')},
            'scope':'whole_process_including_mapped_Guest_RAM_when_role_fc','guestRamOnlyBytes':None}

def resident_bytes(fd,length,page,libc=None,deadline=None):
    """mincore on PROT_NONE mappings; do not fault or read source payload."""
    need(type(length) is int and length>=0 and length<=32*1024**3,'File size exceeds bound')
    need(type(page) is int and page>=4096 and page&(page-1)==0,'Invalid native page size')
    if length==0:return 0
    if deadline is None:deadline=time.monotonic()+5
    libc=libc or ctypes.CDLL(None,use_errno=True)
    libc.mmap.restype=ctypes.c_void_p
    libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_longlong]
    libc.mincore.restype=ctypes.c_int;libc.mincore.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
    libc.munmap.restype=ctypes.c_int;libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    resident=0;offset=0;window=64*1024**2
    while offset<length:
        if time.monotonic()>deadline:raise TimeoutError(errno.ETIMEDOUT,'Scoped residency sampling budget exceeded')
        size=min(window,length-offset);pages=(size+page-1)//page
        address=libc.mmap(None,size,0,1,fd,offset)  # PROT_NONE, MAP_SHARED
        if address==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),'Scoped mmap failed')
        try:
            vector=(ctypes.c_ubyte*pages)()
            if libc.mincore(address,size,vector)!=0:raise OSError(ctypes.get_errno(),'Scoped mincore failed')
            resident+=sum(bool(value&1) for value in vector)*page
        finally:
            if libc.munmap(address,size)!=0:raise OSError(ctypes.get_errno(),'Scoped munmap failed')
        offset+=size
    return resident

def immutable_identity(meta):
    return {'dev':meta.st_dev,'inode':meta.st_ino,'size':meta.st_size,'mtimeNs':meta.st_mtime_ns,'ctimeNs':meta.st_ctime_ns}

def file_sample(row,root,page,deadline=None):
    path=Path(row['path'])
    need(path.is_absolute() and path.is_relative_to(root) and path.resolve(strict=True)==path,'File outside declared root or redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204,'Expected ordinary owned experiment file')
        actual=immutable_identity(before)
        need(all(actual[key]==row['identity'][key] for key in ('dev','inode')),'File inode changed')
        if row['immutable']:need(actual==row['identity'],'Immutable file changed')
        count=resident_bytes(fd,before.st_size,page,deadline=deadline)
        after=os.fstat(fd);stable=immutable_identity(after)==actual
        if row['immutable']:need(stable,'Immutable file changed during mincore')
        return {'path':str(path),'category':row['category'],'identity':actual,
                'residentBytes':count if stable else None,'stableDuringSample':stable,
                'pageSpanBytes':((before.st_size+page-1)//page)*page,'allocatedFileBytes':before.st_blocks*512,
                'payloadReadOrFaulted':False,'cacheEvicted':False}
    finally:os.close(fd)

def unique_file_samples(rows,root,page,deadline=None):
    need(len(rows)<=256,'Too many scoped files')
    unique={};references=[]
    allowed={'rootfs-lower-original','rootfs-lower-ub-source','memory-lower','private-upper','experiment-log'}
    for row in rows:
        need(row['category'] in allowed and type(row['immutable']) is bool,'Invalid file category/mutability')
        key=(row['identity']['dev'],row['identity']['inode'])
        if key not in unique:unique[key]=file_sample(row,root,page,deadline)
        else:
            prior=unique[key]
            need(prior['category']==row['category'],'One inode assigned overlapping categories; cannot add independently')
            if row['immutable']:need(prior['identity']==row['identity'],'Conflicting immutable inode identities')
        references.append({'path':row['path'],'identityKey':list(key),'category':row['category']})
    values=list(unique.values())
    return {'uniqueFiles':values,'references':references,
            'uniqueResidentBytes':sum(r['residentBytes'] for r in values) if all(r['residentBytes'] is not None for r in values) else None,
            'scope':'whole-file residency by unique inode; no access intersection or physical PFN deduplication'}

def device_sample(row,page,deadline=None):
    path=Path(row['path'])
    need(re.fullmatch('/dev/ublkb[0-9]+',str(path)) and path.resolve(strict=True)==path,'Device outside explicit ublk scope')
    need(type(row['bytes']) is int and 0<row['bytes']<=32*1024**3,'Device length outside bound')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISBLK(before.st_mode) and (os.major(before.st_rdev),os.minor(before.st_rdev))==(row['major'],row['minor'])
             and before.st_ino==row['inode'],'Device identity changed/reused')
        # BLKGETSIZE64 queries capacity; it neither flushes nor invalidates cache.
        import fcntl
        import struct
        size=struct.unpack('=Q',fcntl.ioctl(fd,0x80081272,b'\0'*8))[0]
        need(size==row['bytes'],'Device capacity changed')
        count=resident_bytes(fd,size,page,deadline=deadline);after=os.fstat(fd)
        need((after.st_rdev,after.st_ino)==(before.st_rdev,before.st_ino),'Device changed during sample')
        return {'path':str(path),'deviceBytes':size,'residentBytes':count,'major':row['major'],'minor':row['minor'],
                'scope':'block-device cache; may overlap Guest file-backed RAM mappings; not ordinary-file Cached',
                'payloadReadOrFaulted':False,'cacheEvicted':False}
    finally:os.close(fd)

def ub_reservation(manifest):
    """Validate a de-duplicated allocation ledger without interpreting PSS as UB."""
    need(manifest['version']==1 and manifest['mode']=='full-stored' and manifest['presence']=='retained'
         and 1<=len(manifest['objects'])<=64,'Expected retained full-object allocation ledger')
    regions={};objects=set()
    for obj in manifest['objects']:
        need(obj['objectName'] not in objects,'Duplicate UB object accounting')
        objects.add(obj['objectName'])
        for region in obj['regions']:
            need(region.get('role')=='export' and region['exportNode'] in ('a','b')
                 and isinstance(region['exportBootId'],str) and region['exportBootId'],'Only identified export reservations are billable')
            key=(region['exportNode'],region['exportBootId'],region['exportRegionId'])
            need(type(region['bytes']) is int and region['bytes']>0,'Unknown UB reservation size')
            if key in regions:need(regions[key]==region['bytes'],'Conflicting repeated export-region size')
            regions[key]=region['bytes']
    return {'uniqueExportRegions':len(regions),'reportedReservationBytesCountedOnce':sum(regions.values()),
            'reservationLedgerSha256':hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'incrementalPhysicalChargeBytes':None,'importMappingsAddedAsCopies':False,
            'scope':'reported unique export reservation; not an independent physical charge measurement'}

def optional_sample(function,*args):
    try:return {'available':True,**function(*args)}
    except OSError as error:
        if error.errno not in (errno.EACCES,errno.EPERM,errno.EINVAL,errno.ENOSYS,errno.ENODEV,errno.ETIMEDOUT):raise
        return {'available':False,'errorType':type(error).__name__,'errno':error.errno,
                'valueBytes':None,'reason':'scoped kernel observation unavailable; no alternative read or cache operation attempted'}

def sample(scope,include_files=False):
    need(os.name=='posix' and Path('/proc/self').exists(),'Linux sampling required')
    need(scope['version']==1 and len(scope['processes'])<=32,'Bounded scope required')
    root=Path(scope['root']);need(root.resolve(strict=True)==root and root==Path('/home/jwk/agent'),'Unexpected experiment root')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(scope['bootId']==boot,'Scope belongs to another boot')
    identities=[(r['pid'],r['startTicks']) for r in scope['processes']]
    need(len({r['pid'] for r in scope['processes']})==len(identities),'Duplicate process billing')
    for row in scope['processes']:
        need(row['role'] in ('fc','runtime','daemon','provider','collector') and row['uid'] in (0,1204),'Invalid process role/UID')
        need(row['uid']==1204 or row['role']=='collector','Unexpected privileged workload')
    result={'version':1,'node':scope['node'],'bootId':boot,'group':scope['group'],'beginNs':time.monotonic_ns(),
            'hostMemoryBytes':kib_fields(Path('/proc/meminfo').read_text()),
            'processes':[process_sample(row) for row in scope['processes']],
            'ordinaryFiles':None,'blockDevices':None,'uniqueUBReservation':ub_reservation(scope['ubReservation']),
            'disjointTotalBytes':None,'GuestRamVmaOnlyBytes':None,'crossNodeNetSavingsBytes':None,
            'cacheEvictionPerformed':False,'atomicGlobalSnapshot':False,
            'auxiliarySubcategoriesNotSeparated':['indexes','decompression scratch','response buffers']}
    if include_files:
        page=os.sysconf('SC_PAGESIZE')
        deadline=time.monotonic()+5
        result['ordinaryFiles']=optional_sample(unique_file_samples,scope['files'],root,page,deadline)
        devices=scope['devices'];need(len(devices)<=32,'Too many block devices')
        need(len({(r['major'],r['minor']) for r in devices})==len(devices),'Duplicate device billing')
        result['blockDevices']=[optional_sample(device_sample,row,page,deadline) for row in devices]
    for row in scope['processes']:
        need(identity(row['pid'])['startTicks']==row['startTicks'],'Process changed across sample')
    result['endNs']=time.monotonic_ns()
    result['coverage']={'wholeProcess':True,'ordinaryFileResidency':bool(include_files and result['ordinaryFiles']['available']
                           and result['ordinaryFiles']['uniqueFiles'] and result['ordinaryFiles']['uniqueResidentBytes'] is not None),
                        'deviceResidency':bool(include_files and result['blockDevices'] and all(row['available'] for row in result['blockDevices'])),
                        'guestRamOnly':False,'uniqueUBIncrementalPhysicalCharge':False}
    return result
