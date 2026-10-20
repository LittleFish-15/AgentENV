"""Reviewed inline collector: scoped proc metadata, read-only mincore, stdout only.

Never run a jwk-writable file as root. The ordinary launcher prints this exact
SHA-checked source plus literal scope for direct paste into the root terminal.
No process memory, commands, environments, credentials, or raw PFNs are output.
"""
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import time

ROOT=Path('/home/jwk/agent')
BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
UNIT='jwk-aenv-ae9c626-node-a.service'
SHORT=ROOT/'r/fc-a-base'


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


def owned(path,limit=1024**2):
    require(path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Redirected/outside input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        m=os.fstat(f.fileno())
        require(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_size<=limit,'Input metadata differs')
        data=f.read(limit+1);require(len(data)<=limit,'Input grew');return data


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


def pagemap(pid,maps,page):
    result=set();file_backed=set();present=swapped=masked=0;digest=hashlib.sha256()
    fd=os.open('/proc/'+str(pid)+'/pagemap',os.O_RDONLY)
    try:
        for m in maps:
            require(m['start']%page==m['end']%page==0,'Unaligned VMA')
            count=(m['end']-m['start'])//page
            data=os.pread(fd,count*8,(m['start']//page)*8)
            require(len(data)==count*8,'Short pagemap read')
            # Compare stable PFN/present/swap/file identity, not soft-dirty bits.
            for (entry,) in struct.iter_unpack('=Q',data):
                digest.update(struct.pack('=Q',entry & (((1<<55)-1)|(7<<61))))
                if entry & (1<<62): swapped+=1
                if not entry & (1<<63): continue
                present+=1;pfn=entry & ((1<<55)-1)
                if pfn==0: masked+=1;continue
                result.add(pfn)
                if entry & (1<<61):file_backed.add(pfn)
    finally:os.close(fd)
    require(masked==0,'Present PFNs are zero/hidden; no physical-sharing claim')
    require(present>0,'No resident Guest pages observed; no sharing ratio')
    return result,file_backed,{'present_pte_pages':present,'swapped_pte_pages':swapped,
                              'unique_pfn_pages':len(result),'file_flag_unique_pages':len(file_backed),
                              'identity_hash':digest.hexdigest()}


def page_flags(pfns):
    flags={};buckets={}
    for pfn in pfns:buckets.setdefault(pfn//512,[]).append(pfn)
    fd=os.open('/proc/kpageflags',os.O_RDONLY)
    try:
        for bucket,values in buckets.items():
            lo=min(values);hi=max(values)
            data=os.pread(fd,(hi-lo+1)*8,lo*8)
            require(len(data)==(hi-lo+1)*8,'Short kpageflags read')
            for pfn in values:flags[pfn]=struct.unpack_from('=Q',data,(pfn-lo)*8)[0]
    finally:os.close(fd)
    return flags


def sharing(sets,flags,page,file_sets):
    union=set().union(*sets);shared=sets[0]&sets[1]
    def metric(pool):
        consumers=sum(len(s&pool) for s in sets);common=shared&pool
        return {'unique_bytes':len(pool)*page,'shared_unique_bytes':len(common)*page,
                'shared_participating_bytes':len(common)*2*page,
                'avoided_duplicate_bytes':len(common)*page,'consumer_bytes':consumers*page,
                'sharing_participation_ratio':2*len(common)/consumers if consumers else None,
                'duplicate_avoidance_ratio':len(common)/consumers if consumers else None}
    groups={'zero':set(),'ksm':set(),'compound_or_huge':set(),'ordinary_file':set(),
            'ordinary_anon':set(),'unclassified_nonanon':set()}
    for pfn in union:
        f=flags[pfn]
        require(not f & ((1<<19)|(1<<20)|(1<<23)),'Unavailable/error/offline PFN encountered')
        file_consistent=all(pfn not in s or pfn in fs for s,fs in zip(sets,file_sets))
        kind=('zero' if f&(1<<24) else 'compound_or_huge' if f&((1<<15)|(1<<16)|(1<<17)|(1<<22))
              else 'ksm' if f&(1<<21) else 'ordinary_anon' if f&(1<<12)
              else 'ordinary_file' if file_consistent else 'unclassified_nonanon')
        groups[kind].add(pfn)
    return {'all_selected_guest_ram':metric(union),
            'categories':{k:metric(v) for k,v in groups.items()},
            'snapshot_file_shared_bytes_excluding_special_pages':len(shared&groups['ordinary_file'])*page,
            'compound_attribution_complete':not groups['compound_or_huge'],
            'raw_pfns_output':False,'cross_node_comparison':False}


def scoped_file_path(path):
    """Normalize legitimate relative-parent references, then enforce real scope."""
    normalized=Path(os.path.abspath(path))
    require(normalized.is_relative_to(SHORT) or normalized.is_relative_to(BASE/'state'),
            'File cache target is outside the approved experiment roots')
    require(path.resolve(strict=True)==normalized,'Redirected file cache target')
    return normalized


def resident(path,max_bytes,block=False):
    fd=None
    configured_path=str(path)
    try:
        if block:require(re.fullmatch(r'/dev/ublkb[0-9]+',str(path)),'Unexpected block device')
        else:
            path=scoped_file_path(path)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);m=os.fstat(fd)
        if block:
            require(stat.S_ISBLK(m.st_mode),'Expected block device')
            size=int((Path('/sys/class/block')/path.name/'size').read_text())*512
        else:
            require(stat.S_ISREG(m.st_mode) and m.st_uid==1204,'Expected owned upper file');size=m.st_size
        require(0<=size<=max_bytes,'Cache sampling capacity exceeds bound')
        page=os.sysconf('SC_PAGESIZE');libc=ctypes.CDLL(None,use_errno=True)
        libc.mmap.restype=ctypes.c_void_p
        libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
        libc.mincore.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
        libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
        cached=0
        for offset in range(0,size,256*1024**2):
            length=min(256*1024**2,size-offset);address=libc.mmap(None,length,1,1,fd,offset)
            require(address not in (None,ctypes.c_void_p(-1).value),'Cache mmap unsupported')
            try:
                bits=(ctypes.c_ubyte*((length+page-1)//page))()
                require(libc.mincore(address,length,bits)==0,'Device/file mincore unsupported')
                cached+=sum(bool(x&1) for x in bits)
            finally:require(libc.munmap(address,length)==0,'Cache munmap failed')
        return {'available':True,'path':str(path),'configured_path':configured_path,'logical_file_or_device_bytes':size,
                'resident_page_bytes':cached*page,'page_bytes':page,'dev':m.st_dev,'inode':m.st_ino,
                'rdev':m.st_rdev,'allocated_file_bytes':None if block else m.st_blocks*512,
                'data_read_or_faulted':False,'atomic_snapshot':False}
    except Exception as e:
        return {'available':False,'path':str(path),'error_type':type(e).__name__,
                'reason':str(e) if type(e) is RuntimeError else 'Read-only measurement unavailable'}
    finally:
        if fd is not None:os.close(fd)


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


def process_comparison(scope,samples):
    template_values=[];rows=[]
    for sample in samples:
        metrics=[g.get('whole_process',{}) for g in sample['guests']]
        if len(metrics)>=2 and len(metrics)==len(scope['sandbox_ids']) and all(m.get('available') for m in metrics):
            value=sum(m['rss_minus_pss_bytes'] for m in metrics)/(len(metrics)-1)
            if value>=0:template_values.append(value)
    for sid in scope['sandbox_ids']:
        values=[g['whole_process'] for s in samples for g in s['guests']
                if g['sandbox_id']==sid and g.get('whole_process',{}).get('available')]
        row={'template_id':scope['snapshot_id'],'sandbox_id':sid,'scope':'whole_firecracker_process',
             'valid_samples':len(values),'template_valid_samples':len(template_values),
             'template_shared_method':'CONDITIONAL_SUM_PROCESS_RSS_MINUS_PSS_DIV_N_MINUS_1_NOT_PFN',
             'template_min_shared_bytes':min(template_values) if template_values else None,
             'template_max_shared_bytes':max(template_values) if template_values else None}
        for metric in ('rss','pss','rss_minus_pss'):
            numbers=[m[metric+'_bytes'] for m in values]
            row['sandbox_min_'+metric+'_bytes']=min(numbers) if numbers else None
            row['sandbox_max_'+metric+'_bytes']=max(numbers) if numbers else None
        rows.append(row)
    return rows


def bind(scope,child):
    pid=child['pid'];proc=Path('/proc')/str(pid)
    require(identity(pid)[1]==child['start_ticks'],'Child identity changed')
    require((proc/'comm').read_text().strip()=='firecracker','Not a Firecracker process')
    uids=re.search(r'^Uid:\s+(.+)$',(proc/'status').read_text(),re.M)
    require(uids and list(map(int,uids[1].split()))==[1204]*4,'Child UID differs')
    parent=pid
    for _ in range(16):
        parent=identity(parent)[0]
        if parent==scope['main_pid']:break
        require(parent>1,'Child is outside the approved Runtime tree')
    require(parent==scope['main_pid'],'Runtime ancestor not found')
    stderr=Path(os.readlink(proc/'fd/2'))
    require(stderr.parent.parent==BASE/'logs/firecracker' and stderr.name=='firecracker-stderr.log'
            and stderr.parent.name in scope['sandbox_ids'],'Child log does not belong to selected sandbox')
    cwd=Path(os.readlink(proc/'cwd'))
    require(cwd.parent==SHORT and re.fullmatch(r'agentenv-fc-[A-Za-z0-9]+',cwd.name),'Unexpected child work directory')
    backend=memory_backend(owned(stderr.parent/'firecracker.log').decode())
    raw=(proc/'smaps').read_text();require(len(raw)<=4*1024**2,'smaps too large')
    regions=guest_regions(cwd,pid)
    maps=parse_guest_smaps(raw,backend,scope['memory_bytes'],regions)
    require(identity(pid)[1]==child['start_ticks'],'Child changed during Guest region binding')
    return {'pid':pid,'start_ticks':child['start_ticks'],'sandbox_id':stderr.parent.name,
            'memory_device':backend,'cwd':cwd,'maps':maps,'guest_regions':regions,
            'whole_process':whole_process_metrics(pid,child['start_ticks']),
            'binding_method':'PEERCRED_VERIFIED_FC_GET_GUEST_MEMORY_REGIONS_INTERSECT_SMAPS'}


def rootfs_fd_flags(pid,device):
    matches=[];fdroot=Path('/proc')/str(pid)/'fd'
    entries=list(fdroot.iterdir());require(len(entries)<=512,'FD count exceeds bound')
    for fd in entries:
        try:
            if os.readlink(fd)!=str(device):continue
            info=(fdroot.parent/'fdinfo'/fd.name).read_text()
            value=re.search(r'^flags:\s+([0-7]+)$',info,re.M)
            require(value is not None,'FD flags missing')
            flags=int(value[1],8)
            matches.append({'fd':int(fd.name),'flags_octal':value[1],
                            'O_DIRECT':bool(flags&os.O_DIRECT)})
        except FileNotFoundError:continue
    require(matches,'Rootfs device not found among this Guest open FDs')
    return matches


def marker_ranges(binding,target,page):
    """Translate only the declared arena GPAs through the authoritative FC API."""
    require(page==4096 and target.get('guest_page_bytes')==page,'Marker page size differs')
    gpas=target.get('gpas')
    require(isinstance(gpas,list) and len(gpas)==4096
            and all(type(g) is int and g>0 and g%page==0 for g in gpas)
            and len(set(gpas))==len(gpas),'Marker GPA list incomplete/aliased')
    regions=binding['guest_regions'];addresses=[]
    for gpa in gpas:
        matches=[]
        for r in regions:
            base=r.get('guest_phys_addr');size=r.get('size');host=r.get('base_host_virt_addr')
            require(all(type(x) is int and x>=0 for x in (base,size,host)),'Invalid FC GPA region')
            if base<=gpa and gpa+page<=base+size:matches.append(host+gpa-base)
        require(len(matches)==1,'Marker GPA not in exactly one Guest region')
        address=matches[0]
        require(address%page==0 and sum(m['start']<=address and address+page<=m['end'] for m in binding['maps'])==1,
                'Marker HVA outside selected Guest RAM')
        addresses.append(address)
    require(len(set(addresses))==len(addresses),'Marker HVA aliases')
    result=[]
    for index in range(4):
        ranges=[]
        for address in addresses[index*1024:(index+1)*1024]:
            if ranges and ranges[-1]['end']==address:ranges[-1]['end']+=page
            else:ranges.append({'start':address,'end':address+page})
        result.append(ranges)
    return result


def marker_sample(bound,targets,page):
    require(isinstance(targets,dict) and set(targets)=={b['sandbox_id'] for b in bound},'Marker sandbox scope differs')
    ranges=[marker_ranges(b,targets[b['sandbox_id']],page) for b in bound]
    result=[]
    for segment in range(4):
        readings=[pagemap(b['pid'],r[segment],page) for b,r in zip(bound,ranges)]
        require(all(r[2]['present_pte_pages']==r[2]['unique_pfn_pages']==1024
                    and r[2]['swapped_pte_pages']==0 for r in readings),'Marker pages not fully resident/unaliased')
        flags=page_flags(set().union(*(r[0] for r in readings)))
        again=[pagemap(b['pid'],r[segment],page) for b,r in zip(bound,ranges)]
        result.append({'segment':segment,'bytes_per_sandbox':4*1024**2,
            'stable':all(a[2]['identity_hash']==b[2]['identity_hash'] for a,b in zip(readings,again)),
            'physical':sharing([r[0] for r in readings],flags,page,[r[1] for r in readings]),
            'guests':[{'sandbox_id':b['sandbox_id'],'pagemap':r[2],
                      'segment_gpa_sha256':hashlib.sha256(json.dumps(targets[b['sandbox_id']]['gpas'][segment*1024:(segment+1)*1024]).encode()).hexdigest()}
                     for b,r in zip(bound,readings)]})
    return result


def collect_scope(scope):
    report={'revision':'cow-ram-scoped-readonly-v5','scope':{k:v for k,v in scope.items() if k!='marker_targets'},'samples':[],
            'system_changes':False,'process_memory_contents_read':False,'SDK_called':False}
    try:
        require(os.geteuid()==0 and os.uname().nodename=='server1','A existing root terminal only')
        require(scope['memory_bytes']==512*1024**2 and len(scope['children'])==len(scope['sandbox_ids'])==2,'Unexpected sample budget')
        require(len(set(scope['sandbox_ids']))==2 and all(re.fullmatch(r'[0-9a-f-]{36}',x) for x in scope['sandbox_ids']),'Invalid sandbox scope')
        require(re.fullmatch(r'[0-9a-f-]{36}',scope['snapshot_id']),'Invalid snapshot scope')
        require(len({c['pid'] for c in scope['children']})==2,'Duplicate child PIDs')
        require(type(scope['main_pid']) is int and scope['main_pid']>1
                and all(type(c['pid']) is int and c['pid']>1 and re.fullmatch(r'[0-9]+',c['start_ticks']) for c in scope['children']),
                'Invalid process identities')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==scope['boot_id'],'Boot changed')
        signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(RuntimeError('Sampling deadline reached')))
        signal.alarm(120)
        repo=BASE/'state/snapshot-store/repository'
        raw=owned(repo/'catalog/records'/(scope['snapshot_id']+'.json'))
        require(hashlib.sha256(raw).hexdigest()==scope['catalog_sha256'],'Snapshot catalog changed')
        record=json.loads(raw);layer_paths={}
        require(record.get('id')==scope['snapshot_id'],'Snapshot catalog identity differs')
        for kind in ('memory','rootfs'):
            for entry in record['committed'][kind+'_layers']:
                layer=entry if kind=='memory' else entry.get('Managed')
                require(isinstance(layer,dict) and re.fullmatch(r'sha256:[0-9a-f]{64}',layer['digest']),'Unresolved external layer')
                path=repo/'managed-layers'/(layer['digest'].replace(':','_')+'.overlaybd.commit')
                layer_paths.setdefault(str(path),[]).append(kind)
        require(len(layer_paths)<=64,'Layer count exceeds bound')
        for _ in range(3):
            before=time.time()
            props=subprocess.run(['/usr/bin/systemctl','show',UNIT,'--property=MainPID,User,Group'],capture_output=True,text=True,timeout=10,check=True)
            fields=dict(x.split('=',1) for x in props.stdout.splitlines() if '=' in x)
            require(fields.get('MainPID')==str(scope['main_pid']) and fields.get('User')==fields.get('Group')=='jwk','Runtime unit changed')
            require(identity(scope['main_pid'])[1]==scope['main_start_ticks'],'Runtime identity changed')
            bound=[bind(scope,c) for c in scope['children']]
            require({b['sandbox_id'] for b in bound}==set(scope['sandbox_ids']),'Sandbox/process binding is not one-to-one')
            page=os.sysconf('SC_PAGESIZE')
            readings=[pagemap(b['pid'],b['maps'],page) for b in bound]
            flags=page_flags(set().union(*(r[0] for r in readings)))
            again=[pagemap(b['pid'],b['maps'],page) for b in bound]
            stable=all(a[2]['identity_hash']==b[2]['identity_hash'] for a,b in zip(readings,again))
            row={'started_unix':before,'page_bytes':page,'pagemap_stable_during_flags':stable,
                 'physical_page_observation':sharing([r[0] for r in readings],flags,page,[r[1] for r in readings]),
                 'guests':[],'memory_device_cache':{},'rootfs':[],'stored_layer_cache':[]}
            if 'marker_targets' in scope:
                row['marker_segments']=marker_sample(bound,scope['marker_targets'],page)
            for b,r in zip(bound,readings):
                require(identity(b['pid'])[1]==b['start_ticks'],'Child changed during sample')
                row['guests'].append({'sandbox_id':b['sandbox_id'],'pid':b['pid'],'memory_device':b['memory_device'],
                                      'vma_count':len(b['maps']),'vmas_preview':b['maps'][:8],
                                      'virtual_bytes_by_mapping_kind':{kind:sum(m['end']-m['start'] for m in b['maps'] if m.get('mapping_kind')==kind)
                                                                     for kind in ('snapshot_file_vma','anonymous_inside_guest_region')},
                                      'pagemap':r[2],'whole_process':b.get('whole_process',{'available':False}),
                                      'binding_method':b.get('binding_method'),'guest_regions':b.get('guest_regions')})
                if b['memory_device'] not in row['memory_device_cache']:
                    row['memory_device_cache'][b['memory_device']]=resident(Path(b['memory_device']),scope['memory_bytes'],True)
                try:
                    rootdev=(b['cwd']/'user-rootfs').resolve(strict=True)
                    fd_flags=rootfs_fd_flags(b['pid'],rootdev)
                    upper={}
                    cfg=json.loads(owned(b['cwd']/'overlaybd/image.json'))
                    lowers=[]
                    require(isinstance(cfg.get('lowers'),list) and len(cfg['lowers'])<=64,'Unexpected runtime lower list')
                    for lower in cfg['lowers']:
                        value=lower.get('file')
                        item={'digest':lower.get('digest') if re.fullmatch(r'sha256:[0-9a-f]{64}',str(lower.get('digest',''))) else None}
                        if value:
                            path=Path(value);path=path if path.is_absolute() else b['cwd']/'overlaybd'/path
                            item['local_file']=resident(path,2*1024**3)
                        else:item['local_file']={'available':False,'reason':'NO_LOCAL_FILE_REFERENCE'}
                        lowers.append(item)
                    for name in ('data','index'):
                        value=cfg.get('upper',{}).get(name)
                        if value:
                            path=Path(value);path=path if path.is_absolute() else b['cwd']/'overlaybd'/path
                            require(path.parent==b['cwd']/'overlaybd','Upper is outside this Guest runtime')
                            upper[name]=resident(path,64*1024**3)
                    row['rootfs'].append({'sandbox_id':b['sandbox_id'],'fd_flags':fd_flags,
                                          'device_cache':resident(rootdev,64*1024**3,True),'upper_files':upper,
                                          'runtime_lowers':lowers})
                except Exception as e:
                    row['rootfs'].append({'sandbox_id':b['sandbox_id'],'available':False,
                                          'error_type':type(e).__name__,
                                          'reason':str(e) if type(e) is RuntimeError else 'Scoped rootfs observation unavailable'})
            for path,kinds in layer_paths.items():
                row['stored_layer_cache'].append(dict(resident(Path(path),2*1024**3),kinds=kinds))
            row['finished_unix']=time.time();report['samples'].append(row);time.sleep(1)
        report['status']='SCOPED_RAM_PAGE_AND_CACHE_OBSERVATIONS_COMPLETED'
        report['stable_pagemap_samples']=sum(s['pagemap_stable_during_flags'] for s in report['samples'])
        report['whole_process_comparison']=process_comparison(scope,report['samples'])
        report['acceptance_note']='Non-atomic observations; discard unstable samples. Compound/zero/KSM categories are separate. Do not sum Guest RAM and memory-device cache without overlap correction.'
    except Exception as e:
        report.update(status='STOPPED_SCOPED_READONLY_MEASUREMENT',error_type=type(e).__name__,
                      reason=str(e) if isinstance(e,RuntimeError) else 'Bounded read failed; no system changes')
        if isinstance(e,BindingError):report['binding_diagnostics']=e.diagnostics
    finally:
        if hasattr(signal,'SIGALRM'):signal.alarm(0)
    print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
    return report
