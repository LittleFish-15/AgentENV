"""Literal, scope-bound Linux memory accounting additions.

Uses the already reviewed collector's identity, Guest-region, mincore and PFN
helpers. No payload reads, clear_refs, process writes, SDK calls or host scans.
"""
import collections, gc

MEMINFO_KEYS=('MemTotal','MemFree','MemAvailable','Buffers','Cached','SwapCached','Active','Inactive',
    'AnonPages','Shmem','Dirty','Writeback','Mapped','Slab','SReclaimable','SUnreclaim','PageTables',
    'KernelStack','Unevictable','Mlocked','AnonHugePages','ShmemHugePages','FileHugePages','SwapTotal','SwapFree')
VM_FIELDS=('Rss','Pss','Pss_Anon','Pss_File','Pss_Shmem','Shared_Clean','Shared_Dirty','Private_Clean',
    'Private_Dirty','Anonymous','AnonHugePages','ShmemPmdMapped','FilePmdMapped','Shared_Hugetlb','Private_Hugetlb','Swap','SwapPss')


def memory_host():
    start=time.monotonic_ns()
    values={k:int(v.split()[0])*1024 for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines()) if k in MEMINFO_KEYS}
    return {'monotonic_ns':start,'unix':time.time(),'finished_monotonic_ns':time.monotonic_ns(),**values}


def proc_text(pid,name,limit):
    require(name in ('smaps','smaps_rollup','status','comm'),'Unapproved proc field')
    with (Path('/proc')/str(pid)/name).open() as f:raw=f.read(limit+1)
    require(len(raw)<=limit,'Bounded proc field exceeded');return raw


def kb_fields(raw,names):
    values={m[1]:int(m[2])*1024 for m in re.finditer(r'(?m)^(\w+):\s+(\d+) kB\s*$',raw)}
    return {k:values.get(k) for k in names}


def whole_process_metrics(pid,ticks):
    row={'available':False,'scope':'whole_bound_process','pid':pid,'start_ticks':ticks,'measurement_monotonic_ns':time.monotonic_ns(),
         'rss_source':'/proc/PID/status:VmRSS','pss_source':'/proc/PID/smaps_rollup:Pss','atomic_snapshot':False}
    try:
        require(identity(pid)[1]==ticks,'Process identity changed before breakdown')
        row['status_bytes']=kb_fields(proc_text(pid,'status',65536),('VmRSS','RssAnon','RssFile','RssShmem','VmSwap','VmSize','HugetlbPages'))
        row['rollup_bytes']=kb_fields(proc_text(pid,'smaps_rollup',65536),VM_FIELDS)
        rss=row['status_bytes']['VmRSS'];pss=row['rollup_bytes']['Pss'];rollup_rss=row['rollup_bytes']['Rss']
        require(all(type(x) is int for x in (rss,pss,rollup_rss)),'Missing process RSS/PSS fields')
        row['pss_categories_complete']=all(row['rollup_bytes'][k] is not None for k in ('Pss_Anon','Pss_File','Pss_Shmem'))
        require(identity(pid)[1]==ticks,'Process identity changed after breakdown')
        row.update(available=True,rss_bytes=rss,pss_bytes=pss,rss_minus_pss_bytes=rss-pss,smaps_rollup_rss_bytes=rollup_rss)
    except Exception as e:
        row['breakdown_error']={'type':type(e).__name__,'reason':str(e)}
        row['pss_categories_complete']=False
    row['measurement_finished_monotonic_ns']=time.monotonic_ns();return row


def sum_vmas(maps):
    missing={k:sum(k not in m['bytes'] for m in maps) for k in VM_FIELDS}
    return {'vma_count':len(maps),'virtual_bytes':sum(m['end']-m['start'] for m in maps),
        'metrics':{k:sum(m['bytes'][k] for m in maps) if not missing[k] else None for k in VM_FIELDS},
        'missing_field_vma_counts':{k:v for k,v in missing.items() if v}}


def all_smaps(raw):
    result=[];current=None
    for line in raw.splitlines():
        m=re.match(r'^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$',line)
        if m:
            current={'start':int(m[1],16),'end':int(m[2],16),'permissions':m[3],'path':m[5],'bytes':{}};result.append(current)
        elif current is not None:
            m=re.fullmatch(r'(\w+):\s+(\d+) kB',line)
            if m:current['bytes'][m[1]]=int(m[2])*1024
    require(0<len(result)<=4096,'Unexpected VMA count');return result


def ram_classification(binding):
    pid=binding['pid'];ticks=binding['start_ticks']
    row={'sandbox_id':binding['sandbox_id'],'template_id':binding['template_id'],'pid':pid,'start_ticks':ticks,'available':False,'monotonic_ns':time.monotonic_ns()}
    try:
        require(identity(pid)[1]==ticks,'Guest changed before VMA read')
        regions=binding['guest_regions'];raw=proc_text(pid,'smaps',8*1024**2)
        selected=parse_guest_smaps(raw,binding['memory_device'],4096*1024**2,regions)
        complete=not any(m.get('smaps_metrics_omitted_due_to_clipping') for m in selected)
        other=[];boundary=[]
        for m in all_smaps(raw):
            overlaps=[g for g in regions if max(m['start'],g['base_host_virt_addr'])<min(m['end'],g['base_host_virt_addr']+g['size'])]
            if not overlaps:other.append(m)
            elif not any(g['base_host_virt_addr']<=m['start']<m['end']<=g['base_host_virt_addr']+g['size'] for g in overlaps):boundary.append(m)
        row.update(available=True,guest_ram=sum_vmas(selected),fc_outside_guest_ram=sum_vmas(other),
            exact_vma_partition=complete and not boundary,boundary_vmas_not_apportioned=len(boundary),
            snapshot_named_vma=sum_vmas([m for m in selected if m['mapping_kind']=='snapshot_file_vma']),
            anonymous_guest_vma=sum_vmas([m for m in selected if m['mapping_kind']=='anonymous_inside_guest_region']),
            note='Anonymous/private metrics inside file-named VMAs remain included; pathname alone is not a CoW classifier. Private fields are process mapping accounting, not an all-host PFN proof.')
        if not complete:row['guest_ram']['metrics']={k:None for k in VM_FIELDS}
        require(identity(pid)[1]==ticks,'Guest changed during VMA read')
    except Exception as e:row.update(available=False,error_type=type(e).__name__,reason=str(e))
    row['finished_monotonic_ns']=time.monotonic_ns();return row


def descendant_services(active,guest_pids):
    main=int(active['MainPID']);queue=[main];seen=set();selected=[]
    while queue:
        pid=queue.pop()
        if pid in seen:continue
        seen.add(pid);require(len(seen)<=128,'Service descendant budget exceeded')
        try:
            ticks=identity(pid)[1];comm=proc_text(pid,'comm',128).strip()
            if pid==main or comm=='uvm-ublk-daemon':
                require(pid not in guest_pids,'Service/Guest roles overlap')
                selected.append({'role':'runtime' if pid==main else 'ublk_daemon',**whole_process_metrics(pid,ticks)})
            tasks=list((Path('/proc')/str(pid)/'task').iterdir());require(len(tasks)<=512,'Service thread budget exceeded')
            for task in tasks:
                try:children=(task/'children').read_text().split()
                except FileNotFoundError:continue
                require(len(children)<=128,'Service child budget exceeded')
                for child in children:
                    require(child.isdecimal(),'Invalid child PID')
                    try:parent=identity(int(child))[0]
                    except (FileNotFoundError,ProcessLookupError):continue
                    if parent==pid:queue.append(int(child))
            require(identity(pid)[1]==ticks,'Service changed during tree read')
        except (FileNotFoundError,ProcessLookupError):continue
    return {'processes':selected,'visited_descendants':len(seen),'scope':'original Runtime and its ublk daemon descendants only; other host processes excluded','broker_used':False}


def memory_devices(bound):
    if not bound:return {'devices':[],'unique_devices':0,'all_available':True,'unique_resident_bytes':None,'scope':'No live bound Guest devices; not evidence that old device cache is zero.'}
    groups={}
    for b in bound:groups.setdefault(b['memory_device'],[]).append(b)
    rows=[]
    for name,users in groups.items():
        first=users[0]['memory_device_identity'];row={'device':name,'sandbox_ids':[b['sandbox_id'] for b in users],'template_ids':sorted({b['template_id'] for b in users})}
        try:
            require(all(b['memory_device_identity']==first for b in users),'Device identity alias differs')
            for b in users:require(identity(b['pid'])[1]==b['start_ticks'],'Guest changed before device cache query')
            p=Path(name);s=p.stat();require(stat.S_ISBLK(s.st_mode) and (s.st_dev,s.st_ino,s.st_rdev)==tuple(first),'Device replaced before sampling')
            measured=resident(p,4096*1024**2,True)
            after=p.stat();require((after.st_dev,after.st_ino,after.st_rdev)==tuple(first),'Device replaced during sampling')
            for b in users:require(identity(b['pid'])[1]==b['start_ticks'],'Guest changed during device cache query')
            row.update(measured,scope='whole memory ublk device residency; not per-Guest accessed pages',add_to_Guest_RSS=False)
        except Exception as e:row.update(available=False,error_type=type(e).__name__,reason=str(e))
        rows.append(row)
    return {'devices':rows,'unique_devices':len(rows),'all_available':all(r.get('available') for r in rows),
        'unique_resident_bytes':sum(r['resident_page_bytes'] for r in rows) if all(r.get('available') for r in rows) else None,
        'accounting':'Compare with Host Buffers; do not add again to file-backed Guest RSS/PSS.'}


def memory_snapshot(plan,active,bound,phase):
    result={'phase':phase,'started_monotonic_ns':time.monotonic_ns(),'unix':time.time(),'host_before':memory_host(),'atomic_snapshot':False}
    current=unit_state();require((current['MainPID'],current['ticks'])==(active['MainPID'],active['ticks']),'Runtime changed before memory snapshot')
    result['guests']=[ram_classification(b) for b in bound]
    result['memory_devices']=memory_devices(bound)
    result['memory_lower_files']=stored_memory_files(plan)
    if not bound or phase.startswith('T2'):
        result['rootfs_lower_files']=stored_memory_files(plan,'template_lowers',64)
    else:result['rootfs_lower_files']={'available':False,'reason':'Measured separately by the unchanged owner file sampler'}
    result['services']=descendant_services(active,{b['pid'] for b in bound})
    result['measurement_helpers']=[{'role':'root_collector',**whole_process_metrics(os.getpid(),identity(os.getpid())[1])},
                                   {'role':'owner_controller',**whole_process_metrics(plan['owner_pid'],plan['owner_ticks'])}]
    result['host_after']=memory_host();result['finished_monotonic_ns']=time.monotonic_ns()
    result['duration_seconds']=(result['finished_monotonic_ns']-result['started_monotonic_ns'])/1e9
    result['complete']=all(g.get('available') and g.get('exact_vma_partition') and all(g['guest_ram']['metrics'].get(k) is not None for k in ('Rss','Pss','Anonymous','Private_Dirty')) for g in result['guests']) and result['memory_devices']['all_available'] and result['memory_lower_files']['all_available'] and bool(result['services']['processes']) and all(p.get('available') for p in result['services']['processes'])
    return result


def stored_memory_files(plan,inventory='template_memory_lowers',maximum=16):
    groups={}
    for tid,files in plan[inventory].items():
        for f in files:
            key=(f['dev'],f['inode']);entry=groups.setdefault(key,{'expected':f,'template_ids':[]});entry['template_ids'].append(tid)
    require(0<len(groups)<=maximum and sum(g['expected']['file_bytes'] for g in groups.values())<=16*1024**3,'Stored lower inventory exceeds budget')
    rows=[]
    for entry in groups.values():
        f=entry['expected'];path=Path(f['path']);row={'template_ids':entry['template_ids']}
        try:
            require(path.parent==BASE/'state/snapshot-store/repository/managed-layers' and path.resolve(strict=True)==path,'Memory lower outside repository')
            s=path.stat();require((s.st_dev,s.st_ino,s.st_size)==(f['dev'],f['inode'],f['file_bytes']),'Memory lower identity changed')
            row.update(resident(path,2*1024**3))
        except Exception as e:row.update(available=False,error_type=type(e).__name__,reason=str(e))
        rows.append(row)
    return {'files':rows,'all_available':all(r.get('available') for r in rows),
        'scope':'prepared template catalog '+inventory+'; not a per-Guest memory access trace',
        'unique_resident_bytes':sum(r['resident_page_bytes'] for r in rows) if all(r.get('available') for r in rows) else None}


def pfn_checkpoint(bound,phase):
    """Bounded diagnostic. Any instability/masking remains NA, not zero sharing."""
    started=time.monotonic();deadline=started+45;page=os.sysconf('SC_PAGESIZE');result={'phase':phase,'available':False,'pairs':[],'raw_pfns_output':False,'scope':'mapped Guest RAM of these eight Guests only','cross_node_comparison':False}
    require(len(bound)==8 and page==4096,'Unexpected PFN checkpoint scope')
    all_sets=[];all_file=[];all_flags={}
    def read_one(b):
        require(time.monotonic()<deadline,'PFN soft deadline')
        require(identity(b['pid'])[1]==b['start_ticks'],'Guest identity changed')
        maps=parse_guest_smaps(proc_text(b['pid'],'smaps',8*1024**2),b['memory_device'],4096*1024**2,b['guest_regions'])
        value=pagemap(b['pid'],maps,page)
        require(len(value[0])<=600000,'Per-Guest PFN resident-page budget exceeded')
        require(identity(b['pid'])[1]==b['start_ticks'],'Guest changed during PFN read')
        return value
    try:
        for tid in sorted({b['template_id'] for b in bound}):
            pair=[b for b in bound if b['template_id']==tid];require(len(pair)==2,'Expected pair')
            row={'template_id':tid,'sandbox_ids':[b['sandbox_id'] for b in pair],'available':False}
            try:
                first=[read_one(b) for b in pair];second=[read_one(b) for b in pair]
                require(all(a[2]['identity_hash']==b[2]['identity_hash'] for a,b in zip(first,second)),'PFN identity changed between reads')
                union=first[0][0]|first[1][0];require(len(union)<=900000 and time.monotonic()<deadline,'Pair PFN budget exceeded')
                flags=page_flags(union);require(time.monotonic()<deadline,'PFN flags soft deadline')
                measured=sharing([v[0] for v in first],flags,page,[v[1] for v in first])
                require(len(set(all_flags)|set(flags))<=2000000,'Global PFN resident-page budget exceeded')
                row.update(available=True,measurement=measured,stable_reads=[v[2] for v in first])
                all_sets.extend(v[0] for v in first);all_file.extend(v[1] for v in first);all_flags.update(flags)
            except Exception as e:row.update(available=False,error_type=type(e).__name__,reason=str(e))
            result['pairs'].append(row)
        if len(all_sets)==8 and all(p['available'] for p in result['pairs']):
            special=(1<<15)|(1<<16)|(1<<17)|(1<<19)|(1<<20)|(1<<21)|(1<<22)|(1<<23)|(1<<24)
            ordinary={p for p,f in all_flags.items() if not f&special and (f&(1<<12) or all(p not in s or p in fs for s,fs in zip(all_sets,all_file)))}
            counts=collections.Counter(p for s in all_sets for p in s if p in ordinary)
            result.update(available=True,ordinary_mapped_unique_bytes=len(counts)*page,
                ordinary_shared_by_at_least_two_selected_Guests_bytes=sum(n>=2 for n in counts.values())*page,
                ordinary_duplicate_mapping_bytes=sum(n-1 for n in counts.values())*page,
                special_or_unclassified_unique_bytes=(len(all_flags)-len(counts))*page,
                note='Sequential stable pair snapshots, not one atomic eight-Guest snapshot; ordinary counts exclude zero/KSM/compound/error/unclassified pages. Unique-to-selected-Guests does not prove globally unshared.')
    except Exception as e:result.update(error_type=type(e).__name__,reason=str(e))
    finally:
        result['duration_seconds']=time.monotonic()-started
        all_sets.clear();all_file.clear();all_flags.clear();gc.collect()
    return result
