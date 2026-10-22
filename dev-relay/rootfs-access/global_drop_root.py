"""Literal root-only addition: two ordered, reviewed page-cache drops."""


def root_cache_counts():
    return {k:int(v.split()[0])*1024 for k,v in
            (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
            if k in ('Cached','Buffers','Shmem','Dirty','Writeback','SReclaimable','MemAvailable')}


def global_drop_once(request, report, plan, bound, others):
    phase=request.get('phase');drops=report.setdefault('global_pagecache_drops',[])
    require(plan.get('operator_declared_quiet_window') is True,'Quiet-window declaration missing')
    require(len(drops)<2 and phase==('idle_control','replay')[len(drops)],'Unexpected/repeated global drop')
    require(len(bound)==8,'Eight Guests must be bound before global cache drop')
    if drops:require(time.monotonic_ns()-drops[0]['finished_monotonic_ns']>=60*10**9,'Idle control interval incomplete')
    require(other_units()==others,'Other service identities changed; no global cache drop')
    require(set(find_firecrackers(int(unit_state()['MainPID'])))=={b['pid'] for b in bound},
            'Unexpected Guest appeared in original service; no global cache drop')
    for b in bound:
        require(identity(b['pid'])[1]==b['start_ticks'],'Bound Guest identity changed')
        code,body=api_get('/sandboxes/'+b['sandbox_id'])
        require(code==200 and body.get('metadata',{}).get('cow55_run')==plan['run_id'],'Guest ownership changed')
    event={'phase':phase,'value':1,'started_monotonic_ns':time.monotonic_ns(),
           'started_unix':time.time(),'before_sync':root_cache_counts(),
           'sync_completed':False,'drop_requested':False,'drop_write_completed':False}
    drops.append(event) # Record intent before any side effect. Never retry.
    print('ROOT_PHASE=global_pagecache_drop_'+phase,flush=True)
    subprocess.run(['/usr/bin/sync'],check=True,timeout=120)
    event['sync_completed']=True;event['after_sync']=root_cache_counts()
    require(other_units()==others,'Other service identities changed during sync')
    event['drop_requested']=True
    with open('/proc/sys/vm/drop_caches','w',encoding='ascii') as f:
        require(f.write('1\n')==2,'Incomplete drop_caches write');f.flush()
    event['drop_write_completed']=True
    event.update(after_drop=root_cache_counts(),finished_monotonic_ns=time.monotonic_ns(),finished_unix=time.time())
    return event
