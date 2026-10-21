"""Appended to the pinned read-only collector and pasted inline by the operator.

Only the authorized literal Guest identities supplied at launch are eligible. No root
file writes, process signals, service changes, Guest commands, or SDK calls.
"""
import threading

def physical_wave_wait_seconds(wave_phase,current_phase,elapsed):
    return 0 if wave_phase!=current_phase else max(0,300-elapsed)

def cohort_wire_send(client,value):
    data=json.dumps(value,separators=(',',':')).encode()
    require(0<len(data)<=4*1024**2,'Frame exceeds bound');client.sendall(struct.pack('!I',len(data))+data)
def cohort_wire_receive(client):
    def exact(n):
        result=bytearray()
        while len(result)<n:
            block=client.recv(min(65536,n-len(result)))
            if not block:raise RuntimeError('Coordinator disconnected')
            result.extend(block)
        return result
    n=struct.unpack('!I',exact(4))[0];require(0<n<=4*1024**2,'Invalid control frame')
    value=json.loads(exact(n));require(isinstance(value,dict),'Invalid frame');return value

def cohort_reader(scope,endpoint):
    prefix='COW33_BATCH' if scope.get('template_count') in (16,17) else 'COW55'
    result={'revision':'cow55-scoped-reader-v1','run_id':scope['run_id'],'read_only':True,
            'SDK_called':False,'services_modified':False,'process_memory_contents_read':False,'frames':{},'errors':[]}
    stop=threading.Event();send_lock=threading.Lock();phase_lock=threading.Lock()
    phase={'name':'baseline','finished':set()};threads=[]
    client=None
    def send(channel,data):
        with send_lock:
            cohort_wire_send(client,{'channel':channel,'run_id':scope['run_id'],'data':data})
            result['frames'][channel]=result['frames'].get(channel,0)+1
    def current_phase(sids):
        with phase_lock:
            if phase['name']!='replay':return phase['name']
            done=sum(s in phase['finished'] for s in sids)
            return 'replay' if done==0 else 'idle_after_replay' if done==2 else 'mixed_replay_and_idle'
    def guarded(fn):
        try:fn()
        except Exception as e:
            result['errors'].append({'sampler':fn.__name__,'type':type(e).__name__,'reason':str(e) if isinstance(e,RuntimeError) else 'Scoped read/transport failure'})
            stop.set()
    try:
        require(os.geteuid()==0 and os.uname().nodename=='server1','A root inline reader only')
        count=scope.get('template_count',55)
        require(type(count) is int and count in (16,17,55),'Unexpected template count')
        guests=2*count
        require(scope['memory_bytes']==4096*1024**2 and len(scope['pairs'])==count and len(scope['children'])==guests,'Unexpected cohort budget')
        require(re.fullmatch(r'[0-9a-f]{32}',scope['run_id']) and type(scope['main_pid']) is int and scope['main_pid']>1,'Invalid run/process identity')
        require(len({c['pid'] for c in scope['children']})==guests and all(type(c['pid']) is int and c['pid']>1 and re.fullmatch(r'[0-9]+',c['start_ticks']) for c in scope['children']),'Invalid child identity set')
        ids=[sid for p in scope['pairs'] for sid in p['sandbox_ids']]
        require(all(len(p['sandbox_ids'])==2 for p in scope['pairs']),'Each template requires exactly two Guests')
        require(len(set(ids))==guests and all(re.fullmatch(r'[0-9a-f-]{36}',sid) for sid in ids),'Invalid sandbox scope')
        require(len({p['template_id'] for p in scope['pairs']})==count,'Duplicate templates')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==scope['boot_id'],'Boot changed')
        require(identity(scope['main_pid'])[1]==scope['main_start_ticks'],'Original Runtime changed')
        if count in (16,17):
            limits=Path('/proc/'+str(scope['main_pid'])+'/limits').read_text()
            require(re.search(r'Max locked memory\s+2147483648\s+2147483648\s+bytes',limits),'Original process memlock differs')
            result['original_runtime_memlock_bytes']=2147483648
        unit=subprocess.run(['/usr/bin/systemctl','show',UNIT,'--property=ActiveState,MainPID,User'],capture_output=True,text=True,timeout=10,check=True)
        props=dict(s.split('=',1) for s in unit.stdout.splitlines() if '=' in s)
        require(props.get('ActiveState')=='active' and props.get('User')=='jwk' and int(props.get('MainPID','0'))==scope['main_pid'],'Approved original unit differs')
        path=Path(endpoint['path']);require(path.parent==ROOT/'r' and path.name=='c55-'+scope['run_id'][:12]+'.sock','Unexpected control endpoint')
        meta=path.lstat();require(stat.S_ISSOCK(meta.st_mode) and meta.st_uid==1204 and stat.S_IMODE(meta.st_mode)==0o600 and path.resolve(strict=True)==path,'Control socket identity differs')
        client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.settimeout(30);client.connect(str(path))
        pid,uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        require((pid,uid)==(endpoint['pid'],1204) and identity(pid)[1]==endpoint['ticks'],'Coordinator peer differs')
        send('hello',{'scope_run':scope['run_id']})
        catalog={};repo=BASE/'state/snapshot-store/repository'
        for pair in scope['pairs']:
            raw=owned(repo/'catalog/records'/(pair['template_id']+'.json'),2*1024**2)
            require(hashlib.sha256(raw).hexdigest()==pair['catalog_sha256'],'Template catalog changed')
            record=json.loads(raw);require(record['resources']['memory_mib']==4096,'Template RAM differs');catalog[pair['template_id']]=record
        binding_scope=dict(scope,sandbox_ids=ids)
        bound={}
        for child in scope['children']:
            result['last_binding_pid']=child['pid'];result['bound_guest_count']=len(bound)
            b=bind(binding_scope,child);require(b['sandbox_id'] not in bound,'Duplicate Guest binding');bound[b['sandbox_id']]=b
        require(set(bound)==set(ids),'Guest bindings do not match complete cohort')
        result['bound_guest_count']=guests
        result['template_count']=count
        send('ready',{'bound_guests':guests,'template_count':count,'binding_method':'FC_API_PEERCRED_AND_SCOPED_PROCESS_TREE'})

        def process_loop():
            sequence=0
            while not stop.is_set():
                began=time.time();rows=[]
                for pair in scope['pairs']:
                    start=time.time();metrics=[];before_phase=current_phase(pair['sandbox_ids'])
                    for sid in pair['sandbox_ids']:
                        b=bound[sid];value=whole_process_metrics(b['pid'],b['start_ticks'])
                        metrics.append(dict(sandbox_id=sid,identity_verified=value.get('available',False),
                                            rss_bytes=value.get('rss_bytes'),pss_bytes=value.get('pss_bytes'),error_type=value.get('error_type')))
                    phase_stable=before_phase==current_phase(pair['sandbox_ids'])
                    if not phase_stable:
                        for value in metrics:value.update(identity_verified=False,error_type='PHASE_CHANGED_DURING_PAIR_SAMPLE')
                    rows.append({'run_id':scope['run_id'],'variant':'original','mode':'continuous','node':'node-a','boot_id':scope['boot_id'],
                        'phase':before_phase,'phase_stable':phase_stable,'template_id':pair['template_id'],'sample_id':str(sequence),
                        'sandbox_ids':pair['sandbox_ids'],'started_unix':start,'finished_unix':time.time(),'processes':metrics})
                host={k+'_bytes':int(v)*1024 for k,v in re.findall(r'(?m)^(MemAvailable|Cached|SReclaimable|Dirty|Writeback):\s+(\d+) kB',Path('/proc/meminfo').read_text())}
                helper=whole_process_metrics(os.getpid(),identity(os.getpid())[1]);helper['scope']='python_root_collector'
                send('process',{'samples':rows,'sweep_started_unix':began,'sweep_finished_unix':time.time(),'requested_interval_seconds':1,
                                'host_memory_background_not_template_attribution':host,'collector_process':helper})
                sequence+=1;stop.wait(max(.01,1-(time.time()-began)))

        def cache_loop():
            sequence=0
            while not stop.is_set():
                begin=time.time();files={};references=[];devices={};errors=[]
                phase_start={p['template_id']:current_phase(p['sandbox_ids']) for p in scope['pairs']}
                def file_ref(path,kind,tid,sid):
                    normalized=scoped_file_path(path);meta=normalized.stat();require(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204,'Unexpected measured file')
                    key=str(meta.st_dev)+':'+str(meta.st_ino)
                    if key not in files:
                        stamp=time.time();r=resident(normalized,64*1024**3)
                        require(r.get('available') and (r.get('dev'),r.get('inode'))==(meta.st_dev,meta.st_ino),'File cache unavailable or identity changed')
                        files[key]={'file_id':key,'node':'node-a','boot_id':scope['boot_id'],'device':meta.st_dev,'inode':meta.st_ino,
                            'path':str(normalized),'file_bytes':r.get('logical_file_or_device_bytes'),'allocated_bytes':r.get('allocated_file_bytes'),
                            'resident_bytes':r.get('resident_page_bytes'),'available':r.get('available',False),'started_unix':stamp,'finished_unix':time.time()}
                    references.append({'file_id':key,'kind':kind,'template_id':tid,'sandbox_id':sid})
                for pair in scope['pairs']:
                    if stop.is_set():break
                    tid=pair['template_id']
                    for sid in pair['sandbox_ids']:
                        b=bound[sid]
                        try:
                            require(identity(b['pid'])[1]==b['start_ticks'],'Guest identity changed')
                            cfg=json.loads(owned(b['cwd']/'overlaybd/image.json'))
                            require(isinstance(cfg.get('lowers'),list) and 0<len(cfg['lowers'])<=256,'Unexpected lower count')
                            for layer in cfg['lowers']:
                                require(bool(layer.get('file')),'External lower placement unresolved')
                                p=Path(layer['file']);file_ref(p if p.is_absolute() else b['cwd']/'overlaybd'/p,'rootfs_lower',tid,sid)
                            for name in ('data','index'):
                                p=Path(cfg['upper'][name]);file_ref(p if p.is_absolute() else b['cwd']/'overlaybd'/p,'rootfs_upper',tid,sid)
                            for layer in catalog[tid]['committed']['memory_layers']:
                                require(re.fullmatch(r'sha256:[0-9a-f]{64}',layer['digest']),'Invalid memory digest')
                                file_ref(repo/'managed-layers'/(layer['digest'].replace(':','_')+'.overlaybd.commit'),'memory_lower',tid,sid)
                            for kind,dev,size in [('memory',Path(b['memory_device']),scope['memory_bytes']),('rootfs',(b['cwd']/'user-rootfs').resolve(strict=True),64*1024**3)]:
                                key=kind+':'+str(dev)
                                if key not in devices:devices[key]=dict(kind=kind,consumers=[],**resident(dev,size,True))
                                devices[key]['consumers'].append({'template_id':tid,'sandbox_id':sid})
                                if kind=='rootfs':devices[key]['fd_flags']=rootfs_fd_flags(b['pid'],dev)
                            require(identity(b['pid'])[1]==b['start_ticks'],'Guest changed during cache sample')
                        except Exception as e:errors.append({'template_id':tid,'sandbox_id':sid,'type':type(e).__name__,'reason':str(e) if isinstance(e,RuntimeError) else 'Scoped file observation failed'})
                phase_end={p['template_id']:current_phase(p['sandbox_ids']) for p in scope['pairs']}
                send('cache',{'sample_id':str(sequence),'started_unix':begin,'finished_unix':time.time(),'files':list(files.values()),
                    'references':references,'devices':devices,'errors':errors,'complete_reference_inventory':not errors,
                    'template_phases':phase_start,'template_phase_stable':{tid:p==phase_end[tid] for tid,p in phase_start.items()},'requested_interval_seconds':10,
                    'total_host_pagecache_bytes':None,'per_guest_accessed_offset_intersection_bytes':None})
                sequence+=1;stop.wait(max(.01,10-(time.time()-begin)))

        def physical_loop():
            wave=0;page=os.sysconf('SC_PAGESIZE')
            while not stop.is_set():
                began=time.time()
                with phase_lock:wave_phase=phase['name']
                # Short trajectories need a replay sample before they finish.
                for pair in sorted(scope['pairs'],key=lambda p:p.get('recorded_wait_seconds',3600)):
                    if stop.is_set():break
                    start=time.time();before_phase=current_phase(pair['sandbox_ids'])
                    row={'template_id':pair['template_id'],'sandbox_ids':pair['sandbox_ids'],'wave':wave,'started_unix':start,'phase':before_phase,'available':False}
                    try:
                        bs=[bind(binding_scope,{'pid':bound[s]['pid'],'start_ticks':bound[s]['start_ticks']}) for s in pair['sandbox_ids']]
                        first=[pagemap(b['pid'],b['maps'],page) for b in bs]
                        flags=page_flags(set().union(*(r[0] for r in first)))
                        again=[pagemap(b['pid'],b['maps'],page) for b in bs]
                        stable=all(a[2]['identity_hash']==b[2]['identity_hash'] for a,b in zip(first,again))
                        measured=sharing([r[0] for r in first],flags,page,[r[1] for r in first])
                        row.update(pagemap_stable=stable,physical=measured,phase_stable=before_phase==current_phase(pair['sandbox_ids']),
                                   available=stable and before_phase==current_phase(pair['sandbox_ids']),raw_pfns_output=False,cross_node_comparison=False)
                    except Exception as e:row.update(error_type=type(e).__name__,reason=str(e) if isinstance(e,RuntimeError) else 'Scoped physical-page sample unavailable')
                    row['finished_unix']=time.time();send('physical',row)
                wave+=1
                while not stop.is_set():
                    with phase_lock:current=phase['name']
                    wait=physical_wave_wait_seconds(wave_phase,current,time.time()-began)
                    if wait<=0 or stop.wait(min(1,wait)):break

        for fn in (process_loop,cache_loop,physical_loop):
            t=threading.Thread(target=lambda f=fn:guarded(f),daemon=True);t.start();threads.append(t)
        deadline=time.monotonic()+7200
        client.settimeout(20)
        while not stop.is_set() and time.monotonic()<deadline:
            msg=cohort_wire_receive(client);require(msg.get('run_id')==scope['run_id'],'Control run changed')
            if msg['op']=='heartbeat':send('heartbeat',{'time':time.time()})
            elif msg['op']=='phase':
                require(msg['phase'] in ('replay','final_hold'),'Unknown phase')
                with phase_lock:phase['name']=msg['phase']
                send('phase',{'name':msg['phase']})
            elif msg['op']=='finished_jobs':
                require(set(msg['sandbox_ids'])<=set(ids),'Unknown finished Guest')
                with phase_lock:phase['finished'].update(msg['sandbox_ids'])
            elif msg['op']=='stop':break
            else:raise RuntimeError('Unexpected control operation')
        stop.set()
        for t in threads:t.join(timeout=180)
        require(not any(t.is_alive() for t in threads),'Sampler has not exited; owner must retain Guest scope')
        result['status']=prefix+'_ROOT_READERS_STOPPED' if not result['errors'] else prefix+'_ROOT_READERS_STOPPED_WITH_ERRORS'
        send('stopped',result)
    except Exception as e:
        result.update(status='STOPPED_'+prefix+'_ROOT_READER',error_type=type(e).__name__,reason=str(e) if isinstance(e,RuntimeError) else 'Scoped reader failed')
    finally:
        stop.set()
        for t in threads:
            if t.is_alive():t.join(timeout=180)
        if client:client.close()
        print('BEGIN_RETURN_REPORT');print(json.dumps(result,indent=2));print('END_RETURN_REPORT')
