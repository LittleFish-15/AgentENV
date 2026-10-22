"""Original four-template continuous replay with attributed lower-cache samples.

ENGINE, ACCOUNTING, PROCESS and ROOT_SOURCE are pinned embedded public sources.
The private workload stays on the operator host. Root code is printed literally.
"""
import argparse, base64, concurrent.futures, copy, hashlib, json, os, pprint, re, shutil, socket, stat, struct, tempfile, time
from pathlib import Path

CONFIG_SHA='f2a1abe6542c3230bfe3cd81b884cf080dc4a3b2f2c371b40092940c686d01bd'
CANDIDATE_SHA='eed36d01de13f83a8abdc13e93c21883a3a48273da83fa1c813e65e4655babcf'
PATCH_SHA='c553d631d18a01ce5511dec12e50a1a58817c92181d20f1443f17561f87a67ce'
BUILD_WORK='/home/jwk/agent/relay/reports/node-a-rootfs-access-build-abcks95d'


def digest(raw):return hashlib.sha256(raw).hexdigest()


def replace_daemon(raw, candidate):
    text=raw.decode();pattern=r'(?m)^daemon_binary_path\s*=\s*"([^"]+)"\s*$'
    matches=list(re.finditer(pattern,text));ENGINE.need(len(matches)==1,'Ambiguous daemon setting')
    ENGINE.need(matches[0][1]==str(ENGINE.BASE/'bin/uvm-ublk-daemon'),'Original daemon path differs')
    return re.sub(pattern,lambda _: 'daemon_binary_path = '+json.dumps(str(candidate)),text).encode()


def choose(inputs, build, previous):
    allowed={j['instance_id'] for j in previous['jobs']};selected=[]
    for lang,count in [('go',2),('ts',1),('java',1)]:
        choices=sorted([c for c in inputs['cohort']['cases'] if c['instance_id'] in allowed and c['language']==lang],
                       key=lambda c:(c['recorded_wait_seconds'],c['instance_id']))
        ENGINE.need(len(choices)>=count,'Insufficient representative templates');selected+=choices[:count]
    built=[copy.deepcopy(next(b for b in build['cases'] if b['instance_id']==c['instance_id'])) for c in selected]
    ENGINE.need(len({b['template_id'] for b in built})==4 and all(b['state']=='READY' for b in built),'Expected four ready distinct templates')
    return selected,built


def compact_ranges(pages):
    groups={}
    for dev,ino,index in sorted(pages):
        key=str(dev)+':'+str(ino);ranges=groups.setdefault(key,[])
        if ranges and ranges[-1][0]+ranges[-1][1]==index:ranges[-1][1]+=1
        else:ranges.append([index,1])
    return groups


def inventory():
    char=Path('/sys/class/ublk-char');ENGINE.need(char.is_dir(),'ublk inventory unavailable')
    return {'limit':int(Path('/sys/module/ublk_drv/parameters/ublks_max').read_text()),
            'registered':len(list(char.glob('ublkc*')))}


def validate_retry(old, recovery):
    ENGINE.need(old['run_id']=='d64230294a1844b69712a9cf27ac0789' and old['status']=='STOPPED_COW4_ACCESS','Only the reviewed first failure can be retried')
    ENGINE.need(old['all_cohort_guests_released'] and not old['restore_outcome_uncertain'] and old['replay_completed_guests']==0,'Old execution/cleanup is uncertain')
    ids={j['sandbox_id'] for j in old['jobs']}
    ENGINE.need(len(old['jobs'])==len(ids)==8 and ids==set(old['released_sandboxes']) and all(j['steps_completed']==0 for j in old['jobs']),'Previous eight-Guest scope differs')
    ENGINE.need(recovery['status']=='COW4_ORIGINAL_RECOVERED_READY_FOR_REVIEWED_RETRY' and recovery['run_id']==old['run_id'] and recovery['original_config_sha256']==CONFIG_SHA,'Trusted recovery not complete')
    ENGINE.need(recovery['empty_inventory'] and recovery['prior_eight_guests_http404'] and recovery['other_services_unchanged'],'Recovery coverage incomplete')
    return ids


def prepare_retry():
    m=ENGINE;p=Path('/run/cow4-access-recovery-d6423029.json')
    m.need(p.resolve(strict=True)==p,'Redirected root recovery receipt')
    meta=p.stat();m.need(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and not meta.st_mode&0o022 and meta.st_size<65536,'Untrusted root recovery receipt')
    recovery=json.loads(p.read_bytes());raw=m.H.read(m.PENDING,2*1024**2);old=json.loads(raw)
    ids=validate_retry(old,recovery);m.need(digest(raw)==recovery['previous_pending_sha256'],'Previous pending changed since recovery')
    identity=m.H.runtime_pid();m.need(list(identity)==recovery['original_after'],'Recovered Runtime identity changed')
    api=m.Api(identity);m.need(api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Original inventory no longer empty')
    for sid in sorted(ids):m.need(api.call('GET','/sandboxes/'+sid)[0]==404,'Previous Guest still exists')
    archive=m.PENDING.with_name('cow4-access-node-a.previous-d6423029.json')
    m.need(not archive.exists(),'Previous attempt already archived; no repeat')
    m.need(m.H.read(m.PENDING,2*1024**2)==raw,'Previous attempt changed during validation')
    os.link(m.PENDING,archive);m.PENDING.unlink()
    return {'previous_run_id':old['run_id'],'previous_report_preserved':str(archive),
            'recovery_receipt':str(p),'old_eight_guests_http404':True,'old_trajectory_actions':0}


def summarize(work, report, process):
    samples=[]
    p=work/'measurements/access-cache.jsonl'
    if p.exists():
        with p.open() as f:
            for line in f:samples.append(json.loads(line))
    rows=[]
    for tid in sorted({j['template_id'] for j in report['jobs']}):
        matching=[(s,DETAILS.expand_row(r)) for s in samples for r in s.get('templates',[]) if r['template_id']==tid]
        for phase in sorted({r['phase'] for _,r in matching}):
            subset=[r for _,r in matching if r['phase']==phase];metrics={}
            for key in subset[0]:
                vals=[r[key] for r in subset if type(r.get(key)) in (int,float)]
                if vals:metrics[key]={'min':min(vals),'max':max(vals),'valid_samples':len(vals)}
            rows.append({'template_id':tid,'phase':phase,'sandbox_ids':subset[0]['sandbox_ids'],'metrics':metrics,'valid_samples':len(subset)})
    result={'revision':'cow4-attributed-lower-cache-v1','run_id':report['run_id'],'implementation':'original_with_diagnostic_observer',
        'process_rows':process.result()['rows'],'rootfs_access_rows':rows,'jobs':report['jobs'],
        'rootfs_layer_inventory':report['template_lowers'],'whole_lower_residency_used_as_access':False,
        'window_definition':'Successful backing reads completed during each sandbox trajectory; earlier-start straddlers counted explicitly',
        'host_page_identity':'same-node dev/inode/file-page-index','access_cache_samples':len(samples),
        'sample_file':str(p),'trace_file':str(work/'observer/trace.jsonl'),
        'ordinary_guest_ram_physical_sharing_resampled':False,'cross_node_net_saving_bytes':None,
        'global_access_cache_sweeps':[{k:s[k] for k in ('sample_id','unix','global_accessed_resident_union_bytes','global_same_template_shared_accessed_resident_bytes','reference_union_avoided_bytes') if k in s} for s in samples],
        'read_ahead_pages_outside_requested_backing_ranges_included':False,
        'payload_is_host_backing_format_not_decoded_guest_file_bytes':True,
        'boot_id':report['root_plan']['boot_id'],'candidate_sha256':CANDIDATE_SHA,'observer_patch_sha256':PATCH_SHA,
        'phase_note':'both_replaying, mixed_running_idle and after_replay are separate; finished Guest access sets freeze at trajectory completion.'}
    result['rootfs_storage_details']=DETAILS.summarize(report,samples)
    ENGINE.H.save(work/'combined-summary.json',result)
    def amount(v,ratio=False):
        if not v:return 'NA'
        scale=100 if ratio else 1/1024**2
        return f"{v['min']*scale:.3f}–{v['max']*scale:.3f}"+('%' if ratio else '')
    lines=['# '+str(len(report['template_lowers']))+'模板原版rootfs实际读取驻留补测','',
        '原版ae9c626增加只记录元数据的读取观测；复用已有模板，各2沙箱，continuous轨迹。',
        '统计host lower backing读取范围与采样时驻留页的交集；不是整个文件缓存，也不是Guest文件有效字节。IO完成时间定义窗口，启动前读取排除，轨迹结束后该沙箱访问集冻结。',
        'RAM物理PFN本批未重采；整FC RSS/PSS另列。物理净收益与跨节点验收仍为NA。','',
        '|模板ID|阶段|样本|S1读取且驻留MiB|S2读取且驻留MiB|共同读取且驻留MiB|读取驻留并集MiB|交集/并集|重复避免比例|',
        '|---|---|---:|---:|---:|---:|---:|---:|---:|']
    for r in rows:
        m=r['metrics'];fields=['sandbox1_accessed_and_resident_bytes','sandbox2_accessed_and_resident_bytes','shared_accessed_host_pagecache_bytes','accessed_resident_union_bytes']
        lines.append('|'+ '|'.join([r['template_id'],r['phase'],str(r['valid_samples'])]+[amount(m.get(k)) for k in fields]+[amount(m.get(k),True) for k in ('shared_pool_fraction','duplicate_avoidance_fraction')])+'|')
    lines+=['','|模板ID|沙箱ID|阶段|最小RSS MiB|最大RSS MiB|最小PSS MiB|最大PSS MiB|模板最小共享估计MiB|模板最大共享估计MiB|配对样本|',
        '|---|---|---|---:|---:|---:|---:|---:|---:|---:|']
    for r in result['process_rows']:
        fields=('sandbox_min_rss_bytes','sandbox_max_rss_bytes','sandbox_min_pss_bytes','sandbox_max_pss_bytes','template_min_shared_bytes','template_max_shared_bytes')
        lines.append('|'+ '|'.join([r['template_id'],r['sandbox_id'],r['phase']]+['NA' if r[k] is None else f'{r[k]/1024**2:.3f}' for k in fields]+[str(r['template_valid_paired_samples'])])+'|')
    lines+=['','共享估计逐轮Σ(RSS−PSS)/(2−1)，整进程口径不等于memfile物理共享。lower层数/大小及upper各次file/allocated/resident数据见JSON。不得将各模板交集直接相加作为全局去重收益。','']
    lines+=['同节点全批检查点去重统计（包含部分轨迹结束后的保持阶段，单位MiB）：','',
        '|指标|最小|最大|末次|','|---|---:|---:|---:|']
    for label,key in [('所有沙箱访问驻留页并集','global_accessed_resident_union_bytes'),
                      ('各模板两侧共同访问驻留页再做全局并集','global_same_template_shared_accessed_resident_bytes'),
                      ('沙箱引用合计减全局并集（副本比较模型）','reference_union_avoided_bytes')]:
        values=[s[key] for s in result['global_access_cache_sweeps'] if key in s]
        cells=[f'{value/1024**2:.3f}' for value in (min(values),max(values),values[-1])] if values else ['NA']*3
        lines.append('|'+label+'|'+'|'.join(cells)+'|')
    lines+=['','全局页集合按本节点dev/inode/page_index去重；最后一项是引用去重模型，不是UB净物理收益。每轮时间与数值保留在JSON。','']
    (work/'combined-summary.md').write_text('\n'.join(lines)+'\n'+DETAILS.markdown(result['rootfs_storage_details']),encoding='utf-8')
    return result


class FourRun:
    def __init__(self, cohort, plan, files, sock):
        self.c=cohort;self.plan=plan;self.files=files;self.sock=sock;self.bindings={};self.bound=[];self.ends={}
        self.start=None;self.process=PROCESS.Summary();self.index=0;self.cache_index=0;self.observer_pid=None
        self.root_failed=False;self.root_final=None
    def rpc(self,op,**values):
        wire_op='cleanup_complete' if op=='restore' and self.root_failed else op
        ENGINE.send(self.sock,dict(op=wire_op,**values));r=ENGINE.receive(self.sock)
        if r.get('op')=='session_error':
            self.root_failed=True;self.c.report['root_failure']=r
            raise RuntimeError('Root supervisor failed: '+str(r.get('reason')))
        if r.get('op')=='restored':
            self.root_final=r['report'];self.c.report['root_session']=r['report']
        expected={'activate':'activated','bind':'bound','restore':'restored'}.get(op,op)
        ENGINE.need(r.get('op')==expected,'Root session returned unexpected state: '+str(r.get('op')))
        return r
    def phase(self,sids):
        n=sum(s in self.ends for s in sids)
        return 'both_replaying' if n==0 else 'mixed_running_idle' if n==1 else 'after_replay'
    def replay(self,job):
        try:self.c.replay(job)
        finally:
            with self.c.lock:self.ends[job['sandbox_id']]=time.monotonic_ns()
    def metrics(self):
        before={self.c.jobs[i]['template_id']:self.phase([j['sandbox_id'] for j in self.c.jobs[i:i+2]]) for i in range(0,self.c.max_guests,2)}
        began=time.time();r=self.rpc('sample');finished=time.time()
        for i in range(0,self.c.max_guests,2):
            jobs=self.c.jobs[i:i+2];sids=[j['sandbox_id'] for j in jobs]
            phase=self.phase(sids);phase=phase if phase==before[jobs[0]['template_id']] else 'transition'
            frame={'run_id':self.c.run_id,'variant':'original_with_access_observer','mode':'continuous','node':'node-a',
                'boot_id':self.plan['boot_id'],'phase':phase,'template_id':jobs[0]['template_id'],
                'sandbox_ids':sids,'sample_id':str(self.index),'started_unix':began,'finished_unix':finished,
                'processes':[p for p in r['processes'] if p['sandbox_id'] in sids]}
            self.process.add(frame)
            with (self.c.work/'measurements/process.jsonl').open('a') as f:f.write(json.dumps(frame)+'\n')
        self.index+=1
    def cache(self):
        before={self.c.jobs[i]['template_id']:self.phase([j['sandbox_id'] for j in self.c.jobs[i:i+2]]) for i in range(0,self.c.max_guests,2)}
        observer=self.c.work/'observer';status=json.loads(ENGINE.H.read(observer/'trace.status.json',65536))
        ENGINE.need(status['pid']==self.observer_pid,'Observer process changed')
        ENGINE.need(0<=time.monotonic_ns()-status['mono_ns']<10*10**9,'Stale observer heartbeat')
        if status['mono_ns']<=self.start:return
        windows={j['sandbox_id']:(self.start,min(self.ends.get(j['sandbox_id'],status['mono_ns']),status['mono_ns'])) for j in self.c.jobs}
        with (observer/'trace.jsonl').open() as stream:
            sets,audit=ACCOUNTING.read_sets(stream,status,self.bindings,windows,self.files,PATCH_SHA,window_semantics='completion')
        ENGINE.need(audit['direct_lower_reads']==0,'Direct lower IO does not establish the selected buffered-cache metric')
        requested=set().union(*sets.values());resident,probe=ACCOUNTING.resident_accessed_pages(self.files,requested)
        rows=[];global_common=set()
        for i in range(0,self.c.max_guests,2):
            jobs=self.c.jobs[i:i+2];sids=[j['sandbox_id'] for j in jobs];tid=jobs[0]['template_id']
            phase=self.phase(sids);phase=phase if phase==before[tid] else 'transition'
            r=ACCOUNTING.pair_statistics(sets[sids[0]],sets[sids[1]],resident)
            global_common.update(sets[sids[0]]&sets[sids[1]]&resident)
            r.update(template_id=tid,sandbox_ids=sids,phase=phase,
                lower_layer_count=len(self.plan['template_lowers'][tid]),
                lower_file_bytes=sum(f['file_bytes'] for f in self.plan['template_lowers'][tid]),
                lower_page_span_bytes=sum((f['file_bytes']+4095)//4096*4096 for f in self.plan['template_lowers'][tid]),
                sandbox_windows_monotonic_ns={sid:windows[sid] for sid in sids})
            upper=[]
            for sid in sids:
                binding=next(b for b in self.bound if b['sandbox_id']==sid);parts=[]
                for f in binding['uppers']:
                    p=Path(f['path']);meta=p.stat();ENGINE.need((meta.st_dev,meta.st_ino)==(f['dev'],f['inode']),'Upper identity changed')
                    parts.append(ENGINE.R.resident(p,64*1024**3))
                upper.append({'sandbox_id':sid,'files':parts})
            r['upper_observations']=upper;rows.append(r)
        frame={'sample_id':self.cache_index,'unix':time.time(),'observer_status':status,'audit':audit,'residency_probe':probe,
            'templates':rows,'accessed_page_ranges':{sid:compact_ranges(s) for sid,s in sets.items()},
            'resident_page_ranges':compact_ranges(resident),
            'global_accessed_resident_union_bytes':len(requested&resident)*4096,
            'global_same_template_shared_accessed_resident_bytes':len(global_common)*4096,
            'reference_union_avoided_bytes':(sum(len(s&resident) for s in sets.values())-len(requested&resident))*4096}
        path=self.c.work/'measurements/access-cache.jsonl'
        encoded=(json.dumps(frame,separators=(',',':'))+'\n').encode()
        limit=(2 if self.c.max_guests>8 else 1)*1024**3
        ENGINE.need((path.stat().st_size if path.exists() else 0)+len(encoded)<=limit,'Measurement output budget reached')
        with path.open('ab') as f:f.write(encoded)
        self.cache_index+=1
        print('CACHE_SAMPLE='+str(self.cache_index)+' accessed_union_mib='+str(round(frame['global_accessed_resident_union_bytes']/1024**2,3)),flush=True)
    def run(self):
        c=self.c
        for j in c.jobs:c.create(j);self.rpc('heartbeat')
        until=time.monotonic()+10
        while not (c.work/'observer/trace.status.json').exists() and time.monotonic()<until:time.sleep(.25)
        r=self.rpc('bind',jobs=[{k:j[k] for k in ('sandbox_id','template_id')} for j in c.jobs])
        self.bound=r['bindings'];self.observer_pid=r['observer_identity'][0]
        for b in self.bound:
            self.bindings[b['source']]={'sandbox_id':b['sandbox_id'],'template_id':b['template_id'],
                'lower_keys':{(f['dev'],f['inode']) for f in b['lowers']},'upper_keys':{(f['dev'],f['inode']) for f in b['uppers']}}
        c.report['bindings']=self.bound;c.report['observer_identity']=r['observer_identity'];c.persist()
        # All Guests are ready before any replay window starts.
        time.sleep(2);self.start=time.monotonic_ns();c.report['replay_start_monotonic_ns']=self.start
        with concurrent.futures.ThreadPoolExecutor(max_workers=c.max_guests) as pool:
            futures=[pool.submit(self.replay,j) for j in c.jobs];next_cache=time.monotonic()+2
            try:
                while not all(f.done() for f in futures):
                    c.guard();self.metrics()
                    if time.monotonic()>=next_cache:self.cache();next_cache=time.monotonic()+15
                    time.sleep(1)
                for f in futures:f.result()
                time.sleep(2);self.metrics();self.cache()
            except BaseException:c.stop.set();raise
        c.report['trajectory_windows_monotonic_ns']={sid:[self.start,end] for sid,end in self.ends.items()}


def main():
    m=ENGINE;parser=argparse.ArgumentParser();parser.add_argument('mode',choices=('run','status','recover-previous','retry-after-recovery'));args=parser.parse_args()
    m.need(os.getuid()==os.geteuid()==1204 and os.uname().nodename=='server1','A ordinary jwk only');os.umask(0o077)
    caps=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    m.need(all(int(caps[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapAmb')),'Capability-free owner required')
    m.PENDING=m.ROOT/'relay/cow4-access-node-a.pending.json'
    if args.mode=='status':print(m.PENDING.read_text());return 0
    if args.mode=='recover-previous':
        print('Paste the following literal recovery body in A/root. No Guest creation or replay is requested.')
        print("/usr/bin/python3 -I -B - <<'COW4_RECOVER_D6423029'\n"+RECOVERY_SOURCE+'\nrecovery()\nCOW4_RECOVER_D6423029')
        return 0
    m.need(m.PENDING.exists() if args.mode=='retry-after-recovery' else not m.PENDING.exists(),'Unexpected pending state; use status')
    import fcntl
    lock=os.open(m.LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    m.B,_=m.load(m.ROOT/'cow55_build_edf502d.py',m.BUILDER_SHA,'four_builder');m.B.load_helper();m.H=m.B.H
    m.R,collector=m.load(m.ROOT/'cow_ram_readonly.py',m.COLLECTOR_SHA,'four_collector')
    retry=prepare_retry() if args.mode=='retry-after-recovery' else None
    m.B.inputs(m.ROOT/'cow55_inputs.json');inputs=m.B.read_json(m.ROOT/'cow55_inputs.json');build=m.B.read_json(m.B.STATE)
    previous=m.B.read_json(m.ROOT/'relay/cow33-batch1-node-a.pending.json')
    m.need(previous['run_id']=='083604f2f76045c0beb8de4cf92c0758' and previous.get('all_cohort_guests_released') and not previous.get('restore_outcome_uncertain'),'First batch cleanup differs')
    m.need(build.get('status')=='COW55_ALL_TEMPLATES_READY_NO_REPLAY_STARTED' and build.get('final_merge_verified') and build.get('worker_finished'),'Prepared template inventory is not complete')
    m.need(m.B.read_json(m.BASE/'installation.json').get('commit')=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc','Original installation changed')
    receipt=m.B.read_json(m.ROOT/'relay/cow4-rootfs-access-build-v2.json')
    m.need(receipt['status']=='ROOTFS_ACCESS_OBSERVER_BUILT_AND_CALIBRATED_NOT_DEPLOYED' and receipt['patch_sha256']==PATCH_SHA,'Candidate not calibrated')
    m.need(receipt['candidate_sha256']==CANDIDATE_SHA and receipt['work_directory']==BUILD_WORK,'Candidate receipt differs')
    m.need(all(v==0 for v in receipt['phases'].values()) and receipt['calibration']['measurement']['shared_accessed_host_pagecache_bytes']==4096,'Calibration incomplete')
    identity=m.H.runtime_pid();api=m.Api(identity)
    m.need(api.call('GET','/v2/sandboxes?limit=1')==(200,[]) and not m.R.find_firecrackers(identity[0]),'Original service has Guests; no change')
    config=m.BASE/'config/runtime.toml';old=m.H.read(config,65536);m.need(digest(old)==CONFIG_SHA,'Original config changed')
    config_meta=config.stat()
    selected,built=choose(inputs,build,previous)
    for b in built:m.B.verify_ready(b)
    work=Path(tempfile.mkdtemp(prefix='node-a-cow4-access-',dir=m.ROOT/'relay/reports'))
    cohort=m.Cohort(work,dict(build,original_identity=list(identity),cases=built),dict(inputs,cohort=dict(inputs['cohort'],cases=selected)),template_count=4,admission_workers=1)
    cohort.control=lambda _:None;cohort.deadline=time.monotonic()+5400
    cohort.report.update(revision='cow4-attributed-v2',variant='original_with_diagnostic_observer',status='PREPARING_COW4_ACCESS',replay_completed_guests=0)
    cohort.report['previous_attempt_resolution']=retry
    cohort.report.update(configured_guest_ram_bytes=8*4096*1024**2,physical_guest_ram_resampled=False,cache_target_interval_seconds=15)
    observer=work/'observer';observer.mkdir(mode=0o700);candidate=observer/'uvm-ublk-daemon-observe'
    source=Path(receipt['candidate']);m.need(source==Path(BUILD_WORK)/'candidate/uvm-ublk-daemon-observe','Candidate path differs')
    m.need(digest(m.H.read(source,128*1024**2))==CANDIDATE_SHA,'Candidate bytes differ')
    with source.open('rb') as a,candidate.open('xb') as b:shutil.copyfileobj(a,b)
    os.chmod(candidate,0o700);m.need(digest(candidate.read_bytes())==CANDIDATE_SHA,'Candidate copy differs')
    files={};template_lowers={}
    for b in built:
        layers=[{k:r[k] for k in ('path','dev','inode','file_bytes')} for r in b['parent_layer_inventory']['rootfs']]
        template_lowers[b['template_id']]=layers
        for f in layers:files[(f['dev'],f['inode'])]=f
    m.need(len(files)<=256,'Observer whitelist budget exceeded')
    spec='output='+str(observer/'trace.jsonl')+'\nmax_bytes=268435456\nmax_records=1000000\n'+''.join('allow=%d:%d:%d\n'%(k[0],k[1],v['file_bytes']) for k,v in sorted(files.items()))
    candidate.with_suffix('.access-spec').write_text(spec);new=replace_daemon(old,candidate)
    (work/'runtime.original.toml').write_bytes(old);(work/'runtime.observer.toml').write_bytes(new)
    endpoint=m.ROOT/'r'/('c4-'+cohort.run_id[:12]+'.sock');listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(endpoint));os.chmod(endpoint,0o600);listener.listen(1);listener.settimeout(600)
    socket_meta=endpoint.lstat();socket_identity=(socket_meta.st_dev,socket_meta.st_ino)
    plan={'run_id':cohort.run_id,'owner_pid':os.getpid(),'owner_ticks':m.R.identity(os.getpid())[1],
        'endpoint':str(endpoint),'work':str(work),'candidate':str(candidate),'candidate_sha256':CANDIDATE_SHA,
        'original_identity':list(identity),'original_config_base64':base64.b64encode(old).decode(),
        'original_config_sha256':CONFIG_SHA,'new_config_sha256':digest(new),'spec_sha256':digest(spec.encode()),
        'original_config_metadata':{'uid':config_meta.st_uid,'gid':config_meta.st_gid,'mode':stat.S_IMODE(config_meta.st_mode)},
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'template_lowers':template_lowers}
    cohort.report.update(root_plan=plan,template_lowers=template_lowers,selected_templates=[{k:c[k] for k in ('instance_id','language','recorded_wait_seconds')} for c in selected]);cohort.persist()
    command="/usr/bin/python3 -I -B - <<'COW4_ACCESS_ROOT'\n"+collector+'\n'+ROOT_SOURCE+'\nroot_session('+pprint.pformat(plan,width=100)+')\nCOW4_ACCESS_ROOT'
    (work/'root-session-review.txt').write_text(command)
    print('BEGIN_REVIEWED_ROOT_BODY_ONLY');print(command);print('END_REVIEWED_ROOT_BODY_ONLY',flush=True)
    print('Keep this jwk terminal open. Paste the body once in A/root within 600 seconds. The root session restarts only the empty original service twice, samples scoped Guest metadata, then restores exact original configuration. No done input.',flush=True)
    sock=None;runner=None;changed=False
    try:
        sock,_=listener.accept();sock.settimeout(300);peer=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));m.need(peer[1]==0,'Expected root supervisor')
        m.need(m.receive(sock)=={'op':'ready'},'Root supervisor not ready')
        m.need(m.H.runtime_pid()==identity and api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Original service changed before config write')
        m.need(m.H.read(config,65536)==old,'Original config changed before write')
        tmp=config.with_name('runtime.toml.cow4-'+cohort.run_id)
        with tmp.open('xb') as f:f.write(new);f.flush();os.fsync(f.fileno())
        os.chmod(tmp,stat.S_IMODE(config_meta.st_mode));os.chown(tmp,-1,config_meta.st_gid);os.replace(tmp,config);changed=True
        runner=FourRun(cohort,plan,files,sock);r=runner.rpc('activate');cohort.api=m.Api(r['identity'])
        cohort.report['services_modified']=True;cohort.report['modified_services']=['jwk-aenv-ae9c626-node-a.service']
        cohort.report['active_runtime_identity']=r['identity'];cohort.persist()
        capacity=inventory();m.need(capacity['limit']==64 and capacity['limit']-capacity['registered']>=14,'Need 12 devices plus 2 spare after pool restart; no device deletion')
        cohort.report['ublk_before']=capacity;cohort.guard(initial=True)
        cohort.credential.write_text('url = "http://127.0.0.1:18080"\napi_key = '+json.dumps(cohort.api.key)+'\n')
        runner.run();cohort.report['status']='COW4_TRAJECTORIES_COMPLETED'
    except BaseException as e:
        cohort.stop.set();cohort.report.update(status='STOPPED_COW4_ACCESS',error_type=type(e).__name__,reason=str(e).replace(cohort.api.key,'[REDACTED]'))
    finally:
        cohort.cleanup();cohort.report['all_cohort_guests_released']=set(cohort.created)==set(cohort.report['released_sandboxes']) and not cohort.report['restore_outcome_uncertain']
        if cohort.credential.exists():cohort.credential.unlink()
        cohort.report['temporary_cli_credentials_removed']=not cohort.credential.exists()
        if sock and runner:
            try:
                m.need(cohort.report['all_cohort_guests_released'],'Uncertain Guest ownership; no service restoration request')
                cohort.report['root_session']=runner.root_final if runner.root_final is not None else runner.rpc('restore')['report']
            except Exception as e:cohort.report['root_restore_error']={'type':type(e).__name__,'reason':str(e)}
        if sock:sock.close()
        listener.close()
        if endpoint.is_socket():
            meta=endpoint.lstat()
            if (meta.st_dev,meta.st_ino)==socket_identity:endpoint.unlink()
        cohort.report['configuration_changed_this_run']=changed
        cohort.report['services_modified']=changed
        cohort.report['replay_completed_guests']=sum(j['state']=='REPLAY_COMPLETED' for j in cohort.jobs)
        cohort.persist()
        if runner:
            try:
                result=summarize(work,cohort.report,runner.process)
                coverage={r['template_id'] for r in result['rootfs_access_rows'] if r['phase']=='both_replaying' and r['metrics'].get('sandbox1_accessed_lower_bytes',{}).get('max',0)>0 and r['metrics'].get('sandbox2_accessed_lower_bytes',{}).get('max',0)>0}
                cohort.report['access_coverage_templates']=len(coverage)
                restored=cohort.report.get('root_session',{})
                if cohort.report['status']=='COW4_TRAJECTORIES_COMPLETED' and len(coverage)==4 and cohort.report['all_cohort_guests_released'] and restored.get('original_configuration_restored') and restored.get('original_service_healthy') and restored.get('other_services_unchanged') and restored.get('observer_exit_confirmed'):
                    cohort.report['status']='COW4_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED'
                else:cohort.report['full_acceptance']='NOT_COMPLETE_REVIEW_STATUS_AND_GAPS'
                result['validation']={'status':cohort.report['status'],'access_coverage_templates':len(coverage),
                    'all_cohort_guests_released':cohort.report['all_cohort_guests_released'],
                    'replay_completed_guests':cohort.report['replay_completed_guests'],'root_session':restored}
                m.H.save(work/'combined-summary.json',result)
                with (work/'combined-summary.md').open('a',encoding='utf-8') as f:
                    f.write('\n最终状态：'+cohort.report['status']+'；实际访问回放期覆盖 '+str(len(coverage))+'/4 模板。\n')
                cohort.report['combined_summary']=str(work/'combined-summary.json');cohort.report['combined_markdown']=str(work/'combined-summary.md')
            except Exception as e:cohort.report['summary_error']={'type':type(e).__name__,'reason':str(e)}
        try:cohort.report['ublk_after']=inventory()
        except Exception as e:cohort.report['ublk_after_error']=type(e).__name__
        cohort.persist();m.H.save(work/'return.json',cohort.report);os.close(lock)
    print('BEGIN_RETURN_REPORT');print(json.dumps(cohort.report,indent=2));print('END_RETURN_REPORT')
    return 0 if cohort.report['status']=='COW4_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED' else 1
