"""Bounded original-runtime continuous replay, with a separate inline root reader.

Uses the existing private 55-case input. Commands are sent only through aenv exec
to confirmed batch Guests. No host shell evaluation, UB, service/config changes,
template creation, automatic root execution, or repeat uncertain restore.
"""
import argparse,base64,concurrent.futures,hashlib,importlib.util,json,os,pprint,re,shlex,socket,stat,struct,subprocess,sys,tempfile,threading,time,uuid
from pathlib import Path
ROOT=Path('/home/jwk/agent');BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
PENDING=ROOT/'relay/cow55-replay-node-a.pending.json';LOCK=ROOT/'relay/cow55-replay-node-a.lock'
BUILDER_SHA='9bbde92ad5e6552fd22574396c1e72b59c7fe3c66ddbb89150abb604275e86a9'
COLLECTOR_SHA='3ccf6de2e9bcafcff7d00cff62a5c82e3ae1d48804c41fbf881be626d9d6fdf5'
READER_SHA='b89d9cf25fbbbb0d71ef1b57d42b300654d4a6df251967c8df6a111852413d30'
PROCESS_SUMMARY_SHA='8778b697d99b54de027bf674b61cd9e50b7173e2b70d4eb1ccbabd04f0acd554'
ROOTFS_SUMMARY_SHA='79d330c4e72d87224cd7d45496d1a569b7610ad8edb7dad70d06250185e3236c'
B=H=R=None

def need(ok,why):
    if not ok:raise RuntimeError(why)
def load(path,digest,name):
    raw=path.read_bytes();need(path.resolve(strict=True)==path and hashlib.sha256(raw).hexdigest()==digest,'Pinned source differs: '+path.name)
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m,raw.decode()

def normalize_action(action):
    """Independent implementation of the reviewed rendered-editor convention."""
    try:words=shlex.split(action)
    except ValueError:return action
    if words[:2]!=['str_replace_editor','str_replace']:return action
    try:positions=[words.index(flag)+1 for flag in ('--old_str','--new_str')];values=[words[i] for i in positions]
    except (ValueError,IndexError):return action
    def trim(value):
        if value.startswith('\r\n'):value=value[2:]
        elif value.startswith('\n'):value=value[1:]
        if value.endswith('\r\n'):value=value[:-2]
        elif value.endswith('\n'):value=value[:-1]
        return value
    values=list(map(trim,values))
    if not values[0]:return action
    for i,v in zip(positions,values):words[i]=v
    return shlex.join(words)

def steps_from(raw):
    data=json.loads(raw);rows=[];terminal=None
    for item in data['trajectory']:
        if not isinstance(item,dict) or not isinstance(item.get('action'),str) or not item['action'].strip():continue
        action=item['action'].strip()
        if action.lower() in ('submit','finish','done'):terminal=action;break
        delay=item.get('delay_time',0)
        need(type(delay) in (int,float) and 0<=delay<3600,'Invalid trajectory delay')
        rows.append({'action':normalize_action(action),'delay':float(delay)})
    need(rows,'Empty executable trajectory');return rows,terminal

def shell_command(action,marker):
    inner="set +o pipefail; export PAGER=cat; export MANPAGER=cat; export GIT_PAGER=cat; export LESS=-FRX; cd -- / || exit 125; "+action
    return 'set +e; /agentenv/bin/busybox timeout -s TERM -k 5 300 /bin/bash -l -c '+shlex.quote(inner)+"; code=$?; printf '\\n"+marker+" %s\\n' \"$code\"; exit 0"

def send(client,value):
    raw=json.dumps(value,separators=(',',':')).encode();need(len(raw)<=4*1024**2,'Frame too large');client.sendall(struct.pack('!I',len(raw))+raw)
def receive(client):
    def exact(n):
        data=bytearray()
        while len(data)<n:
            chunk=client.recv(min(65536,n-len(data)))
            if not chunk:raise EOFError('Reader disconnected')
            data.extend(chunk)
        return data
    n=struct.unpack('!I',exact(4))[0];need(0<n<=4*1024**2,'Invalid reader frame');return json.loads(exact(n))

def summarize_measurements(work,labels=None):
    process,_=load(ROOT/'cow55_process_summary.py',PROCESS_SUMMARY_SHA,'cohort_process_summary')
    cache,_=load(ROOT/'cow55_rootfs_accounting.py',ROOTFS_SUMMARY_SHA,'cohort_cache_summary')
    def records(channel):
        p=work/'measurements'/(channel+'.jsonl')
        if not p.exists():return
        with p.open() as f:
            for line in f:
                need(len(line)<=4*1024**2,'Measurement record oversized')
                yield json.loads(line)
    summary=process.Summary();host_sweeps=[]
    for frame in records('process'):
        for row in frame['samples']:summary.add(row)
        host_sweeps.append({'started_unix':frame['sweep_started_unix'],'finished_unix':frame['sweep_finished_unix'],
                           'memory':frame.get('host_memory_background_not_template_attribution'), 'collector_process':frame.get('collector_process')})
    physical={};rootfs={};global_cache=[];cache_errors=[]
    def add(group,name,value):
        if value is None:return
        value=float(value) if isinstance(value,float) else value
        g=group.setdefault(name,{'min':value,'max':value,'valid_samples':0});g['min']=min(g['min'],value);g['max']=max(g['max'],value);g['valid_samples']+=1
    for row in records('physical'):
        key=(row['template_id'],row['phase']);g=physical.setdefault(key,{'attempted_samples':0,'valid_samples':0,'metrics':{}});g['attempted_samples']+=1
        if not row.get('available') or not row.get('physical',{}).get('compound_attribution_complete'):continue
        g['valid_samples']+=1;p=row['physical'];ordinary=[p['categories'][k] for k in ('ordinary_file','ordinary_anon')]
        shared=sum(v['shared_unique_bytes'] for v in ordinary);consumers=sum(v['consumer_bytes'] for v in ordinary)
        for name,value in [('ordinary_guest_ram_shared_unique_bytes',shared),('ordinary_guest_ram_participation_ratio',2*shared/consumers if consumers else None),
                           ('ordinary_guest_ram_duplicate_avoidance_ratio',shared/consumers if consumers else None),
                           ('snapshot_file_shared_bytes_excluding_special_pages',p['snapshot_file_shared_bytes_excluding_special_pages']),
                           ('all_selected_guest_ram_shared_unique_bytes',p['all_selected_guest_ram']['shared_unique_bytes'])]:add(g['metrics'],name,value)
    for frame in records('cache'):
        if not frame.get('complete_reference_inventory'):
            cache_errors.append({'sample_id':frame['sample_id'],'errors':frame.get('errors',[])});continue
        result=cache.analyze(frame)
        measured_files={f['file_id']:f for f in frame['files']}
        global_row={'sample_id':frame['sample_id'],'started_unix':frame['started_unix'],'finished_unix':frame['finished_unix'],
                    **{k:v for k,v in result.items() if k.startswith('global_observed_')}}
        for kind in ('rootfs_lower','rootfs_upper','memory_lower'):
            ids={r['file_id'] for r in frame['references'] if r['kind']==kind}
            for field in ('file_bytes','allocated_bytes','resident_bytes'):
                values=[measured_files[i].get(field) for i in ids]
                global_row['global_'+kind+'_'+field]=sum(values) if all(v is not None for v in values) else None
        global_cache.append(global_row)
        for row in result['templates']:
            tid=row['template_id'];phase=frame['template_phases'][tid];g=rootfs.setdefault((tid,phase),{'attempted_samples':0,'metrics':{},'sandbox_ids':row['sandbox_ids']});g['attempted_samples']+=1
            if not frame.get('template_phase_stable',{}).get(tid,False):continue
            for name,value in row.items():
                if type(value) in (int,float):add(g['metrics'],name,value)
            for i,sandbox in enumerate(row['sandbox_metrics'],1):
                for name,value in sandbox.items():
                    if type(value) in (int,float):add(g['metrics'],'sandbox'+str(i)+'_'+name,value)
            memory_ids={r['file_id'] for r in frame['references'] if r['kind']=='memory_lower' and r['template_id']==tid}
            for field in ('file_bytes','allocated_bytes','resident_bytes'):
                values=[measured_files[i].get(field) for i in memory_ids]
                if values and all(v is not None for v in values):add(g['metrics'],'memory_lower_unique_'+field,sum(values))
            for kind in ('memory','rootfs'):
                values=[d.get('resident_page_bytes') for d in frame['devices'].values() if d['kind']==kind and any(c['template_id']==tid for c in d['consumers'])]
                if values and all(v is not None for v in values):add(g['metrics'],kind+'_unique_device_cache_bytes',sum(values))
            root_devices=[d for d in frame['devices'].values() if d['kind']=='rootfs' and any(c['template_id']==tid for c in d['consumers'])]
            if root_devices and all(d.get('fd_flags') for d in root_devices):
                label='all_direct_samples' if all(f['O_DIRECT'] for d in root_devices for f in d['fd_flags']) else 'buffered_fd_samples'
            else:label='unknown_fd_samples'
            g[label]=g.get(label,0)+1
    result={'revision':'cow55-measurement-summary-v1','process_rows':summary.result()['rows'],
            'physical_rows':[dict(template_id=k[0],phase=k[1],**v) for k,v in physical.items()],
            'rootfs_rows':[dict(template_id=k[0],phase=k[1],**v) for k,v in rootfs.items()],
            'global_file_cache_sweeps':global_cache,'incomplete_cache_sweeps':cache_errors,
            'host_background_and_collector_sweeps':host_sweeps,
            'full_host_pagecache_attributed_to_this_cohort':False,'global_guest_physical_union_bytes':None,
            'net_physical_savings_bytes':None,'sample_padding_performed':False}
    H.save(work/'measurement-summary.json',result)
    def amount(v):return 'NA' if v is None else format(v/1024**2,'.3f')
    def metric(row,name,percent=False):
        v=row.get('metrics',{}).get(name)
        if not v:return 'NA'
        scale=100 if percent else 1/1024**2
        return format(v['min']*scale,'.3f')+'~'+format(v['max']*scale,'.3f')+('%' if percent else '')
    lines=['# '+str(len(labels or {}))+'模板原版 continuous 实测汇总','',
           '本报告来自实际采样文件。容量单位MiB；NA为缺失。回放、混合运行/空闲、回放后空闲及最终保持阶段在JSON中分开。',
           '创建使用全员就绪屏障，已结束任务的Guest保留至整批采样结束；传输使用aenv CLI，不能冒称原SDK runner的原封不动性能复现。',
           '整进程RSS/PSS共享估计包含非Guest映射；物理页、文件分配、缓存不同口径不能相加冒充净收益。','',
           '## 沙箱RSS/PSS及同事口径模板共享（仅replay阶段）','',
           '|模板ID|轨迹|沙箱ID|最小RSS|最大RSS|最小PSS|最大PSS|模板最小共享估计|模板最大共享估计|沙箱有效数|模板配对有效数|',
           '|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for row in result['process_rows']:
        if row['phase']!='replay':continue
        values=[amount(row[k]) for k in ('sandbox_min_rss_bytes','sandbox_max_rss_bytes','sandbox_min_pss_bytes','sandbox_max_pss_bytes','template_min_shared_bytes','template_max_shared_bytes')]
        lines.append('|'+ '|'.join([row['template_id'],(labels or {}).get(row['template_id'],'NA'),row['sandbox_id']]+values+[str(row['sandbox_valid_samples']),str(row['template_valid_paired_samples'])])+'|')
    lines+=['','## rootfs文件与cache（仅replay阶段，范围为min~max）','',
            '|模板ID|S1 ID|S2 ID|S1 lower文件|S2 lower文件|共同lower文件|S1 upper分配|S2 upper分配|共同lower cache|S1 upper cache|S2 upper cache|公共文件占比|共同缓存对象占比|',
            '|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for row in result['rootfs_rows']:
        if row['phase']!='replay':continue
        columns=['sandbox1_lower_file_bytes','sandbox2_lower_file_bytes','shared_lower_file_bytes','sandbox1_upper_allocated_bytes','sandbox2_upper_allocated_bytes',
                 'shared_lower_resident_bytes','sandbox1_upper_resident_bytes','sandbox2_upper_resident_bytes']
        lines.append('|'+ '|'.join([row['template_id']]+row['sandbox_ids']+[metric(row,k) for k in columns]+
                    [metric(row,'shared_pool_fraction_allocated_bytes',True),metric(row,'shared_pool_fraction_resident_bytes',True)])+'|')
    lines+=['','共同cache表示两侧引用相同文件对象的驻留量，不表示两个Guest实际访问offset的交集；跨模板引用会重叠，不可直接相加这些行。',
            '全局按文件身份去重的lower/upper/memory文件统计及Host Cached背景时间序列见JSON。设备cache单列，memory设备cache与Guest映射可能重叠。','',
            '## Guest RAM物理共享（各阶段分别列出，已排除不稳定和compound未明确样本）','',
            '|模板ID|阶段|有效样本|普通Guest共享唯一量|共享参与率|重复避免率|snapshot-file共享子集|','|---|---|---:|---:|---:|---:|---:|']
    for row in result['physical_rows']:
        lines.append('|'+ '|'.join([row['template_id'],row['phase'],str(row['valid_samples']),metric(row,'ordinary_guest_ram_shared_unique_bytes'),
              metric(row,'ordinary_guest_ram_participation_ratio',True),metric(row,'ordinary_guest_ram_duplicate_avoidance_ratio',True),metric(row,'snapshot_file_shared_bytes_excluding_special_pages')])+'|')
    (work/'measurement-summary.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    replay=[r for r in result['process_rows'] if r['phase']=='replay']
    return {'file':str(work/'measurement-summary.json'),'sha256':hashlib.sha256((work/'measurement-summary.json').read_bytes()).hexdigest(),
            'replay_process_rows':len(replay),'replay_template_count':len({r['template_id'] for r in replay}),
            'minimum_template_paired_samples':min((r['template_valid_paired_samples'] for r in replay),default=None),
            'maximum_template_paired_samples':max((r['template_valid_paired_samples'] for r in replay),default=None),
            'cache_complete_sweeps':len(global_cache),'cache_incomplete_sweeps':len(cache_errors),
            'replay_rootfs_template_count':len({k[0] for k,v in rootfs.items() if k[1]=='replay' and v['metrics'].get('shared_lower_resident_bytes',{}).get('valid_samples',0)>0}),
            'templates_with_valid_physical_sample':len({k[0] for k,v in physical.items() if v['valid_samples']>0}),
            'replay_templates_with_valid_physical_sample':len({k[0] for k,v in physical.items() if k[1]=='replay' and v['valid_samples']>0}),
            'markdown_file':str(work/'measurement-summary.md')}

class Api:
    def __init__(self,identity):self.identity=tuple(identity);self.key=H.read(BASE/'config/api-key',1024).decode().strip();need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',self.key),'Unexpected credential format')
    def call(self,method,path,body=None,timeout=30):
        import http.client
        need(H.runtime_pid()==self.identity,'Original Runtime changed')
        allowed=path in ('/health','/v2/sandboxes?limit=1') or path=='/sandboxes' and method=='POST' or re.fullmatch('/sandboxes/'+B.ID,path)
        allowed=allowed or method=='GET' and re.fullmatch(r'/v2/sandboxes\?metadata=cow55_create%3D[0-9a-f]{32}-[0-9]{1,3}&limit=2',path)
        need(allowed and method in ('GET','POST','DELETE'),'API outside cohort scope')
        c=http.client.HTTPConnection('127.0.0.1',18080,timeout=timeout)
        try:
            c.request(method,path,body=json.dumps(body).encode() if body is not None else None,headers={'X-API-Key':self.key,'Content-Type':'application/json'})
            r=c.getresponse();raw=r.read(2*1024**2+1);need(len(raw)<=2*1024**2 and not r.getheader('x-next-token'),'Oversized/paginated reply')
            return r.status,json.loads(raw) if raw else None
        finally:c.close()

def repaired_build(build,old_raw,repair):
    """Validate a root-owned repair receipt without rewriting the historical build."""
    old=json.loads(old_raw)
    need(repair.get('revision')=='cow55-original-memlock-repair-v1' and repair.get('status')=='A_ORIGINAL_MEMLOCK_RESTART_VERIFIED','Repair not verified')
    need(repair.get('unit')=='jwk-aenv-ae9c626-node-a.service' and repair.get('new_limit_bytes')==2147483648,'Unexpected repair scope')
    need(repair.get('previous_run_id')==old.get('run_id')=='323ff7550463486f89ebf66264d39257','Wrong failed run')
    need(old.get('status')=='STOPPED_COW55_REPLAY' and old.get('replay_completed_guests')==0,'Previous run was not admission-only')
    need(repair.get('previous_pending_sha256')==hashlib.sha256(old_raw).hexdigest(),'Previous receipt changed')
    need(repair.get('original_before')==build['original_identity'],'Historical runtime differs')
    after=repair.get('original_after');need(isinstance(after,list) and len(after)==2 and after!=build['original_identity'],'No confirmed new runtime')
    result=dict(build);result['original_identity']=after
    return result

def prepare_after_repair(build):
    receipt=Path('/run/cow55-original-memlock-repair.json')
    need(receipt.resolve(strict=True)==receipt,'Redirected root repair receipt')
    meta=receipt.stat();need(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and not meta.st_mode&0o022 and meta.st_size<65536,'Untrusted repair receipt')
    repair=json.loads(receipt.read_bytes());old_raw=H.read(PENDING,2*1024**2)
    updated=repaired_build(build,old_raw,repair)
    need(tuple(updated['original_identity'])==H.runtime_pid(),'Repaired runtime changed')
    need(hashlib.sha256(H.read(BASE/'config/runtime.toml',65536)).hexdigest()==repair['runtime_config_sha256'],'Runtime config changed')
    api=Api(updated['original_identity']);need(api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Original inventory not empty')
    need(not R.find_firecrackers(api.identity[0]),'Existing Firecracker descendants')
    ids={'01a15d10-ed49-72a2-bb83-6763a755ff4c','01a15d10-ef15-7ab0-9a5a-19a0b147cce7'}
    for job in json.loads(old_raw)['jobs']:
        if job.get('sandbox_id'):ids.add(job['sandbox_id'])
        ids.update(re.findall(r'sandbox ([0-9a-f-]{36}) operation Start failed',job.get('error','')))
    need(len(ids)==14,'Previous request identity inventory differs')
    for sid in sorted(ids):need(api.call('GET','/sandboxes/'+sid)[0]==404,'Previous sandbox still exists')
    backup=PENDING.with_name('cow55-replay-node-a.previous-323ff755.json')
    need(not backup.exists(),'Previous run already archived; do not repeat')
    need(H.read(PENDING,2*1024**2)==old_raw,'Previous run changed during review')
    os.link(PENDING,backup);PENDING.unlink()
    return updated,{'previous_run_id':repair['previous_run_id'],'previous_receipt':str(backup),
        'repair_receipt':str(receipt),'original_before':repair['original_before'],'original_after':repair['original_after'],
        'previous_14_sandbox_ids_http404':True,'old_runtime_restarted':True,
        'historical_template_build_receipt_modified':False}

class Cohort:
    def __init__(self,work,build,inputs,template_count=55,admission_workers=2):
        need(template_count in (16,17,55) and len(inputs['cohort']['cases'])==template_count,'Unexpected authorized template budget')
        need(admission_workers in (1,2),'Invalid admission concurrency')
        self.template_count=template_count;self.max_guests=2*template_count;self.admission_workers=admission_workers
        self.initial_memory_gib=512 if template_count==55 else self.max_guests*4+32
        self.work=work;self.api=Api(build['original_identity']);self.lock=threading.RLock();self.send_lock=threading.Lock();self.stop=threading.Event()
        self.reader_ready=threading.Event();self.reader_stopped=threading.Event();self.client=None;self.listener=None
        self.reader_error=None;self.frame_counts={};self.created=[];self.deadline=time.monotonic()+6600
        self.requested_reader_stop=False;self.final_physical_templates=set()
        self.run_id=uuid.uuid4().hex;self.jobs=[]
        by_name={c['instance_id']:c for c in build['cases']}
        for c in inputs['cohort']['cases']:
            built=by_name[c['instance_id']];need(built['state']=='READY' and built['resources']['memory_mib']==4096,'Template not ready')
            raw=base64.b64decode(inputs['replays'][c['replay_file']],validate=True);need(hashlib.sha256(raw).hexdigest()==c['replay_sha256'],'Trace differs')
            steps,terminal=steps_from(raw)
            for slot in range(2):self.jobs.append({'index':len(self.jobs),'instance_id':c['instance_id'],'template_id':built['template_id'],
                'parent_snapshot_id':built['build_id'],'catalog_sha256':built['catalog_sha256'],'slot':slot,'steps':steps,'terminal_action':terminal,'replay_sha256':c['replay_sha256'],'state':'NOT_CREATED','steps_completed':0,'failed_commands':0})
        self.report={'revision':'cow55-continuous-v1','run_id':self.run_id,'report_directory':str(work),'source_build_run_id':build['run_id'],
            'runtime_source_commit':'ae9c62693839ce7effa2b45df31c0039ae4f9fbc',
            'implementation':'original','mode':'continuous','template_count':self.template_count,'max_guests':self.max_guests,'memory_mib_each':4096,'restore_calls':0,
            'restore_outcome_uncertain':False,'released_sandboxes':[],'SDK_called':False,'services_modified':False,'B_accessed':False,
            'workdir':'/','execution_transport':'existing aenv exec CLI; shell/delay/editor normalization aligned, not the original SDK runner',
            'timing_adaptation':'all-ready start barrier; completed Guests retained until cohort end; replay/mixed/idle phases separated',
            'sample_target_interval_seconds':1,'reference_sample_count':1200,'snapshot_capture_calls':0,'status':'PREPARING_COHORT'}
        for name in ('tmp','config/aenv','commands','measurements'):(work/name).mkdir(parents=True,exist_ok=True,mode=0o700)
        self.credential=work/'config/aenv/credentials'
        self.env={'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','PATH':str(BASE/'native/bin')+':/usr/bin:/bin',
            'LD_LIBRARY_PATH':str(BASE/'native/lib')+':'+str(BASE/'native/fallback/lib'),'TMPDIR':str(work/'tmp'),'XDG_CONFIG_HOME':str(work/'config')}
    def persist(self):
        with self.lock:
            self.report['jobs']=[{k:v for k,v in j.items() if k!='steps'} for j in self.jobs];self.report['updated_unix']=time.time();H.save(PENDING,self.report)
    def guard(self,initial=False):
        need(time.monotonic()<self.deadline and not self.stop.is_set(),'Cohort cancelled or deadline reached')
        text=Path('/proc/meminfo').read_text();m=re.search(r'(?m)^MemAvailable:\s+(\d+) kB',text)
        need(m and int(m[1])*1024>=(self.initial_memory_gib if initial else 64)*1024**3,'Insufficient host memory headroom')
        fs=os.statvfs(ROOT);need(not fs.f_flag&os.ST_RDONLY and fs.f_bavail*fs.f_frsize>=512*1024**3,'Filesystem reserve exhausted/read-only')
    def create(self,job):
        try:
            self.guard()
            with self.lock:
                need(self.report['restore_calls']<self.max_guests,'Restore budget exhausted');self.report['restore_calls']+=1;job['state']='CREATE_INTENT';self.persist()
            code,body=self.api.call('POST','/sandboxes',{'templateID':job['template_id'],'timeout':7200,'autoPause':False,'secure':True,
                'allow_internet_access':False,'metadata':{'cow55_run':self.run_id,'cow55_slot':str(job['index']),'cow55_create':self.run_id+'-'+str(job['index'])}},timeout=300)
            need(code==201 and isinstance(body,dict) and re.fullmatch(B.ID,str(body.get('sandboxID',''))),'Restore response unconfirmed: '+json.dumps(H.error_summary(body,self.api.key)))
            with self.lock:
                sid=body['sandboxID'];need(sid not in self.created,'Duplicate restored ID');job.update(sandbox_id=sid,state='READY',created_unix=time.time());self.created.append(sid);self.persist()
            value=self.command(job,'test "$(id -u)" = 0 && /agentenv/bin/busybox timeout -s TERM -k 1 5 /bin/bash -l -c true','probe')
            need(value['return_code']==0,'Guest root/timeout/shell probe failed')
            with self.lock:job['admission_probe_passed']=True;self.persist()
            print('PHASE=admission passed='+str(sum(bool(j.get('admission_probe_passed')) for j in self.jobs))+'/'+str(self.max_guests),flush=True)
        except BaseException as e:
            with self.lock:
                job['error']=str(e).replace(self.api.key,'[REDACTED]')
                if job['state']=='CREATE_INTENT':self.report['restore_outcome_uncertain']=True
                self.stop.set();self.persist()
            raise
    def command(self,job,action,label):
        self.guard();sid=job['sandbox_id'];nonce='COW55_END_'+uuid.uuid4().hex
        path=self.work/'commands'/('%03d-%s'%(job['index'],label));stdout=path.with_suffix('.stdout');stderr=path.with_suffix('.stderr')
        wrapped=shell_command(action,nonce);began=time.time()
        with stdout.open('xb') as out,stderr.open('xb') as err:
            p=subprocess.Popen([str(BASE/'bin/aenv'),'exec',sid,'/bin/bash','-c',wrapped],stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=self.env)
            try:
                until=time.monotonic()+330
                while p.poll() is None:
                    self.guard();need(time.monotonic()<until,'Command/transport deadline exceeded')
                    need(stdout.stat().st_size+stderr.stat().st_size<=16*1024**2,'Command log budget exceeded');time.sleep(.2)
                need(p.returncode==0,'CLI transport failed; inspect scoped command logs')
                need(stdout.stat().st_size+stderr.stat().st_size<=16*1024**2,'Command log budget exceeded')
            finally:
                if p.poll() is None:p.terminate()
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5) # only this ordinary aenv client; Guests cleaned via API
        with stdout.open('rb') as f:f.seek(max(0,stdout.stat().st_size-8192));tail=f.read().decode(errors='replace')
        match=re.findall(r'(?m)^'+re.escape(nonce)+r' ([0-9]+)\s*$',tail);need(len(match)==1,'Guest command exit marker missing')
        return {'started_unix':began,'finished_unix':time.time(),'return_code':int(match[0]),'stdout_file':str(stdout),'stderr_file':str(stderr)}
    def replay(self,job):
        try:
            with self.lock:job.update(state='REPLAYING',replay_started_unix=time.time());self.persist()
            for i,step in enumerate(job['steps']):
                if self.stop.wait(step['delay']):raise RuntimeError('Replay cancelled')
                value=self.command(job,step['action'],str(i));value.update(step=i,requested_delay_seconds=step['delay'])
                with (self.work/'commands'/('%03d-events.jsonl'%job['index'])).open('a') as f:f.write(json.dumps(value)+'\n')
                need(value['return_code'] not in (124,137),'Guest command timed out/killed; stop this cohort')
                with self.lock:job['steps_completed']+=1;job['failed_commands']+=int(value['return_code']!=0)
            with self.lock:job.update(state='REPLAY_COMPLETED',replay_finished_unix=time.time());self.persist()
            print('PHASE=trajectory_finished instance='+job['instance_id']+' slot='+str(job['slot']),flush=True)
            self.control({'op':'finished_jobs','sandbox_ids':[job['sandbox_id']]})
        except BaseException as e:
            with self.lock:job.update(state='REPLAY_FAILED',error=str(e).replace(self.api.key,'[REDACTED]'));self.stop.set();self.persist()
            raise
    def control(self,message):
        with self.send_lock:send(self.client,dict(message,run_id=self.run_id))
    def reader_receive(self):
        try:
            while True:
                msg=receive(self.client);need(msg.get('run_id')==self.run_id,'Reader run mismatch');channel=msg['channel']
                need(channel in ('hello','ready','process','cache','physical','heartbeat','phase','stopped'),'Unknown reader channel')
                path=self.work/'measurements'/(channel+'.jsonl')
                need(not path.exists() or path.stat().st_size<4*1024**3,'Measurement output budget exceeded')
                with path.open('a') as f:f.write(json.dumps(msg['data'],separators=(',',':'))+'\n')
                self.frame_counts[channel]=self.frame_counts.get(channel,0)+1
                if channel=='ready':self.reader_ready.set()
                if channel=='physical' and msg['data'].get('phase')=='final_hold':self.final_physical_templates.add(msg['data']['template_id'])
                if channel=='stopped':
                    with self.lock:self.report['root_reader_report']=msg['data']
                    self.reader_stopped.set()
                    if not self.requested_reader_stop:self.reader_error='Reader stopped before requested end';self.stop.set()
                    return
        except BaseException as e:self.reader_error=str(e);self.stop.set();self.reader_ready.set()
    def cleanup(self):
        for job in self.jobs:
            if job['state']!='CREATE_INTENT' or job.get('sandbox_id'):continue
            try:
                key=self.run_id+'-'+str(job['index'])
                code,rows=self.api.call('GET','/v2/sandboxes?metadata=cow55_create%3D'+key+'&limit=2')
                need(code==200 and isinstance(rows,list) and len(rows)==1,'Uncertain restore not uniquely reconciled')
                sid=rows[0].get('sandboxID');need(isinstance(sid,str) and re.fullmatch(B.ID,sid),'Reconciliation ID invalid')
                code,body=self.api.call('GET','/sandboxes/'+sid)
                need(code==200 and body.get('metadata',{}).get('cow55_run')==self.run_id and body['metadata'].get('cow55_create')==key,'Reconciliation ownership differs')
                with self.lock:
                    need(sid not in self.created,'Reconciled duplicate ID');self.created.append(sid);job.update(sandbox_id=sid,state='RECONCILED_FOR_CLEANUP');self.persist()
            except Exception as e:job['reconciliation_error_type']=type(e).__name__
        self.report['restore_outcome_uncertain']=any(j['state']=='CREATE_INTENT' and not j.get('sandbox_id') for j in self.jobs)
        def release(sid):
            try:
                code,body=self.api.call('GET','/sandboxes/'+sid)
                if code!=404:
                    need(code==200 and body.get('metadata',{}).get('cow55_run')==self.run_id,'Cleanup ownership differs')
                    self.api.call('DELETE','/sandboxes/'+sid,timeout=90)
                    need(self.api.call('GET','/sandboxes/'+sid)[0]==404,'Guest release not confirmed')
                with self.lock:self.report['released_sandboxes'].append(sid);self.persist()
            except Exception as e:
                with self.lock:self.report.setdefault('cleanup_errors',[]).append({'sandbox_id':sid,'type':type(e).__name__});self.persist()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:list(pool.map(release,list(self.created)))
    def run(self,collector_source,reader_source):
        root_thread=None
        try:
            self.guard(initial=True);need(self.api.call('GET','/health')[0]==204,'Original service unhealthy')
            need(self.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Existing sandboxes; no launch')
            need(not R.find_firecrackers(self.api.identity[0]),'Existing Firecracker descendants')
            self.credential.write_text('url = "http://127.0.0.1:18080"\napi_key = '+json.dumps(self.api.key)+'\n')
            self.persist()
            # Two genuine cohort Guests validate the command channel before 108 more.
            for job in self.jobs[:2]:self.create(job)
            # Bound creation pressure independently from the 110-Guest replay concurrency.
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.admission_workers) as pool:list(pool.map(self.create,self.jobs[2:]))
            need(len(self.created)==self.max_guests and not self.stop.is_set(),'Incomplete cohort; no replay')
            pids=R.find_firecrackers(self.api.identity[0]);need(len(pids)==self.max_guests,'Unexpected scoped Firecracker count')
            pairs=[{'template_id':self.jobs[i]['template_id'],'catalog_sha256':self.jobs[i]['catalog_sha256'],
                    'recorded_wait_seconds':sum(step['delay'] for step in self.jobs[i]['steps']),
                    'sandbox_ids':[self.jobs[i]['sandbox_id'],self.jobs[i+1]['sandbox_id']]} for i in range(0,self.max_guests,2)]
            scope={'template_count':self.template_count,'run_id':self.run_id,'main_pid':self.api.identity[0],'main_start_ticks':self.api.identity[1],
                'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'memory_bytes':4096*1024**2,'pairs':pairs,
                'children':[{'pid':p,'start_ticks':R.identity(p)[1]} for p in pids]}
            self.report['scope']=scope;self.report['status']='AWAITING_INLINE_ROOT_READER';self.persist()
            sock=ROOT/'r'/('c55-'+self.run_id[:12]+'.sock');self.socket_path=sock
            self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.listener.bind(str(sock));os.chmod(sock,0o600)
            meta=sock.lstat();self.socket_identity=(meta.st_dev,meta.st_ino);self.listener.listen(1);self.listener.settimeout(600)
            endpoint={'path':str(sock),'pid':os.getpid(),'ticks':R.identity(os.getpid())[1]}
            tag='COW33_BATCH' if self.template_count in (16,17) else 'COW55'
            command="/usr/bin/python3 -I -B - <<'"+tag+"_ROOT_READER'\n"+collector_source+'\n'+reader_source+'\nscope = '+pprint.pformat(scope,width=100)+'\nendpoint = '+pprint.pformat(endpoint,width=100)+'\ncohort_reader(scope, endpoint)\n'+tag+'_ROOT_READER'
            (self.work/'root-reader-review.txt').write_text(command)
            print('BEGIN_REVIEWED_'+tag+'_ROOT_COPY_BODY_ONLY');print(command);print('END_REVIEWED_'+tag+'_ROOT_COPY_BODY_ONLY',flush=True)
            print('Keep this jwk terminal open. Paste the body once into A root within 600 seconds. No done input.',flush=True)
            self.client,_=self.listener.accept();peer=struct.unpack('3i',self.client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));need(peer[1]==0,'Expected root reader peer')
            print('PHASE=root_reader_connected_binding_'+str(self.max_guests)+'_guests',flush=True)
            self.client.settimeout(600);root_thread=threading.Thread(target=self.reader_receive,daemon=True);root_thread.start()
            need(self.reader_ready.wait(600) and self.reader_error is None,'Root binding failed/timed out')
            print('PHASE=root_reader_bound_starting_continuous_replay',flush=True)
            time.sleep(5);self.control({'op':'phase','phase':'replay'});self.report['status']='COW55_CONTINUOUS_REPLAY_RUNNING';self.persist()
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_guests) as pool:
                futures=[pool.submit(self.replay,j) for j in self.jobs]
                try:
                    while not all(f.done() for f in futures):
                        self.guard();self.control({'op':'heartbeat'});self.persist();time.sleep(5)
                    for f in futures:f.result()
                except BaseException:self.stop.set();raise
            self.control({'op':'phase','phase':'final_hold'});end=time.monotonic()+600
            while len(self.final_physical_templates)<self.template_count and time.monotonic()<end:
                self.guard();self.control({'op':'heartbeat'});time.sleep(5)
            self.report['final_hold_templates_attempted']=len(self.final_physical_templates)
            self.report['status']='COW55_REPLAY_COMPLETED_MEASUREMENTS_PENDING_REVIEW'
        except BaseException as e:
            self.report.update(status='STOPPED_COW55_REPLAY',error_type=type(e).__name__,reason=str(e).replace(self.api.key,'[REDACTED]'));self.stop.set()
        finally:
            if self.client:
                self.requested_reader_stop=True
                try:self.control({'op':'stop'});self.report['root_stop_acknowledged']=self.reader_stopped.wait(240)
                except Exception:self.report['root_stop_acknowledged']=False
                self.client.close()
            if self.listener:self.listener.close()
            self.report['measurement_frames']=dict(self.frame_counts);self.report['reader_error']=self.reader_error
            if root_thread:root_thread.join(timeout=5)
            self.cleanup()
            if self.credential.exists():self.credential.unlink()
            self.report['temporary_cli_credentials_removed']=not self.credential.exists()
            if getattr(self,'socket_identity',None) and self.socket_path.is_socket():
                meta=self.socket_path.lstat()
                if (meta.st_dev,meta.st_ino)==self.socket_identity:self.socket_path.unlink()
            self.report['all_known_guests_released']=set(self.created)==set(self.report['released_sandboxes'])
            self.report['all_cohort_guests_released']=self.report['all_known_guests_released'] and not self.report['restore_outcome_uncertain']
            self.report['templates_and_runtime_cache_preserved']=True
            self.report['post_cleanup_device_pool_cache_release_measured']=False
            self.report['replay_completed_guests']=sum(j['state']=='REPLAY_COMPLETED' for j in self.jobs)
            self.report['replay_completed_templates']=sum(all(j['state']=='REPLAY_COMPLETED' for j in self.jobs[i:i+2]) for i in range(0,self.max_guests,2))
            self.report['full_measurement_acceptance']='PENDING_PER_TEMPLATE_EFFECTIVE_SAMPLE_AND_CACHE_COVERAGE_REVIEW'
            try:self.report['measurement_summary']=summarize_measurements(self.work,{j['template_id']:j['instance_id'] for j in self.jobs})
            except Exception as e:self.report['summary_error']={'type':type(e).__name__,'reason':str(e)}
            if self.report['status']=='COW55_REPLAY_COMPLETED_MEASUREMENTS_PENDING_REVIEW':
                if not self.report['all_cohort_guests_released'] or not self.report.get('root_stop_acknowledged') or self.reader_error or self.report.get('summary_error'):
                    self.report['status']='COW55_REPLAY_COMPLETED_CLEANUP_OR_MEASUREMENT_INCOMPLETE'
                else:
                    measured=self.report['measurement_summary'];gaps=[]
                    if measured['replay_process_rows']!=self.max_guests or not measured['minimum_template_paired_samples']:gaps.append('RSS_PSS_PAIR_COVERAGE')
                    if not measured['cache_complete_sweeps'] or measured['replay_rootfs_template_count']!=self.template_count:gaps.append('ROOTFS_CACHE_COVERAGE')
                    if measured['templates_with_valid_physical_sample']!=self.template_count:gaps.append('GUEST_RAM_PHYSICAL_COVERAGE')
                    if measured['replay_templates_with_valid_physical_sample']!=self.template_count:gaps.append('GUEST_RAM_REPLAY_PHYSICAL_COVERAGE')
                    self.report['measurement_gaps']=gaps
                    if gaps:self.report['status']='COW55_REPLAY_COMPLETED_MEASUREMENT_GAPS'
            self.persist();H.save(self.work/'return.json',self.report)
            if getattr(self,'emit_final_report',True):
                print('BEGIN_RETURN_REPORT');print(json.dumps(self.report,indent=2));print('END_RETURN_REPORT',flush=True)
        return 0 if self.report['status']=='COW55_REPLAY_COMPLETED_MEASUREMENTS_PENDING_REVIEW' else 1

def main():
    global B,H,R
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('run','status','run-after-memlock-repair'));a=p.parse_args()
    need(os.getuid()==os.geteuid()==1204 and os.uname().nodename=='server1','A ordinary jwk required');os.umask(0o077)
    caps=dict(s.split(':',1) for s in Path('/proc/self/status').read_text().splitlines() if ':' in s);need(all(int(caps[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapAmb')),'Capability-free owner required')
    B,_=load(ROOT/'cow55_build_edf502d.py',BUILDER_SHA,'cohort_builder');B.load_helper();H=B.H
    if a.mode=='status':print('BEGIN_RETURN_REPORT');print(json.dumps(B.read_json(PENDING),indent=2));print('END_RETURN_REPORT');return
    R,collector_source=load(ROOT/'cow_ram_readonly.py',COLLECTOR_SHA,'cohort_collector');_,reader_source=load(ROOT/'cow55_reader.py',READER_SHA,'cohort_reader_source')
    import fcntl
    fd=os.open(H.safe(LOCK),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if a.mode=='run':need(not PENDING.exists(),'Replay receipt exists; no blind repeat')
        else:need(PENDING.exists(),'Expected failed replay receipt absent')
        B.inputs(ROOT/'cow55_inputs.json');inputs=B.read_json(ROOT/'cow55_inputs.json');build=B.read_json(B.STATE)
        need(B.read_json(BASE/'installation.json').get('commit')=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc','Original installation source differs')
        need(build['status']=='COW55_ALL_TEMPLATES_READY_NO_REPLAY_STARTED' and build.get('final_merge_verified') and build['worker_finished'],'55-template preparation not complete')
        need(build['input_sha256']==B.INPUT_SHA,'Prepared cohort input differs')
        need(len(build['cases'])==55 and len({c['template_id'] for c in build['cases']})==55,'Template set differs')
        for case in build['cases']:B.verify_ready(case)
        recovery=None
        if a.mode=='run-after-memlock-repair':build,recovery=prepare_after_repair(build)
        work=Path(tempfile.mkdtemp(prefix='node-a-cow55-replay-',dir=ROOT/'relay/reports'));cohort=Cohort(work,build,inputs)
        cohort.report['admission_parallelism']=2
        if recovery:cohort.report['previous_attempt_resolution']=recovery
        return cohort.run(collector_source,reader_source)
    finally:os.close(fd)

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_COW55_REPLAY_ENTRY','error_type':type(error).__name__,'reason':str(error)},indent=2));print('END_RETURN_REPORT');raise SystemExit(1)
