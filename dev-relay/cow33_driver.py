"""33 existing original templates, separately measured 17/16-template cohorts.

The single-file delivery supplies ENGINE, SELECTOR and READER_SOURCE from the
reviewed repository sources. No driver/service changes or template creation.
"""
import argparse, collections, copy, hashlib, json, os, re, stat, tempfile, time
from pathlib import Path

EXPECTED_RUNTIME=(3713139,'35114697')
SELECTION_SHA='456c7762fdfb2a380f7be03ad16c953336b37a330880ccb6e5575fafdf7e0c0d'
OLD_PENDING_SHA='8640cd80cbd6870e4ec503a198d46fc1912b3bea54a887b36495a4b184ecd939'
CONFIG_SHA='f2a1abe6542c3230bfe3cd81b884cf080dc4a3b2f2c371b40092940c686d01bd'

def inventory(sysroot=Path('/sys')):
    module=sysroot/'module/ublk_drv'
    char=sysroot/'class/ublk-char';block=sysroot/'class/block'
    ENGINE.need(char.is_dir() and block.is_dir(),'Device inventory unavailable')
    ids=sorted(int(p.name[5:]) for p in char.iterdir() if re.fullmatch(r'ublkc[0-9]+',p.name))
    sizes={}
    for p in block.iterdir():
        if re.fullmatch(r'ublkb[0-9]+',p.name):sizes[str(int(p.name[5:]))]=int((p/'size').read_text().strip())*512
    return {'unix':time.time(),'limit':int((module/'parameters/ublks_max').read_text().strip()),
            'char_ids':ids,'block_size_bytes':sizes}

def device_budget(current,count,previous=None):
    """Plan using observed same-daemon, previous-batch pool devices by size.

    This is admission planning, not proof of pool ownership or physical use.
    Only devices whose names persisted from our previous batch are considered;
    unknown devices remain occupied. No device is deleted by this controller.
    """
    ENGINE.need(current['limit']==64 and count in (16,17),'Unexpected device limit/cohort')
    reusable=set()
    if previous:
        ENGINE.need(set(current['char_ids'])<=set(previous['ublk_after_cleanup']['char_ids']),
                    'Device identities changed between batches; review required')
        reusable=set(previous['ublk_before_cleanup']['char_ids'])-set(previous['ublk_before']['char_ids'])
    demand={4096*1024**2:count,65536*1024**2:2*count}
    retained=collections.Counter(int(size) for i,size in current['block_size_bytes'].items() if int(i) in reusable)
    reusable_by_size={size:min(n,retained[size]) for size,n in demand.items()}
    required_new=sum(demand.values())-sum(reusable_by_size.values())
    free=current['limit']-len(current['char_ids']);reserve=2
    return {'planned_business_devices':3*count,'current_registered':len(current['char_ids']),
        'free_slots':free,'required_new_slots_estimate':required_new,'reserve_slots':reserve,
        'previous_batch_retained_candidates_by_size':reusable_by_size,
        'pool_reuse_is_inferred_not_independently_attested':bool(previous),
        'fits':required_new+reserve<=free}

def old_attempt_absent(api):
    raw=ENGINE.H.read(ENGINE.ROOT/'relay/cow55-replay-node-a.pending.json',2*1024**2)
    ENGINE.need(hashlib.sha256(raw).hexdigest()==OLD_PENDING_SHA,'Old 55-case receipt changed')
    value=json.loads(raw);ENGINE.need(value['run_id']=='e6171de2e0904c78ac69d1c380d05191','Unexpected failed attempt')
    ids=set()
    for j in value['jobs']:
        if j.get('sandbox_id'):ids.add(j['sandbox_id'])
        ids.update(re.findall(r'sandbox ([0-9a-f-]{36}) operation Start failed',j.get('error','')))
    ENGINE.need(len(ids)==38,'Old request identity inventory incomplete')
    for sid in sorted(ids):ENGINE.need(api.call('GET','/sandboxes/'+sid)[0]==404,'Previous sandbox still exists')
    return {'previous_run_id':value['run_id'],'checked_absent_request_ids':len(ids),'old_receipt_modified':False}

def aggregate(receipts):
    rows=[];cache=[];physical=[];batches=[];global_sweeps=[];host_sweeps=[]
    for r in receipts:
        p=Path(r['measurement_summary']['file']);raw=ENGINE.H.read(p,64*1024**2)
        ENGINE.need(hashlib.sha256(raw).hexdigest()==r['measurement_summary']['sha256'],'Summary changed')
        s=json.loads(raw);number=r['batch_number']
        labels={j['template_id']:j['instance_id'] for j in r['jobs']}
        for src,dst in [('process_rows',rows),('rootfs_rows',cache),('physical_rows',physical)]:
            for item in s[src]:dst.append(dict(item,batch_number=number,trajectory=labels.get(item['template_id'],'NA')))
        batches.append({'batch_number':number,'run_id':r['run_id'],'template_count':r['template_count'],
            'simultaneous_guests':r['max_guests'],'status':r['status'],'measurement_summary':r['measurement_summary'],
            'global_file_cache_sweeps_file':str(p),'measurement_gaps':r.get('measurement_gaps',[])})
        global_sweeps.append({'batch_number':number,'sweeps':s['global_file_cache_sweeps']})
        host_sweeps.append({'batch_number':number,'sweeps':s['host_background_and_collector_sweeps']})
    return {'revision':'cow33-combined-v1','selection_sha256':SELECTION_SHA,'batches':batches,
        'reported_batches':len(receipts),'completed_templates':sum(r.get('replay_completed_templates',0) for r in receipts),
        'process_rows':rows,'rootfs_rows':cache,'physical_rows':physical,
        'global_file_cache_sweeps_by_batch':global_sweeps,'host_background_sweeps_by_batch':host_sweeps,
        'simultaneous_66_guests':False,'cross_batch_physical_or_cache_totals_summed':False,
        'cache_preconditioning':'No drop_caches or explicit full-file warmup. Second batch may inherit cache from first.',
        'net_physical_savings_bytes':None,'full_host_pagecache_attributed':False}

def summary_markdown(value):
    def mib(v):return 'NA' if v is None else format(v/1024**2,'.3f')
    def metric(row,key,ratio=False):
        v=row.get('metrics',{}).get(key)
        if not v:return 'NA'
        scale=100 if ratio else 1/1024**2
        return format(v['min']*scale,'.3f')+'~'+format(v['max']*scale,'.3f')+('%' if ratio else '')
    lines=['# 33模板分两批原版CoW实测汇总','',
        '当前已纳入 '+str(value['reported_batches'])+'/2 批回执，完成轨迹的模板数 '+str(value['completed_templates'])+'/33；采样完整性仍以各批状态/缺测项为准。',
        '批次1为17模板/34沙箱；批次2为16模板/32沙箱。两批不同时间执行，不能作为66沙箱同时运行结果。',
        '进程RSS/PSS是整个Firecracker进程口径；共享估计逐轮计算Σ(RSS−PSS)/(n−1)。',
        '批间不清缓存，第二批可能继承热缓存。host缓存与物理页不跨批相加。','',
        '|批次|轨迹|模板ID|沙箱ID|最小RSS|最大RSS|最小PSS|最大PSS|最小RSS−PSS|最大RSS−PSS|模板最小共享估计|模板最大共享估计|有效采样数|模板配对数|',
        '|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in value['process_rows']:
        if r['phase']!='replay':continue
        lines.append('|'+str(r['batch_number'])+'|'+r['trajectory']+'|'+r['template_id']+'|'+r['sandbox_id']+'|'+
            '|'.join(mib(r[k]) for k in ('sandbox_min_rss_bytes','sandbox_max_rss_bytes','sandbox_min_pss_bytes','sandbox_max_pss_bytes',
                                       'sandbox_min_rss_minus_pss_bytes','sandbox_max_rss_minus_pss_bytes','template_min_shared_bytes','template_max_shared_bytes'))+'|'+
            str(r['sandbox_valid_samples'])+'|'+str(r['template_valid_paired_samples'])+'|')
    lines+=['','容量单位均为MiB；以下范围是有效采样的min~max。','',
        '## rootfs文件与host缓存（replay阶段）','','|批次|模板ID|S1 ID|S2 ID|S1 lower文件|S2 lower文件|共同lower文件|S1 upper分配|S2 upper分配|共同lower缓存|S1 upper缓存|S2 upper缓存|公共文件占比|共同缓存对象占比|',
        '|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in value['rootfs_rows']:
        if r['phase']!='replay':continue
        columns=('sandbox1_lower_file_bytes','sandbox2_lower_file_bytes','shared_lower_file_bytes','sandbox1_upper_allocated_bytes','sandbox2_upper_allocated_bytes',
                 'shared_lower_resident_bytes','sandbox1_upper_resident_bytes','sandbox2_upper_resident_bytes')
        lines.append('|'+ '|'.join([str(r['batch_number']),r['template_id']]+r['sandbox_ids']+[metric(r,k) for k in columns]+
                     [metric(r,'shared_pool_fraction_allocated_bytes',True),metric(r,'shared_pool_fraction_resident_bytes',True)])+'|')
    lines+=['','共同缓存是两侧引用相同文件对象的驻留量，不是实际访问offset交集；跨模板下层文件可能重叠，不能直接求和。','',
        '## memfile路径及设备缓存（replay阶段）','','|批次|模板ID|memory lower文件|memory lower文件缓存|memory设备缓存|rootfs设备缓存|',
        '|---|---|---:|---:|---:|---:|']
    for r in value['rootfs_rows']:
        if r['phase']=='replay':lines.append('|'+ '|'.join([str(r['batch_number']),r['template_id']]+[metric(r,k) for k in (
            'memory_lower_unique_file_bytes','memory_lower_unique_resident_bytes','memory_unique_device_cache_bytes','rootfs_unique_device_cache_bytes')])+'|')
    lines+=['','## Guest RAM物理共享（各阶段单列）','','|批次|模板ID|阶段|有效样本|普通Guest共享唯一量|共享参与率|重复避免率|snapshot-file共享子集|',
        '|---|---|---|---:|---:|---:|---:|---:|']
    for r in value['physical_rows']:
        lines.append('|'+ '|'.join([str(r['batch_number']),r['template_id'],r['phase'],str(r['valid_samples']),metric(r,'ordinary_guest_ram_shared_unique_bytes'),
            metric(r,'ordinary_guest_ram_participation_ratio',True),metric(r,'ordinary_guest_ram_duplicate_avoidance_ratio',True),metric(r,'snapshot_file_shared_bytes_excluding_special_pages')])+'|')
    lines+=['','memory设备cache与Guest映射可能重叠，不与PSS相加。整机Cached只作背景；全局物理净收益仍为NA。缺项不补零。','']
    lines+=['## 每批观测文件去重后的宿主机统计（完整采样窗口）','',
        '|批次|rootfs lower文件|rootfs lower分配|rootfs lower缓存|rootfs upper分配|rootfs upper缓存|memory lower缓存|',
        '|---|---:|---:|---:|---:|---:|---:|']
    for batch in value['global_file_cache_sweeps_by_batch']:
        fields=('global_rootfs_lower_file_bytes','global_rootfs_lower_allocated_bytes','global_rootfs_lower_resident_bytes',
                'global_rootfs_upper_allocated_bytes','global_rootfs_upper_resident_bytes','global_memory_lower_resident_bytes')
        cols=[]
        for field in fields:
            values=[row[field] for row in batch['sweeps'] if row.get(field) is not None]
            cols.append(mib(min(values))+'~'+mib(max(values)) if values else 'NA')
        lines.append('|'+str(batch['batch_number'])+'|'+'|'.join(cols)+'|')
    lines+=['','该表按每次采样的设备号/inode去重，覆盖观测文件，不是整个host的pagecache。两批分别列示，不对批次求和。','']
    for b in value['batches']:lines.append('批次 '+str(b['batch_number'])+'：'+b['status']+'；详细报告 '+str(Path(b['measurement_summary']['file']).with_suffix('.md')))
    return '\n'.join(lines)+'\n'

def main():
    m=ENGINE;parser=argparse.ArgumentParser();parser.add_argument('mode',choices=('plan','run','status'));parser.add_argument('--batch',type=int,choices=(1,2),default=1);args=parser.parse_args()
    m.need(os.getuid()==os.geteuid()==1204 and os.uname().nodename=='server1','Ordinary A/jwk only');os.umask(0o077)
    caps=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)
    m.need(all(int(caps[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapAmb')),'Capability-free owner required')
    m.B,_=m.load(m.ROOT/'cow55_build_edf502d.py',m.BUILDER_SHA,'batch_builder');m.B.load_helper();m.H=m.B.H
    m.R,collector=m.load(m.ROOT/'cow_ram_readonly.py',m.COLLECTOR_SHA,'batch_collector')
    m.PENDING=m.ROOT/'relay'/('cow33-batch'+str(args.batch)+'-node-a.pending.json')
    if args.mode=='status':
        value=m.B.read_json(m.PENDING);print('BEGIN_RETURN_REPORT');print(json.dumps(value,indent=2));print('END_RETURN_REPORT');return 0
    import fcntl
    lock=os.open(m.H.safe(m.LOCK),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        m.B.inputs(m.ROOT/'cow55_inputs.json');inputs=m.B.read_json(m.ROOT/'cow55_inputs.json');selection=SELECTOR.select(inputs)
        m.need(selection['selection_sha256']==SELECTION_SHA,'Representative selection changed')
        build=m.B.read_json(m.B.STATE)
        m.need(build['status']=='COW55_ALL_TEMPLATES_READY_NO_REPLAY_STARTED' and build.get('final_merge_verified') and build['worker_finished'],'Prepared 55-case build not complete')
        m.need(m.B.read_json(m.BASE/'installation.json')['commit']=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc','Original installed source differs')
        m.need(hashlib.sha256(m.H.read(m.BASE/'config/runtime.toml',65536)).hexdigest()==CONFIG_SHA,'Original runtime config changed')
        m.need(m.H.runtime_pid()==EXPECTED_RUNTIME,'Restored original Runtime changed')
        limits=m.subprocess.run(['/usr/bin/systemctl','show','jwk-aenv-ae9c626-node-a.service',
            '--property=LimitMEMLOCK,LimitMEMLOCKSoft'],capture_output=True,text=True,check=True,timeout=10)
        settings=dict(line.split('=',1) for line in limits.stdout.splitlines() if '=' in line)
        m.need(settings.get('LimitMEMLOCK')==settings.get('LimitMEMLOCKSoft')=='2147483648','Expected unit memlock changed')
        api=m.Api(EXPECTED_RUNTIME);m.need(api.call('GET','/health')[0]==204,'Original health failed')
        m.need(api.call('GET','/v2/sandboxes?limit=1')==(200,[]) and not m.R.find_firecrackers(EXPECTED_RUNTIME[0]),'Existing original Guests')
        batch_cases=[inputs['cohort']['cases'][i] for i in selection['batch_indexes'][args.batch-1]]
        tids={c['instance_id'] for c in batch_cases};built=[copy.deepcopy(c) for c in build['cases'] if c['instance_id'] in tids]
        m.need(len(built)==len(batch_cases) and all(c['state']=='READY' for c in built),'Selected prepared templates missing')
        for c in built:m.B.verify_ready(c)
        previous=None
        if args.batch==2:
            previous=m.B.read_json(m.ROOT/'relay/cow33-batch1-node-a.pending.json')
            m.need(previous.get('selection_sha256')==SELECTION_SHA and previous.get('batch_number')==1 and
                   previous.get('status')=='COW33_BATCH_REPLAY_COMPLETED_MEASUREMENTS_PENDING_REVIEW' and previous.get('all_cohort_guests_released') and
                   previous.get('root_stop_acknowledged') and previous.get('summary_finalized'),'First batch not fully collected/released; return its report')
            m.need(previous['scope']['main_pid']==EXPECTED_RUNTIME[0] and previous['scope']['main_start_ticks']==EXPECTED_RUNTIME[1],'Runtime changed between batches')
            expected_names={inputs['cohort']['cases'][i]['instance_id'] for i in selection['batch_indexes'][0]}
            expected_ids={c['template_id'] for c in build['cases'] if c['instance_id'] in expected_names}
            m.need(len(previous['jobs'])==34 and {j['template_id'] for j in previous['jobs']}==expected_ids and
                   previous.get('replay_completed_guests')==34 and not previous.get('root_reader_report',{}).get('errors'),
                   'First batch identity/reader evidence differs')
        before=inventory();budget=device_budget(before,len(batch_cases),previous)
        plan={'status':'COW33_BATCH_PLAN_NO_GUEST','batch_number':args.batch,'selection_sha256':SELECTION_SHA,
            'template_count':len(batch_cases),'simultaneous_guests':2*len(batch_cases),'language_counts':dict(collections.Counter(c['language'] for c in batch_cases)),
            'device_budget':budget,'ublk_before':before,'driver_modified':False,'SDK_called':False,'B_accessed':False}
        if args.mode=='plan':print('BEGIN_RETURN_REPORT');print(json.dumps(plan,indent=2));print('END_RETURN_REPORT');return 0
        m.need(not m.PENDING.exists(),'This batch receipt exists; no blind retry')
        if not budget['fits']:
            plan['status']='STOPPED_COW33_CAPACITY_NO_GUEST'
            print('BEGIN_RETURN_REPORT');print(json.dumps(plan,indent=2));print('END_RETURN_REPORT');return 1
        resolution=old_attempt_absent(api)
        adjusted=dict(build,original_identity=list(EXPECTED_RUNTIME),cases=built)
        subset=dict(inputs,cohort=dict(inputs['cohort'],cases=batch_cases))
        work=Path(tempfile.mkdtemp(prefix='node-a-cow33-batch'+str(args.batch)+'-',dir=m.ROOT/'relay/reports'))
        cohort=m.Cohort(work,adjusted,subset,template_count=len(batch_cases),admission_workers=1)
        cohort.emit_final_report=False
        cohort.report.update(batch_number=args.batch,selection_sha256=SELECTION_SHA,admission_parallelism=1,
            ublk_before=before,device_budget=budget,previous_attempt_resolution=resolution,
            cohort_template_target=33,total_batches=2,original_memlock_bytes=2147483648,
            memlock_evidence='Root service-restoration receipt and current unit limits; the inline root reader checks the actual Runtime process limit when binding.',
            configured_guest_ram_bytes=cohort.max_guests*4096*1024**2,initial_memory_headroom_gib=cohort.initial_memory_gib,
            cache_preconditioning='No drop_caches; second batch can inherit first-batch caches; no cross-batch totals.')
        # Record the pool/device inventory before cleanup and after release;
        # never delete devices, infer a new API, or change daemon settings.
        cleanup=cohort.cleanup
        def capture_cleanup():
            try:cohort.report['ublk_before_cleanup']=inventory()
            except Exception as e:cohort.report['ublk_before_cleanup_error']=type(e).__name__
            cleanup()
            try:
                last=None;stable=0;until=time.monotonic()+30
                while True:
                    observed=inventory();current=(observed['char_ids'],observed['block_size_bytes'])
                    stable=stable+1 if current==last else 0;last=current
                    if stable>=2 or time.monotonic()>=until:break
                    time.sleep(1)
                cohort.report['ublk_after_cleanup']=observed
                cohort.report['ublk_after_cleanup_stable']=stable>=2
            except Exception as e:cohort.report['ublk_after_cleanup_error']=type(e).__name__
        cohort.cleanup=capture_cleanup
        code=cohort.run(collector,READER_SOURCE)
        cohort.report['engine_status']=cohort.report['status']
        cohort.report['status']=cohort.report['status'].replace('COW55','COW33_BATCH')
        try:
            m.H.save(work/'selection.json',selection)
            combined=aggregate(([previous] if previous else [])+[cohort.report])
            m.H.save(work/'combined-summary.json',combined)
            (work/'combined-summary.md').write_text(summary_markdown(combined),encoding='utf-8')
            cohort.report.update(summary_finalized=True,combined_summary=str(work/'combined-summary.json'),combined_markdown=str(work/'combined-summary.md'))
        except Exception as e:
            cohort.report.update(summary_finalized=False,combined_summary_error=type(e).__name__);code=1
        cohort.persist();m.H.save(work/'return.json',cohort.report)
        print('BEGIN_RETURN_REPORT');print(json.dumps(cohort.report,indent=2));print('END_RETURN_REPORT');return code
    finally:os.close(lock)
