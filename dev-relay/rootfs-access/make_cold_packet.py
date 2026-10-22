"""Derive an isolated four-template cold-cache run from reviewed lifecycle code."""
import base64, hashlib
from pathlib import Path

HERE=Path(__file__).resolve().parent
RELAY=HERE.parent


def once(text,old,new):
    assert text.count(old)==1,old
    return text.replace(old,new)


def build():
    payload={}
    for name,path in [('engine',RELAY/'cow55_replay.py'),('accounting',HERE/'page_accounting.py'),
                      ('process_summary',RELAY/'cow55_process_summary.py'),('root_session',HERE/'root_session.py'),
                      ('recovery',HERE/'recover_previous.py'),('rootfs_details',RELAY/'cow_rootfs_details.py'),
                      ('cold',HERE/'cold_cache.py')]:
        raw=path.read_bytes()
        if name=='engine':raw=once(raw,b'template_count in (16,17,55)',b'template_count in (4,16,17,55)')
        if name=='root_session':
            raw=once(raw,b'    report={',b"    print('ROOT_PHASE=cold_run_preflight',flush=True)\n    report={")
            raw=once(raw,b'        until=time.monotonic()+5400',b"        print('ROOT_PHASE=original_observer_active',flush=True)\n        last_progress=time.monotonic()\n        until=time.monotonic()+5400")
            raw=once(raw,b"            request=wire_recv(sock);op=request.get('op')",b"            request=wire_recv(sock);op=request.get('op')\n            if time.monotonic()-last_progress>=60:\n                print('ROOT_PHASE=supervising_cold_replay',flush=True);last_progress=time.monotonic()")
        payload[name]={'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()}
    preamble='''"""Four existing templates, targeted host lower-cache cold validation. No rebuild."""
import base64,hashlib,sys,types
EMBEDDED = '''+repr(payload)+'''
def _source(name):
    item=EMBEDDED[name];raw=base64.b64decode(item['base64'],validate=True)
    if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise RuntimeError('Embedded source differs')
    return raw.decode()
def _module(name):
    value=types.ModuleType('cow4cold_'+name);value.__file__=__file__+'#'+name
    sys.modules[value.__name__]=value;exec(compile(_source(name),value.__file__,'exec'),value.__dict__);return value
ENGINE=_module('engine')
ACCOUNTING=_module('accounting')
PROCESS=_module('process_summary')
DETAILS=_module('rootfs_details')
COLD=_module('cold')
ACCOUNTING.resident_accessed_pages=COLD.scan
ROOT_SOURCE=_source('root_session')
RECOVERY_SOURCE=_source('recovery')
'''
    text=(HERE/'four_run.py').read_text(encoding='utf-8')
    text=once(text,"choices=('run','status','recover-previous','retry-after-recovery')","choices=('run','status')")
    text=once(text,"m.PENDING=m.ROOT/'relay/cow4-access-node-a.pending.json'","m.PENDING=m.ROOT/'relay/cow4-cold-node-a.pending.json'")
    text=once(text,"    retry=prepare_retry() if args.mode=='retry-after-recovery' else None", """    retry=None
    prior=m.B.read_json(m.ROOT/'relay/cow4-access-node-a.pending.json')
    m.need(prior['run_id']=='2606e4f482b44f4fb072792215ac9793' and prior['status']=='COW4_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED','Prior four-template run is not the completed baseline')
    m.need(prior['all_cohort_guests_released'] and prior['root_session']['original_configuration_restored'],'Prior cleanup not confirmed')
    seventeen=m.ROOT/'relay/cow17-access-node-a.pending.json'
    m.need(not seventeen.exists(),'17-template receipt exists; review its lifecycle before cold run')""")
    text=text.replace("prefix='node-a-cow4-access-'","prefix='node-a-cow4-cold-'")
    text=once(text,"        c=self.c\n        for j in c.jobs:","""        c=self.c
        COLD.TEMPLATE_KEYS={tid:{(f['dev'],f['inode']) for f in rows} for tid,rows in self.plan['template_lowers'].items()}
        c.report['cache_geometry']=COLD.environment(self.files)
        print('PHASE=owned_cold_cache_calibration',flush=True)
        c.report['cold_calibration']=COLD.calibrate(c.work)
        print('PHASE=evict_target_lowers_before_restore',flush=True)
        initial=COLD.cold_checkpoint(self.files,c.work/'cold-before-restore.json','before_guest_restore')
        c.report['cold_before_restore']={'file':str(c.work/'cold-before-restore.json'),'resident_bytes_after':initial['after']['whole_lower_resident_bytes']}
        c.persist();self.rpc('heartbeat')
        for j in c.jobs:""")
    text=once(text,"        time.sleep(2);self.start=time.monotonic_ns();c.report['replay_start_monotonic_ns']=self.start", """        time.sleep(2)
        print('PHASE=evict_target_lowers_before_replay',flush=True)
        cold=COLD.cold_checkpoint(self.files,c.work/'cold-before-replay.json','after_restore_before_replay')
        c.report['cold_before_replay']={'file':str(c.work/'cold-before-replay.json'),'resident_bytes_after':cold['after']['whole_lower_resident_bytes']}
        c.report['cold_scope']='host lower regular-file cache; Guest and daemon userspace caches not flushed; per-file sweep not atomic'
        c.persist();self.rpc('heartbeat')
        self.start=time.monotonic_ns();c.report['replay_start_monotonic_ns']=self.start""")
    text=once(text,"        path=self.c.work/'measurements/access-cache.jsonl'", "        COLD.enrich(frame,self.files,sets,resident)\n        path=self.c.work/'measurements/access-cache.jsonl'")
    text=once(text,"        c.report['trajectory_windows_monotonic_ns']", """        print('PHASE=independent_fincore_crosscheck',flush=True)
        c.report['independent_cache_crosscheck']=COLD.independent_check(self.files,c.work/'independent-cache-crosscheck.json')
        c.report['trajectory_windows_monotonic_ns']""")
    text=once(text,"    result['rootfs_storage_details']=DETAILS.summarize(report,samples)", """    result['cold_cache_validation']={k:report.get(k) for k in ('cold_calibration','cache_geometry','cold_before_restore','cold_before_replay','cold_scope','independent_cache_crosscheck')}
    result['full_lower_cache_sweeps']=[{'sample_id':s['sample_id'],'probe':s['residency_probe']} for s in samples]
    result['rootfs_storage_details']=DETAILS.summarize(report,samples)""")
    text=once(text,"                restored=cohort.report.get('root_session',{})", """                restored=cohort.report.get('root_session',{})
                cross=cohort.report.get('independent_cache_crosscheck',{})
                cohort.report['cache_crosscheck_passed']=bool(cross.get('files') and cross.get('agreeing_files')==cross.get('available_files')==cross['files'])
                cohort.report['cache_accuracy_status']='SEQUENTIAL_MINCORE_FINCORE_AGREE' if cohort.report['cache_crosscheck_passed'] else 'REVIEW_MISSING_OR_DIFFERENT_FINCORE_RESULTS'
                result['cold_cache_validation']['cache_accuracy_status']=cohort.report['cache_accuracy_status']""")
    text=once(text,"and restored.get('observer_exit_confirmed'):","and restored.get('observer_exit_confirmed') and cohort.report['cache_crosscheck_passed']:")
    text=once(text,"    lines+=['','共享估计逐轮", """    lines+=['','冷缓存复核：4KiB 是实际 SC_PAGESIZE/mincore 单位；256KiB 是同一位图的分组对照，不宣称内核 folio 大小。',
        '仅对本批核验的 lower inode 做 DONTNEED，清理前后完整位图保留。每文件观测为零不代表全局原子冷态，Guest/daemon用户态缓存未清。',
        '所有实际读取驻留与整 lower 驻留来自同一轮完整 mincore 位图；整机 /proc/meminfo 仅作背景，含其他进程及其他文件，不能要求数值等同。','',
        '|模板ID|阶段|整lower驻留MiB|访问驻留并集MiB|驻留但不在本模板访问并集MiB|256KiB共同格容量上界MiB|',
        '|---|---|---:|---:|---:|---:|']
    for row in rows:
        metrics=row['metrics']
        lines.append('|'+ '|'.join([row['template_id'],row['phase']]+[amount(metrics.get(key)) for key in
            ('whole_lower_host_pagecache_bytes','accessed_resident_union_bytes','lower_resident_outside_pair_observed_access_bytes','coarse_256k_common_cell_capacity_upper_bound_bytes')])+'|')
    lines+=['','256KiB共同格容量是粗粒度上界：两个沙箱可能读同一格中不同的4KiB页。该列不能替代精确共同页量。原始位图及系统计数见JSON。']
    lines+=['','共享估计逐轮""")
    text=text.replace('COW4_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED','COW4_COLD_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED')
    # Baseline receipt is intentionally still the already completed warm experiment.
    text=text.replace("prior['status']=='COW4_COLD_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED'", "prior['status']=='COW4_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED'")
    text=text.replace('COW4_ACCESS_ROOT','COW4_COLD_ROOT').replace("revision='cow4-attributed-v2'","revision='cow4-cold-attributed-v1'")
    footer='''
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status':'STOPPED_COW4_COLD_ENTRY','error_type':type(error).__name__,'reason':str(error)},indent=2))
        print('END_RETURN_REPORT');raise SystemExit(1)
'''
    raw=(preamble+text+footer).encode();compile(raw,'cold-packet','exec')
    (RELAY/'cow4_cold_once.py').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


if __name__=='__main__':print(build())
