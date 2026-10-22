"""Reduce saved observations to portable time-series JSON/CSV, never interpolate."""
import csv, json
from collections import Counter
from pathlib import Path


def read_jsonl(path):
    if not path.exists():return []
    if path.stat().st_size>1024**3:raise ValueError('Input time series exceeds budget')
    rows=[]
    with path.open(encoding='utf-8') as f:
        for line in f:
            if len(line)>32*1024**2:raise ValueError('Oversized time-series record')
            rows.append(json.loads(line))
    return rows


def subtract(value,baseline):
    return value-baseline if type(value) in (int,float) and type(baseline) in (int,float) else None


def aux_total(row):
    return row.get('observed_resident_bytes') if row.get('complete_for_listed_prefixes') else None


def reduce(host,frames,baselines,labels):
    starts={key:b['monotonic_ns'] for key,b in baselines.items()}
    host_rows=[];file_rows=[];template_rows=[]
    for r in host:
        phase=r['phase'];baseline=baselines.get(phase);row=dict(r)
        row['seconds_since_phase_baseline']=(r['monotonic_ns']-starts[phase])/1e9 if baseline else None
        row['cached_delta_bytes']=subtract(r.get('Cached'),baseline['host'].get('Cached')) if baseline else None
        host_rows.append(row)
    for frame in frames:
        phase=frame.get('experiment_phase');b=baselines.get(phase)
        if b is None:continue
        probe=frame['residency_probe'];a=frame.get('known_other_file_cache',{})
        timestamp=probe['finished_monotonic_ns'];full=probe['whole_lower_resident_bytes']
        host_before=probe['host_memory_before']['Cached'];host_after=probe['host_memory_after']['Cached']
        lower_delta=full-b['lower_resident_bytes'];other_delta=subtract(aux_total(a),aux_total(b.get('known_other_file_cache',{})))
        dh=host_after-b['host']['Cached']
        row={'phase':phase,'sample_id':frame['sample_id'],'monotonic_ns':timestamp,
             'seconds_since_phase_baseline':(timestamp-b['monotonic_ns'])/1e9,
             'scan_started_monotonic_ns':probe['started_monotonic_ns'],
             'scan_finished_monotonic_ns':probe['finished_monotonic_ns'],
             'host_cached_before_bytes':host_before,'host_cached_after_bytes':host_after,
             'host_cached_delta_before_bytes':host_before-b['host']['Cached'],'host_cached_delta_after_bytes':dh,
             'lower_resident_bytes':full,'lower_resident_delta_bytes':lower_delta,
             'accessed_resident_union_bytes':frame['global_accessed_resident_union_bytes'],
             'same_template_shared_resident_union_bytes':frame['global_same_template_shared_accessed_resident_bytes'],
             'known_other_file_resident_bytes':aux_total(a),'known_other_file_delta_bytes':other_delta,
             'unexplained_delta_bytes':dh-lower_delta-other_delta if other_delta is not None else None,
             'known_other_files_complete':a.get('complete_for_listed_prefixes',False),
             'memory_lower_resident_bytes':a.get('category_bytes',{}).get('memory_lower'),
             'rootfs_upper_resident_bytes':a.get('category_bytes',{}).get('rootfs_upper'),
             'experiment_file_resident_bytes':a.get('category_bytes',{}).get('experiment_files')}
        if not 0<=row['same_template_shared_resident_union_bytes']<=row['accessed_resident_union_bytes']<=full:
            raise ValueError('Invalid global cache set inclusion')
        file_rows.append(row)
        row.update(frame.get('baseline_page_accounting',{}))
        for r in frame['templates']:
            template_rows.append({'phase':phase,'pair_phase':r['phase'],'sample_id':frame['sample_id'],
                'template_id':r['template_id'],'trajectory':labels.get(r['template_id']),
                'sandbox_ids':r['sandbox_ids'],'seconds_since_phase_baseline':row['seconds_since_phase_baseline'],
                **{key:r.get(key) for key in ('lower_layer_count','lower_file_bytes','lower_page_span_bytes',
                   'whole_lower_host_pagecache_bytes','sandbox1_accessed_and_resident_bytes','sandbox2_accessed_and_resident_bytes',
                   'shared_accessed_host_pagecache_bytes','accessed_resident_union_bytes','lower_resident_outside_pair_observed_access_bytes',
                   'coarse_256k_common_cell_capacity_upper_bound_bytes','initial_lower_resident_bytes',
                   'initial_lower_pages_still_resident_bytes','initial_lower_pages_no_longer_resident_bytes',
                   'lower_resident_outside_initial_page_set_bytes','common_read_resident_from_initial_page_set_bytes',
                   'common_read_resident_outside_initial_page_set_bytes')}})
    return {'revision':'cow4-global-cache-timeline-v1','host_rows':host_rows,'file_rows':file_rows,
            'template_rows':template_rows,'baselines':baselines,
            'counts':{'host':len(host_rows),'file':len(file_rows),'template':len(template_rows)},
            'times_are_actual_not_resampled':True,'empty_control_subtracted_from_replay':False,
            'unexplained_delta_is_diagnostic_not_exact_accounting_identity':True,
            'cross_node_saving_measured':False}


def build(work,report,result):
    baselines_path=work/'cache-baselines.json'
    baselines=json.loads(baselines_path.read_text()) if baselines_path.exists() else {}
    frames=read_jsonl(work/'measurements/access-cache.jsonl')
    timeline=reduce(read_jsonl(work/'measurements/host-cache.jsonl'),frames,
                    baselines,{j['template_id']:j['instance_id'] for j in report['jobs']})
    timeline.update(run_id=report['run_id'],global_drop_events=report.get('global_cold_checkpoints',[]),
                    operator_declared_quiet_window=report['root_plan'].get('operator_declared_quiet_window'),
                    host_quietness_independently_verified=False)
    timeline['backing_read_size_profile']=read_size_profile(work,report,frames)
    for name,key in [('host-cache-timeseries.csv','host_rows'),('file-cache-timeseries.csv','file_rows'),('template-cache-timeseries.csv','template_rows')]:
        rows=timeline[key]
        with (work/name).open('w',encoding='utf-8',newline='') as f:
            if rows:
                columns=sorted(set().union(*(r.keys() for r in rows)));w=csv.DictWriter(f,fieldnames=columns);w.writeheader();w.writerows(rows)
    (work/'cache-timeseries.json').write_text(json.dumps(timeline,ensure_ascii=False),encoding='utf-8')
    timeline['output_files']=['host-cache-timeseries.csv','file-cache-timeseries.csv','template-cache-timeseries.csv','cache-timeseries.json']
    return timeline


def read_size_profile(work,report,frames):
    """Successful userspace backing reads, not physical block I/O or folios."""
    try:
        count=frames[-1]['observer_status']['records_written']
        if not 0<=count<=1000000:raise ValueError('Record count out of scope')
        source={b['source']:b['sandbox_id'] for b in report['bindings']}
        windows=report['trajectory_windows_monotonic_ns'];histogram=Counter()
        with (work/'observer/trace.jsonl').open(encoding='utf-8') as f:
            json.loads(next(f))
            for i in range(count):
                line=next(f)
                if len(line)>32768:raise ValueError('Oversized read event')
                row=json.loads(line);sid=source.get(row.get('source'));window=windows.get(sid)
                if window and row.get('allowed_lower') is True and row.get('direct_io') is False and window[0]<=row['end_ns']<=window[1]:
                    size=row['bytes']
                    if type(size) is not int or size<=0:raise ValueError('Invalid successful read length')
                    histogram[size]+=1
                    if len(histogram)>4096:raise ValueError('Read-length profile cardinality exceeded')
        return {'available':True,'histogram':[{'request_bytes':k,'read_calls':v} for k,v in sorted(histogram.items())],
                'calls_exactly_256k':histogram[262144],'calls_total':sum(histogram.values()),
                'scope':'successful buffered lower backing-file reads completed inside replay windows',
                'physical_disk_IO_or_folio_size_inferred':False}
    except (KeyError,IndexError,OSError,ValueError,StopIteration) as e:
        return {'available':False,'error_type':type(e).__name__,'reason':str(e)}


def markdown(timeline):
    lines=['','## 整机清理与缓存时间序列','',
      '整机清理两次：8个沙箱空载60秒前、正式回放前；root执行sync后写drop_caches=1。不会清slab或在回放中重复清理。',
      '这是执行清理请求后的实测基线，可能非零，不宣称全零冷起点。Guest/daemon用户态缓存未清，文件扫描非原子。',
      '初始残留页集合B0单列；每轮区分B0中当前驻留、B0中当前不驻留、B0之外当前驻留。净变化=后者−B0中当前不驻留。相同页被回收再载入无法据离散位图判断，B0之外驻留也不自动证明由轨迹造成。',
      '主机每秒采样与文件约15秒扫描均保存实际时间；空载与回放使用各自T0，不把空载均值扣除后伪称精确归因。',
      '文件扫描前后Cached分别保留；未知差额=Cached增量−lower增量−已知其他文件缓存增量，是诊断残差而不是严格物理恒等式。',
      'memory lower、upper、实验文件仅为已列普通文件的缓存，不包含全部主机文件或memory设备缓存；不能与Guest RSS直接相加。','',
      '|阶段|文件样本数|末次主机Cached增量MiB|末次lower驻留MiB|末次已知其他文件缓存MiB|末次未解释差额MiB|',
      '|---|---:|---:|---:|---:|---:|']
    fmt=lambda v:'NA' if v is None else f'{v/1024**2:.3f}'
    for phase in ('idle_control','replay'):
        rows=[r for r in timeline['file_rows'] if r['phase']==phase]
        last=rows[-1] if rows else {}
        lines.append('|'+ '|'.join([phase,str(len(rows))]+[fmt(last.get(k)) for k in
            ('host_cached_delta_after_bytes','lower_resident_bytes','known_other_file_resident_bytes','unexplained_delta_bytes')])+'|')
    lines+=['','实际原始时间序列已嵌入combined-summary.json的cache_timeseries；同目录另有JSON/CSV。',
            '回传combined-summary.json后生成标准绘图库PNG/SVG曲线；目标节点无需安装绘图库。曲线不得用示例数据冒充本轮实测。','']
    return '\n'.join(lines)
