"""Offline lower/upper reporting from existing four-template evidence only.

Reads saved JSON/JSONL, never accesses a service, Guest, layer payload or device.
No historical upper is reconstructed from current filesystem state.
"""
import argparse, json, tempfile
from pathlib import Path


def expand_row(row):
    result=dict(row)
    lower=row.get('lower_file_bytes')
    if type(lower) is int and lower>0:
        for name,source in [('access_resident_coverage_fraction','accessed_resident_union_bytes'),('shared_access_resident_coverage_fraction','shared_accessed_host_pagecache_bytes')]:
            value=row.get(source);result[name]=value/lower if type(value) is int else None
    sids=row['sandbox_ids']
    observations={x['sandbox_id']:x for x in row.get('upper_observations',[])}
    for number,sid in enumerate(sids,1):
        items=observations.get(sid,{}).get('files',[])
        valid=len(items)==2 and all(x.get('available') for x in items)
        unique={}
        if valid:
            for x in items:
                key=(x.get('dev'),x.get('inode'))
                if any(type(v) is not int for v in key):valid=False;break
                if key in unique and any(x.get(f)!=unique[key].get(f) for f in
                    ('logical_file_or_device_bytes','allocated_file_bytes','resident_page_bytes')):
                    valid=False;break
                unique[key]=x
        for name,field in [('file_bytes','logical_file_or_device_bytes'),('allocated_bytes','allocated_file_bytes'),('resident_bytes','resident_page_bytes')]:
            values=[x.get(field) for x in unique.values()]
            result[f'sandbox{number}_upper_{name}']=sum(values) if valid and all(type(v) is int and v>=0 for v in values) else None
        result[f'sandbox{number}_upper_complete']=valid
    return result


def summarize(report,frames):
    inventory=report.get('template_lowers',report.get('rootfs_layer_inventory',{}))
    labels={j['template_id']:j['instance_id'] for j in report['jobs']}
    jobs={t:[j['sandbox_id'] for j in report['jobs'] if j['template_id']==t and j.get('sandbox_id')] for t in inventory}
    groups={}
    for frame in frames:
        for raw in frame.get('templates',[]):
            r=expand_row(raw);key=(r['template_id'],r['phase'])
            group=groups.setdefault(key,{'sample_count':0,'metrics':{},'sandbox_ids':r['sandbox_ids']})
            if group['sandbox_ids']!=r['sandbox_ids']:raise ValueError('Pair changed inside phase')
            group['sample_count']+=1
            for name,v in r.items():
                if type(v) not in (int,float):continue
                metric=group['metrics'].setdefault(name,{'min':v,'max':v,'valid_samples':0})
                metric['min']=min(metric['min'],v);metric['max']=max(metric['max'],v);metric['valid_samples']+=1
    rows=[];unique={}
    for tid,layers in inventory.items():
        objects={}
        for f in layers:
            key=(f['dev'],f['inode']);size=f['file_bytes']
            if key in unique and unique[key]!=size:raise ValueError('Same lower identity has conflicting lengths')
            unique[key]=size;objects[key]=size
        phases=[k[1] for k in groups if k[0]==tid] or ['NO_RUNTIME_CACHE_SAMPLE']
        for phase in phases:
            g=groups.get((tid,phase),{'sample_count':0,'metrics':{},'sandbox_ids':jobs[tid]})
            rows.append(dict(template_id=tid,trajectory=labels.get(tid),phase=phase,
                lower_layer_reference_count=len(layers),unique_lower_file_count=len(objects),
                lower_file_bytes=sum(objects.values()),lower_page_span_bytes=sum((n+4095)//4096*4096 for n in objects.values()),lower_identity_scope='prepared_template_inventory',
                runtime_binding_present=any(b.get('template_id')==tid for b in report.get('bindings',[])),**g))
    return {'revision':'rootfs-existing-evidence-details-v1','run_id':report['run_id'],
        'source_run_status':report.get('status',report.get('validation',{}).get('status')),
        'rows':rows,'global_unique_lower_file_count':len(unique),'global_unique_lower_file_bytes':sum(unique.values()),
        'source_runtime_samples':sum(g['sample_count'] for g in groups.values()),
        'historical_upper_reconstructed_from_current_files':False,'services_accessed':False,'Guest_created':False,
        'file_size_is_host_stored_layer_format_not_guest_virtual_disk_capacity':True}


def markdown(result):
    def amount(v):return 'NA' if v is None else f'{v/1024**2:.3f}'
    def metric(r,key):
        v=r['metrics'].get(key)
        return 'NA' if not v else amount(v['min'])+'–'+amount(v['max'])
    lines=['# rootfs lower与upper明细（已有数据重汇总）','',
        '实验状态：'+str(result['source_run_status'])+'。容量单位MiB。lower是主机提交层文件长度，不是Guest磁盘逻辑容量；upper区分文件长度、实际分配和缓存驻留。',
        '无运行期样本时，lower只报告准备期清单，upper保持NA；不根据沙箱删除后文件存在与否重建历史upper。','',
        '|轨迹|模板ID|阶段|lower层数|lower文件大小|S1 upper文件|S1 upper分配|S1 upper缓存|S2 upper文件|S2 upper分配|S2 upper缓存|样本|',
        '|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in result['rows']:
        keys=[f'sandbox{i}_upper_{f}' for i in (1,2) for f in ('file_bytes','allocated_bytes','resident_bytes')]
        lines.append('|'+ '|'.join([str(r['trajectory']),r['template_id'],r['phase'],str(r['lower_layer_reference_count']),amount(r['lower_file_bytes'])]+[metric(r,k) for k in keys]+[str(r['sample_count'])])+'|')
    lines+=['',f"跨模板去重lower文件数：{result['global_unique_lower_file_count']}；文件长度：{amount(result['global_unique_lower_file_bytes'])} MiB。",
        'S1/S2的完整沙箱ID对应关系，以及upper各指标有效样本数见JSON；缺项不补0，upper data与index按inode去重。', '',
        '|轨迹|阶段|lower文件MiB|lower页跨度MiB|访问驻留并集MiB|共同访问驻留MiB|并集/lower文件|交集/lower文件|',
        '|---|---|---:|---:|---:|---:|---:|---:|']
    for r in result['rows']:
        def percent(key):
            v=r['metrics'].get(key)
            return 'NA' if not v else f"{v['min']*100:.3f}%–{v['max']*100:.3f}%"
        lines.append('|'+ '|'.join([str(r['trajectory']),r['phase'],amount(r['lower_file_bytes']),amount(r['lower_page_span_bytes']),
            metric(r,'accessed_resident_union_bytes'),metric(r,'shared_accessed_host_pagecache_bytes'),
            percent('access_resident_coverage_fraction'),percent('shared_access_resident_coverage_fraction')])+'|')
    lines+=['','并集/lower、交集/lower是实际访问驻留覆盖率，不是整个lower文件的总驻留率。页跨度另列以说明文件末页取整。','']
    return '\n'.join(lines)


def main():
    p=argparse.ArgumentParser();p.add_argument('report_directory',type=Path,nargs='?');a=p.parse_args()
    if a.report_directory is None:
        pending=Path('/home/jwk/agent/relay/cow4-access-node-a.pending.json')
        if pending.stat().st_size>2*1024**2:raise ValueError('Pending receipt too large')
        a.report_directory=Path(json.loads(pending.read_bytes())['report_directory'])
        if a.report_directory.parent!=Path('/home/jwk/agent/relay/reports'):raise ValueError('Unexpected report location')
    directory=a.report_directory.resolve(strict=True)
    owner=directory/'return.json'
    if not owner.is_file():owner=directory/'combined-summary.json'
    if owner.stat().st_size>64*1024**2:raise ValueError('Report too large')
    report=json.loads(owner.read_bytes());sample_file=directory/'measurements/access-cache.jsonl'
    def frames():
        if not sample_file.exists():return
        if sample_file.stat().st_size>1024**3:raise ValueError('Sample file too large')
        with sample_file.open(encoding='utf-8') as f:
            for line in f:
                if len(line)>16*1024**2:raise ValueError('Sample line too large')
                yield json.loads(line)
    result=summarize(report,frames())
    out=Path(tempfile.mkdtemp(prefix='rootfs-details-',dir=directory))
    (out/'rootfs-details.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (out/'rootfs-details.md').write_text(markdown(result),encoding='utf-8')
    print(json.dumps({'status':'EXISTING_EVIDENCE_REPORTED','directory':str(out),'source_run_status':result['source_run_status'],
                      'runtime_sample_rows':result['source_runtime_samples'],'Guest_created':False},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
