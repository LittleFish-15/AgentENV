"""Read-only sizing for the same 17 templates, 34 concurrent original Guests.

No SDK, Guest creation, service restart, config write, dependency download,
device mutation or layer-payload read. Returns one combined capacity report.
"""
import hashlib, http.client, json, math, os, re, stat, subprocess, time
from pathlib import Path

ROOT=Path('/home/jwk/agent')
BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
UNIT='jwk-aenv-ae9c626-node-a.service'
INPUT_SHA='9f73ce3b95f9f16482660784ae5dcf4bc7b07a938974a22c57e6e90836722a3a'
CONFIG_SHA='f2a1abe6542c3230bfe3cd81b884cf080dc4a3b2f2c371b40092940c686d01bd'
CANDIDATE_SHA='eed36d01de13f83a8abdc13e93c21883a3a48273da83fa1c813e65e4655babcf'
PATCH_SHA='c553d631d18a01ce5511dec12e50a1a58817c92181d20f1443f17561f87a67ce'


def need(ok, why):
    if not ok:raise RuntimeError(why)


def read(path, limit=2*1024**2):
    need(path.resolve(strict=True)==path,'Redirected input: '+str(path))
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_uid==1204 and s.st_size<=limit,'Unexpected input metadata: '+str(path))
        raw=f.read(limit+1);need(len(raw)<=limit,'Input grew');return raw


def unit():
    r=subprocess.run(['/usr/bin/systemctl','show',UNIT,'--property=LoadState,ActiveState,SubState,MainPID,User,Group,LimitMEMLOCK,LimitMEMLOCKSoft'],
                     capture_output=True,text=True,check=True,timeout=10)
    result=dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
    pid=int(result.get('MainPID','0'))
    result['start_ticks']=(Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19] if pid>1 else None
    return result


def api(path):
    key=read(BASE/'config/api-key',1024).decode().strip();need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',key),'Unexpected credential format')
    c=http.client.HTTPConnection('127.0.0.1',18080,timeout=10)
    try:
        c.request('GET',path,headers={'X-API-Key':key});r=c.getresponse();raw=r.read(65537)
        need(len(raw)<=65536,'API reply too large')
        return r.status,json.loads(raw) if raw else None,bool(r.getheader('x-next-token'))
    finally:c.close()


def selection(inputs, old, four):
    need(old['run_id']=='083604f2f76045c0beb8de4cf92c0758' and old['all_cohort_guests_released'],'Original 17-template history differs')
    need(len(old['jobs'])==34 and all(j['state']=='REPLAY_COMPLETED' for j in old['jobs']),'Original cohort was not fully replayed')
    names=[]
    for j in sorted(old['jobs'],key=lambda j:j['index']):
        if j['instance_id'] not in names:names.append(j['instance_id'])
    need(len(names)==17,'Expected exactly 17 prior templates')
    cases={c['instance_id']:c for c in inputs['cohort']['cases']}
    selected=[cases[n] for n in names]
    prior4={j['instance_id'] for j in four['jobs']};need(len(prior4)==4 and prior4<=set(names),'Successful four-template input differs')
    factor=max(17/4,sum(c['recorded_wait_seconds'] for c in selected)/sum(cases[n]['recorded_wait_seconds'] for n in prior4),
               sum(j['steps_completed'] for j in old['jobs'])/sum(j['steps_completed'] for j in four['jobs']))
    return selected,factor


def trace_projection(status, trace_bytes, factor):
    records=status['records_written'];byte_count=max(status['bytes_written'],trace_bytes)
    need(type(records) is int and records>0 and type(byte_count) is int and byte_count>0,'Previous trace counters missing')
    # This is explicitly a heuristic, not a bound on a different workload.
    multiplier=factor*1.5
    projected_records=math.ceil(records*multiplier);projected_bytes=math.ceil(byte_count*multiplier)
    return {'four_template_records_at_last_sample':records,'four_template_trace_file_bytes_after_run':trace_bytes,
        'workload_scale_factor':factor,'planning_headroom_multiplier':1.5,
        'projected_records':projected_records,'projected_bytes':projected_bytes,
        'candidate_record_limit':1000000,'candidate_byte_limit':268435456,
        'projection_is_a_guarantee':False,
        'projected_within_existing_limits':projected_records<=1000000 and projected_bytes<=268435456,
        'previous_sample_errors':{k:status.get(k) for k in ('errors','dropped_records','unsupported_context_calls')}}


def last_frame(path):
    need(path.resolve(strict=True)==path,'Redirected measurements')
    with path.open('rb') as f:
        s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_uid==1204 and 0<s.st_size<=1024**3,'Unexpected measurement file')
        f.seek(max(0,s.st_size-16*1024**2));raw=f.read(16*1024**2)
    need(raw.endswith(b'\n'),'Measurement tail is incomplete')
    lines=raw.splitlines();need(len(lines)>1 or s.st_size<=len(raw),'Last frame exceeds read budget')
    return json.loads(lines[-1])


def main():
    report={'revision':'cow17-access-preflight-v1','requested_templates':17,'sandboxes_per_template':2,'simultaneous_guests':34,
        'implementation':'original_with_same_calibrated_observer','readonly':True,'Guest_created':False,'services_modified':False,
        'SDK_called':False,'B_accessed':False,'layer_payload_read':False,'candidate_binary_read_for_hash':False,
        'automatic_launch':False,'issues':[]}
    try:
        need(os.name=='posix' and os.uname().nodename=='server1' and os.getuid()==os.geteuid()==1204,'A ordinary jwk only')
        report['machine']=os.uname().machine;need(report['machine']=='aarch64','Expected original ARM64 node')
        before=unit();report['original_service']=before
        need(before.get('ActiveState')=='active' and before.get('User')==before.get('Group')=='jwk','Original service not active as expected')
        report['health']=api('/health')[0];code,rows,paginated=api('/v2/sandboxes?limit=1')
        report['original_inventory_empty']=code==200 and rows==[] and not paginated
        need(report['health']==204 and report['original_inventory_empty'],'Original service not healthy and empty')
        need(hashlib.sha256(read(BASE/'config/runtime.toml',65536)).hexdigest()==CONFIG_SHA,'Original config differs')
        need(before['LimitMEMLOCK']==before['LimitMEMLOCKSoft']=='2147483648','Original unit memlock differs')
        raw=read(ROOT/'cow55_inputs.json',8*1024**2);need(hashlib.sha256(raw).hexdigest()==INPUT_SHA,'Private input differs')
        inputs=json.loads(raw);old=json.loads(read(ROOT/'relay/cow33-batch1-node-a.pending.json'))
        four=json.loads(read(ROOT/'relay/cow4-access-node-a.pending.json'))
        need(four['run_id']=='2606e4f482b44f4fb072792215ac9793' and four['status']=='COW4_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED','Latest four-template success differs')
        need(four['all_cohort_guests_released'] and not four['restore_outcome_uncertain'],'Four-template cleanup uncertain')
        for k in ('original_configuration_restored','original_service_healthy','observer_exit_confirmed','other_services_unchanged'):
            need(four['root_session'].get(k) is True,'Four-template restoration evidence missing: '+k)
        selected,factor=selection(inputs,old,four)
        jobs={j['instance_id']:j for j in old['jobs']};repo=BASE/'state/snapshot-store/repository';unique={};items=[]
        for c in selected:
            j=jobs[c['instance_id']];catalog_raw=read(repo/'catalog/records'/(j['template_id']+'.json'))
            need(hashlib.sha256(catalog_raw).hexdigest()==j['catalog_sha256'],'Prepared catalog changed')
            catalog=json.loads(catalog_raw);need(catalog['resources']['memory_mib']==4096,'Template RAM setting changed')
            need(read(repo/'snapshots'/j['template_id']/'commit',64)==b'committed','Template commit absent')
            lower=[]
            for entry in catalog['committed']['rootfs_layers']:
                need(set(entry)=={'Managed'},'External lower placement unsupported')
                layer=entry['Managed'];need(re.fullmatch(r'sha256:[0-9a-f]{64}',layer['digest']),'Invalid digest')
                path=repo/'managed-layers'/(layer['digest'].replace(':','_')+'.overlaybd.commit')
                need(path.resolve(strict=True)==path,'Redirected layer')
                m=path.stat();need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_size==layer['size'],'Lower metadata differs')
                key=(m.st_dev,m.st_ino);unique[key]=m.st_size;lower.append(m.st_size)
            items.append({'instance_id':c['instance_id'],'language':c['language'],'template_id':j['template_id'],
                'rootfs_lower_layers':len(lower),'rootfs_lower_file_bytes':sum(lower),'recorded_wait_seconds':c['recorded_wait_seconds'],
                'resources':catalog['resources']})
        report['templates']=items;report['unique_lower_files']=len(unique);report['unique_lower_file_bytes']=sum(unique.values())
        need(len(unique)<=256,'Existing observer whitelist capacity exceeded')
        build=json.loads(read(ROOT/'relay/cow4-rootfs-access-build-v2.json'))
        need(build['candidate_sha256']==CANDIDATE_SHA and build['patch_sha256']==PATCH_SHA,'Candidate build receipt changed')
        candidate=Path(build['candidate']);need(candidate.resolve(strict=True)==candidate and candidate.is_file(),'Candidate binary missing')
        report['candidate_available']=True;report['candidate_sha256_from_successful_receipt']=CANDIDATE_SHA
        previous_dir=Path(four['report_directory']);need(previous_dir.parent==ROOT/'relay/reports','Unexpected previous report path')
        frame=last_frame(previous_dir/'measurements/access-cache.jsonl');observer=frame['observer_status']
        need(observer['pid']==four['observer_identity'][0],'Observer identity differs')
        report['trace_budget']=trace_projection(observer,(previous_dir/'observer/trace.jsonl').stat().st_size,factor)
        report['previous_last_cache_sample_id']=frame['sample_id']
        capacity=int(Path('/sys/module/ublk_drv/parameters/ublks_max').read_text());char=Path('/sys/class/ublk-char')
        need(char.is_dir(),'ublk inventory unavailable');names=sorted(p.name for p in char.glob('ublkc*'))
        report['device_budget']={'limit':capacity,'currently_registered':len(names),'current_free':capacity-len(names),
            'business_devices_estimate':51,'reserve_devices':2,'required_free_slots':53,
            'fits_without_reclaiming_any_existing_device':capacity-len(names)>=53,
            'old_original_pool_reclaim_not_assumed':True}
        mem={}
        for line in Path('/proc/meminfo').read_text().splitlines():
            parts=line.split()
            if parts[0].rstrip(':') in ('MemTotal','MemAvailable','SwapTotal','SwapFree'):mem[parts[0].rstrip(':')+'_bytes']=int(parts[1])*1024
        report['host_memory']=mem;report['configured_guest_ram_bytes']=34*4096*1024**2
        report['initial_memavailable_requirement_bytes']=168*1024**3
        fs=os.statvfs(ROOT);report['filesystem']={'readonly':bool(fs.f_flag&os.ST_RDONLY),'available_bytes':fs.f_bavail*fs.f_frsize}
        report['online_cpus']=os.cpu_count()
        if capacity!=64:report['issues'].append('UBLK_LIMIT_CHANGED_REVIEW')
        if capacity-len(names)<53:report['issues'].append('FEWER_THAN_53_FREE_UBLK_SLOTS_NO_RECLAIM_ASSUMED')
        if not report['trace_budget']['projected_within_existing_limits']:report['issues'].append('PROJECTED_TRACE_EXCEEDS_EXISTING_OBSERVER_LIMIT')
        if any(observer.get(k)!=0 for k in ('errors','dropped_records','unsupported_context_calls')):report['issues'].append('PREVIOUS_SAMPLE_OBSERVER_COUNTERS_NOT_CLEAN')
        if mem['MemAvailable_bytes']<168*1024**3:report['issues'].append('MEMORY_HEADROOM')
        if report['filesystem']['readonly'] or report['filesystem']['available_bytes']<512*1024**3:report['issues'].append('FILESYSTEM_RESERVE')
        need(unit()==before,'Original unit changed while observing')
        report['original_process_unchanged']=True
        report['status']='COW17_ACCESS_PREFLIGHT_OBSERVED_NO_CHANGES'
        report['next_action']='Return this report; no new Guest has been launched. Review device and trace sizing before the 17-template run.'
    except Exception as error:
        report.update(status='STOPPED_COW17_ACCESS_PREFLIGHT_NO_CHANGES',error_type=type(error).__name__,reason=str(error))
    print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')


if __name__=='__main__':main()
