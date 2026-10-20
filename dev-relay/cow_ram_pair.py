"""Ordinary A launcher: two bounded live restores, reviewed inline read-only probe, cleanup."""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import socket
import sys
import tempfile
import uuid

ROOT=Path('/home/jwk/agent')
BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
PENDING=ROOT/'relay/cow-ram-node-a.pending.json'
COLLECTOR_SHA='cf2f2f33eb4ad2fa5850ef8c299d27b746b8fe7a9e287b5257e092217ad10862'


def load(path,digest,name):
    if path.resolve(strict=True)!=path:raise RuntimeError('Redirected helper')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=digest:raise RuntimeError('Helper SHA256 mismatch: '+path.name)
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module,raw.decode()


def restore(api,snapshot,run_id):
    api_call_identity=api.identity
    if H.runtime_pid()!=api_call_identity:raise RuntimeError('Original runtime changed')
    c=http.client.HTTPConnection('127.0.0.1',18080,timeout=300)
    try:
        c.request('POST','/sandboxes',body=json.dumps({'templateID':snapshot,'timeout':900,
                  'autoPause':False,'secure':True,'allow_internet_access':False,
                  'metadata':{'cow_ram_run':run_id}}).encode(),
                  headers={'X-API-Key':api.key,'Content-Type':'application/json'})
        r=c.getresponse();raw=r.read(1024**2+1)
        H.need(len(raw)<=1024**2,'Restore response too large')
        body=json.loads(raw) if raw else None
        if r.status!=201:raise RuntimeError('Restore HTTP '+str(r.status)+': '+json.dumps(H.error_summary(body,api.key)))
        sid=body.get('sandboxID') if isinstance(body,dict) else None
        H.need(isinstance(sid,str) and H.ID.fullmatch(sid),'Restore ID missing; preserve uncertain receipt')
        return sid
    finally:c.close()


def empty(api):
    H.need(H.runtime_pid()==api.identity,'Original runtime changed')
    c=http.client.HTTPConnection('127.0.0.1',18080,timeout=10)
    try:
        c.request('GET','/v2/sandboxes?limit=1',headers={'X-API-Key':api.key})
        r=c.getresponse();raw=r.read(65537)
        H.need(r.status==200 and len(raw)<=65536 and json.loads(raw)==[]
               and not r.getheader('x-next-token'),'Original runtime is not empty')
    finally:c.close()


def root_command(source,scope):
    return "/usr/bin/python3 -I -B - <<'COW_SCOPED_READONLY'\n"+source+"\ncollect_scope("+repr(scope)+")\nCOW_SCOPED_READONLY"


def lifecycle(api,R,source,work,report):
    env={'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8',
         'PATH':str(BASE/'native/bin')+':/usr/bin:/bin',
         'LD_LIBRARY_PATH':str(BASE/'native/lib')+':'+str(BASE/'native/fallback/lib'),
         'TMPDIR':str(work/'tmp'),'XDG_CONFIG_HOME':str(work/'config')}
    (work/'tmp').mkdir();(work/'config/aenv').mkdir(parents=True)
    credential=work/'config/aenv/credentials'
    try:
        credential.write_text('url = "http://127.0.0.1:18080"\napi_key = '+json.dumps(api.key)+'\n')
        empty(api)
        H.need(R.find_firecrackers(api.identity[0])==[],'Existing Firecracker descendants; no live experiment')
        for number in (1,2):
            print('PHASE=restore_measurement_child_'+str(number),flush=True)
            report['create_calls']+=1;report['create_outcome_uncertain']=True;H.save(PENDING,report)
            sid=restore(api,report['snapshot_id'],report['run_id'])
            H.need(sid not in report['children'],'Restore returned a duplicate sandbox identity')
            report['children'].append(sid);report['create_outcome_uncertain']=False;H.save(PENDING,report)
            log=work/('warm-'+sid+'.log')
            H.checked_process([BASE/'bin/aenv','exec',sid,'python','-c',
                               "import os;os.chdir('/pypika');import pypika;print('COW_RAM_READY')"],env,log,60)
            H.need(b'COW_RAM_READY' in H.read(log),'Guest warmup not confirmed')
        pids=R.find_firecrackers(api.identity[0])
        H.need(len(pids)==2,'Expected exactly two Firecracker descendants; no broad process scan')
        scope={'run_id':report['run_id'],'main_pid':api.identity[0],'main_start_ticks':api.identity[1],
               'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
               'snapshot_id':report['snapshot_id'],'catalog_sha256':report['catalog_sha256'],
               'memory_bytes':512*1024**2,'sandbox_ids':report['children'],
               'children':[{'pid':pid,'start_ticks':R.identity(pid)[1]} for pid in pids]}
        report['scope']=scope;H.save(PENDING,report)
        command=root_command(source,scope)
        (work/'root-readonly-review.txt').write_text(command)
        print('LIVE_PAIR_READY_COPY_BODY_TO_A_ROOT_TERMINAL',flush=True)
        print('BEGIN_REVIEWED_READONLY_ROOT_COMMAND_COPY_BODY_ONLY',flush=True)
        print(command,flush=True)
        print('END_REVIEWED_READONLY_ROOT_COMMAND_COPY_BODY_ONLY',flush=True)
        print('Keep this jwk terminal open. After the root command exits, return here and type done. '
              'This wait is limited to 600 seconds; timeout cleans known children. Return both reports.',flush=True)
        ready,_,_=select.select([sys.stdin],[],[],600)
        H.need(bool(ready),'Root measurement handoff wait expired')
        H.need(sys.stdin.readline().strip()=='done','Handoff ended without done; clean own children')
        report['operator_confirmed_root_command_exited']=True
    finally:
        for sid in reversed(report['children']):
            try:
                code,body=api.call('GET','/sandboxes/'+sid)
                if code!=404:
                    H.need(code==200 and body.get('metadata',{}).get('cow_ram_run')==report['run_id'],'Ownership differs; no delete')
                    H.need(api.call('DELETE','/sandboxes/'+sid,timeout=90)[0] in (200,204,404),'Delete not acknowledged')
                    H.need(api.call('GET','/sandboxes/'+sid)[0]==404,'Child still visible')
                report['released_children'].append(sid)
            except Exception as e:
                report.setdefault('cleanup_errors',[]).append({'sandbox_id':sid,'type':type(e).__name__})
            try:H.save(PENDING,report)
            except Exception:pass
        if credential.exists():credential.unlink()
        report['temporary_cli_credentials_removed']=not credential.exists()


def main():
    global H
    if not(socket.gethostname()=='server1' and os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205):
        raise RuntimeError('A ordinary jwk only')
    caps=re.findall(r'^Cap(?:Inh|Prm|Eff|Amb):\s*(\w+)$',Path('/proc/self/status').read_text(),re.M)
    if len(caps)!=4 or any(int(v,16) for v in caps):raise RuntimeError('Capability-free launcher required')
    H,_=load(ROOT/'cow_parent_424b012.py','edc6ea585021c585fee41ea09d623f64d4df189dfa54c9af08bdab2765b16e11','parent_v4')
    R,source=load(ROOT/'cow_ram_readonly.py',COLLECTOR_SHA,'scoped_reader')
    os.umask(0o077)
    import fcntl
    with open(H.safe(ROOT/'relay/cow-ram-node-a.lock'),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        H.need(not PENDING.exists(),'RAM experiment receipt exists; preserve it, no repeat')
        prior=json.loads(H.read(H.PENDING))
        H.need(prior.get('status')=='ORIGINAL_PARENT_SNAPSHOT_READY_PARENT_RELEASED' and prior.get('parent_deleted'), 'Parent not ready')
        snapshot=prior.get('snapshot_id');H.need(isinstance(snapshot,str) and H.ID.fullmatch(snapshot),'Invalid snapshot')
        raw=H.read(BASE/'state/snapshot-store/repository/catalog/records'/(snapshot+'.json'))
        record=json.loads(raw)
        H.need(record.get('id')==snapshot and record.get('resources',{}).get('memory_mib')==512
               and record['resources'].get('cpu_count')==1,'Parent resource budget differs')
        work=Path(tempfile.mkdtemp(prefix='node-a-cow-ram-',dir=H.safe(ROOT/'relay/reports')))
        report={'revision':'cow-ram-live-pair-v1','report_directory':str(work),'run_id':uuid.uuid4().hex,
                'snapshot_id':snapshot,'catalog_sha256':hashlib.sha256(raw).hexdigest(),'children':[],
                'released_children':[],'create_calls':0,'create_calls_limit':2,'create_outcome_uncertain':False,
                'SDK_called':False,'services_modified':False,'B_accessed':False,
                'root_measurement_success':'NOT_INFERRED_FROM_DONE_RETURN_ROOT_REPORT'}
        try:
            api=H.Api();H.need(api.call('GET','/health')[0]==204,'Original API unhealthy')
            lifecycle(api,R,source,work,report)
            H.need(len(report['released_children'])==2,'Child cleanup incomplete')
            report['status']='RAM_PAIR_RELEASED_RETURN_ROOT_MEASUREMENT_REPORT'
        except (Exception,KeyboardInterrupt) as e:
            report.update(status='STOPPED_RAM_PAIR_REVIEW_RECEIPT',error_type=type(e).__name__,
                          reason=str(e) if type(e) is RuntimeError else 'See bounded diagnostic output')
            if isinstance(e,H.ChildFailure):report['child_diagnostics']=e.diagnostics
        H.save(work/'return.json',report)
        if report['create_calls']:H.save(PENDING,report)
        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
        return 1 if report['status'].startswith('STOPPED') else 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_RAM_PAIR_ENTRY','error_type':type(e).__name__,
              'reason':str(e) if type(e) is RuntimeError else 'Entry failed'}));print('END_RETURN_REPORT');raise SystemExit(1)
