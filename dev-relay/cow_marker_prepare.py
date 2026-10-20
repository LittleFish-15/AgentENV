"""Derive and verify a bounded instrumented snapshot from the retained PyPika parent.

Two sequential restores maximum, one snapshot capture, at most one live Guest.
No root Host action, UB call, download, service change, or physical-CoW claim.
"""
import base64
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import uuid

ROOT=Path('/home/jwk/agent')
BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
PENDING=ROOT/'relay/cow-marker-node-a.pending.json'
GUEST_SHA='34d56e66cfa7065c9240942c6013ac546088ebe51ec2910234c130aad63ad7f8'
H=None


def load_parent():
    path=ROOT/'cow_parent_424b012.py'
    if path.resolve(strict=True)!=path or hashlib.sha256(path.read_bytes()).hexdigest()!='edc6ea585021c585fee41ea09d623f64d4df189dfa54c9af08bdab2765b16e11':
        raise RuntimeError('Known parent helper differs; no execution')
    spec=importlib.util.spec_from_file_location('parent_v4',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def inventory_empty(api):
    H.need(H.runtime_pid()==api.identity,'Original Runtime changed')
    c=http.client.HTTPConnection('127.0.0.1',18080,timeout=10)
    try:
        c.request('GET','/v2/sandboxes?limit=1',headers={'X-API-Key':api.key})
        r=c.getresponse();raw=r.read(65537)
        H.need(r.status==200 and len(raw)<=65536 and json.loads(raw)==[] and not r.getheader('x-next-token'),
               'Original Runtime not empty; no create')
    finally:c.close()


def restore(api,snapshot,run_id,role):
    H.need(H.runtime_pid()==api.identity,'Original Runtime changed')
    c=http.client.HTTPConnection('127.0.0.1',18080,timeout=300)
    try:
        body={'templateID':snapshot,'timeout':900,'autoPause':False,'secure':True,
              'allow_internet_access':False,'metadata':{'cow_marker_run':run_id,'cow_marker_role':role}}
        c.request('POST','/sandboxes',body=json.dumps(body).encode(),
                  headers={'X-API-Key':api.key,'Content-Type':'application/json'})
        r=c.getresponse();raw=r.read(1024**2+1);H.need(len(raw)<=1024**2,'Restore reply too large')
        data=json.loads(raw) if raw else None
        H.need(r.status==201 and isinstance(data,dict),'Restore not confirmed: '+json.dumps(H.error_summary(data,api.key)))
        sid=data.get('sandboxID');H.need(isinstance(sid,str) and H.ID.fullmatch(sid),'Restore identity missing')
        return sid
    finally:c.close()


BOOTSTRAP='''import base64,json,os,subprocess,sys,time
from pathlib import Path
seed=sys.argv[1];base=Path('/pypika')/('.aenv-cow-'+seed)
os.chdir('/pypika');import pypika
base.mkdir(mode=0o700)
script=base/'marker.py'
with script.open('xb') as f:f.write(base64.b64decode(sys.argv[2],validate=True))
with (base/'marker.log').open('xb') as log:
    child=subprocess.Popen([sys.executable,str(script),'serve',seed],stdin=subprocess.DEVNULL,
                           stdout=log,stderr=subprocess.STDOUT,start_new_session=True,close_fds=True,cwd='/pypika')
deadline=time.monotonic()+30
while not (base/'ready.json').exists() and child.poll() is None and time.monotonic()<deadline:time.sleep(0.2)
if not (base/'ready.json').exists():
    print((base/'marker.log').read_text(errors='replace')[-6000:]);raise RuntimeError('Guest marker did not start')
assert json.loads((base/'ready.json').read_text())['seed']==seed
print('COW_MARKER_PROCESS_STARTED')
'''


def expected_hash(seed,label,start,length):
    digest=hashlib.sha256()
    for index in range(start//65536,(start+length)//65536):
        digest.update(hashlib.shake_256((seed+'|'+label+'|'+str(index)).encode()).digest(65536))
    return digest.hexdigest()


def validate_status(response,run_id):
    H.need(response.get('ok') is True and isinstance(response.get('status'),dict),'Guest marker request failed')
    state=response['status']
    H.need(state.get('seed')==run_id and state.get('arena_bytes')==16*1024**2
           and state.get('segment_bytes')==4*1024**2 and state.get('rootfs_file_bytes')==4*1024**2,'Marker identity/budget differs')
    expected=[expected_hash(run_id,'ram-base',i*4*1024**2,4*1024**2) for i in range(4)]
    H.need(state.get('content_verified') is True and state.get('ram_tags')==['ram-base']*4
           and state.get('ram_hashes')==expected and state.get('rootfs_tag')=='rootfs-base'
           and state.get('rootfs_hash')==expected_hash(run_id,'rootfs-base',0,4*1024**2),'Marker content differs')
    mapping=state.get('guest_page_mapping',{})
    H.need(mapping.get('available') is True,'Guest arena page metadata unavailable; no permission changes attempted')
    page=state.get('guest_page_bytes');gpas=mapping.get('guest_physical_addresses')
    H.need(type(page) is int and page>0 and 16*1024**2%page==0,'Invalid Guest page size')
    H.need(isinstance(gpas,list) and len(gpas)==16*1024**2//page and len(set(gpas))==len(gpas)
           and all(type(x) is int and x>0 and x%page==0 for x in gpas),'Guest arena page mapping incomplete or aliased')
    return state


def summarize_status(state):
    row={k:v for k,v in state.items() if k!='guest_page_mapping'}
    mapping=state.get('guest_page_mapping',{});gpas=mapping.get('guest_physical_addresses')
    row['guest_page_mapping']={k:v for k,v in mapping.items() if k!='guest_physical_addresses'}
    row['guest_page_mapping'].update(page_count=len(gpas) if isinstance(gpas,list) else None,
                                     gpa_list_sha256=hashlib.sha256(json.dumps(gpas).encode()).hexdigest() if isinstance(gpas,list) else None,
                                     raw_Guest_addresses_in_return_report=False)
    return row


def lifecycle(api,guest_source,work,report):
    env={'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8',
         'PATH':str(BASE/'native/bin')+':/usr/bin:/bin',
         'LD_LIBRARY_PATH':str(BASE/'native/lib')+':'+str(BASE/'native/fallback/lib'),
         'TMPDIR':str(work/'tmp'),'XDG_CONFIG_HOME':str(work/'config')}
    (work/'tmp').mkdir();(work/'config/aenv').mkdir(parents=True)
    credential=work/'config/aenv/credentials'
    def persist():H.save(PENDING,report)
    def make(snapshot,role):
        report['restore_calls']+=1;report['restore_outcome_uncertain']=True;persist()
        sid=restore(api,snapshot,report['run_id'],role)
        H.need(sid not in report['known_sandboxes'],'Restore returned duplicate identity')
        report['known_sandboxes'].append(sid);report['restore_outcome_uncertain']=False;persist();return sid
    def release(sid):
        if sid in report['cleanup_attempted']:return sid in report['released_sandboxes']
        report['cleanup_attempted'].append(sid)
        try:
            status,detail=api.call('GET','/sandboxes/'+sid)
            if status!=404:
                H.need(status==200 and detail.get('metadata',{}).get('cow_marker_run')==report['run_id'],'Ownership marker differs; no delete')
                H.need(api.call('DELETE','/sandboxes/'+sid,timeout=90)[0] in (200,204,404),'Delete not acknowledged')
                H.need(api.call('GET','/sandboxes/'+sid)[0]==404,'Sandbox remains visible')
            report['released_sandboxes'].append(sid);return True
        except Exception as e:
            report.setdefault('cleanup_errors',[]).append({'sandbox_id':sid,'type':type(e).__name__,
                  'reason':str(e) if type(e) is RuntimeError else 'Cleanup uncertain'})
            return False
    def status(sid,label):
        log=work/(label+'.log');script='/pypika/.aenv-cow-'+report['run_id']+'/marker.py'
        H.checked_process([BASE/'bin/aenv','exec',sid,'python',script,'request',report['run_id'],'status'],env,log,60)
        text=H.read(log).decode();H.need(text.count('BEGIN_COW_MARKER_STATUS')==1 and text.count('END_COW_MARKER_STATUS')==1,'Marker response framing differs')
        response=json.loads(text.split('BEGIN_COW_MARKER_STATUS')[1].split('END_COW_MARKER_STATUS')[0])
        H.save(work/(label+'.json'),response)
        if isinstance(response.get('status'),dict):report[label]=summarize_status(response['status'])
        result=validate_status(response,report['run_id'])
        report[label]=summarize_status(result);persist();return result
    try:
        credential.write_text('url = "http://127.0.0.1:18080"\napi_key = '+json.dumps(api.key)+'\n')
        inventory_empty(api)
        H.need(not PENDING.exists(),'Marker pending appeared concurrently')
        print('PHASE=restore_original_parent_for_instrumentation',flush=True)
        parent=make(report['source_snapshot_id'],'instrument-parent')
        print('PHASE=start_bounded_Guest_RAM_and_rootfs_marker',flush=True)
        log=work/'marker-start.log'
        H.checked_process([BASE/'bin/aenv','exec',parent,'python','-c',BOOTSTRAP,
                           report['run_id'],base64.b64encode(guest_source).decode()],env,log,60)
        H.need(b'COW_MARKER_PROCESS_STARTED' in H.read(log),'Marker start not confirmed')
        initial=status(parent,'parent_marker_status')
        print('PHASE=capture_instrumented_snapshot_once',flush=True)
        report['snapshot_capture_calls']=1;report['snapshot_outcome_uncertain']=True;persist()
        code,body=api.call('POST','/sandboxes/'+parent+'/snapshots',{'name':'jwk-cow-marker-'+report['run_id']},timeout=300)
        report['snapshot_http_status']=code
        if code not in (200,201):report['snapshot_error']=H.error_summary(body,api.key)
        H.need(code in (200,201) and isinstance(body,dict),'Instrumented snapshot capture not confirmed')
        snapshot=body.get('snapshotID');H.need(isinstance(snapshot,str) and H.ID.fullmatch(snapshot),'Snapshot identity missing')
        report['measurement_snapshot_id']=snapshot;report['snapshot_outcome_uncertain']=False;persist()
        H.need(release(parent),'Instrument parent not released; no verifier created')
        persist()
        print('PHASE=restore_and_verify_live_marker_inheritance',flush=True)
        verifier=make(snapshot,'restore-verifier')
        restored=status(verifier,'restored_marker_status')
        H.need(restored['server_pid']==initial['server_pid'] and restored['arena_guest_virtual_address']==initial['arena_guest_virtual_address'],
               'Live marker identity/address differs after restore')
        report['guest_gpa_layout_equal']=restored['guest_page_mapping']['guest_physical_addresses']==initial['guest_page_mapping']['guest_physical_addresses']
        report['marker_survived_snapshot_restore']=True
    finally:
        for sid in reversed(report['known_sandboxes']):release(sid)
        if credential.exists():credential.unlink()
        report['temporary_cli_credentials_removed']=not credential.exists()


def main():
    global H
    if not(socket.gethostname()=='server1' and os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205):
        raise RuntimeError('A ordinary jwk only')
    caps=re.findall(r'^Cap(?:Inh|Prm|Eff|Amb):\s*(\w+)$',Path('/proc/self/status').read_text(),re.M)
    if len(caps)!=4 or any(int(x,16) for x in caps):raise RuntimeError('Capability-free launcher required')
    H=load_parent();os.umask(0o077)
    guest_source=H.read(ROOT/'cow_marker_guest.py')
    H.need(hashlib.sha256(guest_source).hexdigest()==GUEST_SHA,'Guest marker source hash differs')
    import fcntl
    with open(H.safe(ROOT/'relay/cow-marker-node-a.lock'),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        H.need(not PENDING.exists(),'Marker receipt exists; preserve it, do not repeat')
        parent=json.loads(H.read(H.PENDING))
        H.need(parent.get('status')=='ORIGINAL_PARENT_SNAPSHOT_READY_PARENT_RELEASED' and parent.get('parent_deleted') is True,'Original parent not ready')
        snapshot=parent.get('snapshot_id');H.need(isinstance(snapshot,str) and H.ID.fullmatch(snapshot),'Source snapshot identity missing')
        catalog=H.read(BASE/'state/snapshot-store/repository/catalog/records'/(snapshot+'.json'))
        record=json.loads(catalog)
        H.need(record.get('id')==snapshot and record.get('resources',{}).get('cpu_count')==1
               and record['resources'].get('memory_mib')==512,'Source snapshot resource budget differs')
        work=Path(tempfile.mkdtemp(prefix='node-a-cow-marker-',dir=H.safe(ROOT/'relay/reports')))
        report={'revision':'cow-marker-prepare-v1','report_directory':str(work),'run_id':uuid.uuid4().hex,
                'source_snapshot_catalog_sha256':hashlib.sha256(catalog).hexdigest(),
                'source_snapshot_id':snapshot,'measurement_snapshot_id':None,'known_sandboxes':[],
                'cleanup_attempted':[],'released_sandboxes':[],'restore_calls':0,'restore_calls_limit':2,
                'restore_outcome_uncertain':False,'snapshot_capture_calls':0,'snapshot_capture_calls_limit':1,
                'snapshot_outcome_uncertain':False,'max_simultaneous_sandboxes':1,'Guest_memory_mib':512,
                'marker_RAM_bytes':16*1024**2,'marker_rootfs_file_bytes':4*1024**2,
                'measurement_scenario':'Derived PyPika snapshot with prewarmed live RAM/rootfs markers; not the original uninstrumented baseline or full replay',
                'marker_survived_snapshot_restore':False,'source_snapshot_modified_or_deleted':False,
                'physical_CoW_write_measurement_executed':False,'SDK_called':False,'services_modified':False,'B_accessed':False}
        try:
            fs=os.statvfs(ROOT);H.need(fs.f_bavail*fs.f_frsize>=2*1024**3,'Need 2GiB available workspace space; no cleanup attempted')
            installed=json.loads(H.read(BASE/'installation.json'))
            H.need(installed.get('node')=='node-a' and installed.get('commit')=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc',
                   'Original installation identity differs')
            report['source_commit']=installed['commit']
            api=H.Api();H.need(api.call('GET','/health')[0]==204,'Original API not healthy')
            report['runtime_identity']=list(api.identity)
            lifecycle(api,guest_source,work,report)
            H.need(report['marker_survived_snapshot_restore'] and len(report['released_sandboxes'])==2,'Marker validation or cleanup incomplete')
            report['status']='INSTRUMENTED_SNAPSHOT_READY_MARKER_RESTORE_VERIFIED_GUESTS_RELEASED'
        except (Exception,KeyboardInterrupt) as e:
            report.update(status='STOPPED_MARKER_PREPARATION_REVIEW_RECEIPT',error_type=type(e).__name__,
                          reason=str(e) if type(e) is RuntimeError else 'Inspect bounded diagnostics; no retry')
            if isinstance(e,H.ChildFailure):report['child_diagnostics']=e.diagnostics
        H.save(work/'return.json',report)
        if report['restore_calls']:H.save(PENDING,report)
        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
        return 1 if report['status'].startswith('STOPPED') else 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_MARKER_ENTRY','error_type':type(e).__name__,
              'reason':str(e) if type(e) is RuntimeError else 'Entry failure'}));print('END_RETURN_REPORT');raise SystemExit(1)
