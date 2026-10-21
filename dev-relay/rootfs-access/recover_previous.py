"""Literal root recovery for the single failed pre-replay attempt; no Guest creation."""
import base64,hashlib,http.client,json,os,re,stat,subprocess,time
from pathlib import Path
UNIT='jwk-aenv-ae9c626-node-a.service'
ROOT=Path('/home/jwk/agent')
BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
PENDING=ROOT/'relay/cow4-access-node-a.pending.json'
RUN='d64230294a1844b69712a9cf27ac0789'
OLD_SHA='f2a1abe6542c3230bfe3cd81b884cf080dc4a3b2f2c371b40092940c686d01bd'
NEW_SHA='12f60e5d16cce12f0b32e1425a4730a66d9f9b8af49177380a919429b4a0b1ae'
RECEIPT=Path('/run/cow4-access-recovery-d6423029.json')


def need(ok,why):
    if not ok:raise RuntimeError(why)


def read(path,limit=2*1024**2):
    need(path.resolve(strict=True)==path,'Redirected recovery input')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_uid==1204 and s.st_size<=limit,'Unexpected recovery input')
        raw=f.read(limit+1);need(len(raw)<=limit,'Recovery input grew');return raw


def ticks(pid):return (Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19]


def state(unit):
    r=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=MainPID,User,Group,ActiveState'],capture_output=True,text=True,check=True,timeout=10)
    s=dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
    pid=int(s.get('MainPID','0'));s['ticks']=ticks(pid) if pid>1 else None;return s


def others():
    r=subprocess.run(['/usr/bin/systemctl','list-units','--all','--plain','--no-legend','--no-pager','jwk-aenv-*.service'],capture_output=True,text=True,check=True,timeout=10)
    return {line.split()[0]:state(line.split()[0]) for line in r.stdout.splitlines() if line.strip() and line.split()[0]!=UNIT}


def api(path):
    key=read(BASE/'config/api-key',1024).decode().strip();need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',key),'Invalid credential format')
    c=http.client.HTTPConnection('127.0.0.1',18080,timeout=5)
    try:
        c.request('GET',path,headers={'X-API-Key':key});r=c.getresponse();data=r.read(65537)
        need(len(data)<=65536 and not r.getheader('x-next-token'),'API inventory not empty/complete')
        return r.status,json.loads(data) if data else None
    finally:c.close()


def recovery():
    report={'operation':'recover_failed_cow4_before_retry','run_id':RUN,'SDK_called':False,'Guest_created':False,
            'driver_modified':False,'restart_requests':0}
    try:
        need(os.geteuid()==0 and os.uname().nodename=='server1','A/root only')
        pending_raw=read(PENDING);pending=json.loads(pending_raw)
        need(pending['run_id']==RUN and pending['status']=='STOPPED_COW4_ACCESS' and pending['replay_completed_guests']==0,'Wrong failed attempt')
        jobs=pending['jobs'];ids={j['sandbox_id'] for j in jobs}
        need(len(jobs)==len(ids)==8 and all(re.fullmatch(r'[0-9a-f-]{36}',i) for i in ids),'Failed Guest IDs differ')
        need(pending['all_cohort_guests_released'] and not pending['restore_outcome_uncertain'] and set(pending['released_sandboxes'])==ids,'Cleanup receipt incomplete')
        need(all(j['steps_completed']==0 for j in jobs),'This is not the known pre-replay failure')
        plan=pending['root_plan'];need(plan['new_config_sha256']==NEW_SHA and plan['original_config_sha256']==OLD_SHA,'Unexpected config scope')
        try:owner_alive=ticks(plan['owner_pid'])==plan['owner_ticks']
        except (FileNotFoundError,ProcessLookupError):owner_alive=False
        need(not owner_alive,'Prior owner still active')
        need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['boot_id'],'Boot changed')
        original=base64.b64decode(plan['original_config_base64'],validate=True);need(hashlib.sha256(original).hexdigest()==OLD_SHA,'Original bytes differ')
        config=BASE/'config/runtime.toml';current=read(config,65536);sha=hashlib.sha256(current).hexdigest()
        need(sha in (OLD_SHA,NEW_SHA),'Unrecognized current configuration')
        before=state(UNIT);need(before['ActiveState']=='active' and before['User']==before['Group']=='jwk','Original unit not active as expected')
        if sha==NEW_SHA:need((before['MainPID'],before['ticks'])==('3873455','36630090'),'Candidate Runtime identity changed; no blind restart')
        known_candidate=(before['MainPID'],before['ticks'])==('3873455','36630090')
        if sha==OLD_SHA and not known_candidate:
            need(RECEIPT.exists() and RECEIPT.resolve(strict=True)==RECEIPT and RECEIPT.stat().st_uid==0 and not RECEIPT.stat().st_mode&0o022,'Already-restored Runtime needs its trusted recovery receipt')
            saved=json.loads(RECEIPT.read_bytes());need(saved.get('original_after')==[int(before['MainPID']),before['ticks']],'Recovery receipt Runtime differs')
        other_before=others()
        for sid in sorted(ids):need(api('/sandboxes/'+sid)[0]==404,'Previously owned Guest still exists')
        need(api('/v2/sandboxes?limit=1')==(200,[]),'Original inventory not empty')
        need(state(UNIT)==before and others()==other_before,'Service identity changed during recovery checks')
        if sha==NEW_SHA:
            temp=config.with_name('runtime.toml.cow4-recovery-d6423029');meta=plan['original_config_metadata']
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,meta['mode'])
            with os.fdopen(fd,'wb') as f:
                f.write(original);f.flush();os.fsync(f.fileno());os.fchown(f.fileno(),meta['uid'],meta['gid']);os.fchmod(f.fileno(),meta['mode'])
            need(read(config,65536)==current,'Config changed during recovery')
            os.replace(temp,config)
        if sha==NEW_SHA or known_candidate:
            report['restart_requests']=1;subprocess.run(['/usr/bin/systemctl','restart',UNIT],check=True,timeout=90)
        until=time.monotonic()+60;after=None
        while time.monotonic()<until:
            try:
                after=state(UNIT)
                if after['ActiveState']=='active' and api('/health')[0]==204 and api('/v2/sandboxes?limit=1')==(200,[]):break
            except (OSError,RuntimeError,http.client.HTTPException):pass
            time.sleep(1)
        else:raise RuntimeError('Recovered service health not confirmed')
        need(read(config,65536)==original and others()==other_before,'Configuration or other services differ after recovery')
        report.update(status='COW4_ORIGINAL_RECOVERED_READY_FOR_REVIEWED_RETRY',
            original_after=[int(after['MainPID']),after['ticks']],original_config_sha256=OLD_SHA,
            previous_pending_sha256=hashlib.sha256(pending_raw).hexdigest(),prior_eight_guests_http404=True,
            empty_inventory=True,health=204,other_services_unchanged=True,original_pending_modified=False)
        # Publish only verified success, root owned and world-readable, no credentials.
        if RECEIPT.exists():
            need(RECEIPT.resolve(strict=True)==RECEIPT and RECEIPT.stat().st_uid==0 and not RECEIPT.stat().st_mode&0o022,'Untrusted existing recovery receipt')
            saved=json.loads(RECEIPT.read_bytes());need(saved['run_id']==RUN and saved['original_after']==report['original_after'],'Existing different receipt preserved')
        else:
            fd=os.open(RECEIPT,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
            with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o644)
        report['recovery_receipt']=str(RECEIPT)
    except Exception as e:report.update(status='STOPPED_COW4_RECOVERY',error_type=type(e).__name__,reason=str(e))
    print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
