"""Scoped B baseline socket-path repair; no Guest creation or journal reset.

Back up config/installation bytes, change only FC work/log paths and error
logging, normally restart the named baseline unit, and verify old resources.
No SDK, module, OBMM, reboot, DEL_DEV, forced signalling or other-unit changes.
"""
import argparse,hashlib,http.client,json,os,re,stat,subprocess,time,tomllib
from pathlib import Path
ROOT=Path('/home/jwk/agent');BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
WORK=ROOT/'deployments/agentenv-direct-ub-deletefix-v1/comparison/deletefix-full-v1'
OUT=WORK/'original-socket-repair-v1'
UNIT='jwk-aenv-ae9c626-node-b.service'
SID=None
REQUEST=None
RUN_SHA=None
OLD_CONFIG='c6390dc04b7483705aa1cb7c7bd1915c49996a1af11123792ddd56f66351eb50'
BINARIES={'server':'0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff',
 'uvm-ublk-daemon':'13bd2ac381cf877348a39c0b198e2061479ae237c0f54cbcbeae0ab14e700172',
 'aenv':'ac2cf76020ce2ed0cf06f1105e06c34534a35ed8247fca0cb57e2d53269771e1'}
FC_SHA='a64b8f068d47bd6ec85aa755b8f8863e16d0ae14be551376218fed401ee0bdf8'
def need(ok,why):
    if not ok:raise RuntimeError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path,limit=8*1024**2,uid=None):
    need(path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Input path redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_uid in (0,1204) and (uid is None or a.st_uid==uid) and a.st_size<=limit,'Input metadata differs')
        raw=f.read(limit+1);b=os.fstat(f.fileno())
    need((a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'Input changed')
    return raw
def put(path,raw):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def save(name,value):put(OUT/name,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
def properties(unit):
    p=subprocess.run(['systemctl','show',unit,'--no-pager','--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,Job,User,Group'],capture_output=True,text=True,timeout=15,check=True)
    return dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
def identity(pid):
    p=Path('/proc')/str(pid)
    try:return {'pid':pid,'startTicks':(p/'stat').read_text().rsplit(')',1)[1].split()[19],'executable':os.readlink(p/'exe')}
    except FileNotFoundError:return None
def process_scope(group):
    rows=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdecimal():continue
        try:
            if not any(line.endswith(':'+group) or (':'+group+'/') in line for line in (p/'cgroup').read_text().splitlines()):continue
            value=identity(int(p.name))
            if value:rows.append(value)
        except FileNotFoundError:continue
    need(len(rows)<=128,'Unit process scope too large');return rows
def api(method,path):
    need(method=='GET' and path in ('/health','/v2/sandboxes?limit=100','/sandboxes/'+(SID or '')),'Only scoped GET is allowed')
    credential=tomllib.loads(read(BASE/'cli/config/aenv/credentials',uid=1204).decode())
    match=re.fullmatch(r'http://127\.0\.0\.1:(180[0-9]{2})',credential['url']);need(match is not None,'Unexpected baseline endpoint')
    c=http.client.HTTPConnection('127.0.0.1',int(match[1]),timeout=5)
    try:
        c.request(method,path,headers={'X-API-Key':credential['api_key']});r=c.getresponse();raw=r.read(2*1024**2+1)
        need(len(raw)<=2*1024**2 and not r.getheader('X-Next-Token'),'Unbounded/paginated inventory')
        return r.status,json.loads(raw) if raw else None
    finally:c.close()
def configured(raw):
    config=tomllib.loads(raw.decode());old=config['firecracker']
    need(not any(k in old for k in ('work_dir','serial_dir','log_level')),'Original FC overrides already exist; review separately')
    need(config['home_path']==str(BASE/'state'),'Baseline home differs')
    old_socket=str(BASE/'state/firecracker-work/agentenv-fc-XXXXXX/firecracker.socket')
    short=ROOT/'r/ob-fc';logs=ROOT/'r/ob-log'
    new_socket=str(short/'agentenv-fc-XXXXXX/firecracker.socket')
    need(len(old_socket.encode())>=108 and len(new_socket.encode())<=107,'Unexpected socket-path budget')
    text=raw.decode();needle='[firecracker]\n';need(text.count(needle)==1,'Unexpected config section layout')
    new=text.replace(needle,needle+f'work_dir = "{short}"\nserial_dir = "{logs}"\nlog_level = "Error"\n',1).encode()
    parsed=tomllib.loads(new.decode());expected=dict(config);expected['firecracker']={**old,'work_dir':str(short),'serial_dir':str(logs),'log_level':'Error'}
    need(parsed==expected,'Unrelated configuration change')
    return new,short,logs,{'oldSocketPathBytes':len(old_socket.encode()),'newSocketPathBytes':len(new_socket.encode()),'unixPathBudgetBytes':107}
def replace_owned(path,expected,new):
    need(sha(read(path,uid=1204))==expected,'Concurrent file change; do not overwrite')
    m=path.stat();need(m.st_nlink==1 and not m.st_mode&0o022,'Configuration link/permissions differ')
    temp=path.with_name(path.name+'.socket-repair-next')
    fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,stat.S_IMODE(m.st_mode))
    with os.fdopen(fd,'wb') as f:f.write(new);f.flush();os.fchown(f.fileno(),m.st_uid,m.st_gid);os.fsync(f.fileno())
    need(sha(read(path,uid=1204))==expected,'Concurrent change before publication')
    os.replace(temp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def device(number):
    result={}
    for prefix in ('ublkb','ublkc'):
        p=Path('/dev')/(prefix+str(number))
        if p.exists():
            m=p.stat();result[prefix]={'major':os.major(m.st_rdev),'minor':os.minor(m.st_rdev),'inode':m.st_ino}
        else:result[prefix]=None
    result['sysfs']=(Path('/sys/class/ublk-char')/('ublkc'+str(number))).exists()
    return result
def absent_devices():return all(not any(device(i).values()) for i in (0,2))
def restart_and_wait(old):
    print('PHASE=normal-original-unit-restart',flush=True)
    p=subprocess.run(['systemctl','restart','--no-block',UNIT],capture_output=True,text=True,timeout=15)
    need(p.returncode==0,'Normal systemd restart submission failed')
    deadline=time.monotonic()+120;last_progress=0
    while time.monotonic()<deadline:
        now=properties(UNIT);pid=int(now.get('MainPID','0'))
        if time.monotonic()-last_progress>=10:
            print('RESTART_PROGRESS '+json.dumps({k:now.get(k) for k in ('ActiveState','SubState','MainPID','Job')}),flush=True);last_progress=time.monotonic()
        if now.get('ActiveState')=='active' and pid>1 and identity(pid)!=old and not now.get('Job'):
            try:
                if api('GET','/health')[0] in (200,204) and api('GET','/v2/sandboxes?limit=100')==(200,[]):return now
            except (OSError,TimeoutError,http.client.HTTPException):pass
        time.sleep(1)
    raise RuntimeError('Restart/health not confirmed within 120s; preserve state, do not force retry')
def rollback():
    global SID
    plan=json.loads(read(OUT/'plan.json'));props=properties(UNIT)
    SID=plan['sandboxId']
    need(props['LoadState']=='loaded','Original unit definition unavailable; preserve backups for manual restoration')
    need(not any(Path(r['executable']).name=='firecracker' for r in process_scope(props['ControlGroup'])),'A Guest is present; refuse rollback')
    if props['ActiveState']=='active':need(api('GET','/v2/sandboxes?limit=100')==(200,[]),'Baseline is not empty')
    replace_owned(BASE/'config/runtime.toml',plan['newConfigSha256'],read(OUT/'runtime.toml.before'))
    replace_owned(BASE/'installation.json',plan['newInstallationSha256'],read(OUT/'installation.json.before'))
    before=identity(int(props.get('MainPID','0')));after=restart_and_wait(before)
    save('rollback-complete.json',{'status':'ORIGINAL_CONFIG_RESTORED','unit':after,'oldRequestStillPreserved':True})
    print('ORIGINAL_CONFIG_RESTORED; original long socket path is restored too, do not resume measurements with it')
def main():
    global SID,REQUEST,RUN_SHA
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');p.add_argument('--rollback',action='store_true');p.add_argument('--evidence',type=Path);a=p.parse_args()
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='agent1','B root required')
    if a.rollback:return rollback()
    if not a.run:print('PLAN_ONLY: B original short FC path + error logging + normal restart + resource checks');return
    if OUT.exists():
        if (OUT/'complete.json').is_file():print(read(OUT/'complete.json').decode());return
        raise RuntimeError('Previous maintenance state exists; preserve it, no automatic retry')
    need(a.evidence is not None and a.evidence.is_relative_to(WORK) and a.evidence.name=='report.json','Explicit retained inspection report required')
    inspection=json.loads(read(a.evidence));RUN_SHA=inspection['runJournalSha256']
    runraw=read(WORK/'run.json');need(sha(runraw)==RUN_SHA,'Measurement journal changed since inspection')
    run=json.loads(runraw);group=run['groups']['original'];case=group['cases']['0'];context=group['context']
    need(run['runId']==inspection['runId'] and inspection['status']=='ORIGINAL_CREATION_FAILURE_READ_ONLY','Inspection run differs')
    need(case['sandboxIds']==[] and len(case['openRequests'])==1 and not case['operations'],'Failed request identity differs')
    request=case['openRequests'][0];REQUEST=request['id']
    need(re.fullmatch('[0-9a-f]{32}',REQUEST) and request['kind']=='create' and request['route']=='/v2/sandboxes'
         and inspection['cases']['0']['openRequests']==case['openRequests'],'Request differs from returned inspection')
    lines=inspection['logs']['server.log']['windowLines']
    failed={match.group(1) for line in lines if 'failed to start sandbox' in line and 'exited before its API socket appeared' in line and 'exit status: 1' in line
            for match in [re.search(r'sandbox_id=([0-9a-f-]{36})(?:\s|$)',line)] if match}
    need(len(failed)==1,'Exactly one known failed startup required');SID=failed.pop()
    need(any(SID in x and 'exited before its API socket appeared' in x and 'exit status: 1' in x for x in lines),'Known startup failure evidence missing')
    props=properties(UNIT);old=identity(int(props['MainPID']))
    need(props['ActiveState']=='active' and props['User']==props['Group']=='jwk' and old=={'pid':context['pid'],'startTicks':context['startTicks'],'executable':str(BASE/'bin/server')},'Original Runtime changed')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==context['bootId'],'Host rebooted')
    need(api('GET','/v2/sandboxes?limit=100')==(200,[]) and api('GET','/sandboxes/'+SID)[0]==404,'Known failed Guest is still present or inventory uncertain')
    members=process_scope(props['ControlGroup']);need(not any(Path(r['executable']).name=='firecracker' for r in members),'Original unit still has FC; no restart')
    daemons=[r for r in members if r['executable']==str(BASE/'bin/uvm-ublk-daemon')];need(len(daemons)==1,'Expected one original daemon')
    for name,pin in BINARIES.items():need(sha(read(BASE/'bin'/name,128*1024**2,1204))==pin,'Original binary differs: '+name)
    need(sha(read(BASE/'deps/firecracker/1.15.1-patch-v3/firecracker',16*1024**2,1204))==FC_SHA,'Original FC differs')
    config=read(BASE/'config/runtime.toml',uid=1204);need(sha(config)==OLD_CONFIG,'Original config changed')
    installed=read(BASE/'installation.json',uid=1204);install=json.loads(installed)
    need(install['commit']=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc' and install['node']=='node-b' and install['config_sha256']==OLD_CONFIG,'Original installation receipt differs')
    new,short,logs,lengths=configured(config)
    for path in (short,logs):need(not path.exists() and not path.is_symlink() and path.parent.resolve(strict=True)==path.parent,'New short path already exists')
    captured={str(i):device(i) for i in (0,2)};held=set()
    for fd in (Path('/proc')/str(daemons[0]['pid'])/'fd').iterdir():
        try:
            target=os.readlink(fd)
            if re.fullmatch('/dev/ublkc[0-9]+',target):held.add(int(target[len('/dev/ublkc'):]))
        except FileNotFoundError:continue
    need(held=={0,2},'Original daemon device ownership differs; do not stop unknown resources')
    others={u:properties(u) for u in ('jwk-aenv-direct-ub-deletefix-v1-node-b.service','ubse.service','ubsmd.service')}
    install['config_sha256']=sha(new);newinstall=(json.dumps(install,sort_keys=True,indent=2)+'\n').encode()
    OUT.mkdir(mode=0o700);put(OUT/'runtime.toml.before',config);put(OUT/'installation.json.before',installed)
    plan={'oldServer':old,'oldDaemon':daemons[0],'capturedDevices':captured,'preservedUnits':others,'requestId':REQUEST,'sandboxId':SID,
          'newConfigSha256':sha(new),'newInstallationSha256':sha(newinstall),'oldInstallationSha256':sha(installed),**lengths}
    save('plan.json',plan)
    for path in (short,logs):path.mkdir(mode=0o700);os.chown(path,1204,1205)
    replace_owned(BASE/'config/runtime.toml',OLD_CONFIG,new)
    replace_owned(BASE/'installation.json',sha(installed),newinstall)
    save('restart-intent.json',{'unit':UNIT,'startedNs':time.time_ns(),'method':'normal systemd restart','explicitForceKill':False})
    after=restart_and_wait(old)
    need(all(properties(u)==value for u,value in others.items()),'An unrelated watched unit changed')
    need(identity(old['pid'])!=old and identity(daemons[0]['pid'])!=daemons[0],'Old original processes still present')
    need(absent_devices(),'Old devices remain or IDs were reused; preserve state, no DEL_DEV')
    need(api('GET','/sandboxes/'+SID)[0]==404 and api('GET','/v2/sandboxes?limit=100')==(200,[]),'Guest inventory changed')
    need(sha(read(WORK/'run.json'))==RUN_SHA,'Old pending journal changed unexpectedly')
    report={'status':'ORIGINAL_SHORT_SOCKET_READY_FAILED_CREATE_RESOURCES_RECONCILED','node':'b','unit':after,
            'serverIdentity':identity(int(after['MainPID'])),'configSha256':sha(new),'originalBinaryPins':BINARIES,'firecrackerSha256':FC_SHA,
            **lengths,'failedSandboxId':SID,'failedRequestId':REQUEST,'failedGuest404':True,'oldProcessesExited':True,'oldDevicesAbsent':True,
            'oldJournalRewritten':False,'oldRunId':run['runId'],'oldRunJournalSha256':RUN_SHA,
            'oldCreationWasSuccessful':False,'newGuestCreated':False,'comparisonExecuted':False,
            'sharedUBObjectsRetired':False,'watchedOtherUnitsUnchanged':True,'backupDirectory':str(OUT),
            'nextGate':'fresh comparison generation after explicit validation of this receipt; never rerun the old original phase'}
    save('complete.json',report);print('BEGIN_ORIGINAL_SOCKET_REPAIR_REPORT');print(json.dumps(report,indent=2));print('END_ORIGINAL_SOCKET_REPAIR_REPORT')
if __name__=='__main__':
    try:main()
    except Exception as e:
        value={'status':'STOPPED_ORIGINAL_SOCKET_REPAIR_PRESERVE_STATE','errorType':type(e).__name__,'reason':str(e),
               'maintenanceDirectory':str(OUT),'automaticRetry':False,'newGuestCreated':False,'oldJournalRewritten':False}
        if OUT.exists():
            try:save('failure-'+str(time.time_ns())+'.json',value)
            except Exception:pass
        print(json.dumps(value,indent=2));raise SystemExit(1)
