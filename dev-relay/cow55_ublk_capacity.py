"""Print reviewed root maintenance code; the downloaded helper runs only as jwk."""
import os

ROOT_SOURCE = r'''
import errno, hashlib, http.client, json, os, re, stat, subprocess, time
from pathlib import Path
UNIT='jwk-aenv-ae9c626-node-a.service'
OTHER='jwk-aenv-ub-b019f27-node-a.service'
BASE=Path('/home/jwk/agent/deployments/agentenv-ae9c626-baseline')
OTHER_BASE=Path('/home/jwk/agent/deployments/agentenv-ub-b019f27')
PENDING=Path('/home/jwk/agent/relay/cow55-replay-node-a.pending.json')
MODULE=Path('/sys/module/ublk_drv')
RECEIPT=Path('/run/cow55-ublk-capacity-maintenance.json')
TARGET=256

def need(ok,why):
    if not ok:raise RuntimeError(why)
def tool(name):
    for directory in ('/usr/sbin','/usr/bin','/sbin','/bin'):
        p=Path(directory)/name
        if p.is_file() and os.access(p,os.X_OK):
            m=p.stat();need(m.st_uid==0 and not m.st_mode&0o022,'Unsafe tool permissions')
            return str(p)
    raise RuntimeError('Required existing tool unavailable: '+name)
def cmd(args,timeout=30):
    v=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    need(v.returncode==0,'Command failed: '+args[0]+' '+args[1]+': '+v.stderr[-2000:])
    return v.stdout
def props(unit):
    text=cmd([SYSTEMCTL,'show',unit,'--no-pager','--property=MainPID,ActiveState,SubState,User,Group,FragmentPath,LimitMEMLOCK,LimitMEMLOCKSoft,BoundBy,ConsistsOf,PropagatesStopTo,RequiredBy'])
    return dict(line.split('=',1) for line in text.splitlines() if '=' in line)
def identity(pid):
    return [int(pid),Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]]
def read_file(p,uid,limit=2*1024**2):
    need(p.resolve(strict=True)==p,'Redirected input: '+str(p))
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        m=os.fstat(f.fileno());need(stat.S_ISREG(m.st_mode) and m.st_uid==uid and m.st_size<=limit,'Unexpected input file')
        data=f.read(limit+1);need(len(data)<=limit,'Input grew');return data
def get(port,key,path):
    c=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
    try:
        c.request('GET',path,headers={'X-API-Key':key});v=c.getresponse();raw=v.read(65537)
        need(len(raw)<=65536 and not v.getheader('x-next-token'),'Incomplete inventory')
        return v.status,json.loads(raw) if raw else None
    finally:c.close()
def empty(port,key):
    need(get(port,key,'/health')[0]==204,'Service not healthy')
    need(get(port,key,'/v2/sandboxes?limit=1')==(200,[]),'Active sandbox inventory; no maintenance')
def no_original_fc(main):
    parents={};names={}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:
            f=(p/'stat').read_text().rsplit(')',1)[1].split()
            parents[int(p.name)]=int(f[1]);names[int(p.name)]=(p/'comm').read_text().strip()
        except (FileNotFoundError,ProcessLookupError):pass
    own={int(main)}
    while True:
        new={p for p,parent in parents.items() if parent in own}-own
        if not new:break
        own.update(new)
    need(not any(names.get(p)=='firecracker' for p in own),'Original Firecracker still present')
def module_state():
    if not MODULE.is_dir():return {'loaded':False}
    return {'loaded':True,'parameters':{p.name:p.read_text().strip() for p in (MODULE/'parameters').iterdir()},
        'refcnt':int((MODULE/'refcnt').read_text()),'holders':sorted(p.name for p in (MODULE/'holders').iterdir()),
        'char_devices':sorted(p.name for p in Path('/sys/class/ublk-char').glob('ublkc*')),
        'block_devices':sorted(p.name for p in Path('/sys/class/block').glob('ublkb*'))}
def require_quiescent(s):
    need(s['loaded'] and s['refcnt']==0 and not s['holders'] and not s['char_devices'] and not s['block_devices'],
         'Devices/references remain after stop; no module unload authorized')
def node_contract():
    p=Path('/dev/ublk-control');need(p.resolve(strict=True)==p,'Redirected control device')
    m=p.stat();need(stat.S_ISCHR(m.st_mode),'Control node is not a character device')
    try:acl=os.getxattr(p,'system.posix_acl_access').hex()
    except OSError as e:
        if e.errno in (errno.ENODATA,errno.ENOTSUP):acl=None
        else:raise
    return {'uid':m.st_uid,'gid':m.st_gid,'mode':stat.S_IMODE(m.st_mode),'acl':acl}
def save():
    tmp=RECEIPT.with_suffix('.tmp')
    with tmp.open('x') as f:json.dump(report,f,indent=2);f.flush();os.fsync(f.fileno())
    os.chmod(tmp,0o644);os.replace(tmp,RECEIPT)
def load_module(parameters):
    for name,value in parameters.items():
        need(re.fullmatch(r'[A-Za-z0-9_]+',name) and re.fullmatch(r'[A-Za-z0-9_.,:+/-]*',value),'Unexpected module parameter')
    for path,digest in module_files.items():
        need(hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest,'Installed module file changed')
    cmd([MODPROBE,'--ignore-install','ublk_drv']+[k+'='+v for k,v in sorted(parameters.items())])
    cmd([UDEVADM,'settle','--timeout=30'],40)
    need(module_state()['parameters']==parameters,'Loaded parameters differ')
def recover_original():
    if not MODULE.is_dir():
        report['fallback_original_module_load_attempted']=True;save()
        load_module(before_module['parameters'])
    need(node_contract()==before_node,'Control-device permissions/ACL differ; no automatic permission change')
    need(read_file(BASE/'config/runtime.toml',1204)==before_config,'Runtime configuration changed')
    state=props(UNIT)
    if state['ActiveState']!='active':cmd([SYSTEMCTL,'start',UNIT],120)
    until=time.monotonic()+60
    while True:
        try:
            if get(18080,key,'/health')[0]==204:break
        except (OSError,http.client.HTTPException):pass
        need(time.monotonic()<until,'Original health recovery timed out');time.sleep(1)
    state=props(UNIT);after=identity(state['MainPID'])
    need(state['ActiveState']=='active' and state['LimitMEMLOCK']==state['LimitMEMLOCKSoft']=='2147483648','Original service limits changed')
    need(re.search(r'Max locked memory\s+2147483648\s+2147483648\s+bytes',Path('/proc/'+str(after[0])+'/limits').read_text()),'Actual memlock differs')
    empty(18080,key);no_original_fc(after[0])
    need(identity(props(OTHER)['MainPID'])==other_identity,'Modified service process changed')
    need(get(18081,other_key,'/health')[0]==204,'Modified service health changed')
    need(read_file(PENDING,1204)==before_pending,'Pending receipt changed')
    report.update(original_after=after,original_service_restored=True,modified_process_unchanged=True,
        original_health=204,modified_health=204,previous_pending_preserved=True)
    save()
def perform_maintenance(stop,inspect,unload,load,verify,recover):
    # Recovery is attempted after every stop attempt, even if a later gate fails.
    failure=None
    try:
        stop();require_quiescent(inspect());unload();load();verify()
    except Exception as e:failure=e
    try:recover()
    except Exception as e:
        raise RuntimeError('Recovery requires review: '+str(e)+'; initial failure: '+str(failure)) from e
    if failure is not None:raise failure

report={'revision':'cow55-ublk-capacity-maintenance-v1','status':'PRECHECK','unit':UNIT,
    'target_ublks_max':TARGET,'SDK_called':False,'B_accessed':False,'Guest_created':False,
    'stop_requests':0,'module_unload_requests':0,'original_service_restored':False,
    'persistent_module_configuration_modified':False,'forced_unload':False}
try:
    need(os.geteuid()==0 and os.uname().nodename=='server1','A/root only');os.umask(0o077)
    need(not RECEIPT.exists() and not RECEIPT.is_symlink() and not RECEIPT.with_suffix('.tmp').exists(),'Previous maintenance receipt exists; do not repeat')
    SYSTEMCTL=tool('systemctl');MODPROBE=tool('modprobe');RMMOD=tool('rmmod');UDEVADM=tool('udevadm')
    original=props(UNIT);other=props(OTHER)
    need(original['ActiveState']=='active' and original['User']==original['Group']=='jwk','Unexpected original unit')
    need(identity(original['MainPID'])==[3394366,'34733063'],'Original runtime identity changed')
    need(identity(3394806)==[3394806,'34733130'],'Original daemon identity changed')
    need(original['LimitMEMLOCK']==original['LimitMEMLOCKSoft']=='2147483648','2GiB memlock not preserved')
    need(all(not original.get(k) for k in ('BoundBy','ConsistsOf','PropagatesStopTo','RequiredBy')),'Unexpected stop propagation/dependents')
    need(other['ActiveState']=='active','Modified unit not active');other_identity=identity(other['MainPID'])
    key=read_file(BASE/'config/api-key',1204,1024).decode().strip()
    other_key=read_file(OTHER_BASE/'config/api-key',1204,1024).decode().strip()
    need(all(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',v) for v in (key,other_key)),'Unexpected key format')
    before_pending=read_file(PENDING,1204);pending=json.loads(before_pending)
    need(pending['run_id']=='e6171de2e0904c78ac69d1c380d05191' and pending['status']=='STOPPED_COW55_REPLAY','Unexpected previous replay')
    for sid in ('01a15d40-05af-7e01-a9fd-81f184602669','01a15d40-05af-7e01-a9fd-820887ddebf3'):
        need(get(18080,key,'/sandboxes/'+sid)[0]==404,'Failed creation still visible')
    before_config=read_file(BASE/'config/runtime.toml',1204,65536)
    empty(18080,key);empty(18081,other_key);no_original_fc(original['MainPID'])
    before_module=module_state();before_node=node_contract()
    need(before_module['loaded'] and before_module['parameters'].get('ublks_max')=='64' and not before_module['holders'],'Unexpected module state')
    # Record the existing kernel-module files; do not execute a module install hook.
    deps=cmd([MODPROBE,'--show-depends','--ignore-install','ublk_drv']);module_files={}
    for line in deps.splitlines():
        words=line.split();need(len(words)>=2 and words[0]=='insmod' and words[1].startswith('/'),'Unexpected module dependency plan')
        p=Path(words[1]);m=p.stat();need(m.st_uid==0 and not m.st_mode&0o022 and m.st_size<64*1024**2,'Unexpected module file')
        module_files[str(p)]=hashlib.sha256(p.read_bytes()).hexdigest()
    need(module_files,'Loadable module file not found')
    # A transient unit may be garbage-collected after stop. Keep its exact
    # root-owned definition under /run so the same service can be started again.
    fragment=Path(original['FragmentPath']);need(fragment.parent in (Path('/run/systemd/transient'),Path('/run/systemd/system')),'Unexpected unit fragment location')
    fragment_bytes=read_file(fragment,0,65536)
    retained=Path('/run/systemd/system')/UNIT
    need(retained.parent.resolve()==retained.parent,'Redirected systemd directory')
    if retained.exists():need(read_file(retained,0,65536)==fragment_bytes,'Different runtime unit definition exists')
    report.update(original_before=identity(original['MainPID']),modified_before=other_identity,
        previous_run_id=pending['run_id'],previous_pending_sha256=hashlib.sha256(before_pending).hexdigest(),
        runtime_config_sha256=hashlib.sha256(before_config).hexdigest(),module_before=before_module,
        module_files_sha256=module_files,control_node_before=before_node,
        retained_unit_path=str(retained),retained_unit_sha256=hashlib.sha256(fragment_bytes).hexdigest())
    save()
    if not retained.exists():
        with retained.open('xb') as f:f.write(fragment_bytes)
        os.chmod(retained,0o644)
        cmd([SYSTEMCTL,'daemon-reload'])
    need(identity(props(UNIT)['MainPID'])==report['original_before'],'Original process changed during preparation')
    need(identity(props(OTHER)['MainPID'])==other_identity,'Modified process changed during preparation')
    empty(18080,key);no_original_fc(original['MainPID'])
    new_parameters=dict(before_module['parameters'],ublks_max=str(TARGET))
    def stop():
        report.update(status='STOPPING_ORIGINAL',stop_requests=1);save();print('PHASE=stop_original_only',flush=True)
        cmd([SYSTEMCTL,'stop',UNIT],120)
        need(props(UNIT)['MainPID']=='0','Original still has MainPID')
    def inspect():
        cmd([UDEVADM,'settle','--timeout=30'],40)
        value=module_state();report['module_after_stop']=value;save();return value
    def unload():
        need(identity(props(OTHER)['MainPID'])==other_identity,'Modified service changed')
        report.update(status='UNLOADING_QUIESCENT_MODULE',module_unload_requests=1);save()
        print('PHASE=normal_module_reload',flush=True);cmd([RMMOD,'ublk_drv'])
        need(not MODULE.exists(),'Module still loaded')
    def verify():
        need(module_state()['parameters']==new_parameters,'New parameters not verified')
        need(node_contract()==before_node,'udev did not preserve control-device permissions/ACL')
    perform_maintenance(stop,inspect,unload,lambda:load_module(new_parameters),verify,recover_original)
    report.update(status='A_ORIGINAL_UBLK_256_MAINTENANCE_VERIFIED',module_after=module_state())
    save()
except Exception as e:
    report.update(status='STOPPED_UBLK_CAPACITY_MAINTENANCE',error_type=type(e).__name__,reason=str(e))
    for name in ('key','other_key'):
        if name in globals():report['reason']=report['reason'].replace(globals()[name],'[REDACTED]')
    if report.get('original_before'):
        try:save()
        except Exception:pass
print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
'''

if __name__=='__main__':
    if os.geteuid()!=1204 or os.uname().nodename!='server1':
        raise SystemExit('Run the helper as A/jwk. Review and paste the printed body in A/root.')
    print('BEGIN_REVIEWED_ROOT_COPY_BODY_ONLY')
    print("/usr/bin/python3 -I -B - <<'COW55_UBLK_CAPACITY'")
    print(ROOT_SOURCE)
    print('COW55_UBLK_CAPACITY')
    print('END_REVIEWED_ROOT_COPY_BODY_ONLY')
