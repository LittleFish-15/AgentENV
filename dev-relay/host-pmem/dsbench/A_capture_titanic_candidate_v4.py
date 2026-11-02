"""Prepare an isolated repaired-version Runtime and capture Titanic via its API.

Requires specific approval for the new scoped service, temporary builder VMs,
private network namespace and ACLs on new kernel-owned jwk ublk devices.
Does not touch retained DAX services, OBMM or UB objects. No native compilation.
"""
import struct,zlib
import base64,hashlib,json,os,re,secrets,socket,stat,subprocess,sys,threading,time,tomllib,traceback
from pathlib import Path
ROOT=Path('/home/jwk/root/titanic-candidate-capture-20261102')
ACTIVE=Path('/home/jwk/agent/dsbench-20261102/candidate-a')
INPUT=Path('/home/jwk/agent/dsbench-20261031/native-conversion-titanic-v1/converted-rootfs.json')
BASE=None
BINARIES={}
PLAN=Path('/home/jwk/agent/r/hpab-a-v1/service-input-plan.json')
PLAN_SHA='677bfd7a9324831c5819c6f780be06ae702cd222e60aa1c4e2b00db9d889ab23'
UNIT='aenv-titanic-candidate-a-20261102.service'
IMAGE='swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-modeling-titanic'
DIGEST='sha256:d287f235d83c213a5bedd22f7e2ff95b5d1e7c5fe7a570da82a53409447e1c1d'
CONVERSION_RECORD_SHA='0bf25719adc450e5011539eb15687ccee033be3729d6276bd525ade8408762c4'
PINS={'bin/server':'759423e634e25bc2e74067bfaccc16e40720907fc0e717269261dd573f0097df',
 'bin/aenv':'b07e0ad826a6080a4481cb42278023732f21d090edf813f5bedd4438a486e1f2',
 'bin/uvm-ublk-daemon':'5291c267777cd91c4b853c6d40720e8d87200b2a0162024782534c4126cba726',
 'deps/firecracker/1.15.1-patch-v3/firecracker':'e9588526096f45380b8debf2d41bf33a2fb26f8abea0a9bed841627327782a0b'}
OWNER=Path('/home/jwk/root/t1-locality-v1/public/ublk_owner')
OWNER_SHA='1ca1717821569dfc4e36f12e01e7359da0de76919742e6cf3978ef7ab0df9e7c'
OCI_METADATA_WIRE_SHA='265247ad696e59412a3b947f593587998a696a0899b4b81ad65720d545c89dc4'
PREVIOUS_REPORT_SHA='f77f36c47ad3c23de1911c1ffd3aa4d47fedcc1a0544d2b98ab9d580af24df39'
METADATA=None
STATE={};KEY='';STOP=threading.Event();ERRORS=[];CHECKPOINT_LOCK=threading.RLock()

def need(ok,why):
    if not ok:raise RuntimeError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(p,limit=8*1024**2):
    need(p.resolve()==p and p.is_file() and p.stat().st_size<=limit,'Bounded file identity differs')
    with p.open('rb') as f:raw=f.read(limit+1)
    need(len(raw)<=limit,'Input exceeded limit');return raw
def file_sha(p):
    need(p.resolve()==p and p.is_file(),'Payload path redirected')
    h=hashlib.sha256()
    with p.open('rb') as f:
        before=os.fstat(f.fileno())
        for block in iter(lambda:f.read(1024**2),b''):h.update(block)
        after=os.fstat(f.fileno())
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'Payload changed')
    return h.hexdigest()
def wire(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def mkdir(p,uid=1204,mode=0o700):
    need(p.is_relative_to(ROOT) or p.is_relative_to(ACTIVE.parent),'Directory outside experiment')
    if not p.parent.exists():mkdir(p.parent,uid,0o711 if uid==0 else 0o700)
    if not p.exists():
        p.mkdir(mode=mode);os.chown(p,uid,1205 if uid==1204 else 0);os.chmod(p,mode)
    st=p.stat();need(p.resolve()==p and st.st_uid==uid and stat.S_ISDIR(st.st_mode) and not st.st_mode&0o022,'Directory owner/path differs')
def put(p,raw,uid=1204,mode=0o600):
    mkdir(p.parent,uid,0o755 if p.parent==ROOT/'public' else 0o700)
    need(p.resolve()==p,'Output redirected')
    if p.exists():need(p.read_bytes()==raw,'Existing artifact differs; preserve');return
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:f.write(raw);os.fchown(f.fileno(),uid,1205 if uid==1204 else 0);os.fchmod(f.fileno(),mode);f.flush();os.fsync(f.fileno())
def checkpoint():
    with CHECKPOINT_LOCK:
        p=ROOT/'state.json';temp=ROOT/'state.next'
        with temp.open('wb') as f:f.write(wire(STATE));f.flush();os.fsync(f.fileno())
        os.replace(temp,p)
def command(argv,timeout=30,env=None,input=None):
    p=subprocess.run(list(map(str,argv)),input=input,capture_output=True,timeout=timeout,env=env)
    if p.returncode!=0:
        detail=p.stderr[-2000:].decode(errors='replace')
        if KEY:detail=detail.replace(KEY,'[redacted]')
        if ROOT.exists():
            STATE.setdefault('commandFailures',[]).append({'command':Path(str(argv[0])).name,'exitCode':p.returncode,'stderr':detail});checkpoint()
        raise RuntimeError('Command failed: '+Path(str(argv[0])).name+' exit '+str(p.returncode))
    return p.stdout
def props():
    text=command(['systemctl','show',UNIT,'--property=MainPID,ActiveState,LoadState,ControlGroup']).decode()
    return dict(x.split('=',1) for x in text.splitlines() if '=' in x)
def ticks(pid):return Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]
def toml(config):
    lines=[]
    def emit(row,keys):
        if keys:lines.append('['+'.'.join(keys)+']')
        for k,v in row.items():
            need(re.fullmatch('[A-Za-z0-9_-]+',k),'Invalid TOML key')
            if not isinstance(v,dict):lines.append(k+' = '+json.dumps(v))
        lines.append('')
        for k,v in row.items():
            if isinstance(v,dict):emit(v,keys+[k])
    emit(config,[]);raw=('\n'.join(lines)+'\n').encode();need(tomllib.loads(raw.decode())==config,'TOML roundtrip differs');return raw

HTTP_HELPER='''import http.client,json,sys
x=json.load(sys.stdin)
assert x['method'] in ('GET','POST')
c=http.client.HTTPConnection('127.0.0.1',18231,timeout=30)
try:
 c.request(x['method'],x['route'],None if x['body'] is None else json.dumps(x['body']),{'X-API-Key':x['key'],'Content-Type':'application/json'})
 r=c.getresponse();raw=r.read(2*1024**2+1);assert len(raw)<=2*1024**2
 print(json.dumps({'status':r.status,'body':json.loads(raw) if raw else None}))
finally:c.close()
'''

def api(method,route,body=None):
    pid=STATE['runtime']['pid'];need(ticks(pid)==STATE['runtime']['ticks'],'Runtime identity changed')
    allowed=route in ('/health','/v2/sandboxes?limit=100','/v2/templates','/v3/templates') or bool(re.fullmatch(r'/templates/[0-9a-f-]+/builds/[0-9a-f-]+/status',route)) or bool(re.fullmatch(r'/v2/templates/[0-9a-f-]+/builds/[0-9a-f-]+',route))
    need(allowed and (method=='GET' or method=='POST' and (route=='/v3/templates' or route.startswith('/v2/templates/'))),'API out of scope')
    mutation=method=='POST';row={'method':method,'route':route,'bodySha256':sha(wire(body)),'startedNs':time.time_ns()}
    if mutation:need(not STATE.get('pending'),'Unresolved mutation; no retry');STATE['pending']=row;checkpoint()
    result=json.loads(command(['nsenter','-t',pid,'-n','--','/usr/bin/python3','-I','-B',ROOT/'public/http.py'],45,
        input=wire({'method':method,'route':route,'body':body,'key':KEY})))
    if mutation:
        row.update(response=result,finishedNs=time.time_ns());STATE.setdefault('operations',[]).append(row);checkpoint()
        need(result['status'] in (200,201,202,204),'Mutation returned non-success; preserve request')
        if route=='/v3/templates':
            body=result.get('body');need(isinstance(body,dict) and body.get('templateID')==body.get('buildID')
                and re.fullmatch('[0-9a-f-]{36}',body.get('templateID','')),'Template creation acknowledgment malformed; preserve pending')
        STATE['pending']=None;checkpoint()
    return result

def watcher(before,background):
    try:
        while not STOP.wait(.15):
            pid=STATE.get('runtime',{}).get('pid')
            if not pid:continue
            need(ticks(pid)==STATE['runtime']['ticks'],'Runtime changed during ACL monitoring')
            cg=Path('/proc',str(pid),'cgroup').read_text()
            for proc in Path('/proc').iterdir():
                if not proc.name.isdigit():continue
                try:
                    if 'uvm-ublk' not in (proc/'comm').read_text():continue
                    uid=re.search(r'(?m)^Uid:\s+(\d+)',(proc/'status').read_text())
                    if not uid or int(uid[1])!=1204:continue
                    if int(proc.name) in background:
                        need(ticks(int(proc.name))==background[int(proc.name)],'Background daemon changed');continue
                    need((proc/'cgroup').read_text()==cg,'Unrelated new jwk daemon; no new ACL')
                except (FileNotFoundError,ProcessLookupError):continue
            for p in Path('/dev').glob('ublk[bc]*'):
                st=p.lstat();key=(st.st_ino,st.st_rdev)
                if before.get(p.name)==key or any(x['path']==str(p) and x['identity']==list(key) for x in STATE['grants']):continue
                fd=os.open(p,os.O_PATH|os.O_NOFOLLOW)
                try:
                    same=os.fstat(fd);need((same.st_ino,same.st_rdev)==key,'Device reused')
                    check=subprocess.run([str(OWNER),p.name],capture_output=True,timeout=3)
                    if check.returncode!=0:continue
                    need(check.stdout.strip()==b'1204:1205','Kernel device owner differs')
                    target=f'/proc/{os.getpid()}/fd/{fd}'
                    row={'path':str(p),'identity':list(key),'priorAcl':command(['getfacl','-cpn',target]).decode(),'state':'intent'}
                    STATE['grants'].append(row);checkpoint();command(['setfacl','-m','u:1204:rw',target]);row['state']='granted';checkpoint()
                finally:os.close(fd)
    except BaseException as e:ERRORS.append(type(e).__name__+': '+str(e));STOP.set()


def decode_metadata(arguments):
    need(arguments and len(arguments)<=15 and all(len(s)<=480 for s in arguments),'Metadata argument bounds differ')
    compressed=base64.b64decode(''.join(arguments),validate=True)
    d=zlib.decompressobj();raw=d.decompress(compressed,65537)
    need(d.eof and not d.unused_data and not d.unconsumed_tail and 4<len(raw)<=65536,'Metadata expansion invalid')
    need(sha(raw)==OCI_METADATA_WIRE_SHA,'Private metadata package differs')
    length=struct.unpack('>I',raw[:4])[0];need(0<length<len(raw)-4,'Metadata framing invalid')
    manifest=raw[4:4+length];config=raw[4+length:]
    need('sha256:'+sha(manifest)==DIGEST,'Manifest digest differs')
    descriptor=json.loads(manifest)['config']
    need('sha256:'+sha(config)==descriptor['digest'] and len(config)==descriptor['size'],'OCI config digest/size differs')
    value=json.loads(config);need(value['architecture']=='arm64' and value['os']=='linux','OCI platform differs')
    return manifest,config

def resume_metadata_timeout():
    previous=Path('/home/jwk/root/relay/jobs/titanic-candidate-capture-20261102-005-node-a/report.json')
    report=json.loads(read(previous));need(sha(wire(report))==PREVIOUS_REPORT_SHA,'Previous root receipt differs')
    need(report['state']=='completed' and report['exitCode']==1,'Previous job not a completed failure')
    raw=read(ROOT/'state.json');state=json.loads(raw)
    need(state['phase']=='prepared_intent' and state['unit']==UNIT and state.get('pending') is None
         and state.get('operations')==[] and state.get('grants')==[] and 'runtime' not in state and 'templateId' not in state,
         'Previous run attempted a service or API operation; preserve')
    failure=state.get('failure',{})
    need(failure.get('type')=='TimeoutExpired' and DIGEST in failure.get('reason','')
         and "'manifest', 'get'" in failure['reason'] and 'timed out after 90 seconds' in failure['reason'],
         'Different failure; no metadata resume')
    need(state['identity']['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Previous preparation boot changed')
    need(props().get('LoadState')=='not-found' and not (ACTIVE/'deps').exists(),'Service/dependency staging already attempted')
    for path,uid in ((ROOT,0),(ROOT/'public',0),(ACTIVE,1204)):
        info=path.stat();need(path.resolve()==path and info.st_uid==uid and not info.st_mode&0o022,'Prepared directory differs')
    put(ROOT/'metadata-timeout005-state.json',raw,0,0o600)
    return {'previousReportSha256':PREVIOUS_REPORT_SHA,'previousStateSha256':sha(raw),
        'reason':'fixed metadata transferred by private relay; no target registry retry',
        'metadataWireSha256':OCI_METADATA_WIRE_SHA}



def validate_dependency_failure(state):
    need(state['phase']=='runtime_active' and state['unit']==UNIT and state.get('pending') is None
         and state.get('operations')==[] and state.get('grants')==[] and 'templateId' not in state,
         'Template/API/device mutation may have occurred; no startup retry')
    need(state.get('failure')=={'type':'RuntimeError','reason':'Runtime health deadline'},'Not the recorded dependency startup failure')

def private_overlay_config():
    return {'logConfig':{'logLevel':1,'logPath':str(ACTIVE/'logs/overlaybd.log')},
        'cacheConfig':{'cacheType':'file','cacheDir':str(ACTIVE/'state/overlaybd-cache'),'cacheSizeGB':1,'refillSize':262144,'blockSize':65536},
        'credentialFilePath':'','credentialConfig':{},'ioEngine':0,'p2pConfig':{'enable':False},'enableAudit':False,'registryFsVersion':'v2'}

PREVIOUS_DEPENDENCY_REPORT_SHA='dcd336aa49c2a6019784ffe5d483f7eced5926759de4276376024e5d3580c1d3'
PREPARED_RUNTIME_PID=None

def prepare():
    global KEY,BASE,BINARIES,PREPARED_RUNTIME_PID
    previous=Path('/home/jwk/root/relay/jobs/titanic-candidate-capture-20261102-006-node-a/report.json')
    previous_report=json.loads(read(previous))
    need(sha(wire(previous_report))==PREVIOUS_DEPENDENCY_REPORT_SHA,'Previous 006 root receipt differs')
    before=read(ROOT/'state.json');state=json.loads(before)
    validate_dependency_failure(state)
    need(state['identity']['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Capture boot changed')
    unit_before=props()
    need(unit_before.get('MainPID')=='0' and unit_before.get('ActiveState')=='failed' and unit_before.get('LoadState')=='loaded',
         'Only the confirmed failed capture service may be restarted')
    cg=unit_before.get('ControlGroup','')
    if cg:
        candidates=[Path('/sys/fs/cgroup')/cg.lstrip('/')/'cgroup.procs',Path('/sys/fs/cgroup/systemd')/cg.lstrip('/')/'tasks']
        found=[p for p in candidates if p.exists()]
        need(found and all(not p.read_text().strip() for p in found),'Failed unit still has processes or cgroup cannot be checked')
    plan_raw=read(PLAN);need(sha(plan_raw)==PLAN_SHA,'Retained candidate plan changed')
    plan=json.loads(plan_raw);BASE=Path(plan['sourceDeployment']);BINARIES=plan['binaries']
    for name,pin in PINS.items():need(file_sha(Path(BINARIES[name]['path']))==pin,'Reused candidate binary differs: '+name)
    need(file_sha(OWNER)==OWNER_SHA,'Kernel owner query differs')
    cfg=tomllib.loads(read(ROOT/'public/runtime.toml').decode())
    need(cfg['home_path']==str(ACTIVE/'state') and cfg['runtime_path']==str(ACTIVE/'run')
         and cfg['deps_path']==str(ACTIVE/'deps') and 'ub_rootfs_index' not in cfg['snapshot'], 'Private capture config differs')
    env=json.loads(read(ACTIVE/'private/runtime-env.json'))
    KEY=env['AENV_API_KEY'];need(env['API_ADDR']=='127.0.0.1:18231' and env['AENV_CONFIG_PATH']==str(ROOT/'public/runtime.toml'),'Prepared runtime environment differs')
    wrapper='import json,os\ne=json.load(open('+repr(str(ACTIVE/'private/runtime-env.json'))+'))\nos.execve('+repr(str(BINARIES['bin/server']['path']))+','+repr([str(BINARIES['bin/server']['path']),'--config',str(ROOT/'public/runtime.toml')])+',e)\n'
    need(read(ROOT/'public/exec.py')==wrapper.encode() and read(ROOT/'public/http.py')==HTTP_HELPER.encode(),'Prepared launch/API helper differs')
    for path in (ROOT,ROOT/'public',ROOT/'public/exec.py',ROOT/'public/runtime.toml'):
        st=path.stat();need(path.resolve()==path and st.st_uid==0 and not st.st_mode&0o022,'Root capture input ownership differs')
    release=json.loads(read(ACTIVE/'deps/overlaybd/tools-release.json'))
    expected={'tag_name':'v1.0.18-aenv.1','asset_name':'overlaybd-tools-v1.0.18-aenv.1-linux-aarch64.tar.gz','digest':None}
    need(release==expected,'OverlayBD release marker differs; do not download or forge marker')
    binaries={}
    for tool in ('overlaybd-create','overlaybd-apply','overlaybd-commit','overlaybd-resize'):
        staged=ACTIVE/'deps/overlaybd/bin'/tool;original=BASE/'deps/overlaybd/bin'/tool
        need(staged.is_file() and original.is_file() and os.access(staged,os.X_OK),'Retained native tool unavailable')
        actual=file_sha(staged);need(actual==file_sha(original),'Staged tool bytes differ');binaries[tool]=actual
    for name,pin in [('overlaybd-create','68c62104c067d508eb3979117932c14b57dc1d67e10805a9d7ae2b9294efb72c'),
                     ('overlaybd-apply','89c2d0adc300bb93d8d5ae57a39003587d12facfe1b685c9f91f3430500316d5'),
                     ('overlaybd-commit','09b7ed66c074c83cdfd1ef4a316df8d50ce95756041246032a951f81407d0cd1')]:
        need(binaries[name]==pin,'Fixed dependency differs: '+name)
    staged_default=ACTIVE/'deps/overlaybd/etc/overlaybd/overlaybd.json'
    need(not staged_default.exists(),'Expected omitted default config already exists; preserve unknown state')
    STATE.update(state)
    put(ROOT/'dependency-failure006-state.json',before,0,0o600)
    STATE['previousFailure']=STATE.pop('failure');STATE['phase']='private_dependency_config_intent';checkpoint()
    put(staged_default,wire(private_overlay_config()))
    need(staged_default.stat().st_uid==1204 and json.loads(read(staged_default))==private_overlay_config(),'Private default config installation differs')
    # Exercise all remaining offline startup inputs before starting the unit.
    fc=Path(cfg['firecracker']['binary_path']);need(file_sha(fc)==PINS['deps/firecracker/1.15.1-patch-v3/firecracker'],'Staged FC differs')
    for path in (Path(cfg['kernel']['image_path']),Path(cfg['tools']['drive_path'])):
        need(path.is_file() and path.stat().st_size>0,'Explicit kernel/tools drive missing')
    registry=ACTIVE/'deps/regctl/v0.11.5/regctl'
    version=command(['setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs',registry,'version'],20,env)
    need(re.search(rb'(?<![A-Za-z0-9_.-])v0\.11\.5(?![A-Za-z0-9_.-])',version),'Retained regctl version not confirmed')
    manifest=read(ACTIVE/'private/oci-manifest.json');config=read(ACTIVE/'private/oci-config.json')
    need(sha(struct.pack('>I',len(manifest))+manifest+config)==OCI_METADATA_WIRE_SHA,'Offline metadata changed')
    mem=dict((k,int(v.split()[0])*1024) for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines()))
    need(mem['MemAvailable']>=8*1024**3,'Insufficient free RAM for capture')
    STATE.update(phase='private_dependencies_verified_offline',offlineDependencyGate={'release':release,'tools':binaries,
        'privateDefaultConfigPresent':True,'explicitKernelAndToolsPresent':True,'regctlVersionPassed':True,'metadataVerified':True},
        dependencyRepair={'previousReportSha256':PREVIOUS_DEPENDENCY_REPORT_SHA,'modifiedOnly':str(staged_default)})
    checkpoint();print('PRIVATE_CAPTURE_DEPENDENCIES_COMPLETE_NO_DOWNLOAD',flush=True)

def main():
    need(os.getuid()==os.geteuid()==0 and socket.gethostname()=='server1','A root only')
    os.umask(0o077)
    prepare();before={p.name:(p.lstat().st_ino,p.lstat().st_rdev) for p in Path('/dev').glob('ublk[bc]*')}
    background={}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:
            if 'uvm-ublk' in (p/'comm').read_text():background[int(p.name)]=ticks(int(p.name))
        except (FileNotFoundError,ProcessLookupError):continue
    STATE['phase']='runtime_restart_intent';checkpoint()
    command(['systemctl','start',UNIT],40)
    live=props();pid=int(live.get('MainPID','0'));need(live.get('ActiveState')=='active' and pid>0,'Candidate capture Runtime failed')
    STATE['runtime']={'unit':UNIT,'pid':pid,'ticks':ticks(pid)};STATE['phase']='runtime_active';checkpoint()
    thread=threading.Thread(target=watcher,args=(before,background));thread.start()
    try:
        until=time.monotonic()+60
        while True:
            try:
                if api('GET','/health')['status']==204:break
            except (OSError,RuntimeError):pass
            need(time.monotonic()<until,'Runtime health deadline');time.sleep(1)
        created=api('POST','/v3/templates',{'name':'dsbench-titanic-20261102-candidate','cpuCount':2,'memoryMB':4096})
        body=created['body'];sid=body['templateID'];bid=body['buildID']
        need(sid==bid and re.fullmatch('[0-9a-f-]{36}',sid),'Template/build response identity differs')
        STATE.update(templateId=sid,phase='template_registered');checkpoint()
        check="python -c \"import pathlib,pandas,numpy,sklearn; p=pathlib.Path('/task'); assert (p/'train.csv').is_file() and (p/'test.csv').is_file(); print('TITANIC_DEPENDENCIES_AND_TASK_FILES_OK')\""
        api('POST',f'/v2/templates/{sid}/builds/{bid}',{'fromImage':IMAGE+'@'+DIGEST,'steps':[{'type':'RUN','args':[check]}]})
        STATE['phase']='template_build_requested';checkpoint();deadline=time.monotonic()+1800
        while True:
            need(not ERRORS,'New-device guard failed: '+str(ERRORS));need(time.monotonic()<deadline,'Build deadline; preserve active state, no retry')
            result=api('GET',f'/templates/{sid}/builds/{bid}/status');need(result['status']==200,'Build status unavailable')
            STATE['buildStatus']=result['body'];checkpoint()
            if result['body']['status']=='ready':break
            need(result['body']['status'] in ('waiting','building'),'Template build failed; preserve exact status')
            time.sleep(3)
        repo=ACTIVE/'seed/repository';record=repo/'catalog/records'/(sid+'.json')
        need(read(repo/'snapshots'/sid/'commit')==b'committed','Snapshot commit missing')
        data=json.loads(read(record));need(data['id']==sid and data['resources']['cpu_count']==2 and data['resources']['memory_mib']==4096,'Snapshot resource binding differs')
        committed=data['committed'];artifacts=[]
        for kind in ('rootfs_layers','memory_layers'):
            need(committed[kind],kind+' missing')
            for layer in committed[kind]:
                p=repo/'managed-layers'/(layer['digest'].replace(':','_')+'.overlaybd.commit')
                need(p.stat().st_size==layer['size'] and 'sha256:'+file_sha(p)==layer['digest'],'Captured artifact checksum differs')
                artifacts.append({'kind':kind,'digest':layer['digest'],'bytes':layer['size'],'file':str(p)})
        for name in ('vm_state.bin','firecracker-manifest.json'):
            p=repo/'snapshots'/sid/name;need(p.stat().st_size>0,'Captured '+name+' empty');artifacts.append({'kind':name,'file':str(p),'bytes':p.stat().st_size,'sha256':file_sha(p)})
        source=json.loads(read(INPUT))['images'][0]['rootfsLowers'];need({x['digest'] for x in source}<={x['digest'] for x in committed['rootfs_layers']},'Captured rootfs omits converted Titanic base')
        # TemplateBuilder may run a short startup-recording VM after publication.
        # Keep the ACL monitor until all temporary FC processes in this unit exit.
        end=time.monotonic()+120;fc=ACTIVE/'deps/firecracker/1.15.1-patch-v3/firecracker';fm=fc.stat()
        while True:
            remaining=[];cg=Path('/proc',str(pid),'cgroup').read_text()
            for p in Path('/proc').iterdir():
                if not p.name.isdigit():continue
                try:
                    st=(p/'exe').stat()
                    if (st.st_dev,st.st_ino)==(fm.st_dev,fm.st_ino) and (p/'cgroup').read_text()==cg:remaining.append(int(p.name))
                except (FileNotFoundError,ProcessLookupError):continue
            if not remaining:break
            need(not ERRORS and time.monotonic()<end,'Temporary capture/recording FC still active; preserve state');time.sleep(1)
        STATE['temporaryFcExited']=True
        STATE['remainingGrantedDevices']=[r['path'] for r in STATE['grants'] if Path(r['path']).exists() and
            [Path(r['path']).stat().st_ino,Path(r['path']).stat().st_rdev]==r['identity']]
        STATE.update(phase='committed_template_verified',catalogSha256=sha(read(record)),artifacts=artifacts,
            captureDependenciesPassed=True,businessTrainingExecuted=False,SDKCalled=False,UBAllocated=False,
            candidateCaptureServiceRetained=True,captureUsesOrdinaryFiles=True,fullUbBenchmarkAccepted=False,DaxServicesChanged=False,BChanged=False);checkpoint()
        print('TITANIC_CANDIDATE_TEMPLATE_CAPTURED_DEPENDENCIES_VERIFIED');print(json.dumps({k:v for k,v in STATE.items() if k not in ('operations','grants')},indent=2))
    finally:STOP.set();thread.join(10)

def explicit_stop():
    need(os.getuid()==os.geteuid()==0 and socket.gethostname()=='server1','A root only')
    STATE.update(json.loads(read(ROOT/'state.json')))
    need(STATE['unit']==UNIT and STATE['identity']['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Recovery boot/unit differs')
    live=props();pid=int(live.get('MainPID','0'))
    if pid:
        saved=STATE.get('runtime',{})
        need(saved.get('pid')==pid and saved.get('ticks')==ticks(pid),'Recovery process identity unconfirmed; no stop')
    need(not live.get('ActiveState') in ('activating','deactivating'),'Unit transition unresolved')
    STATE['recovery']='explicit_stop_intent_preserve_template_and_requests';checkpoint()
    command(['systemctl','stop',UNIT],100)
    live=props();need(live.get('MainPID')=='0' and live.get('ActiveState') in ('inactive','failed'),'Unit stop unconfirmed')
    remaining=[r['path'] for r in STATE.get('grants',[]) if Path(r['path']).exists() and [Path(r['path']).stat().st_ino,Path(r['path']).stat().st_rdev]==r['identity']]
    STATE.update(recovery='new_capture_service_stopped_artifacts_preserved',remainingGrantedDevices=remaining)
    checkpoint();print(json.dumps({'status':'TITANIC_CAPTURE_SERVICE_STOPPED_ARTIFACTS_PRESERVED','remainingGrantedDevices':remaining,
        'pendingRequestsPreserved':STATE.get('pending'),'snapshotDeleted':False,'DaxServicesChanged':False,'UBReleased':False}))

if __name__=='__main__':
    try:
        if sys.argv[1:]==['stop']:explicit_stop()
        else:
            need(sys.argv[1:]==['--resume-dependency-config'],'Explicit dependency-config continuation required')
            main()
    except BaseException as e:
        if ROOT.exists():
            STATE['failure']={'type':type(e).__name__,'reason':str(e).replace(KEY,'[redacted]') if KEY else str(e)};checkpoint()
            if STATE.get('runtime'):
                p=subprocess.run(['journalctl','-u',UNIT,'--no-pager','-n','60','-o','cat'],capture_output=True,text=True,timeout=15)
                print(p.stdout[-16000:].replace(KEY,'[redacted]'))
            print(json.dumps({'status':'TITANIC_CAPTURE_STOPPED_PRESERVE_STATE','phase':STATE.get('phase'),'failure':STATE.get('failure'),'pending':STATE.get('pending')},indent=2))
        raise
