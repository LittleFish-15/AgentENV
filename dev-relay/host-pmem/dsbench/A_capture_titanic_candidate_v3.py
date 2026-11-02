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


def prepare():
    global KEY,BASE,BINARIES
    need(METADATA is not None,'Pinned metadata required before preparation')
    resume=resume_metadata_timeout()
    need(props().get('LoadState')=='not-found','Capture unit already exists')
    conversion=json.loads(read(INPUT));need(sha(wire(conversion))==CONVERSION_RECORD_SHA,'Converted record differs from verified 003 receipt');image=conversion['images'][0]
    need(conversion['state']=='NATIVE_ROOTFS_CONVERSION_COMPLETED_NOT_A_TEMPLATE' and len(conversion['images'])==1 and image['imageManifestDigest']==DIGEST,'Converted input differs')
    need(len(image['rootfsLowers'])==9 and sum(r['size'] for r in image['rootfsLowers'])==1831857152,'Titanic lower sizes differ')
    for row in image['rootfsLowers']:
        p=Path(row['file']);need(p.is_relative_to(INPUT.parent) and p.stat().st_size==row['size'] and 'sha256:'+file_sha(p)==row['digest'],'Converted lower checksum differs')
    plan_raw=read(PLAN);need(sha(plan_raw)==PLAN_SHA,'Retained candidate component plan differs')
    plan=json.loads(plan_raw);BASE=Path(plan['sourceDeployment']);BINARIES=plan['binaries']
    need(BASE.is_relative_to('/home/jwk/agent/deployments'),'Component base outside retained deployments')
    for name,pin in PINS.items():
        row=BINARIES[name];need(row['sha256']==pin and file_sha(Path(row['path']))==pin,'Repaired-version binary differs: '+name)
    mem=dict((k,int(v.split()[0])*1024) for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines()))
    need(mem['MemAvailable']>=8*1024**3,'Need 8GiB available before capture; no Guest started')

    need(file_sha(OWNER)==OWNER_SHA,'Owner query binary differs')
    mkdir(ROOT,0,0o711);mkdir(ROOT/'public',0,0o755);mkdir(ACTIVE)
    STATE.update(resume=resume,phase='prepared_intent',unit=UNIT,identity={'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'hostname':socket.gethostname()},operations=[],pending=None,grants=[]);checkpoint()
    original=json.loads(read(Path('/home/jwk/root/original-t1/node-a/configuration.json')))
    cfg=original['config'];oldactive='/home/jwk/root/orig-a'
    def remap(x):
        if isinstance(x,dict):return {k:remap(v) for k,v in x.items()}
        if isinstance(x,list):return [remap(v) for v in x]
        return x.replace(oldactive,str(ACTIVE)) if isinstance(x,str) else x
    cfg=remap(cfg);cfg['ublk']['daemon_binary_path']=BINARIES['bin/uvm-ublk-daemon']['path']
    cfg['image']={'cache':{'root_dir':str(ACTIVE/'state/image-cache'),'gc':{'enabled':False}},
        'resolver':{'default_image':IMAGE+'@'+DIGEST,'convert_standard_oci':True,'try_referrers_overlaybd_prefixes':[],'allowed_registries':['swr.cn-north-4.myhuaweicloud.com']}}
    need('ub_rootfs_index' not in cfg['snapshot'],'Capture-only config must not reuse the T1 UB index')
    for leaf in ('state','run','fc','logs','tmp','cache','seed','cli/aenv','private','state/image-cache/configs'):mkdir(ACTIVE/leaf)
    regctls=list((BASE/'deps/regctl').glob('*/regctl'));need(len(regctls)==1,'Ambiguous pinned regctl')
    registry=regctls[0];env={'PATH':str(BASE/'native/bin')+':/usr/bin:/bin','HOME':str(ACTIVE),'REGCTL_CONFIG':str(ACTIVE/'private/registry.json'),
        'LD_LIBRARY_PATH':str(BASE/'native/lib')+':'+str(BASE/'native/fallback/lib')}
    manifest,config_raw=METADATA
    descriptor=json.loads(manifest)['config']
    config=json.loads(config_raw);need(config['architecture']=='arm64' and config['os']=='linux','Wrong OCI platform')
    put(ACTIVE/'private/oci-manifest.json',manifest);put(ACTIVE/'private/oci-config.json',config_raw)
    for p in sorted((BASE/'deps').rglob('*')):
        need(p.resolve()==p,'Original dependency symlink needs explicit handling');dest=ACTIVE/'deps'/p.relative_to(BASE/'deps')
        if p.is_dir():mkdir(dest);continue
        if p==registry or p.name=='overlaybd.json' or p.relative_to(BASE).as_posix()=='deps/firecracker/1.15.1-patch-v3/firecracker':continue
        mkdir(dest.parent)
        if p.suffix=='.json':put(dest,read(p))
        else:os.link(p,dest)
    fc=ACTIVE/'deps/firecracker/1.15.1-patch-v3/firecracker'
    mkdir(fc.parent);os.link(BINARIES['deps/firecracker/1.15.1-patch-v3/firecracker']['path'],fc)
    need(file_sha(fc)==PINS['deps/firecracker/1.15.1-patch-v3/firecracker'],'Staged candidate FC differs')
    shim='''#!/usr/bin/python3
import hashlib,os,sys
from pathlib import Path
a=sys.argv[1:]
if a==['version']:os.execv(REAL,[REAL,'version'])
if a==['manifest','get','--format','raw-body',REF]:p=MANIFEST;pin=MPIN
elif a==['blob','get',REPO,CPIN]:p=CONFIG;pin=CPIN
else:raise SystemExit('Offline metadata-only adapter refuses uncached/image-copy request')
raw=Path(p).read_bytes();assert 'sha256:'+hashlib.sha256(raw).hexdigest()==pin
sys.stdout.buffer.write(raw)
'''
    bindings={'REAL':str(registry),'REF':IMAGE+'@'+DIGEST,'REPO':IMAGE,'MANIFEST':str(ACTIVE/'private/oci-manifest.json'),'CONFIG':str(ACTIVE/'private/oci-config.json'),'MPIN':DIGEST,'CPIN':descriptor['digest']}
    shim=shim.replace('a=sys.argv[1:]','\n'.join(k+'='+repr(v) for k,v in bindings.items())+'\na=sys.argv[1:]')
    put(ACTIVE/'deps'/registry.relative_to(BASE/'deps'),shim.encode(),1204,0o700)
    lower_config={'repoBlobUrl':'','lowers':[{k:r[k] for k in ('file','digest','size')} for r in image['rootfsLowers']],'upper':{},'resultFile':''}
    cache=ACTIVE/'state/image-cache/configs'/(DIGEST.replace(':','-')+'-image.json')
    put(cache,wire(lower_config))
    oc=config.get('config',{});context={'env_vars':dict(v.split('=',1) for v in oc.get('Env',[]) if '=' in v),
        'workdir':oc.get('WorkingDir') or None,'user':oc.get('User') or None,'entrypoint':oc.get('Entrypoint'),'cmd':oc.get('Cmd'),
        'exposed_ports':list((oc.get('ExposedPorts') or {}).keys()),'volumes':list((oc.get('Volumes') or {}).keys()),'labels':oc.get('Labels') or {}}
    put(cache.with_name(cache.stem+'.metadata.json'),wire({'base_context':context,'raw_config':config}))
    put(ROOT/'public/runtime.toml',toml(cfg),0,0o644);put(ROOT/'public/http.py',HTTP_HELPER.encode(),0,0o644)
    KEY=secrets.token_hex(24)
    env.update(AENV_API_KEY=KEY,API_ADDR='127.0.0.1:18231',AENV_CONFIG_PATH=str(ROOT/'public/runtime.toml'),
        HOME='/home/jwk',AENV_HOME_PATH=str(ACTIVE/'state'),AENV_DEPS_PATH=str(ACTIVE/'deps'),AENV_RUNTIME_PATH=str(ACTIVE/'run'),
        XTABLES_LIBDIR=str(BASE/'native/xtables'),TMPDIR=str(ACTIVE/'tmp'),XDG_CACHE_HOME=str(ACTIVE/'cache'))
    put(ACTIVE/'private/runtime-env.json',wire(env))
    put(ACTIVE/'cli/aenv/credentials',('url = "http://127.0.0.1:18231"\napi_key = '+json.dumps(KEY)+'\n').encode())
    wrapper='import json,os\ne=json.load(open('+repr(str(ACTIVE/'private/runtime-env.json'))+'))\nos.execve('+repr(str(BINARIES['bin/server']['path']))+','+repr([str(BINARIES['bin/server']['path']),'--config',str(ROOT/'public/runtime.toml')])+',e)\n'
    put(ROOT/'public/exec.py',wrapper.encode(),0,0o644)
    STATE.update(phase='files_prepared',candidateBinaryPins=PINS,convertedInputSha256=sha(read(INPUT)),metadataAdapter=True,lowerCopyPerformed=False);checkpoint()

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
    pre='import os;assert os.stat("/proc/self/ns/net").st_ino!='+str(os.stat('/proc/self/ns/net').st_ino)+';open("/proc/sys/net/ipv4/ip_forward","w").write("1\\n")'
    code="import base64;exec(base64.b64decode('"+base64.b64encode(pre.encode()).decode()+"'))"
    dev=Path('/dev/ublk-control').stat();need(dev.st_gid!=0 and dev.st_mode&0o060==0o060,'Existing ublk group unavailable')
    props_list=['Type=exec','Restart=no','User=1204','Group=1205','SupplementaryGroups=ubsmd kvm '+str(dev.st_gid),
        'AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN','CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN',
        'PrivateNetwork=yes','PrivateMounts=yes','WorkingDirectory=/','UMask=0077','KillMode=control-group','TimeoutStopSec=90',
        'LimitNOFILE=65536','LimitCORE=0','StandardOutput=journal','StandardError=journal',
        'ExecStartPre=+/usr/bin/python3 -I -B -c "'+code+'"']
    STATE['phase']='runtime_start_intent';checkpoint()
    command(['systemd-run','--unit='+UNIT,*['--property='+x for x in props_list],'--','/usr/bin/python3','-I','-B',ROOT/'public/exec.py'])
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
            need(len(sys.argv)>2 and sys.argv[1]=='--metadata','Fixed private metadata arguments required')
            METADATA=decode_metadata(sys.argv[2:]);main()
    except BaseException as e:
        if ROOT.exists():
            STATE['failure']={'type':type(e).__name__,'reason':str(e).replace(KEY,'[redacted]') if KEY else str(e)};checkpoint()
            if STATE.get('runtime'):
                p=subprocess.run(['journalctl','-u',UNIT,'--no-pager','-n','60','-o','cat'],capture_output=True,text=True,timeout=15)
                print(p.stdout[-16000:].replace(KEY,'[redacted]'))
            print(json.dumps({'status':'TITANIC_CAPTURE_STOPPED_PRESERVE_STATE','phase':STATE.get('phase'),'failure':STATE.get('failure'),'pending':STATE.get('pending')},indent=2))
        raise
