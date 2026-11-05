"""Prepare the ARM64 Wikidata template and run one pinned lifecycle100 round.
Existing original Runtime only; no service restart, kernel/SDK-pool/module change.
"""
import base64,fcntl,hashlib,http.client,json,os,re,signal,socket,stat,subprocess,threading,time,tomllib,zlib
from pathlib import Path
ROOT=Path('/home/jwk/root/b-wikidata100-20261105-v1')
WORK=Path('/home/jwk/agent/r/b-wikidata100-20261105-v1')
BASE=Path('/home/jwk/root/hpo-services-v1');ACTIVE=Path('/home/jwk/agent/r/hpo-b-v1/active')
UNIT='aenv-hpo-b-runtime-61103-v1.service'
CONFIG_SHA='31bb09072bbfd74b2c2e41810cb19d4e118c0c56127283a1daff5fb041f5ee04'
SERVER_SHA='0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff'
OWNER=Path('/home/jwk/root/t1-locality-v1/public/ublk_owner')
OWNER_SHA='1ca1717821569dfc4e36f12e01e7359da0de76919742e6cf3978ef7ab0df9e7c'
IMAGE='swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/swerebench-arm64-wikidata-wikidata-toolkit@sha256:1674571c09695c0b3911d3f0af97f8752698157a6af8e13be5e8761c1c291eca'
NAME='b-wikidata-toolkit-717-lifecycle100-20261105'
BENCHMARK_Z64='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'
BENCHMARK_SHA='63e86721f43cd2dd55c05798594e548807697c59f5ef391cab27c0c55bbb4555'
STATE={};KEY=None;STOP=threading.Event();ERRORS=[];GRANTS=[];PID=None;BEFORE={};DAEMONS={}
def need(ok,why):
    if not ok:raise RuntimeError(why)
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024**2),b''):h.update(b)
    return h.hexdigest()
def atomic(p,d):
    q=p.with_suffix('.next');q.write_text(json.dumps(d,ensure_ascii=False,indent=2));q.replace(p)
def mark(phase,**extra):
    STATE.update(phase=phase,unixNs=time.time_ns(),**extra);atomic(ROOT/'state.json',STATE);print('PHASE='+phase,flush=True)
def api(method,path,body=None):
    c=http.client.HTTPConnection('127.0.0.1',18251,timeout=60)
    try:
        raw=json.dumps(body).encode() if body is not None else None
        c.request(method,path,body=raw,headers={'X-API-Key':KEY,'Content-Type':'application/json'})
        r=c.getresponse();raw=r.read(2*1024**2+1);need(len(raw)<=2*1024**2,'API response too large')
        need(200<=r.status<300,'API request status '+str(r.status)+' for '+path)
        return json.loads(raw) if raw else None
    finally:c.close()
def ident(pid):
    p=Path('/proc')/str(pid)
    return ((p/'stat').read_text().rsplit(')',1)[1].split()[19],(p/'cgroup').read_text())
def daemons():
    out={}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:
            if 'uvm-ublk' in (p/'comm').read_text():out[int(p.name)]=ident(int(p.name))
        except (OSError,ProcessLookupError):continue
    return out
def guard():
    need(ident(PID)==tuple(STATE['runtimeIdentity']),'Bound Runtime changed')
    for pid,row in daemons().items():
        if row[1]==STATE['runtimeIdentity'][1]:continue
        need(pid in DAEMONS and DAEMONS[pid]==row,'New unrelated ublk daemon observed')
def watch():
    try:
        while not STOP.wait(.1):
            guard()
            if STATE.get('phase') not in ('template_build_requested','benchmark_running'):continue
            for p in Path('/dev').glob('ublk[bc]*'):
                if not re.fullmatch(r'ublk[bc][0-9]+',p.name) or p.name in BEFORE:continue
                try:
                    s=p.lstat();identity=(s.st_ino,s.st_rdev)
                    if any(g['path']==str(p) and tuple(g['identity'])==identity for g in GRANTS):continue
                    fd=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
                    try:
                        s2=os.fstat(fd)
                        if (s2.st_ino,s2.st_rdev)!=identity or not (stat.S_ISBLK(s2.st_mode) or stat.S_ISCHR(s2.st_mode)):continue
                        q=subprocess.run([str(OWNER),p.name],capture_output=True,timeout=3)
                        if q.returncode:continue
                        need(q.stdout.strip()==b'1204:1205','New device owner differs')
                        need((p.stat().st_ino,p.stat().st_rdev)==identity,'Device replaced')
                        target=f'/proc/{os.getpid()}/fd/{fd}'
                        prior=subprocess.check_output(['getfacl','-cpn',target],timeout=3,text=True)
                        row={'path':str(p),'identity':list(identity),'priorAcl':prior,'state':'intent'};GRANTS.append(row);atomic(ROOT/'device-acls.json',GRANTS)
                        subprocess.run(['setfacl','-m','u:1204:rw',target],check=True,capture_output=True,timeout=3)
                        row['state']='granted';atomic(ROOT/'device-acls.json',GRANTS)
                    finally:os.close(fd)
                except FileNotFoundError:continue
    except BaseException as e:ERRORS.append(type(e).__name__+': '+str(e));STOP.set()
def ordinary(args):
    return ['setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs',*args]
def child(args,label,env,seconds):
    with (WORK/(label+'.log')).open('xb') as log:
        p=subprocess.Popen(ordinary(args),cwd=WORK,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
        try:return p.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            p.terminate()
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:p.kill();p.wait()
            raise RuntimeError(label+' timed out; no automatic retry')
def ready_template(row):
    return row.get('cpuCount')==2 and row.get('memoryMB')==4096 and row.get('buildStatus',row.get('status','ready'))=='ready'
def main():
    global KEY,PID,BEFORE,DAEMONS
    need(os.geteuid()==0 and socket.gethostname()=='agent1','B unified root entry required');os.umask(0o077)
    need(not ROOT.exists() and not WORK.exists(),'Existing run preserved; do not repeat')
    raw=(BASE/'public/runtime.toml').read_bytes();need(hashlib.sha256(raw).hexdigest()==CONFIG_SHA,'Original Runtime config changed')
    need(sha(OWNER)==OWNER_SHA,'Owner helper changed')
    properties=subprocess.check_output(['systemctl','show',UNIT,'--property=MainPID,ActiveState','--no-pager'],text=True)
    props=dict(x.split('=',1) for x in properties.splitlines() if '=' in x)
    need(props.get('ActiveState')=='active','Original Runtime not active');PID=int(props['MainPID'])
    need(sha(Path('/proc')/str(PID)/'exe')==SERVER_SHA,'Runtime executable changed')
    lock=os.open(BASE/'private/titanic-measure.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    need(not (ACTIVE/'external-mutation-observed').exists(),'Unresolved earlier external mutation marker')
    KEY=tomllib.loads((ACTIVE/'cli/aenv/credentials').read_text())['api_key']
    need(api('GET','/v2/sandboxes?limit=100')==[],'Original Runtime not empty')
    ROOT.mkdir(mode=0o700);WORK.mkdir(mode=0o700);os.chown(WORK,1204,1205)
    STATE.update(runtimePid=PID,runtimeIdentity=list(ident(PID)),image=IMAGE,benchmarkSha256=BENCHMARK_SHA,benchmarkStarted=False,
      kernel=os.uname().release,architecture=os.uname().machine,initialMeminfo=Path('/proc/meminfo').read_text(),
      transport='existing host TCP proxy -> UNIX socket -> namespace TCP proxy -> original Runtime')
    mark('admitted')
    BEFORE={p.name:(p.lstat().st_ino,p.lstat().st_rdev) for p in Path('/dev').glob('ublk[bc]*')};DAEMONS=daemons()
    env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
    mark('sdk_preparation')
    need(child(['/usr/bin/python3.11','-m','venv',str(WORK/'venv')],'venv',env,120)==0,'Private venv failed; inspect log')
    python=str(WORK/'venv/bin/python')
    need(child([python,'-m','pip','install','--disable-pip-version-check','--retries','1','--timeout','30','e2b==2.37.0'],'pip',env,600)==0,'Pinned e2b installation failed; inspect log')
    version=subprocess.check_output(['runuser','-u','jwk','--',python,'-I','-B','-c',"import importlib.metadata; print(importlib.metadata.version('e2b'))"],text=True).strip();need(version=='2.37.0','SDK differs')
    raw=zlib.decompress(base64.b64decode(BENCHMARK_Z64));need(hashlib.sha256(raw).hexdigest()==BENCHMARK_SHA,'Benchmark bytes differ')
    script=WORK/'benchmark_sandbox_lifecycle.py';script.write_bytes(raw);os.chown(script,1204,1205)
    thread=threading.Thread(target=watch,daemon=True);thread.start()
    try:
        matches=[r for r in api('GET','/templates') if NAME in r.get('names',[])]
        need(not matches,'Unexpected pre-existing test template; reconcile first')
        guard();mark('template_register_intent')
        atomic(ACTIVE/'external-mutation-observed',{'runId':'b-wikidata100-20261105-v1','work':str(ROOT),'pendingBeforeCreate':True})
        created=api('POST','/v3/templates',{'name':NAME,'cpuCount':2,'memoryMB':4096});sid=created['templateID'];bid=created['buildID']
        need(re.fullmatch('[0-9a-f-]{36}',sid) and re.fullmatch('[0-9a-f-]{36}',bid),'Template response differs')
        mark('template_registered',templateId=sid,buildId=bid)
        # Persist submission intent before the non-idempotent request; never resubmit an unknown build.
        mark('template_build_requested')
        api('POST',f'/v2/templates/{sid}/builds/{bid}',{'fromImage':IMAGE,'steps':[]})
        deadline=time.monotonic()+1800
        while True:
            guard();need(not ERRORS,'ACL guard stopped');need(time.monotonic()<deadline,'Template build deadline; preserve pending build')
            status=api('GET',f'/templates/{sid}/builds/{bid}/status');STATE['buildStatus']=status;atomic(ROOT/'state.json',STATE)
            if status['status']=='ready':break
            need(status['status'] in ('waiting','building'),'Template build failed; preserve status');time.sleep(3)
        row=next(r for r in api('GET','/templates') if r['templateID']==sid);need(ready_template(row),'Template resources/status differ')
        mark('template_ready',template=row)
        need(api('GET','/v2/sandboxes?limit=100')==[],'Runtime acquired other consumers')
        mapping=WORK/'image-map.json';mapping.write_text(json.dumps({'wikidata__wikidata-toolkit-717':sid}));os.chown(mapping,1204,1205)
        env.update(E2B_API_KEY=KEY,E2B_API_URL='http://127.0.0.1:18251',E2B_SANDBOX_URL='http://127.0.0.1:18251')
        command=[python,'-B',str(script),'--image-map',str(mapping),'--total','100','--batch-size','100','--rounds','1','--api-url','http://127.0.0.1:18251','--request-timeout','600','--sandbox-timeout','86400','--output-dir',str(WORK/'result')]
        mark('benchmark_running',benchmarkStarted=True,command=command)
        stopped=False;start=time.monotonic()
        with (WORK/'benchmark.log').open('xb') as log,(ROOT/'host-samples.jsonl').open('x') as samples:
            p=subprocess.Popen(ordinary(command),cwd=WORK,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
            STATE['benchmarkPid']=p.pid;STATE['benchmarkProcessIdentity']=list(ident(p.pid));atomic(ROOT/'state.json',STATE)
            while p.poll() is None:
                info={k:int(v.split()[0])*1024 for k,v in (x.split(':',1) for x in Path('/proc/meminfo').read_text().splitlines()) if v.strip().endswith('kB')}
                samples.write(json.dumps({'unixNs':time.time_ns(),'MemAvailable':info['MemAvailable'],'MemTotal':info['MemTotal']})+'\n');samples.flush()
                if (ERRORS or info['MemAvailable']<20*1024**3 or time.monotonic()-start>7200) and not stopped:
                    p.send_signal(signal.SIGTERM);stopped=True;STATE['guardReason']=ERRORS or 'memory_or_time_guard';atomic(ROOT/'state.json',STATE)
                time.sleep(1)
        result=WORK/'result/summary.json';summary=json.loads(result.read_text()) if result.is_file() else None
        mark('benchmark_finished',benchmarkExitCode=p.returncode,summary=summary)
        inventory=api('GET','/v2/sandboxes?limit=100');STATE['finalInventoryCount']=len(inventory)
        files={}
        for name in ('summary.json','operations.jsonl','operations.csv','batches.json','rounds.json','config.json','remaining.json'):
            f=WORK/'result'/name
            if f.is_file():files[name]={'sha256':sha(f),'bytes':f.stat().st_size,'text':f.read_text() if f.stat().st_size<500000 else None}
        atomic(ROOT/'returned-files.json',files)
        mark('finished_review_required',valid=bool(summary and summary.get('valid') and not inventory and not ERRORS and p.returncode==0))
        if STATE['valid']:
            marker=ACTIVE/'external-mutation-observed'
            need(json.loads(marker.read_text())=={'runId':'b-wikidata100-20261105-v1','work':str(ROOT),'pendingBeforeCreate':True},'External marker changed; preserve it')
            marker.unlink();STATE['ownedMarkerCleared']=True;atomic(ROOT/'state.json',STATE)
        print(json.dumps({'status':'B_WIKIDATA100_FINISHED','state':STATE,'files':files,'aclGrants':len(GRANTS),'aclErrors':ERRORS},ensure_ascii=False,separators=(',',':')),flush=True)
        need(STATE['valid'],'Benchmark failed or cleanup incomplete; preserve raw state')
    finally:
        STOP.set();thread.join(timeout=5)
        # Device teardown is owned by the Runtime; never remove devices or unrelated Guests here.
        atomic(ROOT/'device-acls.json',GRANTS)
        os.close(lock)
if __name__=='__main__':
    try:main()
    except BaseException as e:
        if ROOT.exists():
            STATE.update(failureType=type(e).__name__,failure=str(e)[:1200]);atomic(ROOT/'state.json',STATE)
        tails={p.name:p.read_text(errors='replace')[-12000:].replace(KEY,'<redacted>') if KEY else p.read_text(errors='replace')[-12000:] for p in WORK.glob('*.log')} if WORK.is_dir() else {}
        print(json.dumps({'status':'B_WIKIDATA100_FAILED_PRESERVE_STATE','state':STATE,'errorType':type(e).__name__,'reason':str(e)[:1200],'aclErrors':ERRORS,'logTails':tails},ensure_ascii=False),flush=True)
        raise
