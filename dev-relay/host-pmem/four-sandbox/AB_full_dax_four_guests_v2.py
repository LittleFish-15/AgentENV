"""Candidate-first two-node Guest experiment; embedded by build_full_four.py.

Only an explicit, current-boot root approval admits execution. Existing SDK,
view and Runtime transactions are read/locked, never restarted or rewritten.
"""
import argparse,base64,concurrent.futures,fcntl,hashlib,http.client,json,os,re,shlex,socket,stat,struct,subprocess,sys,threading,time,tomllib,types,zlib
from pathlib import Path

BASE=Path('/var/lib/agentenv-hpab-services-v1')
HOME=Path('/var/lib/agentenv-hpd4-full-v2')
SESSION='relay-20261029-0d032371'
RUN='hpd4-full-20261030-r2'
RESULTS='LittleFish-15/AgentENV-relay-results'
CONTROL='LittleFish-15/AgentENV-relay-control'
APPROVAL='approvals/'+RUN+'.json'
ENTRY_PIN='1f388bb505c655bfd0b494f20f4ab13ad7e2b3ab57f34cbf525e72b350e89358'

def need(ok,why):
    if not ok:raise RuntimeError(why)

def digest(raw):return hashlib.sha256(raw).hexdigest()
def wire(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def atomic(path,value):
    path=Path(path);tmp=path.with_name(path.name+'.next')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:out.write(wire(value));out.flush();os.fsync(out.fileno())
    os.replace(tmp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def read(path,limit=8*1024**2):
    path=Path(path);need(path.resolve(strict=True)==path,'Redirected input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as src:
        st=os.fstat(src.fileno());need(stat.S_ISREG(st.st_mode) and st.st_uid in (0,1204) and st.st_size<=limit,'Input type/owner/size differs')
        raw=src.read(limit+1);need(len(raw)<=limit,'Input grew beyond bound');return raw

def load_module(name,raw):
    m=types.ModuleType(name);m.__file__=str(BASE/'entry.py') if name=='services' else '<embedded-'+name+'>'
    sys.modules[name]=m;exec(compile(raw,m.__file__,'exec'),m.__dict__);return m

def run(argv,timeout=15):
    p=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    need(p.returncode==0,'Bounded command failed: '+Path(str(argv[0])).name+' exit '+str(p.returncode))
    return p.stdout.decode()

def snapshot_failure_evidence(diag,state,node):
    """Require the observed pre-create failure, not merely an empty inventory."""
    requests=state['openRequests']
    need(len(requests)==1 and requests[0]==diag['request'] and requests[0]['kind']=='create'
         and requests[0]['route']=='/v2/sandboxes' and not state['sandboxIds'] and not state['operations'],
         'Previous request is not the single diagnosed failure')
    journal=diag['runtimeJournal'];need(journal['exitCode']==0,'Runtime log unavailable')
    text=journal['stdout'];path='/home/jwk/agent/r/hpab-'+node[-1]+'-v1/seed/repository/catalog/aliases'
    need(text.count('failed to load runnable snapshot')==1 and path in text and 'Read-only file system (os error 30)' in text
         and "load committed snapshot '01a15c9e-54d0-7b92-a50b-0b6ec2e9136b'" in text,'Different or ambiguous snapshot failure')
    times=re.findall(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z).*failed to load runnable snapshot',text)
    import datetime
    need(len(times)==1,'Missing exact Runtime error time')
    delta=datetime.datetime.fromisoformat(times[0].replace('Z','+00:00')).timestamp()-requests[0]['startedNs']/1e9
    need(0<=delta<=2,'Runtime error not in this request window')
    metrics=diag['httpMetrics'];need(metrics['status']==200,'Request counters unavailable')
    def value(prefix,labels):
        rows=[]
        for line in metrics['lines']:
            if line.startswith(prefix+'{') and all(k in line.split('}',1)[0] for k in labels):rows.append(float(line.rsplit(' ',1)[1]))
        return rows
    need(value('agentenv_http_request_duration_seconds_count',('method="POST"','route="/v2/sandboxes"'))==[1.0], 'Unexpected prior POST count')
    need(value('agentenv_http_request_duration_seconds_count',('method="POST"','route="/v2/sandboxes"','status="5xx"'))==[1.0], 'Prior POST not a server failure')
    need(value('agentenv_sandbox_stage_duration_seconds_count',('operation="create_warm"','stage="load_snapshot"','status="error"'))==[1.0], 'Snapshot failure count differs')
    need(value('agentenv_sandbox_stage_inflight',('operation="create_warm"','stage="load_snapshot"'))==[0.0], 'Snapshot load remains active')
    need(diag['devices']==[] and diag['recentFirecrackerLogs']==[] and diag['inventory']['httpStatus']==200
         and diag['inventory']['items']==[], 'Additional runtime resources need separate reconciliation')
    return {'outcome':'request_failed_during_snapshot_load_before_orchestrator_create','request':requests[0],
            'evidence':'Runtime error within request window plus sole failed POST, failed completed load_snapshot, and resource checks',
            'errorAfterRequestSeconds':delta,'emptyInventoryAloneUsed':False,'previousJournalPreserved':True}

class UnixHTTP(http.client.HTTPConnection):
    def __init__(self,path,timeout):super().__init__('localhost',timeout=timeout);self.path=path
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect(str(self.path))

class Api:
    def __init__(self,ctx):self.ctx=ctx
    def call(self,method,path,body=None,timeout=30):
        need((method=='GET' and (path=='/v2/sandboxes?limit=1' or re.fullmatch('/sandboxes/[A-Za-z0-9_-]+',path))) or
             (method=='POST' and path=='/v2/sandboxes') or
             (method=='DELETE' and re.fullmatch('/sandboxes/[A-Za-z0-9_-]+',path)),'Route outside experiment')
        self.ctx.guard();c=UnixHTTP(self.ctx.active/'api.sock',timeout)
        try:
            c.request(method,path,None if body is None else wire(body),{'X-API-Key':self.ctx.key,'Content-Type':'application/json'})
            r=c.getresponse();raw=r.read(2*1024**2+1);need(len(raw)<=2*1024**2,'API result exceeds bound')
            if method in ('POST','DELETE'):
                # Record the actual HTTP outcome before JSON decoding or engine
                # validation can fail. Never persist returned access tokens.
                preview=None
                if not 200<=r.status<300:
                    preview=self.ctx.transport.redact(raw[:32768],[self.ctx.key]).decode(errors='replace')
                    preview=re.sub(r'(?i)(["\']?[\w-]*(?:token|secret|password)["\']?\s*[:=]\s*)["\'][^"\']*["\']',r'\1"[REDACTED]"',preview)
                evidence={'method':method,'route':path,'httpStatus':r.status,'responseBytes':len(raw),'responseSha256':digest(raw),
                    'errorPreview':preview,'previewTruncated':len(raw)>32768,'receivedUnixNs':time.time_ns()}
                fd=os.open(self.ctx.work/'http-outcomes.jsonl',os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'ab') as out:out.write(wire(evidence)+b'\n');out.flush();os.fsync(out.fileno())
            value=json.loads(raw) if raw else None
            return r.status,value
        finally:c.close()

class Context:
    def __init__(self):
        need(os.geteuid()==0,'Run as root under the reviewed four-Guest approval')
        raw=read(BASE/'entry.py',256*1024);need(digest(raw)==ENTRY_PIN,'Existing service controller changed')
        self.service=load_module('services',raw);self.transport=self.service.module('api')
        self.node={'server1':'node-a','agent1':'node-b'}.get(socket.gethostname());need(self.node,'Only A/B')
        self.peer='node-b' if self.node=='node-a' else 'node-a';self.n=self.node[-1]
        creds=Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json')
        need(not creds.stat().st_mode&0o077,'Credentials permissions differ')
        tokens=json.loads(read(creds,8192))
        self.control=self.transport.GitHub(tokens['controlToken']);self.results=self.transport.GitHub(tokens['resultToken'])
        self.control.private_repo(CONTROL,1438089258);self.results.private_repo(RESULTS,1438089386)
        code,raw,_=self.control.contents(CONTROL,APPROVAL,'main');need(code==200,'Four-Guest approval missing')
        self.approval=json.loads(raw);self.pin=digest(read(Path(__file__),512*1024))
        need(self.approval['humanApproved'] is True and self.approval['scope']=='AB_FULL_DAX_FOUR_GUESTS_KEEP_BACKING' and
             self.approval['entrySha256']==self.pin and self.approval['runId']==RUN,'Exact four-Guest approval differs')
        self.expected=self.approval['nodes'][self.node]
        need(self.service.identity()==self.expected['identity'],'Boot/node changed; no automatic rejoin')
        self.work=HOME/self.node;HOME.mkdir(mode=0o700,exist_ok=True);self.work.mkdir(mode=0o700,exist_ok=True)
        for path in (HOME,self.work):need(path.resolve()==path and path.stat().st_uid==0 and not path.stat().st_mode&0o077,'Unsafe output directory')
        installed=HOME/'entry.py';raw=read(Path(__file__),512*1024)
        if installed.exists():need(read(installed,512*1024)==raw,'Different installed experiment entry; preserve it')
        else:
            with installed.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        starter=HOME/'start.sh'
        start_raw=b'#!/bin/bash\nset -eu\numask 077\nexec /usr/bin/python3 -I -B /var/lib/agentenv-hpd4-full-v2/entry.py "${1:-run}"\n'
        if starter.exists():need(read(starter)==start_raw,'Different experiment start entry')
        else:
            with starter.open('xb') as f:f.write(start_raw);f.flush();os.fsync(f.fileno())
            os.chmod(starter,0o700)
        self.locks=[]
        for path in (BASE/'private/operation.lock',self.work/'experiment.lock'):
            fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.locks.append(fd)
        auth=json.loads(read(BASE/'private/approval.json'))
        self.app=self.service.Start(self.transport,auth,self.control,self.results,self.node)
        self.active=self.app.active;self.runtime=self.app.bound('runtime');self.pid=self.runtime['pid']
        need(self.runtime==self.expected['runtime'],'Runtime differs from acknowledged healthy instance')
        self.indexraw=read(BASE/'public/rootfs-index.json');need(digest(self.indexraw)==self.expected['indexSha256'],'Index changed')
        self.index=json.loads(self.indexraw)
        self.key=tomllib.loads(read(self.active/'cli/aenv/credentials').decode())['api_key']
        self.api=Api(self);self.case=None;self.jobs=[];self.bindings={};self.processes=[];self.devices=[]
        self.lock=threading.RLock();self.permissions=[];self.permission_error=None;self.stop=threading.Event()
        self.helper=Path(self.expected['ownerHelper'])
        need(digest(read(self.helper.with_suffix('.c')))==self.approval['ownerHelperSourceSha256'],'Owner helper source differs')
        need(self.helper.stat().st_uid==0 and not self.helper.stat().st_mode&0o022 and read(self.helper,1024**2)[:4]==b'\x7fELF','Unsafe existing owner helper')
        atomic(self.work/'reused-owner-helper.json',{'path':str(self.helper),'sha256':digest(read(self.helper,1024**2)),
            'sourceSha256':self.approval['ownerHelperSourceSha256'],'nativeCompilationPerformed':False,
            'previousBinaryDigestAvailable':False,'provenance':'root-owned output of acknowledged native compile diagnostic'})
        self.before_devices={p.name:(p.lstat().st_ino,p.lstat().st_rdev) for p in Path('/dev').glob('ublk[bc]*')}
        self.guard()

    def guard(self):
        need(self.service.identity()==self.expected['identity'],'Identity changed')
        for label in ('runtime','sdk','view'):self.app.bound(label)
        self.app.candidate_live()
        need(self.app.bound('runtime')==self.runtime and digest(read(BASE/'public/rootfs-index.json'))==self.expected['indexSha256'],'Runtime/index changed')
        if self.permission_error:raise RuntimeError(self.permission_error)

    def event(self,kind,data):
        value={'runId':RUN,'node':self.node,'identity':self.expected['identity'],'entrySha256':self.pin,'kind':kind,'data':data}
        raw=wire(value);atomic(self.work/(kind+'.json'),value)
        print('PHASE='+self.node+':'+kind,flush=True)
        key='four-guest/'+SESSION+'/'+RUN+'/'+self.node+'/'+kind+'.json'
        # Retry only idempotent receipt publication, never the underlying action.
        for attempt in range(4):
            try:
                self.results.immutable_result(RESULTS,1438089386,'main',key,raw);return value
            except Exception:
                code,old,_=self.results.contents(RESULTS,key,'main')
                if code==200:need(old==raw,'Conflicting immutable receipt');return value
                if attempt==3:raise
                time.sleep(2+attempt)

    def peer_event(self,kind,seconds=900):
        deadline=time.monotonic()+seconds
        while True:
            self.guard()
            for name in ('failed',kind):
                key='four-guest/'+SESSION+'/'+RUN+'/'+self.peer+'/'+name+'.json'
                code,raw,_=self.results.contents(RESULTS,key,'main')
                need(code in (200,404),'Peer GitHub read failed')
                if code==200:
                    value=json.loads(raw);need(value['identity']==self.approval['nodes'][self.peer]['identity'] and value['entrySha256']==self.pin and
                        value['runId']==RUN and value['node']==self.peer and value['kind']==name,'Peer receipt identity differs')
                    need(name!='failed','Peer stopped; no workload advancement');return value['data']
            need(time.monotonic()<deadline,'Peer barrier timed out; preserve owned Guests')
            print('WAIT_PEER='+self.peer+':'+kind,flush=True)
            time.sleep(10)

    def owner_permissions(self):
        try:
            while not self.stop.wait(.1):
                self.guard()
                self.no_foreign_jwk_daemon()
                for path in Path('/dev').glob('ublk[bc]*'):
                    if not re.fullmatch('ublk[bc][0-9]+',path.name):continue
                    meta=path.lstat();key=(meta.st_ino,meta.st_rdev)
                    if path.name in self.before_devices:continue
                    with self.lock:
                        if any(row['path']==str(path) and tuple(row['identity'])==key for row in self.permissions):continue
                    fd=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
                    try:
                        now=os.fstat(fd)
                        if (now.st_ino,now.st_rdev)!=key or not (stat.S_ISBLK(now.st_mode) or stat.S_ISCHR(now.st_mode)):continue
                        check=subprocess.run([str(self.helper),path.name],capture_output=True,timeout=3)
                        if check.returncode!=0:continue  # Unknown/other owner: never grant.
                        need(check.stdout.strip()==b'1204:1205','Unexpected kernel ownership reply')
                        need((path.stat().st_ino,path.stat().st_rdev)==key,'Device replaced during ownership check')
                        target=f'/proc/{os.getpid()}/fd/{fd}'
                        prior=run(['getfacl','-cpn',target])
                        row={'path':str(path),'identity':list(key),'priorAcl':prior,'state':'grant_intent'}
                        with self.lock:self.permissions.append(row);atomic(self.work/'device-acls.json',self.permissions)
                        run(['setfacl','-m','u:1204:rw',target]);row['state']='granted'
                        with self.lock:atomic(self.work/'device-acls.json',self.permissions)
                    finally:os.close(fd)
        except BaseException as error:self.permission_error='New-device permission guard stopped: '+type(error).__name__;self.stop.set()

    def no_foreign_jwk_daemon(self):
        # Do not grant new device access while another jwk daemon can be the
        # creator. Existing nodes are always excluded regardless of ownership.
        cg=Path('/proc',str(self.pid),'cgroup').read_text()
        for p in Path('/proc').iterdir():
            if not p.name.isdigit():continue
            try:
                if 'uvm-ublk' not in (p/'comm').read_text():continue
                ident=MEM.identity(int(p.name))
                if ident['uids']==[1204]*4:need((p/'cgroup').read_text()==cg,'Other jwk ublk daemon active; no device permission changes')
            except (FileNotFoundError,ProcessLookupError):continue

    def process_row(self,pid,role):
        ident=MEM.identity(pid);p=Path('/proc')/str(pid);st=(p/'exe').stat()
        need(len(set(ident['uids']))==1 and ident['uids'][0] in (0,1204),'Unexpected process owner')
        return {'pid':pid,'startTicks':ident['startTicks'],'uid':ident['uids'][0],'role':role,
                'executable':os.readlink(p/'exe'),'exeDev':st.st_dev,'exeInode':st.st_ino}

    def observe(self):
        self.guard();expected={j['sandboxId']:j for j in self.jobs};found={};runtime_cg=Path('/proc',str(self.pid),'cgroup').read_text()
        fcmeta=Path(self.app.plan['binaries']['deps/firecracker/1.15.1-patch-v3/firecracker']['path']).stat()
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():continue
            try:
                if (proc/'cgroup').read_text()!=runtime_cg:continue
                st=(proc/'exe').stat()
                if (st.st_dev,st.st_ino)!=(fcmeta.st_dev,fcmeta.st_ino):continue
                err=Path(os.readlink(proc/'fd/2'));sid=err.parent.name
                need(sid in expected and sid not in found and err.name=='firecracker-stderr.log','Unexpected FC in owned Runtime')
                cwd=(proc/'cwd').resolve();need(cwd.parent==self.active/'fc' and cwd.name.startswith('agentenv-fc-'),'FC directory differs')
                raw=read(cwd/'overlaybd/image.json');config=json.loads(raw)
                BIND.check_binding(config,self.template['rootfsLayers'],'full',self.index)
                row={'sandboxId':sid,'process':self.process_row(int(proc.name),'fc'),'cwd':str(cwd),'configSha256':digest(raw),'upper':[],'devices':[]}
                for key in ('data','index'):
                    p=Path(config['upper'][key]);p=p if p.is_absolute() else cwd/'overlaybd'/p
                    need(p.resolve()==p and p.is_relative_to(cwd),'Upper escaped Guest directory');m=p.stat()
                    need(m.st_uid==1204 and m.st_nlink==1 and stat.S_ISREG(m.st_mode),'Upper ownership/type differs')
                    row['upper'].append({'path':str(p),'category':'private-upper','identity':MEM.immutable_identity(m),'immutable':False})
                for fd in (proc/'fd').iterdir():
                    try:
                        m=fd.stat()
                        if not stat.S_ISBLK(m.st_mode):continue
                        target=Path(os.readlink(fd))
                        if not re.fullmatch('/dev/ublkb[0-9]+',str(target)):continue
                        h=os.open(target,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
                        try:size=struct.unpack('=Q',fcntl.ioctl(h,0x80081272,b'\0'*8))[0]
                        finally:os.close(h)
                        row['devices'].append({'path':str(target),'inode':m.st_ino,'major':os.major(m.st_rdev),'minor':os.minor(m.st_rdev),'bytes':size,
                            'maxSectorsKiB':int(Path('/sys/class/block',target.name,'queue/max_sectors_kb').read_text())})
                    except FileNotFoundError:continue
                rootdev=(cwd/'user-rootfs').resolve()
                need(any(d['path']==str(rootdev) for d in row['devices']),'FC lacks declared rootfs device')
                need(all(d['maxSectorsKiB']==256 for d in row['devices']),'Actual rootfs/memory I/O limits differ from 256KiB')
                row['rootfsDevice']=str(rootdev);found[sid]=row
            except (FileNotFoundError,ProcessLookupError):continue
        need(set(found)==set(expected),'Not every confirmed Guest has an actual FC/DAX binding')
        upper=[(x['identity']['dev'],x['identity']['inode']) for r in found.values() for x in r['upper']]
        need(len(set(upper))==4,'Private upper aliases across Guests')
        return found

    def file_sample(self,row):
        try:
            fd=os.open(row['path'],os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
            try:FSDAX.validate_fd(fd,os.fstat(fd).st_size,fs_dax=False)
            finally:os.close(fd)
            return MEM.file_sample(row,Path('/home/jwk/agent'),os.sysconf('SC_PAGESIZE'))
        except (OSError,ValueError,TimeoutError) as error:return {'path':row['path'],'category':row['category'],'residentBytes':None,'errorType':type(error).__name__}

    def dax_evidence(self):
        view=self.app.state['steps']['view']['result']['journal'];broker=view['rootfsBroker'];pid=broker['pid']
        # The root view process remains bound; also freeze its broker child identity.
        need(MEM.identity(pid)==self.broker_identity,'DAX broker changed')
        values=[]
        for item in broker['inheritedFiles']:
            fd=os.open(f'/proc/{pid}/fd/{item["fd"]}',os.O_RDONLY|os.O_CLOEXEC)
            try:values.append({'layerDigest':item['replica']['layerDigest'],**FSDAX.validate_fd(fd,item['replica']['fileBytes'])})
            finally:os.close(fd)
        return {'files':values,'ordinaryFileDataPageCacheApplicable':False,'mincoreUsed':False,'publication':view['publication']}

    def collect(self,include_files=False):
        self.guard();begin=time.monotonic_ns()
        values={'node':self.node,'unixNs':time.time_ns(),'beginNs':begin,'hostMemoryBytes':MEM.kib_fields(Path('/proc/meminfo').read_text()),
                'processes':[MEM.process_sample(p) for p in self.processes],'ordinaryFiles':None,'blockDevices':None,
                'uniqueLogicalUbBytes':1811939328,'incrementalPhysicalUbBytes':None,'netSavingsBytes':None,
                'GuestRamOnlyBytes':None,'samplingAtomicAcrossNodes':False,'cacheDropPerformed':False}
        if include_files:
            values['ordinaryFiles']=[self.file_sample(row) for row in self.files]
            values['blockDevices']=[]
            for row in self.devices:
                try:values['blockDevices'].append(MEM.device_sample(row,os.sysconf('SC_PAGESIZE')))
                except (OSError,ValueError,TimeoutError) as e:values['blockDevices'].append({'path':row['path'],'residentBytes':None,'errorType':type(e).__name__})
            values['dax']=self.dax_evidence()
        values['endNs']=time.monotonic_ns();return values

    def launcher(self,argv,**kwargs):
        self.guard();return subprocess.Popen(['nsenter','-t',str(self.pid),'-n','--',*argv],**kwargs)

    def setup_inputs(self):
        self.no_foreign_jwk_daemon()
        source=Path('/home/jwk/agent/deployments/agentenv-lazy-four-32ce41c')
        templates,steps=INPUT.load_inputs(source,self.n,1,read,REPLAY.steps_from);self.template=templates[0];self.steps=steps[0]
        INPUT.check_catalogs(source,templates,read)
        need(self.template['templateId']=='01a15c9e-54d0-7b92-a50b-0b6ec2e9136b' and len(self.steps)==32,'Fixed T1/32-step scope differs')
        self.files=[]
        for layer in self.app.plan['layers']:
            path=Path(layer['source']);self.files.append({'path':str(path),'category':layer['kind']+'-lower-source',
                'identity':MEM.immutable_identity(path.stat()),'immutable':True})
        if self.n=='a':
            p=Path(self.app.plan['image']['path']);self.files.append({'path':str(p),'category':'full-source-image','identity':MEM.immutable_identity(p.stat()),'immutable':True})
        self.broker_identity=MEM.identity(self.app.state['steps']['view']['result']['journal']['rootfsBroker']['pid'])
        self.processes=[self.process_row(self.pid,'runtime'),self.process_row(os.getpid(),'collector'),self.process_row(self.broker_identity['pid'],'dax-broker')]
        for label in ('sdk','view'):
            row=self.app.bound(label);self.processes.append(self.process_row(row['pid'],label))
        self.dax_evidence()
        # Binary hashing only, no payload reads or rebuilding.
        for entry in self.app.plan['binaries'].values():need(digest(read(Path(entry['path']),128*1024**2))==entry['sha256'],'Reused binary digest differs')
        self.env={'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','PATH':'/usr/sbin:/usr/bin:/sbin:/bin',
            'XDG_CONFIG_HOME':str(self.active/'cli'),'LD_LIBRARY_PATH':str(Path(self.app.plan['sourceDeployment'])/'native/lib')+':'+str(Path(self.app.plan['sourceDeployment'])/'native/fallback/lib')}

    def repair_catalog_layout(self):
        self.guard()
        old=Path('/var/lib/agentenv-hpd4-full-v1')/self.node
        oldlock=os.open(old/'experiment.lock',os.O_RDWR|os.O_NOFOLLOW)
        fcntl.flock(oldlock,fcntl.LOCK_EX|fcntl.LOCK_NB);self.locks.append(oldlock)
        state_raw=read(old/'cohort.json');diag_raw=read(old/'creation-diagnosis-v1.json')
        previous=self.expected['previousFailure']
        need(digest(state_raw)==previous['cohortSha256'] and digest(diag_raw)==previous['diagnosisSha256'],
             'Previous failure evidence changed; no automatic reconciliation')
        state=json.loads(state_raw);diag=json.loads(diag_raw)
        need(diag['identity']==self.expected['identity'] and diag['runtime']==self.runtime,'Diagnosed process no longer current')
        resolution=snapshot_failure_evidence(diag,state,self.node)
        c=UnixHTTP(self.active/'api.sock',10)
        try:
            c.request('GET','/metrics',headers={'X-API-Key':self.key});r=c.getresponse();raw=r.read(2*1024**2+1)
            need(r.status==200 and len(raw)<=2*1024**2,'Fresh metrics unavailable')
            fresh=dict(diag,httpMetrics={'status':200,'lines':raw.decode().splitlines()})
            snapshot_failure_evidence(fresh,state,self.node)
        finally:c.close()
        need(self.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'New consumers appeared since diagnosis')
        self.no_foreign_jwk_daemon()
        need(not list((self.active/'fc').glob('agentenv-fc-*')),'FC work directories require inspection before resuming')
        resolution.update(previousCohortSha256=digest(state_raw),diagnosisSha256=digest(diag_raw),runtime=self.runtime)
        # This separate record resolves the known failed request; the original
        # request journal/failed archive are never cleared, edited or removed.
        atomic(self.work/'prior-request-resolution.json',resolution)
        root=self.app.work/'seed/repository'
        need(root.resolve()==root and root.stat().st_uid==1204,'Unexpected experiment seed directory')
        relative=('catalog','catalog/aliases','catalog/records','volumes','volumes/aliases','volumes/records','snapshots')
        catalog=root/'catalog/records'/('01a15c9e-54d0-7b92-a50b-0b6ec2e9136b.json')
        before=digest(read(catalog));created=[]
        for rel in relative:
            p=root/rel
            need(p.parent.resolve()==p.parent,'Directory parent redirected')
            if not p.exists():
                # Create only empty directory metadata as jwk in Host namespace.
                # The Runtime sees the same inode through its unchanged RO bind.
                run(['/usr/bin/setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all',
                    '--ambient-caps=-all','--bounding-set=-all','--no-new-privs','/usr/bin/mkdir','-m','700','--',p])
                created.append(str(p))
            need(p.resolve()==p and p.is_dir() and p.stat().st_uid==1204,'Unexpected catalog layout entry')
        need(digest(read(catalog))==before,'Catalog record changed')
        check="""import os,sys,json,hashlib
from pathlib import Path
root=Path(sys.argv[1]);names=json.loads(sys.argv[2]);expected=json.loads(sys.argv[3]);out=[]
assert os.getuid()==1204
for name in names:
 p=root/name
 assert p.is_dir() and p.stat().st_uid==1204
 assert [p.stat().st_dev,p.stat().st_ino]==expected[name]
 os.makedirs(p,exist_ok=True)
 out.append({'path':str(p),'readonly':bool(os.statvfs(p).f_flag & os.ST_RDONLY)})
assert all(x['readonly'] for x in out if '/catalog' in x['path'] or x['path'].endswith('/snapshots'))
print(json.dumps(out))
"""
        identities={rel:[(root/rel).stat().st_dev,(root/rel).stat().st_ino] for rel in relative}
        visible=json.loads(run(['nsenter','-t',str(self.pid),'-m','--','/usr/bin/setpriv','--reuid=1204','--regid=1205',
            '--clear-groups','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs',
            '/usr/bin/python3','-I','-B','-c',check,str(root),json.dumps(relative),json.dumps(identities)]))
        need(read(old/'cohort.json')==state_raw,'Old request journal changed')
        self.event('catalog-repaired',{'createdEmptyDirectories':created,'runtimeVisible':visible,'catalogSha256':before,
            'priorRequestResolution':resolution,'remounted':False,'servicesRestarted':False,'SDKCalled':False})

    def execute(self):
        need(self.transport.timestamp(self.approval['notBefore'])<=time.time()<self.transport.timestamp(self.approval['expiresAt']),'Start approval expired')
        need(not (self.work/'cohort.json').exists() and not (self.work/'started.json').exists(),'Prior run exists; never repeat creates')
        self.repair_catalog_layout()
        self.setup_inputs();need(self.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Runtime is not empty')
        atomic(self.work/'started.json',{'boot':self.expected['identity'],'entrySha256':self.pin,'startUnixNs':time.time_ns()})
        atomic(self.work/'before-guests.json',self.collect(True))
        ready={'unixNs':time.time_ns(),'sdkObject':self.expected['sharedObjectName'],'replaySha256':self.template['replaySha256']}
        self.event('admitted',ready);peer=self.peer_event('admitted')
        need(peer['sdkObject']==ready['sdkObject'] and peer['replaySha256']==ready['replaySha256'],'Peer source/replay differs')
        watcher=threading.Thread(target=self.owner_permissions,name='owned-new-device-acl');watcher.start()
        try:
            case_id=hashlib.sha256((RUN+self.node).encode()).hexdigest()[:32]
            self.case=ENGINE.Cohort(self.api,{'version':1,'phase':'prepared','sandboxIds':[],'openRequests':[],'outcomeUncertain':False},
                lambda state:atomic(self.work/'cohort.json',state),None,None,
                lambda _:need(MEM.kib_fields(Path('/proc/meminfo').read_text())['MemAvailable']>=6*1024**3,'Insufficient available memory'),None,
                run_id=case_id,mutation_guard=self.guard)
            for slot in (0,1):
                sid=self.case.create('/v2/sandboxes',{'templateID':self.template['templateId'],'timeout':7200,'secure':True,'autoPause':False,
                    'allow_internet_access':False,'metadata':{'cow_batch':case_id,'full_compare_batch':RUN,'slot':str(slot)}})
                self.jobs.append({'sandboxId':sid,'slot':slot,'templateId':self.template['templateId'],'replaySha256':self.template['replaySha256'],
                    'catalogSha256':self.template['catalogSha256'],'lowerContentSha256':BIND.content_signature(self.template['rootfsLayers']),
                    'resources':self.template['resources'],'steps':self.steps})
            self.bindings=self.observe();atomic(self.work/'bindings.json',self.bindings)
            # All four local upper data/index files and FC block FDs are now
            # bound. No permission worker remains during replay or destruction.
            self.stop.set();watcher.join(timeout=10);need(not watcher.is_alive(),'Permission worker did not exit');self.guard()
            devices={}
            for binding in self.bindings.values():
                self.processes.append(binding['process']);self.files.extend(binding['upper'])
                for d in binding['devices']:devices[(d['major'],d['minor'])]=d
            self.devices=list(devices.values())
            # Include daemon(s) only in this Runtime cgroup, without changing them.
            cg=Path('/proc',str(self.pid),'cgroup').read_text()
            daemon=Path(self.app.plan['binaries']['bin/uvm-ublk-daemon']['path']).stat()
            for proc in Path('/proc').iterdir():
                if not proc.name.isdigit():continue
                try:
                    st=(proc/'exe').stat()
                    if (st.st_dev,st.st_ino)==(daemon.st_dev,daemon.st_ino) and (proc/'cgroup').read_text()==cg:self.processes.append(self.process_row(int(proc.name),'daemon'))
                except (FileNotFoundError,ProcessLookupError):continue
            need(any(p['role']=='daemon' for p in self.processes),'Actual daemon not bound to owned Runtime')
            self.event('guests-ready',{'unixNs':time.time_ns(),'sandboxIds':[j['sandboxId'] for j in self.jobs],'bindings':self.bindings})
            peer=self.peer_event('guests-ready')
            local=json.loads(read(self.work/'guests-ready.json'))['data']
            start=max(peer['unixNs'],local['unixNs'])/1e9+45
            need(time.time()<start,'Missed agreed replay window; do not silently desynchronize')
            while time.time()<start:self.guard();time.sleep(min(.5,start-time.time()))
            atomic(self.work/'replay-window.json',{'plannedUnixSeconds':start,'actualUnixNs':time.time_ns(),'clockSynchronizationIndependentProof':False})
            report=GROUP.NativeGroupReplay(self.work,self.active/'aenv-host-dax',self.env,self.jobs,REPLAY.shell_command,self.case.owned,
                self.collect,lambda value:atomic(self.work/'replay.json',value),launcher=self.launcher).run()
            need(report['status']=='LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED' and report['pendingCommands']==0,'Replay incomplete; retain journal')
            self.event('replay-complete',{'completedCommands':report['completedCommands'],'nonzeroCommands':report['nonzeroCommands'],'unixNs':time.time_ns()})
            self.peer_event('replay-complete',1800)
            self.performance()
            self.release()
            self.event('completed',{'status':'FULL_DAX_LOCAL_TWO_GUESTS_REPLAYED_RELEASED_BACKING_HELD','completedCommands':report['completedCommands'],
                'nonzeroCommands':report['nonzeroCommands'],'SDKAllocationChanged':False,'servicesRestarted':False,
                'logicalUbBytes':1811939328,'incrementalPhysicalUbBytes':None,'netSavingsBytes':None,'baselineDeferred':True})
        finally:self.stop.set();watcher.join(timeout=10)

    def performance(self):
        # Main workload cache endpoint is already frozen. This separate window
        # measures actual pread calls; no claim of cold reads or pure UB bandwidth.
        rows=[];broker=self.app.state['steps']['view']['result']['journal']['rootfsBroker']
        for item in broker['inheritedFiles']:
            fd=os.open(f'/proc/{broker["pid"]}/fd/{item["fd"]}',os.O_RDONLY|os.O_CLOEXEC)
            try:
                FSDAX.validate_fd(fd,item['replica']['fileBytes'])
                limit=min(4*1024**2,item['replica']['fileBytes'])
                for passno in (0,1):
                    for offset in range(0,limit,262144):
                        before=time.monotonic_ns();data=os.pread(fd,min(262144,limit-offset),offset);after=time.monotonic_ns()
                        need(len(data)==min(262144,limit-offset),'DAX short read')
                        rows.append({'digest':item['replica']['layerDigest'],'pass':passno,'offset':offset,'bytes':len(data),'startNs':before,'endNs':after})
            finally:os.close(fd)
        atomic(self.work/'host-dax-pread.json',{'reads':rows,'scope':'Host DAX pread including caller allocation/copy','cacheStateInferred':False,'bufferBoundBytes':262144})
        probe=base64.b64encode(PROBE).decode()
        action='umask 077; d=$(/agentenv/bin/busybox mktemp -d /tmp/hpd4-read.XXXXXX) || exit 1; printf %s '+shlex.quote(probe)+' | /agentenv/bin/busybox base64 -d > "$d/probe" && /agentenv/bin/busybox chmod 700 "$d/probe" && "$d/probe" --max-bytes 67108864 --block-bytes 262144 -- "$(/agentenv/bin/busybox readlink -f /bin/bash)"; rc=$?; /agentenv/bin/busybox rm -f "$d/probe"; /agentenv/bin/busybox rmdir "$d"; exit "$rc"'
        # Reuse exact Guest300/CLI330 execution contract in a separate directory.
        p=self.work/'performance';p.mkdir(mode=0o700);jobs=[dict(j,steps=[{'action':action,'delay':0}]) for j in self.jobs]
        perf=GROUP.NativeGroupReplay(p,self.active/'aenv-host-dax',self.env,jobs,REPLAY.shell_command,self.case.owned,
            self.collect,lambda value:atomic(p/'replay.json',value),launcher=self.launcher).run()
        need(perf['status']=='LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED' and perf['nonzeroCommands']==0,'Read probe failed')
        for i in range(2):
            data=read(p/'commands'/f'{i}-0.stdout',4*1024**2).decode()
            parsed=[json.loads(line) for line in data.splitlines() if line.startswith('{"version":1,"scope":"Guest pread')]
            need(len(parsed)==1 and parsed[0]['state']=='completed' and parsed[0]['actualBytes']>0,'Missing actual Guest pread evidence')
            atomic(p/f'guest-{i}.json',parsed[0])

    def release(self):
        self.guard();need(self.case is not None and not self.case.state['openRequests'],'Uncertain operation: explicit reconciliation required')
        for sid in list(self.case.state['sandboxIds']):self.case.delete(sid)
        deadline=time.monotonic()+30
        for value in self.bindings.values():
            p=value['process']
            while Path('/proc',str(p['pid'])).exists():
                if MEM.identity(p['pid'])['startTicks']!=p['startTicks']:break
                need(time.monotonic()<deadline,'Owned FC exit unconfirmed');time.sleep(.2)
        # Device paths can be reused; confirm original inode is gone, not merely
        # that a path name currently exists. Never alter replacement devices.
        for row in self.permissions:
            p=Path(row['path'])
            need(not p.exists() or (p.stat().st_ino,p.stat().st_rdev)!=tuple(row['identity']),'Owned device retained; do not claim complete release')
        atomic(self.work/'release.json',{'ownedGuestsReleased':True,'deviceGrantsGone':True,'backingHeld':True,'modulesRestored':False})

    def upload(self):
        # Only experiment-owned files, bounded archive, no tokens/environment.
        import io,tarfile
        frozen=self.work/'report.tar.gz'
        if frozen.exists():raw=read(frozen,24*1024**2)
        else:
            out=io.BytesIO()
            with tarfile.open(fileobj=out,mode='w:gz') as tar:
                for path in sorted(self.work.rglob('*')):
                    if not path.is_file() or path.is_symlink() or path.name in ('experiment.lock','archive.json','report.tar.gz'):continue
                    need(path.stat().st_size<=256*1024**2,'Report file too large');tar.add(path,arcname=str(path.relative_to(self.work)),recursive=False)
            raw=out.getvalue();need(len(raw)<=24*1024**2,'Report exceeds private transport bound')
            with frozen.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        chunks=[]
        for n,start in enumerate(range(0,len(raw),384*1024)):
            piece=raw[start:start+384*1024];key=f'four-guest/{SESSION}/{RUN}/{self.node}/artifacts/{digest(raw)}/{n}.json'
            self.results.immutable_result(RESULTS,1438089386,'main',key,wire({'sha256':digest(piece),'dataBase64':base64.b64encode(piece).decode()}));chunks.append({'path':key,'sha256':digest(piece),'bytes':len(piece)})
        self.event('archive',{'sha256':digest(raw),'bytes':len(raw),'chunks':chunks})

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('run','collect','cleanup-known'));args=parser.parse_args()
    os.umask(0o077);ctx=Context()
    try:
        if args.action=='run':ctx.execute()
        elif args.action=='cleanup-known':
            state=json.loads(read(ctx.work/'cohort.json'));need(not state['openRequests'],'Unconfirmed API request; do not clear or retry')
            # Explicit recovery deletes only metadata-verified known Guests.
            case=object.__new__(ENGINE.Cohort);case.api=ctx.api;case.state=state;case.run_id=state['runId'];case.mutation_guard=ctx.guard
            case.persist=lambda value:atomic(ctx.work/'cohort.json',value);ctx.case=case
            for sid in list(state['sandboxIds']):case.delete(sid)
            ctx.event('cleanup-known',{'knownGuestDeletesAcknowledged':True,'resourceReleaseFullyChecked':False,'backingHeld':True})
    except BaseException as error:
        info={'status':'FULL_DAX_FOUR_STOPPED_PRESERVE_STATE','errorType':type(error).__name__,
              'reason':str(error)[:500] if isinstance(error,RuntimeError) else type(error).__name__,'automaticRetry':False,'backingHeld':True}
        atomic(ctx.work/'failure-local.json',info)
        try:ctx.event('failed',info)
        except Exception:pass
        print(json.dumps(info),flush=True);raise
    finally:
        try:ctx.upload()
        except Exception as error:print('PRIVATE_REPORT_UPLOAD_PENDING='+type(error).__name__,flush=True)


BUNDLED={'REPLAY': {'sha256': '2e0f31142d8fca47724f319c96aae8758f4b0a07d051614a1d92537a9f23a259', 'z64': 'eNp1VduO2zYQfd+vmAoJJMGS17tB8iBFCPLgBgs0QbEJigK2YdDSeM21RKokfUvTf++QlGwh6/hBpuZy5nJmKN60Uhl41lIkChO9qfF4U+EaBGIVyW0CDWrNnjDOboB+nDTSgNxmoBjXCI87YXiDU6WkinrbGw8hVcNq/h2XrDRcisj/dUhBEDyIClukhzDAm7bGhk7M2oBcg9kgKNxzPGBFBzJTWKVYcSMVlFLsyZhMxwTkAI06ZQepKl24Ksa6rbnpYzoLPJbYGviL1TufcKbQ7JQAb9QX6EBm2f3it2IWaqOWCtualbj0scNkKAwXV0BsKq3U3Ap0MXOAY04VHKN1zZ7i0R2sqQh7Bi4gCtNU1tWSYAk8TQUe3Dle5Hubaw8x4wvnx63TGX8xrC26FJfY9h7dMb6So2XIKN5ELkRHStcBJxprw5TRB242UThXcxHGmVMU7jm7zxZnH6yve/3sczfwOXsQtb+OkqX3V8MMnF663F1cusKdxgm7jtZcm6hhbWR7kHhhHA9n3Mtmk2sEOxaSveXhO2+jMxc9UNbzVexvBln4wXyWXETOoFsUbbDVy7WSTaTYoaOiYoYVdi/HtWSVdppcyQMNwyI3qBouWF18kQIvGRlsbErWdRYaxZ6xpIE90YwOu26L45oLYkqUGFmvpOKliYEwrijHT2ii0FcfxglN5sWS1LNetSDuFXUjzmg7DRddw+3PWxTXzYe5eR2VfEAVxX459G7VcEObseaC6w0dKqqaSD93wXvlK4Vse0arsGan4lKAe1/ayypMJpeg7qIzpxYjZ+BjcmGSNfWdesJEBZP3hVO+f/NuMknCB0E08wouHfbBwguqJWrMWnu7Rf/2FWe/uhETn1yYuZhdIv95NJefhUvCadOaE206ljvDVjUOEghpNvyMOdO+M918bbCul6VsGiqmi5k0TG1R9de6EKiKQKOBkYSWt7hmvM4plvs8/Pnx0/SxKJk5Sz5//PJS+Onh2/Kl9I/p169F+vvj3zmUFaQp3MKPH6TkBu7u3+YQjAaL1RURukwwh1v6nAiDYn+74uJ2tdOnlTyCJVHuDKQavk0fP0O6hbfwZjIBb8X0BtIa0hLCkV+5f3bS0DDbKuNRQInICotXH3JoFVG9hnA+F8HIt2QUwGtN7yHMg1fWcB7kPt1J8D+2JGG+'}, 'GROUP': {'sha256': '49c650a4fd7383d4cf24876b440bb2dbd9460719b4ef980778ed688ee9a9e095', 'z64': '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'}, 'ENGINE': {'sha256': '5d0cd8d4cf45b8301532517af832710c3928458f20c1cc64b0991500ddb1b89d', 'z64': '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'}, 'MEM': {'sha256': '8efd02869237d0d9e960706912b2f994f58d3012414b2478c8ef187421781ce2', 'z64': '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'}, 'INPUT': {'sha256': '4def90ce7b150ef2d9fc71beb6c3e99b9d416be7130ad2ce37dc0509df066260', 'z64': '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'}, 'BIND': {'sha256': '8e19fa3e9e95963152fb689ee526b5d4a564eeb1d2c2233f792f1609ac7d6c4f', 'z64': 'eNplU0uP2yAQvu+vmBu2hLJtpfYQiUpd9aFeWinSnqJoRcw4oSHgAt7d7Gr/eweM7aTBFzMM8z1m0MfO+Qh7GfZGb/mf4OzNjcIWLKKq3IE/7U/18gZoaQq6CO6w9FIHhFVvoz7iN++dr1LacLFxNqKND0HvrIy9x8rIE/pQqnikmB0BF2EvP3z8VCXcheqPXajWlV8zpXcYIttw+g/6BdmmhtZ58KAtDPU2PGAnvYzOB1ExTt+S1fUCbeMUVvS3x+ehTjVS22NzeNhqq7TdVUS01TuOzx02ERV/lF5LGzkd43Nhm10oBwm6Ys7rnbbSEFzbG8NqkFaBQVvqrZlxT0SPGAuRwmP9+vM7zlbOxTZAaFyHoHTbpsy6GNMG8fqWbC6AQsxogIYsfyU7svqvxZ+ln23JvNfMY2d0I4nA29i2uV6mvMyqSvojMdDOso0Q77OUEg9RRkxRKijViU0yE88i7Qqx5sB+2kdptLpVfY5GhAQ6lC1SE2XZxF4a/kS8MIHCi+6uLJyaU9oxtWS4Pc+JEEOhOZL5jmnDCM1Jw56zL/kcMtw4uLfOK9pdNufKyKkxyzM+ix3GivVbGgod4JezyNnvkgg/euIFvR0lmRP0AQPc351hpC7PUstYoKeZRpGMzwj/S60vLmQ+061EJL3aRCZbMp2smTQkfIWdC5oe0ek77beyOZB3dIl2Ac9MnLUJMdXgF8h5sRX+7bWnnt7fQXlqo5lAfe/QH3UM0I5o9T8oToGe'}}
for name,item in BUNDLED.items():
    raw=zlib.decompress(base64.b64decode(item['z64']));need(digest(raw)==item['sha256'],'Embedded module differs')
    globals()[name]=load_module(name,raw)
PROBE=zlib.decompress(base64.b64decode('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'))
need(digest(PROBE)=='6313625749f5addd473de374038a75cf888dfbec0296bb2f612abb38939158bc','Guest probe changed')
sys.path.insert(0,str(BASE/'code'))
# FSDAX is imported only on the approved target, not during local logic tests.
FSDAX=None

if __name__=='__main__':
    from aenv_ub_provider import fsdax as FSDAX
    main()

