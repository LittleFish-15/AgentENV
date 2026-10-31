"""Two-node, read-only SDK/DAX measurements; no Guest or service changes.

SDK timing includes the existing bytewise ABI3 wrapper and caller copies.
It is not a bare-load latency or a hardware peak-bandwidth measurement.
"""
import base64,ctypes,errno,fcntl,grp,hashlib,http.client,io,json,os,platform,re,select,socket,stat,struct,subprocess,sys,tarfile,threading,time,types,zlib
from pathlib import Path
PAYLOADS={'sdk': {'bytes': 4395, 'sha256': 'd7fe2d35aeedb2423cbed387c284a71b5336fe24a221b91aa9e7d30cac0189f3', 'z64': 'eNqlV1Fz2zYMfvev4PwiqVW1ruv6kNS7a9rsmmuX5ZpmL72cjpIom61MKSTl1svlvw+kRImkbCfZ9GKTAkDgA/CBms/nF21W0fzZiuCCcHT57gPCBW4k4ceI1ajhdIMl0fsFETmnjaw5kjiriEjm8/mMrpuaS5TLbUPErOT1GjVYriqaof7VBSxns7fvr84/oAX65fmLl+iJ/pnN8goLgS6Lb6ec1zz81DJJ10QvoqMZgqcgJUpTyqhM01CQqoxR3RCOJa1ZjHjei6lHtPAijJJBvAyU27eD/B0qMa1IcQR6i1ue3wXRqAymE8uyXvMcHHaOm82M0+ewtyEnOP9GWLHXV4CBY76NEWWiIbkyk1Z0TeXixW+vAAaNih2DOlZht+gRTd6++/gxFJKHvakomggnmLBN2mYpzmi6IVzAKQnmS20ALH25fpgKJ0KpjGfnEIwcdGl5UD2M0E8L9OsYi3o4poKgv3HVdlkNg6sTU2DozckZWlOxxjJfBQfCymtW0mXLScrJ0o9tcDVfYZ42148wc0+82sAaNw1ly10w+ikFEX/LVchrgAovSZpt0zr7CoKgcnvnCuGqqnNdb2kO/9XBz8cUxOgmRo3ncTyuWli+emltbGpapM1goCBQvV05K8u3TrKC/mwSHE1whYOvY1caoNktGCs/++2Lv87OP59+Cmk02bqJfIscSEiZ7MPUZ6LgO6edS/a2q9iy3hmqFApyIBAlUFKGK/qPfu2bUu1Ld70d81QCAzK8JjGCQhSQdAfWBLxdizByG6FkAPeSSCyhlU1pgiumOAP0VNuMPK2h1mO1GCtWnQw4zwbiUcUyJcgnSs5yRTPaPW4M6lHYqdsMMLyE6SBV6GGXtSFPXtwwQJjsmDi9eP/m8nRh87HhYQiuasVq8Zm3xDmO57v4ZBgY7igYwTD57wHhpIEZh32enbTaUxhPXssqVMe+GEwlXf+eQ8YSwvK6IGE0vuxJ42QribC8GktL++W7051l1Z+l6nPXEJha7DbkqwRGfHDYsg8eu1jFSKVTjfnFH7gSxDpjhVlRQfEbOvPYKIwmfBRGbgFOqFkd/2hk3cbd9ShvTBijV9mWkzLsovB3TUzWlJ1WMDhhKhdlcAEAh1KL28G1xa1ZJxs1+/ZVuAqHFIDIec2IXfedd52y2wGjir6A/NkB0ifPVnOZxBlmibLBirCz9ZiG06TfNZul1PtEhY4DKXoEctiVM/R6gVxo1M7OcXrfReKMgT4tfm5qIZ/lQEKalfp8jMVJfuSEFMIazUibD/wsJH4qke/qfdP8y7SEr/cbUdepdh3usdUJwxiJ0O//DZ8rRm8A3v6iMcFDw6Yq2QImawuYDcc6exiKiReoWW0FhFShm7aW2AKNE9ly1mM3Esk4ew9zb8dR1qQ+SK02E1a1IIowhE+i6nIPdOdd1dSwNvXJ3DZwEZR8ezRhlL409KGh21EKyEaiU/2j0MMCEQX91IrxzPSdus5r0chpIyO2K7P2p1EYHKMg+VpTFhoVGyFzuzkwZIYLUOR/0PR8sveDJus+eAzV+OaH13plJkV3ssJQEZdnIkZ6wIz+q/uEucmUpSDqfltD+NZZ5lOkt9kTznP0upNUnKK/rB7KIb2dDJQL+NU3mjE1dSutGaeYhqSQQsUVWVuW8NHZ+bcTih7x/pLkwGKiA/smRL+94FXC8fcRHH3J8tApsMQPAqciLNTC/xeg/qp3KOBOZE/Eh7DUDsajr37v+2UN4ar4rJCPppPP9a37XHB82zEth4JVM3v2L1INTRc='}, 'worker': {'bytes': 7446, 'sha256': '4ed297ff2bf6b6e17fe48af74d43f4601ec8345ee541ddd992324cf62288147a', 'z64': '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'}}
SESSION='relay-20261029-0d032371'
RUN='ub-host-read-20261031-r1'
RESULTS='LittleFish-15/AgentENV-relay-results'
ROOT=Path('/home/jwk/root/ub-read-perf-v1')
ROOT_ENTRY_SHA='f41f111a5d92d9ba373f34b65d7686b02a0c63ce6d11e114ab2be0b5ea98357d'
MIB=1048576
META_PREFIX=struct.Struct('<BBIII52s16sQQQ16s16sQI52s')


def need(ok,why):
    if not ok:raise RuntimeError(why)


def wire(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def digest(x):return hashlib.sha256(x).hexdigest()


def source(name):
    row=PAYLOADS[name];d=zlib.decompressobj();raw=d.decompress(base64.b64decode(row['z64']),row['bytes']+1)
    need(d.eof and not d.unused_data and not d.unconsumed_tail and len(raw)==row['bytes'] and digest(raw)==row['sha256'],'Checked payload changed')
    return raw


def read(path,limit=2*1024**2):
    path=Path(path);need(path.resolve(strict=True)==path,'Redirected metadata input')
    with path.open('rb') as f:
        s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_uid in (0,1204) and s.st_size<=limit,'Metadata owner/type/size differs')
        raw=f.read(limit+1)
    need(len(raw)<=limit,'Input exceeded bound');return raw


def atomic(path,x):
    tmp=path.with_name(path.name+'.next');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(wire(x));f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)


def current_identity():
    return {'hostname':platform.node(),'machineId':Path('/etc/machine-id').read_text().strip(),
            'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel':platform.release(),'architecture':platform.machine()}


def load_module(name,raw):
    m=types.ModuleType(name);m.__file__='<checked-'+name+'>';sys.modules[name]=m
    exec(compile(raw,m.__file__,'exec'),m.__dict__);return m


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self,path):super().__init__('localhost',timeout=10);self.path=path
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(10);self.sock.connect(str(self.path))


def classify(rows):
    kinds={r.get('kind') for r in rows}
    return 'remote' if kinds=={'import'} else ('local' if kinds=={'export'} else 'unknown')


def verify_library(path,expected):
    size=path.stat().st_size
    need(0<size<=16*1024**2,'Existing library exceeds reviewed bound')
    need(file_digest(path,size)==expected,'Existing library bytes differ')


class Experiment:
    def __init__(self,spec):
        need(os.getuid()==os.geteuid()==0,'Run through the root unified entry')
        self.spec=spec;self.node=spec['node'];self.peer='node-b' if self.node=='node-a' else 'node-a'
        self.pin=digest(Path(__file__).read_bytes());self.worker=None;self.pending=b'';self.daxfd=None
        self.stop=threading.Event();self.sampler_error=None;self.sampler=None;self.phase='preflight';self.measurements=[]
        self.createdWork=False
        self.identity=current_identity();need(self.identity==spec['identity'],'Node boot changed')
        if not ROOT.exists():ROOT.mkdir(mode=0o700)
        need(ROOT.resolve()==ROOT and ROOT.stat().st_uid==0 and not ROOT.stat().st_mode&0o077,'Unsafe root experiment directory')
        self.work=ROOT/self.node;need(not self.work.exists(),'Prior measurement exists; do not rerun SDK work')
        self.work.mkdir(mode=0o700)
        self.createdWork=True
        self.lock=os.open(self.work/'experiment.lock',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        entry=Path('/home/jwk/root/relay/entry.py');raw=read(entry,256*1024)
        need(digest(raw)==ROOT_ENTRY_SHA and entry.stat().st_uid==0,'Unified API implementation differs')
        api=load_module('ub_perf_transport',raw).API;self.api=api
        credentials=Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json')
        need(not credentials.stat().st_mode&0o077,'Credential permissions differ')
        tokens=json.loads(read(credentials,8192))
        self.results=api.GitHub(tokens['resultToken']);self.results.private_repo(RESULTS,1438089386)
        self.plan=json.loads(read(Path(spec['planPath'])));need(digest(read(Path(spec['planPath'])))==spec['planSha256'],'Preparation plan differs')
        self.journal=json.loads(read(Path(spec['viewJournalPath'])))
        need(self.journal['phase']=='rootfs_broker_ready' and self.journal['publication']['manifestSha256']==spec['manifestSha256']
             and self.journal['bootId']==self.identity['bootId'],
             'DAX view publication differs')
        self.broker=self.journal['rootfsBroker'];self.broker_pid=self.broker['pid']
        self.guard()
        parent=Path('/proc',str(self.broker_pid));fields=(parent/'stat').read_text().rsplit(')',1)[1].split()
        need(int(fields[1])==spec['processes']['view']['pid'] and (parent/'cgroup').read_text()==Path('/proc',str(spec['processes']['view']['pid']),'cgroup').read_text(),
             'DAX broker is not the retained view child')
        self.broker_ticks=fields[19]
        self.procrows=[]
        for role,row in {**spec['processes'],'broker':{'pid':self.broker_pid,'startTicks':self.broker_ticks,'uid':1204},
                         'collector':{'pid':os.getpid(),'startTicks':process_identity(os.getpid()),'uid':0}}.items():
            p=Path('/proc',str(row['pid']));m=(p/'exe').stat()
            self.procrows.append({**row,'role':role,'executable':os.readlink(p/'exe'),'exeDev':m.st_dev,'exeInode':m.st_ino})
        # Validate every real DAX FD; only the largest layer is the timed L2 set.
        observed=[]
        for row in self.broker['inheritedFiles']:
            fd=os.open('/proc/'+str(self.broker_pid)+'/fd/'+str(row['fd']),os.O_RDONLY|os.O_CLOEXEC)
            try:observed.append(validate_fd(fd,row['replica']['fileBytes']))
            finally:os.close(fd)
        chosen=max(self.broker['inheritedFiles'],key=lambda r:r['replica']['fileBytes'])
        self.daxfd=os.open('/proc/'+str(self.broker_pid)+'/fd/'+str(chosen['fd']),os.O_RDONLY|os.O_CLOEXEC)
        self.dax=validate_fd(self.daxfd,chosen['replica']['fileBytes']);self.dax['layerDigest']=chosen['replica']['layerDigest']
        self.files=[]
        for row in self.plan['layers']:
            p=Path(row['source'])
            try:meta=immutable_identity(p.stat())
            except FileNotFoundError:meta=None
            self.files.append({'path':str(p),'category':row['kind']+'-lower-source','identity':meta,'immutable':True})
        if self.node=='node-a':
            p=Path(self.plan['image']['path'])
            try:meta=immutable_identity(p.stat())
            except FileNotFoundError:meta=None
            self.files.append({'path':str(p),'category':'full-source-image','identity':meta,'immutable':True})
        # Use only GET on the existing private API socket, with its local key.
        import tomllib
        key=tomllib.loads(read(Path(spec['active'])/'cli/aenv/credentials').decode())['api_key']
        c=UnixHTTP(Path(spec['active'])/'api.sock')
        try:
            c.request('GET','/v2/sandboxes?limit=1',headers={'X-API-Key':key});r=c.getresponse();body=r.read(65536)
            need(r.status==200 and json.loads(body)==[],'Retained Runtime has consumers; do not add measurement load')
        finally:c.close()
        ubse=int(subprocess.run(['systemctl','show','ubse.service','--property=MainPID','--value'],capture_output=True,check=True,text=True,timeout=15).stdout)
        self.ubse={'pid':ubse,'ticks':process_identity(ubse)}
        schema=engine_schema('/usr/bin/rpm',ubse,self.ubse['ticks']);need(schema.get('attested'),'Engine schema not attested')
        ranges=self.journal['volume']['segments'];sdk=spec['processes']['sdk']
        mappings=region_evidence(sdk['pid'],sdk['startTicks'],ranges,True,None)
        need(all(r.get('provenance',{}).get('globalName')==spec['objectName'] for r in mappings),'SDK region object differs')
        self.provenance={'engineSchema':schema,'mappingEvidence':mappings,'classification':classify(mappings),
            'identity':self.identity,'observedUnixNs':time.time_ns()}
        need(self.provenance['classification']==('remote' if self.node=='node-a' else 'local'),'Physical role changed')
        try:
            clock=subprocess.run(['timedatectl','show','--property=NTPSynchronized','--value'],capture_output=True,text=True,timeout=15)
            synchronized=clock.stdout.strip() if clock.returncode==0 else None
        except (OSError,subprocess.TimeoutExpired):synchronized=None
        topology={}
        for name,path in [('onlineCPUs','/sys/devices/system/cpu/online'),('onlineNUMANodes','/sys/devices/system/node/online')]:
            try:topology[name]=Path(path).read_text().strip()
            except OSError:topology[name]=None
        atomic(self.work/'preflight.json',{'daxFiles':observed,'chosenDax':self.dax,'provenance':self.provenance,'GuestCreated':False,
            'topology':topology,'ntpSynchronizedReported':synchronized,
            'clockOffsetIndependentlyMeasured':False,'probeExplicitlySetsCPUOrNUMAAffinity':False})

    def guard(self):
        need(current_identity()==self.spec['identity'],'Node identity changed')
        need(Path('/sys/module/obmm/srcversion').read_text().strip()=='C2BBB64D75C618180ABA3A6'
             and Path('/sys/module/obmm/parameters/pmem_ro_enable').read_text().strip()=='Y','Candidate module changed')
        for role,row in self.spec['processes'].items():
            need(process_identity(row['pid'])==row['startTicks'],'Retained '+role+' PID changed')
            uidline=next(x for x in Path('/proc',str(row['pid']),'status').read_text().splitlines() if x.startswith('Uid:'))
            need(list(map(int,uidline.split()[1:]))==[row['uid']]*4,'Retained process UID changed')
        if self.sampler_error:raise RuntimeError(self.sampler_error)
        if hasattr(self,'ubse'):need(process_identity(self.ubse['pid'])==self.ubse['ticks'],'UBSE identity changed')

    def event(self,kind,data):
        value={'runId':RUN,'node':self.node,'identity':self.identity,'entrySha256':self.pin,'kind':kind,'data':data}
        raw=wire(value);atomic(self.work/(kind+'.json'),value)
        self.transport_retry('immutable_result',RESULTS,1438089386,'main','ub-locality/'+SESSION+'/'+RUN+'/'+self.node+'/'+kind+'.json',raw)
        print('PHASE='+self.node+':'+kind,flush=True);return data

    def transport_retry(self,name,*args):
        # Only control/result transport is retried, never a read benchmark,
        # initialize/map, or underlying SDK operation.
        for attempt in range(4):
            try:return getattr(self.results,name)(*args)
            except self.api.Network as error:
                if error.status not in (0,409,422,429,500,502,503,504) or attempt==3:raise
                time.sleep(2+attempt)

    def peer_event(self,kind,seconds=900):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            self.guard()
            for key in ('failed',kind):
                code,raw,_=self.transport_retry('contents',RESULTS,'ub-locality/'+SESSION+'/'+RUN+'/'+self.peer+'/'+key+'.json','main')
                need(code in (200,404),'Peer result unavailable')
                if code==200:
                    value=json.loads(raw)
                    need(value['identity']==self.spec['peerIdentity'] and value['entrySha256']==self.pin and value['runId']==RUN and value['kind']==key,'Peer receipt binding differs')
                    need(key!='failed','Peer stopped; keep all existing services');return value['data']
            print('WAIT_PEER='+self.peer+':'+kind,flush=True);time.sleep(5)
        raise RuntimeError('Peer barrier timed out; no automatic retry')

    def sample(self,files=False):
        row={'unixNs':time.time_ns(),'monotonicNs':time.monotonic_ns(),'phase':self.phase,
             'host':kib_fields(Path('/proc/meminfo').read_text()),'loadavg':Path('/proc/loadavg').read_text().strip(),
             'processes':[],'ordinaryFiles':None,'uniqueUbLogicalBytes':1811939328,'physicalUbIncrementBytes':None,'netSavingsBytes':None}
        for proc in self.procrows:
            try:row['processes'].append(process_sample(proc))
            except (OSError,ValueError,RuntimeError) as e:row['processes'].append({'role':proc['role'],'unavailable':type(e).__name__})
        if files:
            row['ordinaryFiles']=[]
            for item in self.files:
                try:
                    need(item['identity'] is not None,'Source file absent at baseline; cache not inferred')
                    fd=os.open(item['path'],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
                    try:validate_fd(fd,os.fstat(fd).st_size,False)
                    finally:os.close(fd)
                    row['ordinaryFiles'].append(file_sample(item,Path('/home/jwk/agent'),os.sysconf('SC_PAGESIZE')))
                except (OSError,ValueError,RuntimeError,TimeoutError) as e:row['ordinaryFiles'].append({'path':item['path'],'category':item['category'],'residentBytes':None,'reason':str(e)[:180]})
        return row

    def sampler_loop(self):
        try:
            i=0
            with (self.work/'observations.jsonl').open('x') as f:
                while not self.stop.is_set():
                    start=time.monotonic();f.write(wire(self.sample(i%15==0)).decode()+'\n');f.flush();i+=1
                    self.stop.wait(max(0,1-(time.monotonic()-start)))
        except BaseException as e:self.sampler_error='Memory sampler failed: '+type(e).__name__

    def receive(self,kind,seconds):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if b'\n' not in self.pending:
                ready,_,_=select.select([self.worker.stdout],[],[],max(0,min(1,end-time.monotonic())))
                if not ready:self.guard();continue
                data=os.read(self.worker.stdout.fileno(),65536)
                need(data,'Measurement worker exited before its reply');self.pending+=data
                need(len(self.pending)<=2*1024**2,'Measurement reply exceeds bound')
                continue
            line,self.pending=self.pending.split(b'\n',1)
            if not line.startswith(b'UBPERF_JSON='):continue
            value=json.loads(line[12:])
            need(value['kind']!='failed','Measurement worker failed: '+str(value.get('reason')))
            need(value['kind']==kind,'Unexpected measurement reply');return value
        raise RuntimeError('Measurement worker reply timeout; no restart')

    def start_worker(self):
        adapter=Path('/home/jwk/agent/r/lazy4-'+self.node[-1]+'-v1/libaenv-ub.so')
        verify_library(adapter,'34ed1c5666b5628cc37b4c75f95a44766b0cd119eb02f0df8c9ce15a54bcdfa0')
        library=Path('/usr/lib64/libubsm_sdk.so').resolve(strict=True)
        verify_library(library,'88686bc4e869c6442eb7d88128a2d3efd82468696c489734fc80b4692ac60223')
        error=(self.work/'worker.stderr').open('xb')
        import resource
        old_limit=resource.getrlimit(resource.RLIMIT_MEMLOCK);limit=4*1024**3
        hard=old_limit[1] if old_limit[1]==resource.RLIM_INFINITY or old_limit[1]>=limit else limit
        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK,(limit,hard))
            self.worker=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',source('worker').decode()],stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=error,pass_fds=(self.daxfd,),user=1204,group=1205,
                extra_groups=[grp.getgrnam('ubsmd').gr_gid],umask=0o077,cwd=self.plan['workDirectory'],
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/home/jwk','LANG':'C.UTF-8'})
        finally:
            resource.setrlimit(resource.RLIMIT_MEMLOCK,old_limit);error.close()
        atomic(self.work/'worker-intent.json',{'pid':self.worker.pid,'globalAllocateAllowed':False,'globalDeleteAllowed':False,
            'processMemlockSoftLimitBytes':limit,'memlockLimitIsNotPhysicalUbQuota':True,'callerMaxBufferBytes':2*1024**2})
        cfg={'sdkSource':source('sdk').decode(),'sdkSourceSha256':PAYLOADS['sdk']['sha256'],'adapter':str(adapter),
             'objectName':self.spec['objectName'],'bytes':1811939328,'sha256':self.spec['imageSha256'],
             'daxFd':self.daxfd,'daxBytes':self.dax['bytes']}
        self.worker.stdin.write(wire(cfg)+b'\n');self.worker.stdin.flush()
        ready=self.receive('ready',300);need(ready['allocationCalls']==0 and ready['sha256']==self.spec['imageSha256'],'Worker source/allocation contract differs')
        self.worker_ready=ready
        rows=region_evidence(ready['pid'],ready['startTicks'],ready['segments'],True,None)
        need(all(r.get('provenance',{}).get('globalName')==self.spec['objectName'] for r in rows),'Timed worker maps a different UB object')
        self.worker_source={'engineSchema':self.provenance['engineSchema'],'mappingEvidence':rows,'classification':classify(rows)}
        need(shared_graph(self.worker_source,self.provenance,1811939328)['matched'] is True,'Timed worker does not match the retained DAX source')
        need(self.worker_source['classification']==self.provenance['classification'],'Timed reader physical role differs')
        atomic(self.work/'worker-provenance.json',self.worker_source)
        p=Path('/proc',str(ready['pid']));m=(p/'exe').stat()
        self.procrows.append({'role':'measurement-worker','pid':ready['pid'],'startTicks':ready['startTicks'],'uid':1204,
                             'executable':os.readlink(p/'exe'),'exeDev':m.st_dev,'exeInode':m.st_ino})
        atomic(self.work/'worker-ready.json',ready)

    def execute(self):
        local=self.event('admitted',{'provenance':self.provenance,'objectName':self.spec['objectName']})
        peer=self.peer_event('admitted');need(peer['objectName']==self.spec['objectName'],'Peer object differs')
        graph=shared_graph(self.provenance,peer['provenance'],1811939328);need(graph['matched'] is True,'Fresh two-node mappings do not match')
        atomic(self.work/'fresh-shared-graph.json',graph);atomic(self.work/'before-worker.json',self.sample(True))
        self.sampler=threading.Thread(target=self.sampler_loop,name='readonly-memory-sampler');self.sampler.start()
        self.start_worker();self.event('worker-ready',{'unixNs':time.time_ns(),'provenance':self.worker_source})
        peer=self.peer_event('worker-ready')
        worker_graph=shared_graph(self.worker_source,peer['provenance'],1811939328)
        need(worker_graph['matched'] is True,'Actual timed readers do not share the same exported contents')
        atomic(self.work/'timed-worker-shared-graph.json',worker_graph)
        for roundno in range(3):
            for owner in ('node-a','node-b','both'):
                for layer in ('sdk','dax'):
                    stage='r'+str(roundno)+'-'+owner+'-'+layer;self.phase=stage;self.guard()
                    local=self.event(stage+'-ready',{'unixNs':time.time_ns()});peer=self.peer_event(stage+'-ready')
                    if owner=='both':
                        start=max(local['unixNs'],peer['unixNs'])/1e9+30
                        need(time.time()<start,'Missed coordinated start; do not silently shift timing')
                        while time.time()<start:time.sleep(min(.25,max(0,start-time.time())))
                    if owner in (self.node,'both'):
                        self.worker.stdin.write(wire({'operation':'measure','layer':layer,'round':roundno,'stage':stage})+b'\n');self.worker.stdin.flush()
                        result=self.receive('measurement',120);need(result['stage']==stage,'Measurement stage differs')
                        atomic(self.work/(stage+'.json'),result);self.measurements.append({'stage':stage,'file':stage+'.json'})
                    self.event(stage+'-done',{'unixNs':time.time_ns(),'activeReader':owner in (self.node,'both')});self.peer_event(stage+'-done')
        after={'engineSchema':self.provenance['engineSchema'],'mappingEvidence':region_evidence(self.worker_ready['pid'],self.worker_ready['startTicks'],self.worker_ready['segments'],True,None)}
        need(shared_graph(after,self.worker_source,1811939328)['matched'] is True,'Timed worker mapping changed during measurement')
        atomic(self.work/'worker-provenance-after.json',after)
        self.worker.stdin.write(wire({'operation':'close'})+b'\n');self.worker.stdin.flush()
        closed=self.receive('closed',60);need(self.worker.wait(timeout=15)==0 and closed['allocationCalls']==0,'Worker closure unconfirmed')
        atomic(self.work/'worker-closed.json',closed)
        self.stop.set();self.sampler.join(10);need(not self.sampler.is_alive(),'Sampler did not exit');self.guard()
        atomic(self.work/'after-worker.json',self.sample(True))
        self.event('completed',{'status':'SDK_AND_HOST_DAX_READ_MEASUREMENTS_COMPLETE_SERVICES_HELD','measurementFiles':self.measurements,
            'sourceGraph':graph,'timedWorkerGraph':worker_graph,'GuestCreated':False,'SDKGlobalAllocateCalled':False,'servicesRestarted':False,
            'physicalUbIncrementBytes':None,'netSavingsBytes':None,'hardwarePeakBandwidth':False,
            'samplingAtomicAcrossNodes':False,'clockSynchronizationIndependentlyVerified':False,
            'crossLayerRangeMatched':False,'rangeNote':'SDK uses UB object prefix; DAX uses the largest lower-file prefix. Compare A/B within each method, not stack-only overhead across methods.',
            'UBWriteBenchmark':'not run: shared base readonly; isolated write object not approved',
            'GuestBenchmarks':'next batch, not run by this entry','globalCacheDropPerformed':False})

    def upload(self):
        frozen=self.work/'report.tar.gz'
        if frozen.exists():raw=read(frozen,24*1024**2)
        else:
            out=io.BytesIO()
            with tarfile.open(fileobj=out,mode='w:gz') as tar:
                for path in sorted(self.work.iterdir()):
                    if path.name=='archive.json':continue
                    if path.is_file() and path.suffix in ('.json','.jsonl','.stderr') and not path.is_symlink():
                        need(path.stat().st_size<=32*1024**2,'Report file exceeds bound');tar.add(path,arcname=path.name,recursive=False)
            raw=out.getvalue();need(len(raw)<=24*1024**2,'Report exceeds bounded private transport')
            with frozen.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        chunks=[]
        for i,start in enumerate(range(0,len(raw),384*1024)):
            piece=raw[start:start+384*1024];path='ub-locality/'+SESSION+'/'+RUN+'/'+self.node+'/artifacts/'+digest(raw)+'/'+str(i)+'.json'
            self.transport_retry('immutable_result',RESULTS,1438089386,'main',path,wire({'sha256':digest(piece),'dataBase64':base64.b64encode(piece).decode()}))
            chunks.append({'path':path,'bytes':len(piece),'sha256':digest(piece)})
        self.event('archive',{'sha256':digest(raw),'bytes':len(raw),'chunks':chunks})


def main():
    compressed=base64.b64decode(''.join(sys.argv[1:]),validate=True);d=zlib.decompressobj();raw=d.decompress(compressed,65537)
    need(d.eof and not d.unused_data and not d.unconsumed_tail and len(raw)<=65536,'Bounded job spec differs')
    ctx=None
    try:
        ctx=Experiment.__new__(Experiment);ctx.__init__(json.loads(raw));ctx.execute()
        return 0
    except BaseException as error:
        detail={'status':'UB_HOST_READ_STOPPED_SERVICES_HELD','errorType':type(error).__name__,'reason':str(error)[:700],
                'globalAllocationAllowed':False,'globalDeletionAllowed':False,'automaticRetry':False}
        if ctx is not None and getattr(ctx,'createdWork',False):
            atomic(ctx.work/'failure-local.json',detail)
            try:
                if hasattr(ctx,'results'):ctx.event('failed',detail)
            except Exception:pass
        print(json.dumps(detail),flush=True);return 1
    finally:
        if ctx is not None and getattr(ctx,'createdWork',False):
            ctx.stop.set()
            if ctx.sampler:ctx.sampler.join(10)
            if ctx.worker and ctx.worker.poll() is None:
                ctx.worker.terminate()
                try:ctx.worker.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    atomic(ctx.work/'worker-exit-unconfirmed.json',{'pid':ctx.worker.pid,'releaseNotConfirmed':True})
            if ctx.daxfd is not None:os.close(ctx.daxfd)
            try:
                if ctx.sampler and ctx.sampler.is_alive():raise RuntimeError('Sampler still active; preserve mutable reports')
                if hasattr(ctx,'results'):ctx.upload()
            except Exception as e:print('PRIVATE_REPORT_UPLOAD_PENDING='+type(e).__name__,flush=True)


def kib_fields(text):
    result={}
    for line in text.splitlines():
        match=re.fullmatch(r'([A-Za-z_]+):\s+(\d+) kB',line.strip())
        if match:result[match[1]]=int(match[2])*1024
    return result

def identity(pid):
    need(type(pid) is int and pid>1,'Invalid PID')
    proc=Path('/proc')/str(pid)
    ticks=proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]
    status=proc.joinpath('status').read_text()
    uid=re.search(r'(?m)^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$',status)
    need(uid is not None,'Process UID unavailable')
    return {'pid':pid,'startTicks':ticks,'uids':[int(x) for x in uid.groups()]}

def process_sample(row):
    before=identity(row['pid'])
    need(before['startTicks']==row['startTicks'] and before['uids']==[row['uid']]*4,'Process identity changed')
    proc=Path('/proc')/str(row['pid']);meta=os.stat(proc/'exe')
    need(os.readlink(proc/'exe')==row['executable'] and (meta.st_dev,meta.st_ino)==(row['exeDev'],row['exeInode']),
         'Process executable identity changed')
    begin=time.monotonic_ns();rollup=kib_fields((proc/'smaps_rollup').read_text())
    need(identity(row['pid'])==before,'Process changed during sampling')
    need('Rss' in rollup and 'Pss' in rollup,'Required process RSS/PSS missing')
    return {'role':row['role'],**before,'beginNs':begin,'endNs':time.monotonic_ns(),
            'metricsBytes':{key:rollup.get(key) for key in ('Rss','Pss','Pss_Anon','Pss_File','Pss_Shmem',
                'Private_Clean','Private_Dirty','Shared_Clean','Shared_Dirty','Anonymous','Swap','SwapPss')},
            'scope':'whole_process_including_mapped_Guest_RAM_when_role_fc','guestRamOnlyBytes':None}

def resident_bytes(fd,length,page,libc=None,deadline=None):
    """mincore on PROT_NONE mappings; do not fault or read source payload."""
    need(type(length) is int and length>=0 and length<=32*1024**3,'File size exceeds bound')
    need(type(page) is int and page>=4096 and page&(page-1)==0,'Invalid native page size')
    if length==0:return 0
    if deadline is None:deadline=time.monotonic()+5
    libc=libc or ctypes.CDLL(None,use_errno=True)
    libc.mmap.restype=ctypes.c_void_p
    libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_longlong]
    libc.mincore.restype=ctypes.c_int;libc.mincore.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
    libc.munmap.restype=ctypes.c_int;libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    resident=0;offset=0;window=64*1024**2
    while offset<length:
        if time.monotonic()>deadline:raise TimeoutError(errno.ETIMEDOUT,'Scoped residency sampling budget exceeded')
        size=min(window,length-offset);pages=(size+page-1)//page
        address=libc.mmap(None,size,0,1,fd,offset)  # PROT_NONE, MAP_SHARED
        if address==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),'Scoped mmap failed')
        try:
            vector=(ctypes.c_ubyte*pages)()
            if libc.mincore(address,size,vector)!=0:raise OSError(ctypes.get_errno(),'Scoped mincore failed')
            resident+=sum(bool(value&1) for value in vector)*page
        finally:
            if libc.munmap(address,size)!=0:raise OSError(ctypes.get_errno(),'Scoped munmap failed')
        offset+=size
    return resident

def immutable_identity(meta):
    return {'dev':meta.st_dev,'inode':meta.st_ino,'size':meta.st_size,'mtimeNs':meta.st_mtime_ns,'ctimeNs':meta.st_ctime_ns}

def file_sample(row,root,page,deadline=None):
    path=Path(row['path'])
    need(path.is_absolute() and path.is_relative_to(root) and path.resolve(strict=True)==path,'File outside declared root or redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204,'Expected ordinary owned experiment file')
        actual=immutable_identity(before)
        need(all(actual[key]==row['identity'][key] for key in ('dev','inode')),'File inode changed')
        if row['immutable']:need(actual==row['identity'],'Immutable file changed')
        count=resident_bytes(fd,before.st_size,page,deadline=deadline)
        after=os.fstat(fd);stable=immutable_identity(after)==actual
        if row['immutable']:need(stable,'Immutable file changed during mincore')
        return {'path':str(path),'category':row['category'],'identity':actual,
                'residentBytes':count if stable else None,'stableDuringSample':stable,
                'pageSpanBytes':((before.st_size+page-1)//page)*page,'allocatedFileBytes':before.st_blocks*512,
                'payloadReadOrFaulted':False,'cacheEvicted':False}
    finally:os.close(fd)

def file_digest(path,expected_bytes):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size!=expected_bytes:
            raise ValueError('Dedicated experiment file length/type differs')
        sha=hashlib.sha256()
        for data in iter(lambda:stream.read(MIB),b''):sha.update(data)
        after=os.fstat(stream.fileno())
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(
                after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
            raise RuntimeError('Experiment file changed while reading')
        return sha.hexdigest()

def process_identity(pid):
    return (Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19]

def decode_reference_metadata(data):
    """Decode only the fixed prefix from public ubs-engine 1.0.1 source.

    Caller must report runtime-package/source matching separately. No raw
    physical addresses, credentials or username are emitted by this decoder.
    """
    if len(data)<2+META_PREFIX.size:raise ValueError('OBMM private metadata prefix is unavailable')
    value=META_PREFIX.unpack_from(data,2)
    version,kind=value[:2]
    if version!=1 or kind!=2:raise ValueError('Not the reference version1 shared-memory metadata')
    def text(raw):
        prefix=raw.split(b'\0',1)[0]
        if not prefix:raise ValueError('Empty shared-object provenance field')
        return prefix.decode('ascii')
    return {'schema':'ubs-engine-1.0.1-custom-v1-prefix','schemaRuntimeAttested':False,
            'version':version,'kind':kind,'exportNodeId':text(value[10]),
            'exportMemId':value[12],'globalName':text(value[14]),
            'rawMetadataSha256':hashlib.sha256(data).hexdigest()}

def region_evidence(pid,ticks,ranges,runtime_attested=False,evidence_dir=None):
    if process_identity(pid)!=ticks:raise ValueError('Root helper identity differs')
    found={}
    for fd in (Path('/proc')/str(pid)/'fd').iterdir():
        try:
            target=os.readlink(fd)
            match=re.fullmatch('/dev/obmm_shmdev([0-9]+)',target)
            if not match:continue
            info=fd.stat();number=int(match[1]);root=Path('/sys/devices/obmm')/('obmm_shmdev'+str(number))
            if not stat.S_ISCHR(info.st_mode):raise ValueError('Region is not a character device')
            kind=(root/'type').read_text().strip();size=int((root/'size').read_text().strip(),0)
            row={'localRegionId':number,'kind':kind,'bytes':size,
                 'device':[os.major(info.st_rdev),os.minor(info.st_rdev)],
                 'ranges':[value for value in ranges if value['rdev']==info.st_rdev]}
            if not row['ranges']:continue
            count=int((root/'priv_len').read_text().strip())
            if not 0<count<=512:raise ValueError('Unexpected private metadata length')
            with (root/'priv').open('rb') as stream:data=stream.read(count)
            if evidence_dir is not None:
                directory=Path(evidence_dir)
                directory.mkdir(mode=0o700,exist_ok=True)
                directory_info=directory.lstat()
                if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid!=0
                        or directory_info.st_mode&0o077 or directory.resolve(strict=True)!=directory):
                    raise ValueError('Private evidence directory differs')
                saved=directory/('region-'+str(number)+'-priv.bin')
                if saved.exists() or saved.is_symlink():
                    info_saved=saved.lstat()
                    if (not stat.S_ISREG(info_saved.st_mode) or info_saved.st_uid!=0 or info_saved.st_mode&0o077
                            or info_saved.st_size!=len(data) or saved.read_bytes()!=data):
                        raise ValueError('Private provenance artifact changed')
                else:
                    out=os.open(saved,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(out,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
                row['privateMetadataFile']=str(saved)
            try:
                row['provenance']=decode_reference_metadata(data)
                row['provenance']['schemaRuntimeAttested']=runtime_attested is True
            except (ValueError,UnicodeError) as error:row['provenance']=None;row['reason']=str(error)
            found[number]=row
        except (OSError,ValueError) as error:
            # Missing evidence is explicit, never a positive mapping claim.
            found['fd-'+fd.name]={'provenance':None,'reason':str(error)}
    if process_identity(pid)!=ticks:raise ValueError('Root helper changed during evidence capture')
    return list(found.values())

def engine_schema(rpm,pid,ticks):
    observed={}
    try:
        if process_identity(pid)!=ticks:raise ValueError('UBSE process changed')
        exe=Path(os.readlink(Path('/proc')/str(pid)/'exe')).resolve(strict=True)
        info=exe.stat()
        if info.st_uid!=0 or info.st_mode&0o022 or not 0<info.st_size<=128*MIB:
            raise ValueError('UBSE executable ownership/size differs')
        query='%{NAME}\n%{VERSION}\n%{RELEASE}\n%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{FILEDIGESTS}\n]'
        result=subprocess.run([rpm,'-qf','--qf',query,str(exe)],capture_output=True,text=True,
                              timeout=30,env={'PATH':'/usr/sbin:/sbin:/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
        lines=result.stdout.splitlines()
        observed['observedPackage']=lines[:4]
        observed['executable']=str(exe)
        if result.returncode or lines[:4]!=['ubs-engine','1.0.1','1.oe2403sp3','8']:
            raise ValueError('Installed engine package does not match reviewed schema source')
        rows=dict(line.split('\t',1) for line in lines[4:] if '\t' in line)
        expected=rows.get(str(exe))
        if expected is None or not re.fullmatch('[0-9a-f]{64}',expected):raise ValueError('RPM executable digest missing')
        actual=file_digest(exe,info.st_size)
        observed['executableSha256']=actual
        if (actual!=expected or actual!='22ce7d2f4309765d18e4df41a8a2941aacd023cac46d8f135aee0cd4a2e19d45'
                or info.st_size!=9704056 or process_identity(pid)!=ticks):
            raise ValueError('Runtime executable differs from the pinned official RPM binary')
        return {'attested':True,'package':'ubs-engine-1.0.1-1.oe2403sp3','executableSha256':actual,
                'executable':str(exe),'fileIdentity':[info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns],
                'binaryRpmSha256':'e777429d01d7f99aedceafb0cf723bb39fa626c49a8d0078ea657f718b1a0e84',
                'sourceRpmSha256':'8cd3800d1056c0fa76bc36a7ebf13f513c9d094eb754cd9ce2dd459efa6efc8b'}
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        return {'attested':False,'reason':str(error),**observed}

def shared_graph(first,second,image_bytes):
    """Match logical ranges to the same export node/region under pinned schema."""
    def ranges(sample):
        if not sample.get('engineSchema',{}).get('attested'):
            raise ValueError('Runtime engine schema not attested')
        result=[];capacity={}
        for row in sample.get('mappingEvidence',[]):
            meta=row.get('provenance')
            if (not meta or meta.get('schemaRuntimeAttested') is not True
                    or meta.get('version')!=1 or meta.get('kind')!=2 or row.get('kind') not in ('export','import')):
                raise ValueError('Incomplete region provenance')
            origin=(meta['exportNodeId'],row['localRegionId'] if row['kind']=='export' else meta['exportMemId'])
            if not origin[0] or origin[1]<=0:raise ValueError('Unknown export origin')
            previous=capacity.setdefault(origin,row['bytes'])
            if previous!=row['bytes']:raise ValueError('Conflicting origin region sizes')
            for region in row.get('ranges',[]):
                offset,count,logical=region['offset'],region['bytes'],region['logicalOffset']
                if min(offset,logical)<0 or count<=0 or offset+count>row['bytes']:
                    raise ValueError('Region range exceeds backing')
                result.append((logical,count,origin,offset))
        result.sort();cursor=0
        for logical,count,_,_ in result:
            if logical!=cursor:raise ValueError('Logical source ranges have holes or duplicates')
            cursor+=count
        if cursor!=image_bytes:raise ValueError('Mapping evidence does not cover the complete image')
        return result,capacity
    try:
        a,ac=ranges(first);b,bc=ranges(second)
        if a!=b:return {'matched':False,'reason':'Logical ranges refer to different export origins'}
        if ac!=bc:return {'matched':False,'reason':'Export origin capacities differ'}
        return {'matched':True,'originCount':len(ac),'referencedRegionCapacityBytes':sum(ac.values()),
                'physicalIncrementBytes':None,
                'meaning':'same exported region identities/ranges; capacity is not new physical allocation'}
    except (KeyError,TypeError,ValueError) as error:
        return {'matched':None,'reason':str(error),'physicalIncrementBytes':None}

def validate_fd(fd, length, fs_dax=True):
    import fcntl
    info = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    if (not stat.S_ISREG(info.st_mode) or info.st_size != length
            or flags & os.O_ACCMODE != os.O_RDONLY or flags & os.O_SYNC):
        raise ValueError('FS-DAX requires an exact-length readonly regular FD')
    libc = ctypes.CDLL(None, use_errno=True)
    statx = libc.statx
    statx.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                     ctypes.c_uint, ctypes.c_void_p]
    statx.restype = ctypes.c_int
    data = ctypes.create_string_buffer(256)
    if statx(fd, b'', 0x1000, 0x7ff, data) != 0:  # AT_EMPTY_PATH, BASIC_STATS
        raise OSError(ctypes.get_errno(), 'statx on FS-DAX FD failed')
    attributes = struct.unpack_from('=Q', data.raw, 8)[0]
    size = struct.unpack_from('=Q', data.raw, 40)[0]
    supported = struct.unpack_from('=Q', data.raw, 56)[0]
    if not supported & 0x200000 or bool(attributes & 0x200000) != fs_dax or size != length:
        raise ValueError('File does not have the required S_DAX state')
    readonly_mount = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
    if fs_dax and not readonly_mount:
        raise ValueError('FS-DAX publication must be on a readonly mount')
    return {'device': info.st_dev, 'inode': info.st_ino, 'bytes': size,
            'activeDax': fs_dax, 'readonlyMount': readonly_mount,
            'crossNodePhysicalIdentityAccepted': False}
if __name__=='__main__':raise SystemExit(main())
