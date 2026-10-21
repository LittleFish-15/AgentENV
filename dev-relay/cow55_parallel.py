"""Ten bounded template tasks, single journal writer and digest-locked OCI cache.

Handoff waits for the serial worker's read-only BUILDING poll phase. Only that
verified ordinary-user coordinator is interrupted; its backend build continues.
A separate watchdog releases a temporarily stopped coordinator on parent death.
No service signals, deletion, force retries, UB, or 110-Guest replay operations.
"""
import argparse,base64,concurrent.futures,contextlib,copy,hashlib,importlib.util,json,os,re,signal,socket,stat,subprocess,sys,tempfile,threading,time,uuid
from pathlib import Path
ROOT=Path('/home/jwk/agent');CONTROL=ROOT/'relay/cow55-parallel-control-node-a.json';CONTROL_LOCK=ROOT/'relay/cow55-parallel-control-node-a.lock'
SERIAL=ROOT/'cow55_build_edf502d.py';SERIAL_SHA='9bbde92ad5e6552fd22574396c1e72b59c7fe3c66ddbb89150abb604275e86a9'
B=H=None

def need(ok,why):
    if not ok:raise RuntimeError(why)
def load():
    global B,H
    need(SERIAL.resolve(strict=True)==SERIAL and hashlib.sha256(SERIAL.read_bytes()).hexdigest()==SERIAL_SHA,'Pinned serial builder differs')
    s=importlib.util.spec_from_file_location('cow55_parallel_base',SERIAL);B=importlib.util.module_from_spec(s);s.loader.exec_module(B);B.load_helper();H=B.H
def ticks(pid):return Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
def same_process(pid,start):
    try:return ticks(pid)==start and Path('/proc/'+str(pid)).stat().st_uid==1204
    except OSError:return False
def serial_identity(pid,start):
    if not same_process(pid,start):return False
    try:
        args=Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0');args=[x.decode() for x in args if x]
        status=dict(x.split(':',1) for x in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in x)
        return len(args)==7 and args[1:5]==['-I','-B',str(SERIAL),'worker'] and args[5]=='--lock-fd' and args[6].isdigit() and int(status['CapEff'].strip(),16)==0
    except (OSError,ValueError,UnicodeError):return False

def watchdog(fd,pid,start):
    with socket.socket(fileno=fd) as s:
        need(serial_identity(pid,start),'Watchdog target identity differs');s.settimeout(10);s.sendall(b'R')
        try:s.recv(1)
        except (OSError,socket.timeout):pass
        finally:
            if serial_identity(pid,start):os.kill(pid,signal.SIGCONT)

@contextlib.contextmanager
def guarded_stop(pid,start):
    need(serial_identity(pid,start),'Serial coordinator identity differs')
    parent,child=socket.socketpair();watch=None;stopped=False
    try:
        watch=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).resolve()),'watchdog','--watch-fd',str(child.fileno()),'--target-pid',str(pid),'--target-ticks',start],
              stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,pass_fds=(child.fileno(),),start_new_session=True)
        child.close();parent.settimeout(3);need(parent.recv(1)==b'R','Watchdog did not become ready')
        need(serial_identity(pid,start),'Serial identity changed before checkpoint')
        os.kill(pid,signal.SIGSTOP);stopped=True
        until=time.monotonic()+1
        while time.monotonic()<until:
            status=Path('/proc/'+str(pid)+'/status').read_text()
            if re.search(r'(?m)^State:\s+T',status):break
            time.sleep(.01)
        else:raise RuntimeError('Coordinator did not reach stopped checkpoint')
        yield
    finally:
        if stopped and serial_identity(pid,start):os.kill(pid,signal.SIGCONT)
        try:parent.sendall(b'D')
        except OSError:pass
        parent.close();child.close()
        if watch:
            try:watch.wait(timeout=12)
            except subprocess.TimeoutExpired:pass # never kill a watchdog

def active_children(pid):
    children=set()
    for task in list(Path('/proc/'+str(pid)+'/task').iterdir())[:512]:
        try:children.update(int(x) for x in (task/'children').read_text().split())
        except FileNotFoundError:pass
    result=[]
    for child in children:
        try:
            state=Path('/proc/'+str(child)+'/stat').read_text().rsplit(')',1)[1].split()[0]
            if state not in ('Z','X'):result.append(child)
        except FileNotFoundError:pass
    return result

def transferable(s):
    pending=[c for c in s['cases'] if c['state']!='READY']
    return bool(pending) and pending[0]['state'] in ('BUILDING','WAITING_ASYNC') and not any(c['state'] in ('CREATE_INTENT','BUILD_INTENT','CREATED','IMAGE_VERIFIED','DOWNLOADING') for c in pending)

def handoff(control):
    deadline=time.monotonic()+1800
    while time.monotonic()<deadline:
        s=B.read_json(B.STATE);need(s['run_id']==control['source_run_id'] and s['input_sha256']==B.INPUT_SHA,'Original batch changed')
        if s['status']=='COW55_ALL_TEMPLATES_READY_NO_REPLAY_STARTED':return False
        pid,start=s.get('worker_pid'),s.get('worker_start_ticks')
        if s.get('worker_finished'):return True
        need(same_process(pid,start),'Coordinator disappeared without a finished receipt; possible orphan download, no automatic takeover')
        need(s.get('max_parallel_builds')==1 and serial_identity(pid,start),'Unexpected active coordinator; no signals')
        if transferable(s):
            interrupted=False
            with guarded_stop(pid,start):
                latest=B.read_json(B.STATE)
                # No downloader is interrupted. A child or ambiguous write
                # phase causes an immediate release and a later retry.
                if latest['run_id']==s['run_id'] and transferable(latest) and not active_children(pid):
                    os.kill(pid,signal.SIGINT);interrupted=True
            if interrupted:
                control['handoff']={'serial_pid':pid,'serial_start_ticks':start,'checkpoint':'known backend build; no active child',
                                    'signals':['SIGSTOP','SIGINT','SIGCONT'],'service_signals_sent':False}
                H.save(CONTROL,control)
                end=time.monotonic()+60
                while same_process(pid,start) and time.monotonic()<end:time.sleep(.2)
                need(not same_process(pid,start),'Coordinator has not exited; no forced termination')
                return True
        time.sleep(1)
    raise RuntimeError('No safe build-wait checkpoint reached; main coordinator left running')

def fingerprint(path):
    H.safe(path);m=path.stat();need(stat.S_ISREG(m.st_mode),'Blob is not a regular file')
    return (m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns)
def verify_blob(path,digest,size):
    before=fingerprint(path);need(before[2]==size,'Existing blob size mismatch; preserved')
    h=hashlib.sha256()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        for chunk in iter(lambda:f.read(1024**2),b''):h.update(chunk)
    need(before==fingerprint(path) and 'sha256:'+h.hexdigest()==digest,'Existing blob hash/identity mismatch; preserved')
    return before
def put_new(path,raw):
    H.safe(path);H.safe(path.parent);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.exists():need(H.read(path,2*1024**2)==raw,'Existing metadata differs; preserved');return
    temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.part')
    try:
        with temp.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        try:os.link(temp,path)
        except FileExistsError:need(H.read(path,2*1024**2)==raw,'Concurrent different metadata; preserved')
    finally:
        if temp.exists():temp.unlink()

class Journal:
    def __init__(self,state):self.state=state;self.lock=threading.RLock()
    def publish(self,local):
        with self.lock:
            self.state['cases'][local['_index']]=copy.deepcopy(local['cases'][0]);self.persist()
    def persist(self):
        with self.lock:
            self.state['updated_unix']=time.time();H.save(B.STATE,self.state)

class BlobCache:
    def __init__(self,state,root,env):
        self.state=state;self.root=root;self.env=env;self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.mutex=threading.Lock();self.locks={};self.verified={};self.downloads=set();self.reused=set();self.failed=set();self.attempts=set()
    def lock(self,digest):
        with self.mutex:return self.locks.setdefault(digest,threading.Lock())
    def get(self,descriptor,repository):
        digest,size=descriptor['digest'],descriptor['size'];need(re.fullmatch(B.DIGEST,digest) and type(size) is int and 0<size<=B.MAX_IMAGE,'Invalid blob descriptor')
        name=digest.split(':')[1];dest=self.root/name
        with self.lock(digest):
            need(digest not in self.failed,'Prior download of this digest failed; no implicit retry by another task')
            if dest.exists():
                meta=fingerprint(dest)
                need(meta[2]==size,'Same digest with different declared size')
                if self.verified.get(digest)!=meta:self.verified[digest]=verify_blob(dest,digest,size)
                return dest
            # Search only this batch's known OCI input directories, never caches
            # owned by another experiment. Reuse bytes only after SHA verification.
            for i in range(len(self.state['cases'])):
                source=Path(self.state['work_directory'])/('case-%02d'%i)/'image/blobs/sha256'/name
                H.safe(source)
                if source.exists():
                    verify_blob(source,digest,size);os.link(source,dest);self.verified[digest]=fingerprint(dest)
                    with self.mutex:self.reused.add(digest)
                    return dest
            B.capacity();tmp=self.root/(name+'.'+uuid.uuid4().hex+'.download')
            with self.mutex:self.attempts.add(digest)
            try:
                H.checked_process([B.BASE/'deps/regctl/v0.11.5/regctl','blob','get',repository,digest],self.env,tmp,1800)
                verify_blob(tmp,digest,size)
            except BaseException:
                self.failed.add(digest);raise
            # Files are immutable after verified publication. No overwrite.
            os.link(tmp,dest);tmp.unlink();self.verified[digest]=fingerprint(dest)
            with self.mutex:self.downloads.add(digest)
            return dest
    def statistics(self):
        with self.mutex:return {'unique_blob_download_attempts_this_worker':len(self.attempts),'unique_blob_digests_downloaded_this_worker':len(self.downloads),'unique_existing_blob_digests_reused':len(self.reused),
                               'network_partial_transfer_retry_bytes_measured':False,'per_digest_concurrent_download_limit':1}

def prepare_image(index,case,state,cache):
    work=Path(state['work_directory'])/('case-%02d'%index);raw=None
    for name in ('platform-manifest.json','tag-manifest.json'):
        p=work/name
        if p.exists():
            value=H.read(p,2*1024**2)
            if 'sha256:'+B.sha(value)==case['manifest_digest']:raw=value;break
    need(raw is not None,'Pinned resolved manifest unavailable; no tag re-resolution')
    manifest=json.loads(raw);need(B.descriptors(manifest)==case['compressed_bytes'],'Manifest budget changed')
    image=work/'image';H.safe(image);blobs=image/'blobs/sha256';blobs.mkdir(parents=True,exist_ok=True,mode=0o700)
    put_new(blobs/case['manifest_digest'].split(':')[1],raw)
    repository=case['pinned_image'].split('@')[0]
    need(re.fullmatch(r'swr\.cn-north-4\.myhuaweicloud\.com/kunpeng-ai/swerebench-arm64-[A-Za-z0-9_.-]+',repository),'Unexpected blob source')
    for descriptor in [manifest['config']]+manifest['layers']:
        source=cache.get(descriptor,repository);target=blobs/descriptor['digest'].split(':')[1];H.safe(target)
        if target.exists():verify_blob(target,descriptor['digest'],descriptor['size'])
        else:os.link(source,target)
        if descriptor is manifest['config']:
            config=json.loads(H.read(target,2*1024**2));need(config.get('os')=='linux' and config.get('architecture')=='arm64','Wrong image architecture')
    layout=image/'oci-layout'
    if layout.exists():need(json.loads(H.read(layout))=={'imageLayoutVersion':'1.0.0'},'OCI layout differs')
    else:put_new(layout,b'{"imageLayoutVersion":"1.0.0"}\n')
    idx=image/'index.json';descriptor={'mediaType':manifest['mediaType'],'digest':case['manifest_digest'],'size':len(raw),'annotations':{'org.opencontainers.image.ref.name':'input'}}
    if idx.exists():
        old=json.loads(H.read(idx));need(any(r.get('digest')==case['manifest_digest'] for r in old.get('manifests',[])),'Existing OCI index differs')
    else:put_new(idx,(json.dumps({'schemaVersion':2,'manifests':[descriptor]})+'\n').encode())
    case['verification']=B.verify_layout(image,case['manifest_digest']);case['local_oci_directory']=str(image);case['state']='IMAGE_VERIFIED'

def execute(index,journal,cache,api):
    case=copy.deepcopy(journal.state['cases'][index]);local={'_index':index,'cases':[case]}
    try:
        if case['state'] in ('RESOLVED','DOWNLOADING'):
            case['state']='DOWNLOADING';journal.publish(local);prepare_image(index,case,journal.state,cache);journal.publish(local)
        B.build_case(case,local,api,Path(journal.state['work_directory'])/('case-%02d'%index),cache.env)
    except BaseException as error:
        case['parallel_error']={'type':type(error).__name__,'reason':H.redact_child_output(str(error),cache.env).replace(api.key,'[REDACTED]')}
        journal.publish(local);raise

def parallel_run(state,control):
    need(all(c['state'] not in ('NEW','CREATE_INTENT','CREATE_RESPONSE_UNCONFIRMED','BUILD_ERROR') for c in state['cases']),'Unresolved create/build or manifest state requires review')
    active_states={'BUILD_INTENT','BUILDING','WAITING_ASYNC'}
    need(sum(c['state'] in active_states for c in state['cases'])<=control['jobs'],'Known pending backend builds exceed requested concurrency')
    prior_capacity=B.capacity
    def capacity():
        prior_capacity()
        match=re.search(r'(?m)^MemAvailable:\s+(\d+) kB',Path('/proc/meminfo').read_text())
        need(match and int(match[1])*1024>=max(32,4*control['jobs']+24)*1024**3,'Insufficient host headroom for parallel preparation')
    B.capacity=capacity
    api=B.Api(state['original_identity']);B.empty(api);B.capacity()
    work=H.safe(Path(control['work_directory']));env,_=B.environment(work)
    journal=Journal(state);cache=BlobCache(state,work/'verified-blobs/sha256',env)
    state.update(status='COW55_TEMPLATE_PREPARATION_RUNNING',max_parallel_builds=control['jobs'],coordinator_revision='cow55-parallel-v1',
                 worker_pid=os.getpid(),worker_start_ticks=ticks(os.getpid()),worker_finished=False,
                 state_write_policy='One coordinator; serialized whole-journal snapshots; independent per-case working copies',
                 image_download_policy='Content-addressed verified cache; per-digest lock; reuse existing batch OCI blobs before network')
    state.pop('reason',None);state.pop('error_type',None);journal.persist()
    B.save=journal.publish # local per-case snapshots only; one serialized writer
    failure=None;pending={};queue=sorted((i for i,c in enumerate(state['cases']) if c['state']!='READY'),
                                        key=lambda i:(state['cases'][i]['state'] not in active_states,i))
    try:
        for c in state['cases']:
            if c['state']=='READY':B.verify_ready(c)
        with concurrent.futures.ThreadPoolExecutor(max_workers=control['jobs']) as pool:
            while queue or pending:
                while queue and len(pending)<control['jobs'] and failure is None:
                    i=queue.pop(0);pending[pool.submit(execute,i,journal,cache,api)]=i
                if not pending:break
                done,_=concurrent.futures.wait(pending,timeout=10,return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    pending.pop(future)
                    try:future.result()
                    except BaseException as error:failure=error
                with journal.lock:
                    state['download_cache_statistics']=cache.statistics();state['completed_templates']=sum(c['state']=='READY' for c in state['cases']);journal.persist()
        need(failure is None,'A task failed; remaining in-flight tasks drained; no new tasks admitted')
        need(all(c['state']=='READY' for c in state['cases']),'Incomplete cohort')
        ids=[c['template_id'] for c in state['cases']];need(len(set(ids))==55 and all(c['template_id']==c['build_id'] for c in state['cases']),'Duplicate or mismatched template IDs')
        need(all(c['resources']['memory_mib']==4096 and c['layer_inventory_summary']['available'] for c in state['cases']),'Final resource/inventory merge failed')
        need(H.runtime_pid()==tuple(state['original_identity']),'Original service changed');B.empty(api)
        state['status']='COW55_ALL_TEMPLATES_READY_NO_REPLAY_STARTED';state['final_merge_verified']=True
    except BaseException as error:
        state['status']='STOPPED_COW55_PARALLEL_PREPARATION';state['reason']=H.redact_child_output(str(error),env).replace(api.key,'[REDACTED]')
    finally:
        state['worker_finished']=True;state['download_cache_statistics']=cache.statistics();journal.persist();H.save(work/'return.json',state)

def coordinator(control,resume=False):
    import fcntl
    fd=None
    try:
        control.update(status='COW55_WAITING_SAFE_HANDOFF',worker_pid=os.getpid(),worker_start_ticks=ticks(os.getpid()));H.save(CONTROL,control)
        if not resume and not handoff(control):control['status']='COW55_MAIN_ALREADY_COMPLETED';return
        fd=os.open(H.safe(B.LOCK),os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
        meta=os.fstat(fd);named=B.LOCK.stat()
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and (meta.st_dev,meta.st_ino)==(named.st_dev,named.st_ino),'Original batch lock identity differs')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        state=B.read_json(B.STATE);need(state['run_id']==control['source_run_id'] and state['input_sha256']==B.INPUT_SHA,'Batch changed at handoff')
        need(not same_process(state.get('worker_pid'),state.get('worker_start_ticks')),'Previous coordinator still present')
        need(state.get('worker_finished') is True,'Previous coordinator did not acknowledge its exit; no automatic adoption')
        H.save(Path(control['work_directory'])/('before-'+uuid.uuid4().hex+'.json'),state)
        control['status']='COW55_PARALLEL_RUNNING';H.save(CONTROL,control);parallel_run(state,control)
        control['status']='COW55_PARALLEL_WORKER_FINISHED_CHECK_MAIN_RESULT'
    except BaseException as error:control.update(status='STOPPED_COW55_PARALLEL_CONTROL',error_type=type(error).__name__,reason=str(error))
    finally:
        if fd is not None:os.close(fd)
        control['worker_finished']=True;H.save(CONTROL,control)
        print('BEGIN_RETURN_REPORT');print(json.dumps(control,indent=2));print('END_RETURN_REPORT',flush=True)

def run():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('start','resume','worker','status','watchdog'));p.add_argument('--jobs',type=int,choices=range(1,11),default=10)
    p.add_argument('--lock-fd',type=int);p.add_argument('--watch-fd',type=int);p.add_argument('--target-pid',type=int);p.add_argument('--target-ticks');p.add_argument('--resume-worker',action='store_true')
    a=p.parse_args();need(os.getuid()==os.geteuid()==1204 and os.uname().nodename=='server1','A ordinary jwk required')
    status=dict(s.split(':',1) for s in Path('/proc/self/status').read_text().splitlines() if ':' in s)
    need(all(int(status[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapAmb')),'Capability-free coordinator required')
    os.umask(0o077);load()
    if a.mode=='watchdog':watchdog(a.watch_fd,a.target_pid,a.target_ticks);return
    if a.mode=='status':
        c=B.read_json(CONTROL);s=B.read_json(B.STATE);print('BEGIN_RETURN_REPORT');print(json.dumps({'control':c,'build':B.summary(s)},indent=2));print('END_RETURN_REPORT');return
    import fcntl
    fd=a.lock_fd if a.mode=='worker' else os.open(H.safe(CONTROL_LOCK),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    need(type(fd) is int and fd>=0,'Missing coordinator lock')
    try:
        m=os.fstat(fd);n=CONTROL_LOCK.stat();need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and (m.st_dev,m.st_ino)==(n.st_dev,n.st_ino),'Control lock identity differs')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if a.mode=='worker':coordinator(B.read_json(CONTROL),a.resume_worker);return
        B.inputs(ROOT/'cow55_inputs.json');s=B.read_json(B.STATE);need(s['input_sha256']==B.INPUT_SHA and s['declared_compressed_bytes_sum']<=B.MAX_TOTAL,'Batch limits differ');B.capacity()
        need(H.runtime_pid()==tuple(s['original_identity']),'Original service changed')
        if a.mode=='start':
            need(not CONTROL.exists(),'Parallel control exists; use status, not another start')
            need(s['status']=='COW55_TEMPLATE_PREPARATION_RUNNING' and s['max_parallel_builds']==1,'Expected active serial builder')
            work=Path(tempfile.mkdtemp(prefix='node-a-cow55-parallel-',dir=ROOT/'relay/reports'))
            c={'revision':'cow55-parallel-control-v1','source_run_id':s['run_id'],'work_directory':str(work),'jobs':a.jobs,
               'status':'COW55_PARALLEL_CONTROL_STARTING','services_modified':False,'SDK_called':False,'replay_started':False,'worker_finished':False}
        else:
            c=B.read_json(CONTROL);need(c['source_run_id']==s['run_id'] and c.get('worker_finished'),'Control still active or batch changed')
            need(s['status']!='COW55_ALL_TEMPLATES_READY_NO_REPLAY_STARTED','All templates already completed')
            c.update(jobs=a.jobs,worker_finished=False);work=H.safe(Path(c['work_directory']))
        H.save(CONTROL,c);log=work/('worker-'+uuid.uuid4().hex[:8]+'.log')
        cmd=[sys.executable,'-I','-B',str(Path(__file__).resolve()),'worker','--lock-fd',str(fd)]
        if a.mode=='resume':cmd.append('--resume-worker')
        with log.open('xb') as output:
            child=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,pass_fds=(fd,),start_new_session=True,cwd=ROOT)
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'COW55_PARALLEL_CONTROL_LAUNCHED','pid':child.pid,'jobs':a.jobs,'log':str(log),
           'handoff_and_template_success_not_inferred':True},indent=2));print('END_RETURN_REPORT')
    finally:os.close(fd)

if __name__=='__main__':
    try:run()
    except Exception as error:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_COW55_PARALLEL_ENTRY','error_type':type(error).__name__,'reason':str(error)},indent=2));print('END_RETURN_REPORT');raise SystemExit(1)
