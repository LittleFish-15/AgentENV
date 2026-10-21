"""Serial original-runtime template preparation; never starts the 110-Guest run.

The private input is transferred separately and pinned; no private traces are
published with this script. API mutation intents are persisted before sending.
Uncertain creates are never retried; uncertain builds are only polled on resume.
"""
import argparse,base64,hashlib,http.client,importlib.util,json,os,re,stat,subprocess,sys,tempfile,time,uuid
from pathlib import Path
ROOT=Path('/home/jwk/agent');BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
STATE=ROOT/'relay/cow55-template-build-node-a.json';LOCK=ROOT/'relay/cow55-template-build-node-a.lock'
INPUT_SHA='9f73ce3b95f9f16482660784ae5dcf4bc7b07a938974a22c57e6e90836722a3a'
HELPER_SHA='edc6ea585021c585fee41ea09d623f64d4df189dfa54c9af08bdab2765b16e11'
MAX_IMAGE=8*1024**3;MAX_TOTAL=256*1024**3;MIN_FREE=512*1024**3
DIGEST=r'sha256:[0-9a-f]{64}';ID=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
H=None

def need(ok,why):
    if not ok:raise RuntimeError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read_json(path):return json.loads(H.read(path,16*1024**2))
def save(state):state['updated_unix']=time.time();H.save(STATE,state)
def load_helper():
    global H
    p=ROOT/'cow_parent_424b012.py';need(p.resolve(strict=True)==p and sha(p.read_bytes())==HELPER_SHA,'Pinned existing parent helper differs')
    spec=importlib.util.spec_from_file_location('cow55_parent_helpers',p);H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)

def inputs(path):
    raw=H.read(path,16*1024**2);need(sha(raw)==INPUT_SHA,'Private input checksum differs')
    x=json.loads(raw);need(x['revision']=='cow55-private-input-v1','Input revision differs');cohort=x['cohort'];cases=cohort['cases']
    need(len(cases)==55 and len({c['instance_id'] for c in cases})==55 and len({c['template_name'] for c in cases})==55,'Expected 55 unique cases')
    need(set(x['replays'])=={c['replay_file'] for c in cases},'Replay inventory differs')
    for c in cases:
        need(c['memory_mib']==4096 and c['language'] in ('go','ts','java'),'Unexpected case resources')
        need(re.fullmatch(r'[A-Za-z0-9_-]{1,180}',c['template_name']),'Invalid template name')
        need(re.fullmatch(r'swr\.cn-north-4\.myhuaweicloud\.com/kunpeng-ai/swerebench-arm64-[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+',c['arm_or_x86_image_tag']),'Unexpected image origin')
        replay=base64.b64decode(x['replays'][c['replay_file']],validate=True)
        need(sha(replay)==c['replay_sha256'],'Replay checksum differs')
    # This stage never executes replay actions, even inside a Guest.
    return cases

class Api:
    def __init__(self,identity):
        self.identity=tuple(identity);self.key=H.read(BASE/'config/api-key',1024).decode().strip()
        need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',self.key),'Unexpected API key; value withheld')
    def call(self,method,path,body=None):
        need(H.runtime_pid()==self.identity,'Original service changed')
        allowed=(method=='GET' and (path in ('/health','/v2/templates','/v2/sandboxes?limit=1') or re.fullmatch('/templates/'+ID+'/builds/'+ID+'/status',path)))
        allowed=allowed or (method=='POST' and (path=='/v3/templates' or re.fullmatch('/v2/templates/'+ID+'/builds/'+ID,path)))
        need(allowed,'API outside bounded template preparation')
        c=http.client.HTTPConnection('127.0.0.1',18080,timeout=30)
        try:
            c.request(method,path,body=json.dumps(body).encode() if body is not None else None,headers={'X-API-Key':self.key,'Content-Type':'application/json'})
            r=c.getresponse();raw=r.read(2*1024**2+1);need(len(raw)<=2*1024**2 and not r.getheader('x-next-token'),'Oversized/paginated API reply')
            data=json.loads(raw) if raw else None
            if r.status>=400:raise RuntimeError('API HTTP '+str(r.status)+': '+json.dumps(H.error_summary(data,self.key)))
            return r.status,data
        finally:c.close()

def empty(api):
    status,rows=api.call('GET','/v2/sandboxes?limit=1');need(status==200 and rows==[],'Existing public sandbox inventory; stop before next build')
def capacity():
    fs=os.statvfs(ROOT);need(not fs.f_flag&os.ST_RDONLY and fs.f_bavail*fs.f_frsize>=MIN_FREE,'Less than 512GiB filesystem reserve or read-only filesystem')
    info=dict(re.findall(r'(?m)^(MemAvailable):\s+(\d+) kB',Path('/proc/meminfo').read_text()))
    need(int(info.get('MemAvailable','0'))*1024>=32*1024**3,'Less than 32GiB host headroom for serial template preparation')

def cgroup_observation(pid):
    result={'scope':'original unit and memory-controller ancestors','items':[]}
    try:
        membership=Path('/proc/'+str(pid)+'/cgroup').read_text()
        mounts=Path('/proc/self/mountinfo').read_text()
        need(len(membership)<65536 and len(mounts)<1024**2,'Cgroup metadata exceeds limit')
        for line in membership.splitlines():
            hierarchy,controllers,group=line.split(':',2)
            unified=controllers==''
            if not unified and 'memory' not in controllers.split(','):continue
            for mount in mounts.splitlines():
                left,right=mount.split(' - ',1);a=left.split();b=right.split()
                if b[0]!=('cgroup2' if unified else 'cgroup'):continue
                if not unified and 'memory' not in b[2].split(','):continue
                root,point=a[3],a[4]
                need(point.startswith('/sys/fs/cgroup') and '\\' not in point and '..' not in group.split('/'),'Unexpected cgroup mount')
                if root!='/' and not (group==root or group.startswith(root+'/')):continue
                suffix=group if root=='/' else group[len(root):]
                base=Path(point);current=base/suffix.lstrip('/')
                for _ in range(16):
                    row={'hierarchy':'v2' if unified else 'v1','path':str(current)}
                    names=('memory.max','memory.current') if unified else ('memory.limit_in_bytes','memory.usage_in_bytes','memory.use_hierarchy')
                    for name in names:
                        try:
                            value=(current/name).read_text()[:128].strip();row[name]=int(value) if value.isdecimal() else value if value=='max' else None
                        except OSError:row[name]=None
                    result['items'].append(row)
                    if current==base:break
                    current=current.parent
        result['available']=any(any(type(v) is int or v=='max' for k,v in r.items() if k.startswith('memory.')) for r in result['items'])
    except Exception as error:result.update(available=False,error_type=type(error).__name__)
    return result

def descriptors(manifest):
    need(isinstance(manifest,dict) and isinstance(manifest.get('layers'),list) and 0<len(manifest['layers'])<=128,'Expected single-platform image manifest')
    rows=[manifest['config']]+manifest['layers']
    for r in rows:need(re.fullmatch(DIGEST,str(r.get('digest',''))) and type(r.get('size')) is int and 0<r['size']<=MAX_IMAGE,'Invalid OCI descriptor')
    total=sum(r['size'] for r in rows);need(total<=MAX_IMAGE,'Image exceeds reviewed 8GiB compressed budget')
    return total

def verify_layout(layout,digest):
    def blob(d,expected=None):
        need(re.fullmatch(DIGEST,d),'Invalid blob digest');p=H.safe(layout/'blobs/sha256'/d.split(':')[1]);fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_uid==1204 and a.st_size<=MAX_IMAGE,'Unexpected blob metadata')
            need(expected is None or a.st_size==expected,'Blob length differs');h=hashlib.sha256();n=0
            for chunk in iter(lambda:f.read(1024**2),b''):n+=len(chunk);need(n<=a.st_size,'Blob grew');h.update(chunk)
            b=os.fstat(f.fileno());need((a.st_ino,a.st_size,a.st_mtime_ns)==(b.st_ino,b.st_size,b.st_mtime_ns) and n==a.st_size,'Blob changed')
        need('sha256:'+h.hexdigest()==d,'Blob SHA differs');return p
    manifest=json.loads(H.read(blob(digest),2*1024**2));total=descriptors(manifest)
    cfg=manifest['config'];config=json.loads(H.read(blob(cfg['digest'],cfg['size']),2*1024**2))
    need(config.get('os')=='linux' and config.get('architecture')=='arm64','Image is not Linux ARM64')
    for r in manifest['layers']:blob(r['digest'],r['size'])
    return {'manifest_digest':digest,'compressed_bytes_verified':total,'architecture':'arm64','layers':len(manifest['layers'])}

def environment(work):
    for name in ('tmp','cache','docker','cli-config'): (work/name).mkdir(exist_ok=True,mode=0o700)
    H.save(work/'docker/config.json',{'auths':{}});H.save(work/'regctl.json',{'incDockerCert':False,'incDockerCred':False})
    e={'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','PATH':str(BASE/'native/bin')+':/usr/bin:/bin',
       'LD_LIBRARY_PATH':str(BASE/'native/lib')+':'+str(BASE/'native/fallback/lib'),'TMPDIR':str(work/'tmp'),'XDG_CACHE_HOME':str(work/'cache'),
       'XDG_CONFIG_HOME':str(work/'cli-config'),'DOCKER_CONFIG':str(work/'docker'),'REGCTL_CONFIG':str(work/'regctl.json'),'GOMAXPROCS':'2'}
    proxy,metadata=H.network_environment(os.environ);e.update(proxy);return e,metadata

def resolve(case,work,env):
    ref=case['image_tag'];regctl=BASE/'deps/regctl/v0.11.5/regctl'
    H.checked_process([regctl,'manifest','get','--format','raw-body',ref],env,work/'tag-manifest.json',120)
    raw=H.read(work/'tag-manifest.json',2*1024**2);manifest=json.loads(raw);top='sha256:'+sha(raw)
    if 'manifests' in manifest:
        candidates=[r for r in manifest['manifests'] if r.get('platform',{}).get('os')=='linux' and r.get('platform',{}).get('architecture')=='arm64' and r.get('platform',{}).get('variant','v8')=='v8']
        need(len(candidates)==1 and re.fullmatch(DIGEST,candidates[0].get('digest','')),'Ambiguous/missing ARM64 index entry')
        pinned=ref.rsplit(':',1)[0]+'@'+candidates[0]['digest']
        H.checked_process([regctl,'manifest','get','--format','raw-body',pinned],env,work/'platform-manifest.json',120)
        raw=H.read(work/'platform-manifest.json',2*1024**2);need('sha256:'+sha(raw)==candidates[0]['digest'],'Platform descriptor SHA differs');manifest=json.loads(raw)
    digest='sha256:'+sha(raw)
    case.update(manifest_digest=digest,tag_manifest_digest=top,pinned_image=ref.rsplit(':',1)[0]+'@'+digest,compressed_bytes=descriptors(manifest),state='RESOLVED')

def layer_inventory(repo,record):
    """Use the already validated catalog and its explicit repository root.

    The pinned 424b012 parent helper omits repository/ in its inventory root.
    Its file/networking utilities are reusable, but that inventory path is not.
    """
    result={'scope':'stored_layer_metadata_only_no_shared_page_claim','snapshot_id':record['id'],
            'repository':str(repo),'content_hashes_verified':False,'available':True}
    for kind in ('memory','rootfs'):
        raw=record['committed'].get(kind+'_layers')
        need(isinstance(raw,list) and 0<len(raw)<=256,'Missing/invalid '+kind+' layer list')
        rows=[]
        for item in raw:
            need(isinstance(item,dict),'Invalid layer record')
            origin='Managed' if kind=='memory' else next(iter(item),'')
            need(kind=='memory' or len(item)==1,'Ambiguous rootfs layer type')
            layer=item if kind=='memory' else item.get(origin)
            need(isinstance(layer,dict),'Invalid layer descriptor')
            digest,size=layer.get('digest'),layer.get('size')
            need(isinstance(digest,str) and re.fullmatch(DIGEST,digest) and type(size) is int and size>=0,'Invalid layer digest/size')
            row={'origin':origin,'digest':digest,'stored_bytes_declared':size,'available':False}
            if origin=='Managed':
                path=repo/'managed-layers'/(digest.replace(':','_')+'.overlaybd.commit');row['path']=str(path)
                try:
                    H.safe(path);meta=path.stat();need(stat.S_ISREG(meta.st_mode),'Managed layer is not a regular file')
                    row.update(file_bytes=meta.st_size,allocated_file_bytes=meta.st_blocks*512,dev=meta.st_dev,inode=meta.st_ino,mtime_ns=meta.st_mtime_ns)
                    need(meta.st_size==size,'Managed layer descriptor/file size mismatch')
                    row['available']=True
                except Exception as error:
                    row.update(error_type=type(error).__name__,errno=getattr(error,'errno',None),reason=str(error))
            else:row['reason']='External placement unresolved; no local-file measurement claimed'
            result['available']=result['available'] and row['available'];rows.append(row)
        result[kind]=rows
    return result

def verify_ready(case):
    sid=case['build_id'];repo=BASE/'state/snapshot-store/repository';raw=H.read(repo/'catalog/records'/(sid+'.json'),2*1024**2);record=json.loads(raw)
    need(record['id']==sid and record['resources']['memory_mib']==4096,'Built template resource/identity mismatch')
    need(H.read(repo/'snapshots'/sid/'commit')==b'committed','Built snapshot not committed')
    need(record['committed'],'Ready template lacks committed artifacts')
    need('catalog_sha256' not in case or case['catalog_sha256']==sha(raw),'Previously ready catalog changed')
    inv=layer_inventory(repo,record)
    case.update(catalog_sha256=sha(raw),resources=record['resources'],parent_layer_inventory=inv,
       build_vm_stop_evidence='Ready publication follows successful TemplateBuildRunner sandbox.stop; not an independent process audit')
    # Preserve observations before rejecting an incomplete inventory, so status
    # exposes the precise failed files without another diagnostic round trip.
    failures=[r for k in ('memory','rootfs') for r in inv[k] if not r['available']]
    case['layer_inventory_summary']={'repository':str(repo),'memory_layers':len(inv['memory']),
        'rootfs_layers':len(inv['rootfs']),'available':inv['available'],'failed_layer_count':len(failures),'failed_layers':failures[:16]}
    need(inv['available'],'Built layers unavailable; inspect case layer_inventory_summary (strict metadata checks preserved)')

def build_case(case,state,api,work,env,wait_seconds=1800):
    current=case['state']
    need(current not in ('CREATE_INTENT','CREATE_RESPONSE_UNCONFIRMED','BUILD_ERROR'),'Unresolved create or failed build preserved; no new POST')
    if current=='READY':verify_ready(case);return
    if current in ('RESOLVED','DOWNLOADING'):
        capacity();empty(api);case['state']='DOWNLOADING';save(state)
        layout=work/'image';regctl=BASE/'deps/regctl/v0.11.5/regctl'
        H.checked_process([regctl,'image','copy','--platform','linux/arm64',case['pinned_image'],'ocidir://'+str(layout)+':input'],env,work/'image-copy.log',1800)
        case['verification']=verify_layout(layout,case['manifest_digest']);case['local_oci_directory']=str(layout);case['state']='IMAGE_VERIFIED';save(state)
    elif current in ('IMAGE_VERIFIED','CREATED'):
        # Recheck immutable OCI inputs before resuming a not-yet-submitted build.
        verify_layout(H.safe(Path(case['local_oci_directory'])),case['manifest_digest'])
    if case['state']=='IMAGE_VERIFIED':
        capacity();empty(api);case['state']='CREATE_INTENT';save(state)
        status,response=api.call('POST','/v3/templates',{'name':case['template_name'],'memoryMB':4096,'tags':[]})
        need(status==202 and isinstance(response,dict),'Template create response unconfirmed')
        tid,bid=response.get('templateID'),response.get('buildID')
        need(isinstance(tid,str) and re.fullmatch(ID,tid) and tid==bid,'Unexpected template/build identity')
        case.update(template_id=tid,build_id=bid,state='CREATED');save(state)
    if case['state']=='CREATED':
        empty(api);capacity();case['state']='BUILD_INTENT';save(state)
        status,_=api.call('POST','/v2/templates/'+case['template_id']+'/builds/'+case['build_id'],
                         {'fromImage':'ocidir://'+case['local_oci_directory']+'@'+case['manifest_digest'],'steps':[]})
        need(status==202,'Build submission not acknowledged');case['state']='BUILDING';save(state)
    need(case['state'] in ('BUILD_INTENT','BUILDING','WAITING_ASYNC'),'Unexpected case state')
    # BUILD_INTENT on resume polls only. Never resubmit an uncertain build.
    deadline=time.monotonic()+wait_seconds;last_print=0
    while True:
        status,body=api.call('GET','/templates/'+case['template_id']+'/builds/'+case['build_id']+'/status')
        need(status==200 and isinstance(body,dict),'Cannot query known build')
        progress=body.get('status');case['last_build_status']=progress
        if progress=='ready':verify_ready(case);case['state']='READY';save(state);empty(api);return
        if progress=='error':
            case['state']='BUILD_ERROR';case['build_error']=H.error_summary({'message':(body.get('reason') or {}).get('message','Build error')},api.key);save(state)
            raise RuntimeError('Template build failed; known build ID and error preserved')
        need(progress in ('waiting','building'),'Unknown build status; preserve')
        if time.monotonic()>=deadline:
            case['state']='WAITING_ASYNC';save(state);raise RuntimeError('Known build still pending after bounded wait; resume will poll only')
        if time.monotonic()-last_print>30:
            print('BUILD_PROGRESS '+case['instance_id']+' '+progress,flush=True);save(state);last_print=time.monotonic()
        time.sleep(5)

def worker(state):
    api=None;env={};work=H.safe(Path(state['work_directory']))
    try:
        api=Api(state['original_identity']);env,network=environment(work);state['network_environment']=network
        state.update(status='COW55_TEMPLATE_PREPARATION_RUNNING',worker_pid=os.getpid(),
            worker_start_ticks=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19],
            memory_controller=cgroup_observation(api.identity[0]));save(state)
        need(api.call('GET','/health')[0]==204,'Original unhealthy');empty(api)
        for i,case in enumerate(state['cases']):
            if case['state']=='NEW':
                item=work/('case-%02d'%i);item.mkdir(exist_ok=True,mode=0o700)
                print('RESOLVE %d/55 %s'%(i+1,case['instance_id']),flush=True);resolve(case,item,env);save(state)
        total=sum(c['compressed_bytes'] for c in state['cases']);state['declared_compressed_bytes_sum']=total
        need(total<=MAX_TOTAL,'55-image compressed input exceeds 256GiB budget');save(state)
        for i,case in enumerate(state['cases']):
            print('BUILD %d/55 %s state=%s'%(i+1,case['instance_id'],case['state']),flush=True)
            build_case(case,state,api,work/('case-%02d'%i),env)
        need(all(c['state']=='READY' for c in state['cases']),'Not all templates ready')
        need(H.runtime_pid()==tuple(state['original_identity']),'Original service changed before completion')
        state['status']='COW55_ALL_TEMPLATES_READY_NO_REPLAY_STARTED';state['completed_templates']=55
    except BaseException as error:
        state['status']='STOPPED_COW55_TEMPLATE_PREPARATION';state['error_type']=type(error).__name__
        state['reason']=H.redact_child_output(str(error),env)
        if api is not None:state['reason']=state['reason'].replace(api.key,'[REDACTED]')
        state['completed_templates']=sum(c['state']=='READY' for c in state['cases'])
    finally:
        state['worker_finished']=True;save(state);H.save(work/'return.json',state)
        print('BEGIN_RETURN_REPORT');print(json.dumps(summary(state),indent=2));print('END_RETURN_REPORT',flush=True)

def summary(state):
    result={k:v for k,v in state.items() if k not in ('cases','network_environment')}
    result['case_states']=[{k:c.get(k) for k in ('instance_id','state','template_id','build_id','last_build_status','resources','build_error','layer_inventory_summary')} for c in state['cases']]
    result['completed_templates']=sum(c['state']=='READY' for c in state['cases'])
    result['worker_liveness']='not_attested'
    if state.get('worker_pid') and state.get('worker_start_ticks'):
        try:
            now=Path('/proc/'+str(state['worker_pid'])+'/stat').read_text().rsplit(')',1)[1].split()[19]
            result['worker_liveness']='same_process_present' if now==state['worker_start_ticks'] else 'PID_reused'
        except OSError:result['worker_liveness']='not_present'
    return result

def run():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('start','resume','status','worker'))
    parser.add_argument('--input',type=Path,default=ROOT/'cow55_inputs.json');parser.add_argument('--lock-fd',type=int)
    args=parser.parse_args();need(os.getuid()==os.geteuid()==1204 and os.uname().nodename=='server1','A ordinary jwk required')
    caps=dict(s.split(':',1) for s in Path('/proc/self/status').read_text().splitlines() if ':' in s)
    need(all(int(caps[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapAmb')),'No effective/permitted/ambient capabilities')
    os.umask(0o077);load_helper()
    if args.mode=='status':
        state=read_json(STATE);print('BEGIN_RETURN_REPORT');print(json.dumps(summary(state),indent=2));print('END_RETURN_REPORT');return
    import fcntl
    fd=args.lock_fd if args.mode=='worker' else os.open(H.safe(LOCK),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    need(type(fd) is int and fd>=0,'Missing inherited lock')
    try:
        m=os.fstat(fd);lm=LOCK.stat();need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and (m.st_dev,m.st_ino)==(lm.st_dev,lm.st_ino),'Lock identity differs')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.mode=='worker':
            state=read_json(STATE);worker(state);return
        selected=inputs(args.input);identity=list(H.runtime_pid());api=Api(identity);need(api.call('GET','/health')[0]==204,'Original unhealthy');empty(api);capacity()
        if args.mode=='start':
            need(not STATE.exists(),'Batch receipt exists; inspect status and use resume, never delete it')
            status,templates=api.call('GET','/v2/templates');need(status==200 and isinstance(templates,list),'Template inventory unavailable')
            need(all(r.get('buildStatus') in ('ready','error') for r in templates),'Existing template build pending; do not overlap')
            names={v for row in templates for k in ('names','aliases') for v in row.get(k,[]) if isinstance(v,str)}
            need(not names&{c['template_name'] for c in selected},'A selected template name already exists without this batch receipt; preserve')
            work=Path(tempfile.mkdtemp(prefix='node-a-cow55-build-',dir=ROOT/'relay/reports'))
            state={'revision':'cow55-template-build-v1','run_id':uuid.uuid4().hex,'status':'COW55_BUILD_STARTING','work_directory':str(work),
              'input_sha256':INPUT_SHA,'original_identity':identity,'prepared_templates_target':55,'max_parallel_builds':1,
              'memory_mib_per_build':4096,'cpu_policy':'Omitted, same as colleague pull; record actual backend default',
              'max_image_compressed_bytes':MAX_IMAGE,'max_total_compressed_bytes':MAX_TOTAL,'filesystem_reserve_bytes':MIN_FREE,
              'storage_hard_quota_enforced':False,'measurement_cache_state':'Preparation copy/hash prewarms files; no cold-cache claim',
              'SDK_called':False,'services_modified':False,'B_accessed':False,'replay_started':False,'test_sandboxes_created':0,
              'temporary_build_VMs_used_by_template_backend':True,'worker_finished':False,
              'cases':[{'instance_id':c['instance_id'],'template_name':c['template_name'],'image_tag':c['arm_or_x86_image_tag'],
                        'replay_sha256':c['replay_sha256'],'state':'NEW'} for c in selected]}
            save(state)
        else:
            state=read_json(STATE);need(state['input_sha256']==INPUT_SHA and state['original_identity']==identity,'Batch input or Runtime changed')
            need(state['status']!='COW55_ALL_TEMPLATES_READY_NO_REPLAY_STARTED','Batch already completed; no repeat build')
            need(not any(c['state'] in ('CREATE_INTENT','CREATE_RESPONSE_UNCONFIRMED','BUILD_ERROR') for c in state['cases']),'Uncertain creation/failed build requires review; no retry')
            state['worker_finished']=False;state['status']='COW55_BUILD_RESUMING';state.pop('reason',None);state.pop('error_type',None);save(state)
        work=H.safe(Path(state['work_directory']));log=work/('worker-'+uuid.uuid4().hex[:8]+'.log')
        with log.open('xb') as output:
            child=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).resolve()),'worker','--lock-fd',str(fd)],
                  stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,pass_fds=(fd,),start_new_session=True,cwd=ROOT)
        launch={'status':'COW55_TEMPLATE_WORKER_LAUNCHED','pid':child.pid,'log':str(log),'receipt':str(STATE),
                'next_action':'Use this script status; launch acknowledgement is not template success','replay_started':False}
        H.save(work/('launch-'+str(child.pid)+'.json'),launch)
        print('BEGIN_RETURN_REPORT');print(json.dumps(launch,indent=2));print('END_RETURN_REPORT')
    finally:os.close(fd)

if __name__=='__main__':
    try:run()
    except Exception as error:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_COW55_CONTROLLER','error_type':type(error).__name__,'reason':str(error),'automatic_retry':False},indent=2));print('END_RETURN_REPORT');raise SystemExit(1)
