"""Prepare, activate, validate or restore this one isolated DSec Runtime update.

All target effects require the human to execute this entry on node A. The old
failed journal, original services, source images and snapshot files are retained.
"""
import argparse,base64,copy,hashlib,json,os,re,signal,socket,stat,subprocess,sys,time,types,uuid,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
D=ROOT/'deployments/agentenv-dsec-hostfile-v1'
STAGE=D/'updates/pmem-id-fix-v1'
OLD_WORK=D/'dsec-real-template-smoke-v1'
NEW_WORK=D/'dsec-real-template-smoke-v2'
RUNTIME=ROOT/'r/dsec-hostfile-a-v1'
UNIT='jwk-aenv-dsec-hostfile-v1-node-a.service'
PROVIDER='jwk-dsec-file-provider-node-a-v1.service'
OLDER=('jwk-aenv-ae9c626-node-a.service','jwk-aenv-ub-b019f27-node-a.service',
       'jwk-aenv-native-fe63038-node-a.service','ubsmd.service','ubse.service')
CORE='268104ecc65080d776c2301e09e7902686ac4253'
PAYLOAD={}

def need(ok,message):
    if not ok:raise RuntimeError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def unpack(name):
    row=PAYLOAD[name];raw=zlib.decompress(base64.b64decode(row['z64'],validate=True))
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'Embedded helper differs: '+name)
    return raw

def module(name):
    value=types.ModuleType(name);value.__file__=str(STAGE/(name+'.py'))
    exec(compile(unpack(name),value.__file__,'exec'),value.__dict__)
    return value

def read(path,limit=2*1024**2):
    path=Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Redirected/outside input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204 and 0<before.st_size<=limit,'Unexpected input owner/type/length')
        raw=stream.read(limit+1);after=os.fstat(stream.fileno())
    stamp=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    need(stamp(before)==stamp(after)==stamp(path.stat()) and len(raw)==before.st_size,'Input changed while reading')
    return raw

def load(path):return json.loads(read(path))

def mkdir(path):
    path=Path(path)
    if not path.exists():
        mkdir(path.parent);path.mkdir(mode=0o700)
        if os.geteuid()==0:os.chown(path,1204,1205)
    need(path.resolve(strict=True)==path and path.is_relative_to(ROOT) and path.is_dir()
         and path.stat().st_uid==1204,'Unexpected output directory')

def put(path,data,mode=0o600):
    path=Path(path);mkdir(path.parent)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    with os.fdopen(fd,'wb') as out:
        if os.geteuid()==0:os.fchown(out.fileno(),1204,1205)
        out.write(data);out.flush();os.fsync(out.fileno())
    os.chmod(path,mode)

def save(path,value):
    path=Path(path);mkdir(path.parent)
    if path.exists():read(path)
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    put(temporary,(json.dumps(value,indent=2)+'\n').encode())
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def unit(name):
    result=subprocess.run(['/usr/bin/systemctl','show',name,
        '--property=LoadState,ActiveState,MainPID,User,Group,ControlGroup,WorkingDirectory'],
        capture_output=True,text=True,timeout=10)
    fields=dict(x.split('=',1) for x in result.stdout.splitlines() if '=' in x)
    need(result.returncode==0 or fields.get('LoadState')=='not-found','Unable to inspect unit '+name)
    return fields

def ticks(pid):return Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]

def proc_identity(pid):
    need(type(pid) is int and pid>1,'Invalid process identity')
    return {'pid':pid,'ticks':ticks(pid)}

def same_process(value):
    try:return ticks(value['pid'])==value['ticks']
    except FileNotFoundError:return False

def older_state():
    result={}
    for name in OLDER:
        fields=unit(name);pid=int(fields.get('MainPID','0'))
        result[name]=[fields.get('LoadState'),fields.get('ActiveState'),pid,ticks(pid) if pid>1 else None]
    return result

def api_for_old(rt,gate):
    api=rt.Api(D,UNIT,18084)
    context={'unit':UNIT,'pid':api.pid,'ticks':api.ticks,'configSha256':api.config_sha,
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    need(context==gate.CONTEXT,'Old Runtime changed since the observed failed request')
    return api

def make_smoke(prepare_sha,entry_sha):
    source=unpack('smoke').decode()
    replacements={"CORE='eb2301e7bd924784287f6c50d4faa4cabc7ca52b'":"CORE="+repr(CORE),
      "PREPARE_SHA='d17183de4707cc4631eb6692cbd6e8bce00a995174cc571b37ac8c3d6ba049cd'":"PREPARE_SHA="+repr(prepare_sha),
      "WORK=D/'dsec-real-template-smoke-v1'":"WORK=D/'dsec-real-template-smoke-v2'"}
    for old,new in replacements.items():
        need(source.count(old)==1,'Smoke template changed');source=source.replace(old,new)
    old="        need(self.api.pid==1880294 and self.api.ticks=='52944913' and self.api.port==18084,\n             'Runtime changed since the returned healthy deployment; preserve it')"
    new="""        proof=self.rt.load(D/'updates/pmem-id-fix-v1/activation-proof.json')
        need(proof.get('coreCommit')==CORE and proof.get('entrySha256')==ENTRY_SHA
             and proof.get('serverSha256')==installation['binaries']['server']
             and proof.get('runtimeContext',{}).get('pid')==self.api.pid
             and proof['runtimeContext'].get('ticks')==self.api.ticks
             and proof['runtimeContext'].get('configSha256')==self.api.config_sha
             and proof['runtimeContext'].get('bootId')==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
             and self.api.port==18084,'Updated Runtime activation proof differs')"""
    need(source.count(old)==1,'Smoke Runtime gate changed');source=source.replace(old,new)
    source='ENTRY_SHA='+repr(entry_sha)+'\n'+source
    # Surface already-redacted HTTP diagnostics in the return, without another
    # request to the operator for a separate tail command after a failed create.
    old="            report['journal']=self.case.state;report['commands']=self.commands"
    new="""            errors=WORK/'api-errors.jsonl'
            if errors.exists():
                raw=self.rt.read(errors,32768)
                report['apiErrors']=[json.loads(line) for line in raw.decode().splitlines() if line.strip()]
            report['journal']=self.case.state;report['commands']=self.commands"""
    need(source.count(old)==1,'Smoke report gate changed');source=source.replace(old,new)
    compile(source,'updated-smoke','exec');return source.encode()

def bootstrap(plan_sha,mode='activate'):
    entry=Path(__file__).resolve();raw=read(entry,2*1024**2)
    return ("/usr/bin/python3 -I -B - <<'DSEC_FIXED_RUNTIME_ROOT'\n"+
        "import hashlib,os,runpy,stat,sys\nfrom pathlib import Path\n"+
        'p=Path('+repr(str(entry))+');expected='+repr(sha(raw))+'\n'+
        "assert os.geteuid()==0 and os.uname().nodename=='server1'\n"+
        "assert p.resolve(strict=True)==p and p.stat().st_uid==1204 and p.is_file()\n"+
        'assert p.stat().st_size=='+str(len(raw))+'\n'+
        "assert hashlib.sha256(p.read_bytes()).hexdigest()==expected\n"+
        'sys.argv=[str(p),'+repr(mode)+",'--plan-sha',"+repr(plan_sha)+']\n'+
        "runpy.run_path(str(p),run_name='__main__')\nDSEC_FIXED_RUNTIME_ROOT\n")

def prepare():
    if STAGE.exists():
        plan=load(STAGE/'plan.json')
        need(plan.get('entrySha256')==sha(read(Path(__file__).resolve(),2*1024**2)),'Existing plan belongs to another entry')
        need(not (STAGE/'root-state.json').exists(),'Activation already began; use status or explicit rollback')
        module('file_transaction').Transaction(D,STAGE,plan['files']).validate()
        print(bootstrap(sha(read(STAGE/'plan.json'))));return 0
    build_path=ROOT/'builds/dsec-pmem-id-fix-v1/return.json'
    if not build_path.exists():
        builder=module('builder');before=list(sys.argv)
        try:
            sys.argv=['builder','--run'];need(builder.main()==0,'Fixed Runtime build did not complete; outputs preserved')
        finally:sys.argv=before
    build_raw=read(build_path);build=json.loads(build_raw)
    rt=module('four_runtime');gate=module('failed_start_contract');meta=module('update_metadata');tx=module('file_transaction')
    lock=take_lock()
    try:
        evidence=gate.check_failed_request(load(OLD_WORK/'state.json'),read(OLD_WORK/'api-errors.jsonl',32768),load(D/'cohort-state.json'))
        api=api_for_old(rt,gate)
        original={name:read(D/name,2*1024**2) for name in meta.TARGETS}
        definition=json.loads(original['definition-native.json'])
        need(definition['config']==read(D/'config/runtime.toml').decode(),'Installed definition/config disagree')
        for name,pin in definition['binaries'].items():
            need(name in ('server','aenv','uvm-ublk-daemon','aenv-native-fd-verify') and
                 sha(read(D/'bin'/name,128*1024**2))==pin,'Installed executable differs: '+name)
        replacements=meta.compose(original,build_raw)
        server_path=Path(build['server']['path'])
        need(server_path==ROOT/'builds/dsec-pmem-id-fix-v1/artifacts/server','Unexpected candidate path')
        server=read(server_path,128*1024**2)
        need(len(server)==build['server']['bytes'] and sha(server)==build['server']['sha256'],'Candidate server differs')
        mkdir(STAGE);save(STAGE/'failure-evidence.json',evidence)
        status,body=api.call('GET','/sandboxes/'+gate.SANDBOX)
        inv_status,inventory=api.call('GET','/v2/sandboxes?limit=1')
        observation=gate.check_api_observation(status,body,inv_status,inventory)
        if observation=='KNOWN_OWNED_FAILED_GUEST_REQUIRES_EXPLICIT_DELETE':
            save(STAGE/'known-failed-delete.json',{'phase':'intent','sandboxId':gate.SANDBOX,'runId':gate.RUN})
            code,_=api.call('DELETE','/sandboxes/'+gate.SANDBOX,timeout=120)
            need(code in (200,204,404),'Owned failed Guest deletion unconfirmed; do not repeat it')
        need(api.call('GET','/sandboxes/'+gate.SANDBOX)[0]==404 and
             api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Failed Guest/inventory remains; no activation prepared')
        save(STAGE/'api-before-update.json',{'failedIdGet404':True,'apiInventoryEmpty':True,'initialObservation':observation})
        original['bin/server']=read(D/'bin/server',128*1024**2);replacements['bin/server']=server
        need(sha(original['bin/server'])==meta.OLD_SERVER,'Installed old server differs')
        manifest={}
        for name in sorted(original):
            _,pin=tx.stable(D/name)
            need(pin['uid']==1204 and pin['gid']==1205,'Unexpected installed file ownership')
            for kind,data in (('before',original[name]),('after',replacements[name])):put(STAGE/kind/name,data,pin['mode'])
            manifest[name]={kind:tx.stable(STAGE/kind/name)[1] for kind in ('before','after')}
        tx.Transaction(D,STAGE,manifest).validate()
        proxy=load(RUNTIME/'host-proxy.json')
        need(proxy.get('pid')==1880994 and proxy.get('revision')=='aenv-dsec-hostfile-v1','Unexpected old Host proxy')
        proxy_identity={'pid':proxy['pid'],'ticks':str(proxy['start_ticks'])}
        need(same_process(proxy_identity),'Old Host proxy exited or changed')
        provider=unit(PROVIDER);provider_identity=proc_identity(int(provider.get('MainPID','0')))
        need(provider.get('ActiveState')=='active' and provider.get('User')==provider.get('Group')=='jwk','Provider is not the owned active unit')
        entry_sha=sha(read(Path(__file__).resolve(),2*1024**2))
        smoke=make_smoke(sha(replacements['libexec/native_prepare.py']),entry_sha);put(STAGE/'smoke-v2.py',smoke)
        put(STAGE/'cohort-before.json',read(D/'cohort-state.json'))
        plan={'version':1,'entrySha256':entry_sha,'coreCommit':CORE,'runtimeContext':gate.CONTEXT,
            'oldProxy':proxy_identity,'oldProvider':provider_identity,'files':manifest,
            'smokeSha256':sha(smoke),'newServer':build['server'],'buildReceiptSha256':sha(build_raw),
            'failureEvidenceSha256':sha(read(STAGE/'failure-evidence.json')),
            'oldCohortSha256':sha(read(STAGE/'cohort-before.json'))}
        save(STAGE/'plan.json',plan)
        print('BEGIN_DSEC_UPDATE_PREPARED');print(json.dumps({'status':'DSEC_FIX_STAGED_NOT_ACTIVATED',
            'stage':str(STAGE),'coreCommit':CORE,'SDK_called':False,'Guest_created':False,
            'oldPendingPreserved':True,'candidateServerSha256':build['server']['sha256']},indent=2));print('END_DSEC_UPDATE_PREPARED')
        print('BEGIN_DSEC_UPDATE_ROOT');print(bootstrap(sha(read(STAGE/'plan.json'))));print('END_DSEC_UPDATE_ROOT')
        return 0
    finally:os.close(lock)

def take_lock():
    import fcntl
    fd=os.open(D/'cohort.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        meta=os.fstat(fd);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204,'Unexpected lifecycle lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return fd
    except BaseException:os.close(fd);raise

def cgroup_empty(group):
    need(isinstance(group,str) and group.startswith('/') and '..' not in group.split('/'),'Invalid owned cgroup')
    need(group.endswith('/'+UNIT),'Cgroup does not belong to the selected Runtime unit')
    candidates=[]
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left,right=line.split(' - ',1);a=left.split();b=right.split()
        if b[0]=='cgroup2' or b[0]=='cgroup' and 'name=systemd' in b[2].split(','):
            need(a[3]=='/' and '\\' not in a[4],'Unsupported cgroup mount root')
            candidates.append(Path(a[4])/group.lstrip('/'))
    need(0<len(candidates)<=8,'No bounded systemd cgroup hierarchy')
    for parent in candidates:
        for attempt in range(3):
            if not parent.exists():break
            try:
                need(parent.resolve(strict=True)==parent,'Redirected cgroup')
                files=list(parent.rglob('cgroup.procs'))
                if not files and not parent.exists():break
                need(len(files)<=1024 and files,'Unexpected cgroup subtree')
                need(all(p.resolve(strict=True)==p and p.is_relative_to(parent) for p in files),'Redirected cgroup member list')
                if any(p.read_text().strip() for p in files):return False
                break
            except FileNotFoundError:
                # systemd --collect can remove an empty group during this scan.
                # Retry the scoped hierarchy, never infer emptiness from EACCES.
                if attempt==2:raise
    return True

def stop_owned(name,expected):
    need(name in (UNIT,PROVIDER),'Service stop outside update scope')
    fields=unit(name)
    if fields.get('LoadState')=='not-found' or fields.get('ActiveState')=='inactive' and fields.get('MainPID','0')=='0':
        need(not same_process(expected),'Old process still exists despite inactive unit');return
    need(int(fields.get('MainPID','0'))==expected['pid'] and same_process(expected)
         and fields.get('User')==fields.get('Group')=='jwk','Owned service identity changed')
    subprocess.run(['/usr/bin/systemctl','stop',name],check=True,timeout=120)
    need(not same_process(expected),'Owned service process exit unconfirmed')

def owned_proxy_handle(expected):
    fd=os.pidfd_open(expected['pid'])
    try:
        need(same_process(expected),'Host proxy identity changed')
        proc=Path('/proc',str(expected['pid']))
        status=dict(x.split(':',1) for x in (proc/'status').read_text().splitlines() if ':' in x)
        need([int(x) for x in status['Uid'].split()]==[1204]*4 and
            all(int(status[k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapAmb')),'Unexpected Host proxy credentials')
        expected_cmd=[b'/usr/bin/python3',b'-I',b'-B',os.fsencode(D/'libexec/native_service.py'),b'proxy-host',b'']
        need((proc/'cmdline').read_bytes().split(b'\0')==expected_cmd,'Unexpected Host proxy command')
        return fd
    except BaseException:os.close(fd);raise

def stop_current_provider():
    fields=unit(PROVIDER);pid=int(fields.get('MainPID','0'))
    if pid<=1:return
    expected=proc_identity(pid)
    need(fields.get('User')==fields.get('Group')=='jwk','Unexpected provider owner')
    proc=Path('/proc',str(pid))
    command=(proc/'cmdline').read_bytes().split(b'\0')
    need(command==[b'/usr/bin/python3',b'-I',b'-B',os.fsencode(ROOT/'r/dsec-hostfile-plan-v2/provider.py'),b''],
         'Provider is not the staged Host-file helper')
    status=dict(x.split(':',1) for x in (proc/'status').read_text().splitlines() if ':' in x)
    need([int(x) for x in status['Uid'].split()]==[1204]*4 and
         all(int(status[k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapAmb')),'Provider credentials differ')
    stop_owned(PROVIDER,expected)

def activate(plan_sha):
    need(sha(read(STAGE/'plan.json'))==plan_sha,'Activation plan changed')
    plan=load(STAGE/'plan.json');need(plan['entrySha256']==sha(read(Path(__file__).resolve(),2*1024**2)) and plan['coreCommit']==CORE,'Wrong update entry')
    need(not (STAGE/'root-state.json').exists(),'Prior activation preserved; use status/rollback, not another activation')
    rt=module('four_runtime');gate=module('failed_start_contract');tx=module('file_transaction')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==gate.CONTEXT['bootId'],'Boot changed')
    lock=take_lock();proxy_fd=None
    state={'phase':'preflight','runtimeContext':gate.CONTEXT,'entrySha256':plan['entrySha256'],'filesApplied':False}
    try:
        transaction=tx.Transaction(D,STAGE,plan['files']);transaction.validate()
        runuser=next((p for p in ('/usr/sbin/runuser','/usr/bin/runuser') if Path(p).is_file()),None)
        need(runuser is not None,'Existing runuser executable unavailable; no service changed')
        evidence=gate.check_failed_request(load(OLD_WORK/'state.json'),read(OLD_WORK/'api-errors.jsonl',32768),load(D/'cohort-state.json'))
        need(evidence==load(STAGE/'failure-evidence.json') and sha(read(STAGE/'failure-evidence.json'))==plan['failureEvidenceSha256'],'Failure evidence changed')
        api=api_for_old(rt,gate)
        need(api.call('GET','/sandboxes/'+gate.SANDBOX)[0]==404 and api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Inventory not empty before retirement')
        current=unit(UNIT);group=current['ControlGroup'];older=older_state()
        actual=Path('/proc',str(api.pid),'exe').stat();installed=(D/'bin/server').stat()
        need((actual.st_dev,actual.st_ino)==(installed.st_dev,installed.st_ino),'Running executable differs from installed old server')
        proxy_fd=owned_proxy_handle(plan['oldProxy'])
        state['phase']='retiring_old';state['oldControlGroup']=group;save(STAGE/'root-state.json',state)
        stop_owned(UNIT,{'pid':api.pid,'ticks':api.ticks})
        need(cgroup_empty(group),'Old Runtime cgroup still contains processes; files untouched')
        stop_owned(PROVIDER,plan['oldProvider'])
        try:signal.pidfd_send_signal(proxy_fd,signal.SIGTERM)
        except ProcessLookupError:pass
        import select
        poll=select.poll();poll.register(proxy_fd,select.POLLIN)
        need(bool(poll.poll(10000)),'Host proxy exit unconfirmed; files untouched')
        proof={'runtimeContext':gate.CONTEXT,'requestId':gate.REQUEST,'runId':gate.RUN,
            'apiInventoryEmpty':True,'failedIdGet404':True,'oldMainProcessExitConfirmed':True,
            'oldRuntimeCgroupEmpty':True,'oldHostProxyExitConfirmed':True,'oldProviderStopped':True,
            'olderServicesUnchanged':older_state()==older}
        save(STAGE/'retirement-proof.json',proof)
        next_state=gate.resolved_state(evidence,proof)
        state['phase']='old_retired';save(STAGE/'root-state.json',state)
        try:transaction.apply()
        except BaseException:
            state['phase']='swap_interrupted';save(STAGE/'root-state.json',state);raise
        state.update(phase='files_applied',filesApplied=True);save(STAGE/'root-state.json',state)
        save(STAGE/'failed-request-resolution.json',{'evidence':evidence,'retirement':proof,'preparedState':next_state})
        save(D/'cohort-state.json',next_state)
        # Reuse the reviewed activation implementation with the coherent new
        # hashes, rather than hand-copying its capabilities/namespace settings.
        scope={'__name__':'updated_adapter','__file__':str(D/'libexec/native_prepare.py')}
        exec(compile(read(D/'libexec/native_prepare.py',512*1024),scope['__file__'],'exec'),scope)
        pins={str(D/relative):row['sha256'] for relative,row in load(D/'input-manifest.json').items()}
        for name in ('config/runtime.toml','config/api-key','installation.json','definition-native.json',
                     'libexec/native_service.py','libexec/native_base.py','libexec/native_prepare.py','cli/bin/aenv-native','cli/config/aenv/credentials'):
            pins[str(D/name)]=sha(read(D/name,128*1024**2))
        definition=load(D/'definition-native.json');bound=definition['rootfsBinding'];pins[bound['path']]=bound['sha256']
        deadline=time.monotonic()+20
        while time.monotonic()<deadline and any(unit(n).get('LoadState')!='not-found' for n in (UNIT,PROVIDER)):time.sleep(.2)
        text=scope['root_block'](pins,gate.CONTEXT['bootId'],older_state(),18084)
        body=text.split('\n',1)[1].rsplit('NATIVE_NEW_UNIT_REVIEWED_ROOT',1)[0]
        state['phase']='starting_candidate';save(STAGE/'root-state.json',state)
        exec(compile(body,'reviewed-new-unit-activation','exec'),{'__name__':'root_activation'})
        health=subprocess.run([runuser,'-u','jwk','--','/usr/bin/python3','-I','-B',str(D/'libexec/native_service.py'),'health'],
            capture_output=True,text=True,timeout=150)
        save(STAGE/'health-command.json',{'exitCode':health.returncode,'stdout':health.stdout,'stderr':health.stderr})
        need(health.returncode==0,'Candidate health failed; preserve new service and logs')
        active=unit(UNIT);new_pid=int(active.get('MainPID','0'));new_ticks=ticks(new_pid)
        need(active.get('ActiveState')=='active' and (new_pid,new_ticks)!=(api.pid,api.ticks),'Candidate Runtime did not replace the old process')
        actual=Path('/proc',str(new_pid),'exe').stat();installed=(D/'bin/server').stat()
        need((actual.st_dev,actual.st_ino)==(installed.st_dev,installed.st_ino),'Candidate process executable differs')
        need(sha(read(D/'bin/server',128*1024**2))==plan['newServer']['sha256'],'Installed candidate hash changed')
        activation={'coreCommit':CORE,'entrySha256':plan['entrySha256'],'serverSha256':plan['newServer']['sha256'],
            'runtimeContext':{'unit':UNIT,'pid':new_pid,'ticks':new_ticks,'bootId':gate.CONTEXT['bootId'],
                              'configSha256':sha(read(D/'config/runtime.toml'))}}
        save(STAGE/'activation-proof.json',activation)
        state.update(phase='candidate_healthy',activationProof=activation,olderServicesUnchanged=older_state()==older)
        save(STAGE/'root-state.json',state)
        print('DSEC_FIXED_RUNTIME_HEALTHY_RUN_VALIDATE_AS_JWK')
        print(json.dumps({'coreCommit':CORE,'apiPort':18084,'validationCommand':'python3 -I -B '+str(Path(__file__).resolve())+' validate',
            'Guest_created':False,'SDK_called':False,'oldFailedRequestRetired':True},indent=2))
        return 0
    except BaseException as error:
        state['errorType']=type(error).__name__;state['reason']=str(error)[:1000]
        save(STAGE/'root-state.json',state)
        print('DSEC_UPDATE_STOPPED_PRESERVE_STAGE');print(json.dumps(state,indent=2));return 1
    finally:
        if proxy_fd is not None:os.close(proxy_fd)
        os.close(lock)

def rollback(plan_sha):
    need(sha(read(STAGE/'plan.json'))==plan_sha,'Rollback plan changed')
    plan=load(STAGE/'plan.json');need(plan['entrySha256']==sha(read(Path(__file__).resolve(),2*1024**2)),'Rollback entry changed')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['runtimeContext']['bootId'],'Boot changed; preserve update state')
    lock=take_lock();proxy_fd=None
    try:
        state=load(STAGE/'root-state.json')
        need(state.get('phase') in ('old_retired','swap_interrupted','files_applied','starting_candidate','candidate_healthy'),
             'Rollback only accepts an incomplete activation; running validations require owned cleanup first')
        transaction=module('file_transaction').Transaction(D,STAGE,plan['files'])
        transaction.validate(allow_after=True)
        current=unit(UNIT)
        if int(current.get('MainPID','0'))>1:
            for relative,row in plan['files'].items():transaction.pin(D/relative,row['after'])
            rt=module('four_runtime');engine=module('cohort_engine')
            need(engine.quiescent(load(D/'cohort-state.json')),'Validation has pending requests or Guests; use recover first')
            api=rt.Api(D,UNIT,18084)
            need(api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Candidate inventory not empty; preserve it')
            actual=Path('/proc',str(api.pid),'exe').stat();installed=(D/'bin/server').stat()
            need((actual.st_dev,actual.st_ino)==(installed.st_dev,installed.st_ino),'Candidate executable identity differs')
            proxy=load(RUNTIME/'host-proxy.json')
            proxy_fd=owned_proxy_handle({'pid':proxy['pid'],'ticks':str(proxy['start_ticks'])})
            stop_owned(UNIT,{'pid':api.pid,'ticks':api.ticks})
            need(cgroup_empty(current['ControlGroup']),'Candidate cgroup still contains processes')
            stop_current_provider()
            try:signal.pidfd_send_signal(proxy_fd,signal.SIGTERM)
            except ProcessLookupError:pass
            import select
            poll=select.poll();poll.register(proxy_fd,select.POLLIN)
            need(bool(poll.poll(10000)),'Candidate proxy exit unconfirmed')
        else:
            need(cgroup_empty(state['oldControlGroup']),'Inactive Runtime still has child processes')
            engine=module('cohort_engine')
            need(engine.quiescent(load(D/'cohort-state.json')) or state['phase'] in ('old_retired','swap_interrupted'),
                 'Inactive candidate has unresolved validation state')
            stop_current_provider()
            proxy_path=RUNTIME/'host-proxy.json'
            if proxy_path.exists():
                proxy=load(proxy_path);expected={'pid':proxy['pid'],'ticks':str(proxy['start_ticks'])}
                if same_process(expected):
                    proxy_fd=owned_proxy_handle(expected)
                    try:signal.pidfd_send_signal(proxy_fd,signal.SIGTERM)
                    except ProcessLookupError:pass
                    import select
                    poll=select.poll();poll.register(proxy_fd,select.POLLIN)
                    need(bool(poll.poll(10000)),'Inactive candidate proxy exit unconfirmed')
        for name in (UNIT,PROVIDER):
            fields=unit(name)
            need(int(fields.get('MainPID','0'))==0 and fields.get('ActiveState') in ('inactive','failed',None),
                 'New service still active; preserve it before any rollback')
        need(cgroup_empty(state['oldControlGroup']),'Owned cgroup not empty')
        if transaction.journal.exists():transaction.rollback()
        else:transaction.validate()
        state['phase']='rolled_back_service_stopped';save(STAGE/'root-state.json',state)
        print('DSEC_UPDATE_FILES_RESTORED_NEW_SERVICE_STOPPED');return 0
    finally:
        if proxy_fd is not None:os.close(proxy_fd)
        os.close(lock)

def validate(recovery=False):
    plan=load(STAGE/'plan.json');proof=load(STAGE/'activation-proof.json')
    need(plan['entrySha256']==sha(read(Path(__file__).resolve(),2*1024**2)) and proof['coreCommit']==CORE,'Update proof differs')
    raw=read(STAGE/'smoke-v2.py',128*1024);need(sha(raw)==plan['smokeSha256'],'Staged smoke differs')
    scope={'__name__':'updated_smoke','__file__':str(STAGE/'smoke-v2.py')}
    exec(compile(raw,scope['__file__'],'exec'),scope)
    before=list(sys.argv)
    try:sys.argv=['updated-smoke','recover' if recovery else 'run'];return scope['main']()
    finally:sys.argv=before

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('plan','prepare','activate','validate','recover','status','rollback'),nargs='?',default='plan')
    p.add_argument('--plan-sha');args=p.parse_args()
    if args.mode=='plan':
        print(json.dumps({'status':'PLAN_ONLY','coreCommit':CORE,'stage':str(STAGE),
            'phases':['ordinary prepare/build','root activate','ordinary validate'],'SDK_called':False}));return 0
    need(sys.platform=='linux' and os.uname().machine=='aarch64' and socket.gethostname()=='server1','Use node A ARM64')
    if args.mode in ('activate','rollback'):
        need(os.getuid()==os.geteuid()==0 and re.fullmatch('[0-9a-f]{64}',args.plan_sha or ''),'Use printed root command with pinned plan')
        return activate(args.plan_sha) if args.mode=='activate' else rollback(args.plan_sha)
    need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Use ordinary jwk')
    caps=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)
    need(all(int(caps[x],16)==0 for x in ('CapInh','CapPrm','CapEff','CapAmb')),'Capability-free caller required')
    os.umask(0o077)
    if args.mode=='prepare':return prepare()
    if args.mode in ('validate','recover'):return validate(args.mode=='recover')
    for path in (STAGE/'root-state.json',NEW_WORK/'return.json'):
        if path.exists():print(json.dumps(load(path),indent=2))
    if (STAGE/'plan.json').exists():
        print(bootstrap(sha(read(STAGE/'plan.json')),'rollback' if (STAGE/'root-state.json').exists() else 'activate'))
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'DSEC_COORDINATOR_STOPPED_PRESERVE_ALL_OUTPUTS','type':type(error).__name__,
            'reason':re.sub(r'e2b_[A-Za-z0-9._~-]+','<redacted>',str(error))[:1000],'stage':str(STAGE)}));raise SystemExit(1)
