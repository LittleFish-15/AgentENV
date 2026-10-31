"""Resume only the proven pre-import DAX failure; never restart the live SDK."""
import ast,base64,hashlib,json,os,platform,stat,sys,types,zlib
from pathlib import Path
BASE=Path('/home/jwk/root/hpra-v1')
PREVIOUS=Path('/home/jwk/root/relay/jobs/locality-a-dax-rejoin-003/task.py')
PREVIOUS_SHA='42cf492d85621877266a1566249a186f2cdb871953a7f19ee5861a0dfb20c38c'


def need(ok,why):
    if not ok:raise RuntimeError(why)


def checked_read(path,limit=256*1024):
    need(path.resolve(strict=True)==path,'Redirected root input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_uid==0 and not a.st_mode&0o022 and a.st_size<=limit,'Root input owner/type/size differs')
        raw=f.read(limit+1);b=os.fstat(f.fileno())
    sig=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    need(len(raw)<=limit and sig(a)==sig(b)==sig(path.stat()),'Root input changed')
    return raw


def verify_import_failure(source,state):
    # Source plus the exact exception establish that view() stopped on its
    # first statement, before configuration, unit creation or CREATE ioctl.
    tree=ast.parse(source)
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Rejoin')
    view=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='view')
    first=view.body[0]
    need(isinstance(first,ast.ImportFrom) and first.module=='aenv_ub_provider','First view statement differs')
    failure=state.get('failure',{})
    need(state.get('phase')=='stopped_preserve_state' and failure.get('errorType')=='ModuleNotFoundError'
         and failure.get('reason')=="No module named 'aenv_ub_provider'",'Failure is not the proven pre-import failure')
    steps=state['steps']
    need(all(steps[k]['state']=='done' for k in ('code','permissions','sdk'))
         and steps['view']=={'state':'intent'} and not any(k in steps for k in ('provenance','runtime','proxies'))
         and set(state['units'])=={'sdk'},'Unexpected attempted operation; preserve without continuation')


def install_parent_path(old):
    code=BASE/'code';folder=code/'aenv_ub_provider'
    for directory in (BASE,code,folder):
        info=directory.lstat()
        need(directory.resolve()==directory and stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
             'Provider directory is not coordinator-owned')
    package=json.loads(old.source('provider-package'))
    for name,row in package.items():
        need(name.startswith('aenv_ub_provider/') and len(Path(name).parts)==2,'Unexpected provider package path')
        raw=checked_read(code/name)
        need(hashlib.sha256(raw).hexdigest()==row['sha256'] and raw==base64.b64decode(row['base64'],validate=True),
             'Installed provider source differs from the already running SDK version')
    for name,module in list(sys.modules.items()):
        if name=='aenv_ub_provider' or name.startswith('aenv_ub_provider.'):
            need(code in Path(module.__file__).resolve().parents,'Another provider package is already imported')
    import_parent_modules(code)
    return len(package)


def import_parent_modules(code):
    # Exercise the exact import that failed before any kernel or SDK action.
    # Called only after install_parent_path has verified every installed file.
    sys.path.insert(0,str(code))
    from aenv_ub_provider import host_pmem_rootfs,stored,contract


def decode_spec(argv):
    compressed=base64.b64decode(''.join(argv),validate=True);d=zlib.decompressobj()
    raw=d.decompress(compressed,65537)
    need(d.eof and not d.unused_data and not d.unconsumed_tail and len(raw)<=65536,'Resume specification too large')
    return json.loads(raw)


def main():
    need(os.getuid()==os.geteuid()==0 and platform.node()=='server1','A root only')
    spec=decode_spec(sys.argv[1:]);os.umask(0o077)
    current={'hostname':platform.node(),'machineId':Path('/etc/machine-id').read_text().strip(),
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'kernel':platform.release(),'architecture':platform.machine()}
    need(current==spec['identity'],'A boot or machine changed; preserve live state')
    raw=checked_read(PREVIOUS)
    need(hashlib.sha256(raw).hexdigest()==PREVIOUS_SHA,'Existing composed driver changed')
    old=types.ModuleType('checked_previous_rejoin');old.__file__=str(PREVIOUS)
    sys.modules[old.__name__]=old;exec(compile(raw,str(PREVIOUS),'exec'),old.__dict__)
    oldstate=checked_read(BASE/'private/state.json');state=json.loads(oldstate)
    need(state['identity']==current and state['SDK_called'] is True,'A SDK rejoin was not confirmed')
    verify_import_failure(raw,state)
    ctx=old.Rejoin.__new__(old.Rejoin)
    ctx.spec=spec;ctx.node='node-a';ctx.n='a';ctx.auth={'runId':'hpra-20261031-v1'}
    ctx.work=Path(spec['workDirectory']);ctx.active=ctx.work/'rejoin-r1';ctx.state=state
    ctx.api=types.SimpleNamespace(digest=lambda b:hashlib.sha256(b).hexdigest(),
        encoded=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode())
    ctx.plan=json.loads(old.read(Path(spec['planPath'])))
    need(old.digest(Path(spec['planPath']))==spec['planSha256'],'Retained input plan changed')
    pubraw=checked_read(BASE/'public/publisher.json');ctx.publication=json.loads(pubraw)
    need(ctx.api.digest(pubraw)==spec['manifestSha256'][7:] and old.wire(ctx.publication)==pubraw,
         'Original canonical publication order/identity changed')
    ctx.candidate_live();sdk=ctx.bound('sdk')
    need(sdk['pid']==spec['expectedExistingSdkPid'] and old.zero_caps(sdk['pid']),'Unexpected SDK process or capabilities')
    owner=json.loads(old.read(ctx.active/'provider/owner.json'))
    need(owner==state['steps']['sdk']['result']['ownerJournal'] and owner['state']=='serving'
         and owner['role']=='rejoin' and owner['globalObjectDeletionAllowed'] is False and not owner['objects']
         and owner['manifestSha256']==spec['manifestSha256'],'Live SDK ownership changed')
    need(json.loads(old.read(ctx.active/'provider/replicas.json'))==ctx.publication,'Live SDK object changed')
    for label in ('view','runtime','inside-proxy','host-proxy'):
        name='aenv-hpra-a-'+label+'-'+ctx.auth['runId'][-8:]+'.service'
        need(old.props(name)['LoadState']=='not-found','Unexpected existing continuation unit')
    for path in (BASE/'view',BASE/'private/rootfs-config.json',BASE/'public/rootfs-index.json'):
        need(not path.exists() and not path.is_symlink(),'View work was attempted; preserve without retry')
    count=install_parent_path(old)
    # Preserve the exact old state bytes before reconciling this one known,
    # non-mutating failure. Neither SDK intent nor owner journal is cleared.
    old.put(BASE/'private/resume-r1-before.json',oldstate,mode=0o600)
    old.put(BASE/'private/resume-r1-intent.json',ctx.api.encoded({'previousEntrySha256':PREVIOUS_SHA,
        'previousStateSha256':ctx.api.digest(oldstate),'existingSDK':sdk,'providerFilesVerified':count,
        'SDKRestartPlanned':False,'UBAllocationPlanned':False}),mode=0o600)
    need('reconciledPreImportFailure' not in state,'Prior resume already attempted')
    state['reconciledPreImportFailure']={'failure':state.pop('failure'),'viewStep':state['steps'].pop('view'),
        'reason':'Exact frozen view first statement raised ModuleNotFoundError before side effects; live SDK retained',
        'beforeStateSha256':ctx.api.digest(oldstate)}
    # Sorted relay/journal JSON must not change the publication's canonical hash.
    state['steps']['sdk']['result']['publication']=ctx.publication
    ctx.mark('parent_provider_import_fixed_existing_sdk_retained')
    try:
        for label in ('view','provenance','runtime','proxies'):
            ctx.once(label,getattr(ctx,label))
        ctx.bound('sdk');ctx.mark('A_REJOINED_DAX_RUNTIME_HEALTHY_NO_GUEST')
        print('BEGIN_A_REJOIN_RESULT_JSON',flush=True)
        print(json.dumps(state,sort_keys=True),flush=True)
        print('END_A_REJOIN_RESULT_JSON',flush=True)
        print('A_REJOINED_DAX_RUNTIME_HEALTHY_NO_GUEST',flush=True)
        return 0
    except Exception as error:
        detail={'status':'A_REJOIN_RESUME_STOPPED_PRESERVE_STATE','errorType':type(error).__name__,
            'reason':str(error)[:1000],'SDKRestartAttempted':False,'UBAllocationAttempted':False,'automaticRetry':False}
        state['failure']=detail;ctx.mark('stopped_preserve_state')
        detail['units']={k:old.props(v['name']) for k,v in state['units'].items()}
        detail['workerDiagnostics']={}
        for label in ('view','runtime'):
            if label in state['units']:
                # Runtime logs can include user configuration; only collect
                # the DAX worker journal automatically. Full logs stay local.
                if label=='view':
                    p=old.cmd([old.tool('journalctl'),'-u',state['units'][label]['name'],'-n','40','--no-pager','-o','cat'],30,check=False)
                    detail['workerDiagnostics'][label]=p.stdout[-16000:].decode(errors='replace')
        print(json.dumps(detail,sort_keys=True),flush=True)
        return 1


if __name__=='__main__':
    try:code=main()
    except Exception as error:
        print(json.dumps({'status':'A_REJOIN_RESUME_STOPPED_BEFORE_CONTINUATION','errorType':type(error).__name__,
            'reason':str(error)[:800],'SDKRestartAttempted':False,'UBAllocationAttempted':False}),flush=True)
        code=1
    raise SystemExit(code)
