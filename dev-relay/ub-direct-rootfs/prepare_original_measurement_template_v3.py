"""Create only missing per-deployment CLI configuration from the live baseline.

The existing Runtime key is reused locally, never returned in receipts. No
server configuration, binary, service or user-global CLI config is changed.
"""
import json,os,re,stat,tomllib

def baseline_endpoint(environment):
    value=environment.get(b'API_ADDR',b'').decode('ascii')
    match=re.fullmatch(r'127\.0\.0\.1:(180[0-9]{2})',value)
    if match is None:raise RuntimeError('Live original Runtime must declare a retained loopback API_ADDR')
    return int(match[1])

def baseline_cli_config(base,api,read):
    def directory(path):
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=0o700);os.chown(path,1204,1205)
        meta=path.stat()
        if path.resolve(strict=True)!=path or not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=1204 or meta.st_mode&0o022:
            raise RuntimeError('Baseline CLI directory identity differs: '+str(path))
    api.stable()
    for relative in ('cli','cli/config','cli/config/aenv','cli/cache','cli/tmp'):directory(base/relative)
    path=base/'cli/config/aenv/credentials'
    expected={'url':'http://127.0.0.1:'+str(api.port),'api_key':api.key}
    if path.exists() or path.is_symlink():
        # Existing equivalent configuration is retained byte for byte.
        actual=tomllib.loads(read(path).decode())
        if actual!=expected:raise RuntimeError('Existing baseline CLI endpoint/authentication differs; preserved')
        created=False
    else:
        raw=('url = '+json.dumps(expected['url'])+'\napi_key = '+json.dumps(expected['api_key'])+'\n').encode()
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fchown(stream.fileno(),1204,1205);os.fchmod(stream.fileno(),0o600);os.fsync(stream.fileno())
        created=True
    if tomllib.loads(read(path).decode())!=expected:raise RuntimeError('Baseline CLI configuration verification failed')
    api.stable()
    return {'status':'BASELINE_MEASUREMENT_CLI_READY','createdCredentials':created,
            'existingRuntimeAuthenticationReused':True,'credentialValueReturned':False,'serverConfigurationChanged':False}


"""Publish one retained snapshot into the genuine baseline, catalog last.

Uses existing on-node immutable files, never allocates UB or transfers payload.
Original server/config stay unchanged; only absent snapshot dependencies are
hard-linked. Payload checks use O_DIRECT with no buffered fallback. No alias is
created, existing catalog/dependency contents are never overwritten.
"""
import hashlib,json,mmap,os,re,stat,time,tomllib
from pathlib import Path

def prep_need(ok,why):
    if not ok:raise RuntimeError(why)

def prep_stamp(m):return (m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns)

def prep_meta(path,size=None):
    prep_need(path.resolve(strict=True)==path,'Snapshot input redirected: '+str(path))
    m=path.stat()
    prep_need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and not m.st_mode&0o022
              and 0<m.st_size<=16*1024**3 and (size is None or m.st_size==size),'Snapshot file metadata differs: '+str(path))
    return m

def prep_digest(path,direct=False):
    before=prep_meta(path)
    flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK
    if direct:
        prep_need(hasattr(os,'O_DIRECT') and hasattr(os,'preadv'),'Direct source validation unsupported; no buffered fallback')
        flags|=os.O_DIRECT
    fd=os.open(path,flags)
    try:
        prep_need(prep_stamp(os.fstat(fd))==prep_stamp(before),'Input changed before checksum')
        h=hashlib.sha256();position=0
        if direct:
            with mmap.mmap(-1,1024**2) as buf:
                while position<before.st_size:
                    count=os.preadv(fd,[buf],position)
                    prep_need(0<count<=min(len(buf),before.st_size-position),'Short/changed direct input')
                    h.update(memoryview(buf)[:count]);position+=count
                    prep_need(position==before.st_size or count==len(buf),'Unaligned short direct input')
        else:
            prep_need(before.st_size<=64*1024**2,'Snapshot artifact exceeds metadata bound')
            while position<before.st_size:
                raw=os.read(fd,min(1024**2,before.st_size-position));prep_need(bool(raw),'Truncated snapshot artifact')
                h.update(raw);position+=len(raw)
        after=os.fstat(fd)
        prep_need(prep_stamp(after)==prep_stamp(before) and after.st_ctime_ns==before.st_ctime_ns,'Input changed during checksum')
        return h.hexdigest(),before
    finally:os.close(fd)

def prep_contract(record,manifest,files,template):
    sid=template['templateId'];committed=record['committed']
    prep_need(record['id']==sid and record['resources']==template['resources'],'Template resources/identity differ')
    prep_need(not any(committed.get(k) for k in ('attached_drives','volume_snapshots','memory_startup')),'Unsupported snapshot dependencies')
    prep_need(not manifest.get('nativeRootfs') and not manifest.get('attachedDrives')
              and manifest['memory']['virtualSize']==4096*1024**2,'Expected ordinary memory/rootfs snapshot')
    roots=committed['rootfs_layers']
    prep_need(all(type(row) is dict and set(row)=={'Managed'} for row in roots),'Unsupported rootfs kind')
    roots=[row['Managed'] for row in roots]
    prep_need(roots==template['rootfsLayers'] and len(roots)==8 and len(committed['memory_layers'])==1,'First-template dependency scope differs')
    names={}
    for layer in roots+committed['memory_layers']:
        digest,size=layer['digest'],layer['size']
        prep_need(re.fullmatch('sha256:[0-9a-f]{64}',digest) and type(size) is int and size>0,'Invalid lower identity')
        name='managed-layers/'+digest.replace(':','_')+'.overlaybd.commit'
        desc={'bytes':size,'sha256':digest[7:]}
        prep_need(name not in names or names[name]==desc,'Conflicting lower identity')
        prep_need(files.get(name)==desc,'Frozen archive lower checksum differs');names[name]=desc
    for name in ('catalog/records/'+sid+'.json',*(f'snapshots/{sid}/{n}' for n in ('vm_state.bin','firecracker-manifest.json','commit'))):
        desc=files[name]
        prep_need(type(desc['bytes']) is int and 0<desc['bytes']<=64*1024**2 and re.fullmatch('[0-9a-f]{64}',desc['sha256']),'Invalid artifact descriptor')
        names[name]=desc
    prep_need(sum(row['bytes'] for row in names.values())<=16*1024**3,'Snapshot validation byte budget exceeded')
    return names

def prepare_original_template(pipeline,node):
    import fcntl
    root=Path('/home/jwk/agent');source=root/'deployments/agentenv-lazy-four-32ce41c'
    original=root/'deployments/agentenv-ae9c626-baseline';repo=original/'state/snapshot-store/repository'
    src=source/'state/snapshot-store/repository'
    comp=pipeline.loaded('comparison');inputs=comp.module('inputs');gate=comp.module('admission')
    runtime=comp.module('ready').ReadyRun();rt=runtime.rt
    template_list,_=inputs.load_inputs(source,node,1,rt.read,runtime.replay.steps_from);template=template_list[0];sid=template['templateId']
    prep_need(sid=='01a15c9e-54d0-7b92-a50b-0b6ec2e9136b','First template changed')
    work=comp.WORK
    prep_need(not any((work/name).exists() for name in ('controller.lock','run.json','original','full','failure-original.json','failure-full.json')),
              'Existing measurement attempt preserved; no repository preparation')
    context=gate.inspect_runtime(node,'original')
    config=tomllib.loads(rt.read(original/'config/runtime.toml').decode())
    env=dict(x.split(b'=',1) for x in (Path('/proc')/str(context['pid'])/'environ').read_bytes().split(b'\0') if b'=' in x)
    prep_need(config['home_path']==str(original/'state') and config.get('backend',{}).get('posix_fs',{}).get('snapshot_store') in (None,str(original/'state/snapshot-store'))
              and not any(k in env for k in (b'AENV_HOME',b'AENV_SNAPSHOT_STORE')),'Original repository configuration differs')
    api=rt.Api(original,context['unit'],baseline_endpoint(env))
    prep_need(api.pid==context['pid'] and api.ticks==context['startTicks'],'Original process identity changed')
    def guard():
        api.stable();runtime.guard()
        prep_need(api.call('GET','/v2/sandboxes?limit=1')==(200,[]) and runtime.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Both Runtime inventories must be empty')
    guard()
    print('BASELINE_CLI_PREPARATION '+json.dumps(baseline_cli_config(original,api,rt.read)),flush=True)
    seed=json.loads(rt.read(source/'rootfs-inputs.json'))
    manifest_raw=rt.read(Path(seed['inputDirectory'])/'manifest.json')
    prep_need(hashlib.sha256(manifest_raw).hexdigest()==seed['sourceManifestSha256'],'Frozen archive manifest changed')
    archive=json.loads(manifest_raw)
    record_raw=rt.read(src/'catalog/records'/(sid+'.json'))
    prep_need(hashlib.sha256(record_raw).hexdigest()==template['catalogSha256'],'Retained catalog checksum differs')
    record=json.loads(record_raw);manifest=json.loads(rt.read(src/'snapshots'/sid/'firecracker-manifest.json'))
    names=prep_contract(record,manifest,archive['files'],template)
    prep_need(rt.read(src/'snapshots'/sid/'commit')==b'committed','Snapshot is not committed')
    for p in (src,src/'catalog/records',src/'managed-layers',src/'snapshots',repo,repo/'catalog/records'):
        prep_need(p.resolve(strict=True)==p and p.is_dir() and p.stat().st_uid==1204,'Repository layout differs: '+str(p))
    target_directories=[repo/'managed-layers',repo/'snapshots',repo/'snapshots'/sid]
    for p in target_directories:
        if p.exists() or p.is_symlink():
            prep_need(p.resolve(strict=True)==p and p.is_dir() and p.stat().st_uid==1204 and not p.stat().st_mode&0o022,
                      'Existing repository directory differs: '+str(p))
    receipt_dir=root/'r'/('original-template-measurement-'+node+'-v1')
    receipt_dir.mkdir(mode=0o700,exist_ok=True)
    prep_need(receipt_dir.resolve(strict=True)==receipt_dir and receipt_dir.stat().st_uid==0 and not receipt_dir.stat().st_mode&0o077,'Preparation directory differs')
    lockfd=os.open(receipt_dir/'lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        lockmeta=os.fstat(lockfd)
        prep_need(stat.S_ISREG(lockmeta.st_mode) and lockmeta.st_uid==0 and not lockmeta.st_mode&0o077,'Preparation lock differs')
        fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        prep_need(not (receipt_dir/'intent.json').exists() or (receipt_dir/'complete.json').exists(),
                  'Previous template preparation incomplete; preserve and reconcile')
        catalog=repo/'catalog/records'/(sid+'.json');missing=[];validated=[]
        # Validate every required dependency BEFORE publishing anything. A
        # hard link changes ctime/link count, but does not populate PageCache.
        for name,desc in sorted(names.items()):
            source_path=src/name;sm=prep_meta(source_path,desc['bytes'])
            direct=name.startswith('managed-layers/')
            digest,_=prep_digest(source_path,direct)
            prep_need(digest==desc['sha256'],'Retained dependency checksum differs: '+name)
            target=repo/name
            if target.exists() or target.is_symlink():
                tm=prep_meta(target,desc['bytes'])
                if (sm.st_dev,sm.st_ino)!=(tm.st_dev,tm.st_ino):
                    prep_need(prep_digest(target,direct)[0]==desc['sha256'],'Existing baseline dependency conflicts: '+name)
            else:missing.append(name)
            validated.append({'name':name,'sha256':digest,'bytes':desc['bytes'],'sourceDev':sm.st_dev,'sourceInode':sm.st_ino,'sourceMtimeNs':sm.st_mtime_ns})
        prep_need(not catalog.exists() or not missing,'Committed baseline template has missing dependencies; preserve')
        guard()
        # Require both namespaces to resolve the same repository directory.
        visible=Path('/proc')/str(api.pid)/'root'/str(repo).lstrip('/')
        prep_need(os.path.samestat(repo.stat(),visible.stat()),'Baseline mount namespace points at another repository')
        if missing:
            prep_need(not (receipt_dir/'complete.json').exists(),'Previously completed template now missing files')
            intent={'node':node,'templateId':sid,'catalogSha256':template['catalogSha256'],'sourceRepository':str(src),'targetRepository':str(repo),
                    'missingFiles':missing,'directoriesToCreate':[str(p) for p in target_directories if not p.exists()],'validated':validated,'originalRuntime':context,'createdNs':time.time_ns(),
                    'payloadChecks':'O_DIRECT SHA256; no buffered fallback','publication':'hard links; catalog last; no aliases',
                    'automaticCleanup':False}
            pipeline.put(receipt_dir/'intent.json',pipeline.canonical(intent))
            for p in target_directories:
                guard()
                if not p.exists():p.mkdir(mode=0o700);os.chown(p,1204,1205)
                prep_need(p.resolve(strict=True)==p and p.is_dir() and p.stat().st_uid==1204 and not p.stat().st_mode&0o022,
                          'Repository directory changed: '+str(p))
            order=sorted(missing,key=lambda n:(n.startswith('catalog/records/'),n.endswith('/commit'),n))
            for name in order:
                guard();row=next(x for x in validated if x['name']==name);p=src/name;before=prep_meta(p,row['bytes'])
                prep_need((before.st_dev,before.st_ino,before.st_mtime_ns)==(row['sourceDev'],row['sourceInode'],row['sourceMtimeNs']),'Verified input changed')
                prep_need(p.stat().st_dev==(repo/name).parent.stat().st_dev,'Cross-filesystem linking unavailable; no payload-copy fallback')
                os.link(p,repo/name,follow_symlinks=False)
                prep_need(os.path.samestat(p.stat(),(repo/name).stat()),'Published link identity differs')
                fd=os.open((repo/name).parent,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(fd)
                finally:os.close(fd)
        inputs.check_catalogs(original,template_list,rt.read)
        # /proc/PID/root is intentionally a namespace view; the ordinary
        # canonical-path reader correctly rejects it, so read this bounded
        # metadata after verifying the repository directory identity above.
        with (visible/'catalog/records'/(sid+'.json')).open('rb') as stream:
            seen=os.fstat(stream.fileno())
            prep_need(stat.S_ISREG(seen.st_mode) and seen.st_size==len(record_raw),'Visible catalog metadata differs')
            observed=stream.read(len(record_raw)+1)
        prep_need(hashlib.sha256(observed).hexdigest()==template['catalogSha256'],'Runtime mount does not see committed catalog')
        guard()
        result={'status':'ORIGINAL_TEMPLATE_READY_FOR_COMPARISON','node':node,'templateId':sid,'catalogSha256':template['catalogSha256'],
                'resources':template['resources'],'newHardlinks':len(missing),'payloadCopiedBytes':0,'servicesChanged':False,'binariesChanged':False,
                'SDKCalled':False,'GuestCreated':False,'sourcePayloadHashMode':'O_DIRECT','coldCacheClaimed':False,
                'existingSourceCacheEvicted':False,'repository':str(repo),'receiptDirectory':str(receipt_dir)}
        if not (receipt_dir/'complete.json').exists():pipeline.put(receipt_dir/'complete.json',pipeline.canonical(result))
        print('ORIGINAL_TEMPLATE_PREPARATION '+json.dumps(result),flush=True)
        return result
    except Exception as error:
        failure={'status':'STOPPED_ORIGINAL_TEMPLATE_PREPARATION_PRESERVE_STATE','node':node,'errorType':type(error).__name__,
                 'reason':str(error),'publicationIntentPresent':(receipt_dir/'intent.json').exists(),
                 'receiptDirectory':str(receipt_dir),'automaticCleanup':False,'GuestCreatedByPreparation':False}
        try:pipeline.put(receipt_dir/('failure-'+str(time.time_ns())+'.json'),pipeline.canonical(failure))
        except Exception:pass
        print(json.dumps(failure),flush=True)
        raise
    finally:os.close(lockfd)
