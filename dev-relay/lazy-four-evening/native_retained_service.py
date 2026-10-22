"""Prepare a pinned, capability-free native provider unit. No automatic root execution."""
import argparse,hashlib,json,os,re,socket,stat,subprocess,sys,uuid
from contextlib import contextmanager
from pathlib import Path

ROOT=Path('/home/jwk/agent')
COMMIT='bd6d72a55066d07ceeda8db765658900ed85988b'
PINS={'aenv_ub_provider/__init__.py': 'd2874d88f7d86870ee8386ef2f7bad5e451b4fce5beef6c7b488998b0250665b', 'aenv_ub_provider/__main__.py': '1b29b9dcdcba2813c13dd0b616e5942c24aba97be245869ee145a04f47e5d9d9', 'aenv_ub_provider/bindings.py': '64aded662c0566e8f60018814b76b961af4729e1871571e098f8dbe926b833ef', 'aenv_ub_provider/contract.py': '0c47efda619977b708fdb88f9195e49ea7b9bc45c9ec28de75e9173d3cfe8be9', 'aenv_ub_provider/io.py': '0a42d175d199e676819c02a1a8594af7e2946c0563f4e966ef902ce2e3f20956', 'aenv_ub_provider/lazy.py': '78936996bbf9b3a61950208da9e03c96fa1fa41517f7add66efb2c942a3c25ee', 'aenv_ub_provider/lazy_service.py': 'f4e87898430d6b51640cce171e6be672fe2530a03d72c7580e72f89285a7f0e3', 'aenv_ub_provider/prebuilt.py': 'ceb383cdecd3dae158abdeefa5717f347367c073d19a281f15f9ac2940df49ff', 'aenv_ub_provider/raw.py': 'e8a95882197eec441a49ffb7cea11ab5b8d939c14c181f21cea1ae3a547684e7', 'aenv_ub_provider/retained.py': '81472cfc0d079a75b3ff632e689fc4d76c5cd570b152a2032010ab38085807d2', 'aenv_ub_provider/sdk.py': 'd7fe2d35aeedb2423cbed387c284a71b5336fe24a221b91aa9e7d30cac0189f3', 'aenv_ub_provider/service.py': '2a12a74fce3c5751c29cdd31459186020d6338071011ead1bd284e5c06578907', 'aenv_ub_provider/stored.py': 'dd2c001b2e87fe07e6be9db287221e0686845e90b8a14b11039baa7b3cd762a8'}
ENTRY_SHA='fb28c99a35a9285f52ab6370d5383cb980a5a98591816e359079a94abdfac59c'
GIB=1024**3

def need(ok,message):
    if not ok:raise RuntimeError(message)

def ordinary(node):
    need(sys.platform=='linux' and os.uname().machine=='aarch64' and os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205
         and socket.gethostname()==('server1' if node=='node-a' else 'agent1'),'Use intended ordinary experiment user')
    status=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)
    need(all(int(status[k].strip(),16)==0 for k in ('CapInh','CapPrm','CapEff','CapAmb')),'Capability-free provider required')

def owned(path,limit=1024**2):
    path=Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Redirected or out-of-workspace source')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204 and before.st_nlink==1
             and before.st_size<=limit and not before.st_mode&0o022,'Unexpected input metadata')
        raw=stream.read(limit+1);after=os.fstat(stream.fileno())
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(raw)==before.st_size,'Input changed')
    return raw

def put(path,value):
    with path.open('x') as stream:json.dump(value,stream,indent=2);stream.flush();os.fsync(stream.fileno())

def root_put(path,value):
    put(path,value)
    os.chmod(path,0o644)

def memory_headroom(coverage):
    fields=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines() if ':' in line)
    available=int(fields['MemAvailable'].split()[0])*1024
    need(available>=coverage+8*GIB,'Insufficient current memory headroom for this bounded native generation')
    return available

@contextmanager
def coordination_mutex(name):
    import fcntl
    need(name in ('native-four-prepare.lock','ub-layer-sdk-node-a.lock','ub-layer-sdk-node-b.lock'),'Unexpected coordination lock')
    path=ROOT/'relay'/name
    if name=='native-four-prepare.lock' and not path.exists():
        need(path.parent.resolve(strict=True)==path.parent and path.parent.stat().st_uid==1204,'Unexpected local coordination directory')
        try:
            created=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            os.close(created)
        except FileExistsError:pass
    need(path.resolve(strict=True)==path,'Existing coordination lock required')
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        meta=os.fstat(fd);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1,'Coordination mutex differs')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:os.close(fd)

def validate_request(value,node):
    need(isinstance(value,dict),'Expected a native service request object')
    selectors=[key for key in ('manifest','snapshotSet','imageSet','bindingCatalog') if key in value]
    need(len(selectors)==1,'Choose exactly one native input kind')
    selector=selectors[0]
    need(selector!='imageSet' or node=='node-a','Only the owner publishes prebuilt image sets')
    need(selector!='bindingCatalog' or node=='node-b','Only the importer accepts the owner binding catalog')
    common={'version','scenario','installation',selector,'deviceRuntime','output','adapter','adapterSha256',
            'region','logicalBudgetBytes','coverageBytes'}
    expected=common|(({'artifactRoot'} if selector=='manifest' else set()) if node=='node-a' else {'publisherManifest','publisherManifestSha256'})
    if selector=='bindingCatalog':expected.add('bindingCatalogSha256')
    need(isinstance(value,dict) and set(value)==expected and type(value['version']) is int and value['version']==1,'Unexpected native service request')
    need(value['scenario'] in ('single-a','dual-ab') and (node=='node-a' or value['scenario']=='dual-ab'),'Scenario/node differs')
    for key,cap in (('logicalBudgetBytes',16*GIB),('coverageBytes',18*GIB)):
        need(type(value[key]) is int and 0<value[key]<=cap,'Declared native budget exceeds this experiment scope')
    need(value['coverageBytes']>=value['logicalBudgetBytes'],'Coverage guard below logical budget')
    role_paths=(['artifactRoot'] if selector=='manifest' else []) if node=='node-a' else ['publisherManifest']
    for key in ('installation',selector,'deviceRuntime','output','adapter',*role_paths):
        path=Path(value[key]);need(path.is_absolute() and path.is_relative_to(ROOT) and '..' not in path.parts,'Request path outside experiment workspace')
    output=Path(value['output'])
    need(not output.is_relative_to(Path(value['installation'])),'Provider output must not mutate the pinned source installation')
    if node=='node-a' and selector=='manifest':need(not output.is_relative_to(Path(value['artifactRoot'])),'Provider output must not mutate snapshot artifacts')
    for key in ('adapterSha256',*(['publisherManifestSha256'] if node=='node-b' else []),*(['bindingCatalogSha256'] if selector=='bindingCatalog' else [])):
        need(isinstance(value[key],str) and re.fullmatch(r'sha256:[0-9a-f]{64}',value[key]),'Expected explicit file SHA256')
    need(isinstance(value['region'],str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,127}',value['region']),'Invalid existing region')
    return value

def input_identity(value,node,destination=None):
    """Pin reviewed metadata and keep every archive separate from new outputs.

    Core rehashes the actual raw images before SDK publication. These pins bind
    activation to the same selection, manifests and runtime reviewed in prepare.
    """
    files=[value['deviceRuntime']]
    if node=='node-b':files.append(value['publisherManifest'])
    if 'bindingCatalog' in value:
        files.append(value['bindingCatalog']);items=[]
    elif 'imageSet' in value:
        files.append(value['imageSet']);selection=json.loads(owned(value['imageSet']))
        need(isinstance(selection,dict) and set(selection)=={'version','images'}
             and type(selection['version']) is int and selection['version']==1
             and isinstance(selection['images'],list) and 1<=len(selection['images'])<=32,'Invalid prebuilt image set')
        for image in selection['images']:
            need(isinstance(image,dict) and set(image)=={'sourceConfig','paths','filesystem'}
                 and isinstance(image['paths'],list) and 1<=len(image['paths'])<=8,'Invalid prepared image entry')
            files.append(image['sourceConfig'])
            for name in [image['sourceConfig'],*image['paths']]:
                need(isinstance(name,str),'Expected absolute prepared image path')
                path=Path(name)
                need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True)==path
                     and path.is_file() and path.stat().st_uid==1204,'Prepared image path or owner differs')
                for new in (value['output'],*([destination] if destination is not None else [])):
                    need(not Path(new).is_relative_to(path.parent),'New output must be separate from prepared image directories')
        items=[]
    elif 'snapshotSet' in value:
        files.append(value['snapshotSet']);selection=json.loads(owned(value['snapshotSet']))
        need(isinstance(selection,dict) and set(selection)=={'version','snapshots'}
             and type(selection['version']) is int and selection['version']==1
             and isinstance(selection['snapshots'],list) and 1<=len(selection['snapshots'])<=32,'Invalid snapshot set')
        items=selection['snapshots']
    else:items=[{k:value[k] for k in (('manifest','artifactRoot') if node=='node-a' else ('manifest',))}]
    expected={'manifest','artifactRoot'} if node=='node-a' else {'manifest'}
    for item in items:
        need(isinstance(item,dict) and set(item)==expected,'Invalid role-specific snapshot entry')
        for name in item.values():
            need(isinstance(name,str),'Expected explicit snapshot path')
            path=Path(name);need(path.is_absolute() and path.is_relative_to(ROOT) and '..' not in path.parts,'Snapshot path outside experiment workspace')
        files.append(item['manifest'])
        if node=='node-a':
            archive=Path(item['artifactRoot']);need(archive.resolve(strict=True)==archive and archive.is_dir(),'Redirected archive directory')
            for new in (value['output'],*([destination] if destination is not None else [])):
                need(not Path(new).is_relative_to(archive),'New output must not mutate a snapshot archive')
    return {name:hashlib.sha256(owned(name)).hexdigest() for name in sorted(set(files))}

def command_args(value,node):
    validate_request(value,node)
    is_set='snapshotSet' in value
    prebuilt='imageSet' in value or 'bindingCatalog' in value
    args=[('publish-' if node=='node-a' else 'import-')+('prebuilt-set' if prebuilt else 'retained-'+('set' if is_set else 'snapshot'))]
    selection={'image-set':'imageSet'} if 'imageSet' in value else ({'binding-catalog':'bindingCatalog','binding-catalog-sha256':'bindingCatalogSha256'} if 'bindingCatalog' in value else {('snapshot-set' if is_set else 'manifest'):('snapshotSet' if is_set else 'manifest')})
    fields={**selection,'device-runtime':'deviceRuntime','output':'output','adapter':'adapter',
            'adapter-sha256':'adapterSha256','region':'region','max-bytes':'logicalBudgetBytes','coverage-bytes':'coverageBytes'}
    fields.update(({} if is_set or prebuilt else {'artifact-root':'artifactRoot'}) if node=='node-a' else {
        'publisher-manifest':'publisherManifest','publisher-manifest-sha256':'publisherManifestSha256'})
    for flag,key in fields.items():args+=['--'+flag,str(value[key])]
    if value['scenario']=='dual-ab':args+=['--reader','node-b-native-retained']
    return args

def verify_source(directory):
    receipt=json.loads(owned(directory/'installation.json'))
    need(receipt.get('status')=='NATIVE_RETAINED_PROVIDER_INSTALLED_TESTED_NO_SDK' and receipt.get('testsExit')==0
         and receipt.get('release',{}).get('coreCommit')==COMMIT,'Pinned source installation/tests not confirmed')
    for name,pin in PINS.items():need(hashlib.sha256(owned(directory/name)).hexdigest()==pin,'Installed provider source differs')
    entry=owned(directory/'provider_entry.py',65536)
    need(hashlib.sha256(entry).hexdigest()==ENTRY_SHA,'Provider entry differs')
    return entry

def service_command(plan,script,plan_path,plan_sha):
    need(re.fullmatch(r'jwk-native-retained-node-[ab]-[0-9a-f]{12}\.service',plan['unit']),'Unexpected owned unit name')
    wait_args=['--wait','--pipe'] if plan.get('waitForRelease',True) else ['--property=StandardOutput=journal','--property=StandardError=journal']
    return ['/usr/bin/systemd-run','--unit='+plan['unit'],'--collect',*wait_args,
        '--property=User=jwk','--property=Group=jwk','--property=SupplementaryGroups=ubsmd',
        '--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=NoNewPrivileges=yes',
        '--property=RestrictSUIDSGID=yes','--property=Type=exec','--property=Restart=no',
        '--property=KillMode=control-group','--property=TimeoutStopSec=90s','--property=LimitNOFILE=4096',
        '--property=LimitCORE=0','--property=UMask=0077',
        '--property=MemoryMax='+str(plan['request']['coverageBytes']+GIB),
        '--property=LimitMEMLOCK='+str(plan['request']['coverageBytes']),
        '/usr/bin/python3','-I','-B',str(script),'serve','--node',plan['node'],
        '--plan',str(plan_path),'--sha256',plan_sha,'--run']

def activation_receipt(plan,pin):
    # Root receipts stay outside directories writable by the experiment user.
    parent=Path('/run/agentenv-native-retained')
    for path in (parent.parent,):
        meta=path.lstat();need(path.resolve(strict=True)==path and stat.S_ISDIR(meta.st_mode)
                              and meta.st_uid==0 and not meta.st_mode&0o022,'Unexpected root receipt ancestor')
    try:
        parent.mkdir(mode=0o755);os.chmod(parent,0o755)
    except FileExistsError:pass
    meta=parent.lstat();need(parent.resolve(strict=True)==parent and stat.S_ISDIR(meta.st_mode)
                           and meta.st_uid==0 and not meta.st_mode&0o022,'Root receipt parent is not protected')
    need(re.fullmatch(r'jwk-native-retained-node-[ab]-[0-9a-f]{12}\.service',plan['unit']),'Invalid activation identity')
    directory=parent/plan['unit'];directory.mkdir(mode=0o755)  # One activation attempt; never reuse.
    os.chmod(directory,0o755)
    root_put(directory/'intent.json',{'state':'intent_before_systemd_run','unit':plan['unit'],'planSha256':pin,'bootId':plan['bootId']})
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    return directory

def prepare(request_path,node,destination,detached=False):
    ordinary(node)
    with coordination_mutex('native-four-prepare.lock'):
        return prepare_locked(request_path,node,destination,detached)

def prepare_locked(request_path,node,destination,detached=False):
    ordinary(node);os.umask(0o077)
    value=validate_request(json.loads(owned(request_path)),node)
    memory_headroom(value['coverageBytes'])
    installation=Path(value['installation']);verify_source(installation)
    output=Path(value['output'])
    need(output.resolve()==output and output.parent.is_dir() and not output.exists() and not output.is_symlink(),'Provider output already exists or is redirected')
    adapter=owned(value['adapter'],16*1024**2)
    need('sha256:'+hashlib.sha256(adapter).hexdigest()==value['adapterSha256'],'Adapter differs')
    # Reuse the exact adapter already proven by this node's released v1 run.
    previous=ROOT/('r/lazy4-a-v1' if node=='node-a' else 'r/lazy4-b-v1')
    old=json.loads(owned(previous/'prepared.json'))
    need(old.get('adapterSha256')==value['adapterSha256'][7:] and owned(previous/'libaenv-ub.so',16*1024**2)==adapter,
         'This service entry reuses only the node retained SDK adapter')
    released=json.loads(owned(previous/'provider/owner.json'))
    need(released.get('state')=='released' and released.get('finalizeAcknowledged') is True
         and (node=='node-b' or released.get('deleteAcknowledged') is True),'Old experiment release is unconfirmed')
    destination=Path(destination)
    need(destination.is_absolute() and destination.is_relative_to(ROOT) and destination.resolve()==destination
         and destination.parent.is_dir() and not destination.exists() and not destination.is_symlink(),'Use a fresh plan directory')
    need(not destination.is_relative_to(output) and not output.is_relative_to(destination)
         and not destination.is_relative_to(installation),'Plan and provider/source directories must be separate')
    input_pins=input_identity(value,node,destination)
    args=command_args(value,node)
    destination.mkdir(mode=0o700)
    try:
        result=subprocess.run(['/usr/bin/python3','-I','-B',str(installation/'provider_entry.py'),*args],capture_output=True,timeout=1800)
        with (destination/'validation.stdout').open('xb') as stream:stream.write(result.stdout)
        with (destination/'validation.stderr').open('xb') as stream:stream.write(result.stderr)
        need(result.returncode==0 and len(result.stdout)<=65536,'Native source/budget validation failed; inspect preserved validation logs')
        validated=json.loads(result.stdout)
        need(validated.get('state')=='retained_generation_validated_no_sdk','Unexpected provider dry-run result')
        need(isinstance(validated.get('planSha256'),str) and re.fullmatch(r'sha256:[0-9a-f]{64}',validated['planSha256']),
             'Core did not provide a complete reviewed plan identity')
        need(input_identity(value,node,destination)==input_pins,'Native inputs changed during validation')
    except BaseException as error:
        if isinstance(error,subprocess.TimeoutExpired):
            with (destination/'validation-timeout.stdout').open('xb') as stream:stream.write(error.stdout or b'')
            with (destination/'validation-timeout.stderr').open('xb') as stream:stream.write(error.stderr or b'')
        put(destination/'preparation-failure.json',{'state':'STOPPED_NATIVE_VALIDATION_NO_SDK_OR_UNIT',
            'errorType':type(error).__name__,'SDK_called':False,'servicesChanged':False})
        raise
    script=destination/'native_service.py';source=owned(Path(__file__),512*1024)
    with script.open('xb') as stream:stream.write(source)
    plan={'version':1,'node':node,'request':value,'unit':'jwk-native-retained-'+node+'-'+uuid.uuid4().hex[:12]+'.service',
          'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
          'scriptSha256':hashlib.sha256(source).hexdigest(),'inputPins':input_pins,'dryRun':validated,'SDK_called':False,'servicesChanged':False,
          'waitForRelease':not detached}
    put(destination/'plan.json',plan)
    plan_sha=hashlib.sha256(owned(destination/'plan.json')).hexdigest()
    code="""import hashlib,os,socket,stat,sys
from pathlib import Path
assert os.geteuid()==0 and socket.gethostname()==HOST,'Use declared root terminal'
p=Path(SCRIPT);assert p.resolve(strict=True)==p and p.stat().st_uid==1204 and stat.S_ISREG(p.stat().st_mode)
raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==PIN
sys.argv=[SCRIPT,'activate','--node',NODE,'--plan',PLAN,'--sha256',PLAN_SHA,'--run']
exec(compile(raw,SCRIPT,'exec'),{'__name__':'__main__','__file__':SCRIPT})
"""
    constants={'HOST':'server1' if node=='node-a' else 'agent1','NODE':node,'SCRIPT':str(script),'PIN':plan['scriptSha256'],
               'PLAN':str(destination/'plan.json'),'PLAN_SHA':plan_sha}
    block="/usr/bin/python3 -I -B - <<'NATIVE_RETAINED_SCOPED_SERVICE'\n"+''.join(k+'='+repr(v)+'\n' for k,v in constants.items())+code+'NATIVE_RETAINED_SCOPED_SERVICE\n'
    with (destination/'activate-root.sh').open('x') as out:out.write(block)
    print('NATIVE_SERVICE_PREPARED_NO_SDK_NO_UNIT\n'+block,flush=True)

def load_plan(path,pin,node):
    raw=owned(path);need(hashlib.sha256(raw).hexdigest()==pin,'Reviewed plan changed')
    plan=json.loads(raw)
    need(plan['version']==1 and plan['node']==node and plan['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Plan node or boot changed')
    validate_request(plan['request'],node)
    need(type(plan.get('waitForRelease',True)) is bool,'Invalid provider activation wait policy')
    need(input_identity(plan['request'],node,Path(path).parent)==plan['inputPins'],'Reviewed native input metadata changed')
    need(hashlib.sha256(owned(Path(__file__),512*1024)).hexdigest()==plan['scriptSha256'],'Service wrapper changed')
    return plan

def serve(plan):
    ordinary(plan['node']);need(984 in os.getgroups(),'Scoped existing SDK IPC group missing')
    request=plan['request'];entry=verify_source(Path(request['installation']))
    with coordination_mutex('native-four-prepare.lock'),coordination_mutex('ub-layer-sdk-'+plan['node']+'.lock'):
        need(input_identity(request,plan['node'])==plan['inputPins'],'Native inputs changed before SDK start')
        sys.argv=[str(Path(request['installation'])/'provider_entry.py'),*command_args(request,plan['node']),
                  '--expected-plan-sha256',plan['dryRun']['planSha256'],'--run']
        exec(compile(entry,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})

def activate(plan,path,pin):
    need(os.geteuid()==0 and socket.gethostname()==('server1' if plan['node']=='node-a' else 'agent1'),'Use intended root terminal')
    for command,expected in ((['id','-u','jwk'],'1204'),(['id','-g','jwk'],'1205')):
        need(subprocess.check_output(['/usr/bin/'+command[0],*command[1:]],text=True).strip()==expected,'Experiment account changed')
    need(subprocess.check_output(['/usr/bin/getent','group','ubsmd'],text=True).split(':')[2]=='984','SDK group changed')
    memory_headroom(plan['request']['coverageBytes'])
    state=subprocess.run(['/usr/bin/systemctl','show',plan['unit'],'--property=LoadState','--value'],capture_output=True,text=True,timeout=10)
    need(state.stdout.strip()=='not-found','Existing unit preserved; no repeated activation')
    need(not Path(plan['request']['output']).exists(),'Native generation output exists; no implicit restart')
    receipts=activation_receipt(plan,pin)
    try:
        result=subprocess.run(service_command(plan,Path(__file__),path,pin))
    except BaseException as error:
        root_put(receipts/'uncertain.json',{'state':'activation_or_wait_uncertain','errorType':type(error).__name__,
                                    'unit':plan['unit'],'retryPermitted':False})
        raise
    root_put(receipts/'result.json',{'state':'systemd_run_returned','exitCode':result.returncode,'unit':plan['unit'],
                              'providerReleaseInferred':False,'retryPermitted':False})
    print('OWN_NATIVE_PROVIDER_UNIT_EXIT='+str(result.returncode),flush=True)
    return result.returncode

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('prepare','activate','serve'))
    p.add_argument('--node',choices=('node-a','node-b'),required=True);p.add_argument('--request',type=Path)
    p.add_argument('--directory',type=Path);p.add_argument('--plan',type=Path);p.add_argument('--sha256');p.add_argument('--run',action='store_true')
    p.add_argument('--detached',action='store_true',help='Prepare an explicit systemd submission; readiness and retirement remain separately required');a=p.parse_args()
    if not a.run:print('PLAN_ONLY_NO_SDK_OR_SERVICE_ACTION');return 0
    if a.mode=='prepare':need(a.request is not None and a.directory is not None,'Explicit private request and fresh plan directory required');prepare(a.request,a.node,a.directory,a.detached);return 0
    need(a.plan is not None and a.sha256 is not None,'Pinned prepared plan required');plan=load_plan(a.plan,a.sha256,a.node)
    if a.mode=='activate':return activate(plan,a.plan,a.sha256)
    serve(plan);return 0

if __name__=='__main__':raise SystemExit(main())
