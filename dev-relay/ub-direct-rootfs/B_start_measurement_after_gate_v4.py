"""Online transport for the resource-schema-corrected measurement pipeline.

Only public code is fetched. Private context stays in human-relayed capsules.
"""
import base64,hashlib,json,os,re,stat,subprocess,textwrap,types,urllib.error,urllib.parse,urllib.request,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
REPOSITORY='LittleFish-15/AgentENV'
PREFIX='dev-relay/ub-direct-rootfs/'
NAME='B_start_measurement_after_gate_v4.py'
PIPELINE_NAME='AB_deletefix_measurement_pipeline_v2.py'
PIPELINE_COMMIT='3f71837c7c13adb57c8889159b3e05dc63d80443'
PIPELINE_SHA='710adbbbc7aaa41f939819d7d333dafeddaae5398b5ab2cbfad68120ed51f56f'
PIPELINE_BYTES=215219

def need(ok,why):
    if not ok:raise RuntimeError(why)

def check_bytes(raw,pin,length):
    need(len(raw)==length and hashlib.sha256(raw).hexdigest()==pin,'Pinned source size/SHA256 mismatch; no execution')
    return raw

class GitHubRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        parsed=urllib.parse.urlparse(newurl)
        need(parsed.scheme=='https' and parsed.netloc in ('raw.githubusercontent.com','api.github.com'),'Unexpected code-download redirect')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def read_cached(path,pin,length):
    need(path.parent.resolve(strict=True)==path.parent and not path.is_symlink(),'Code cache path redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0,1204) and not before.st_mode&0o022
             and before.st_size==length,'Code cache differs: '+str(path)+' uid='+str(before.st_uid)
             +' mode='+oct(stat.S_IMODE(before.st_mode))+' bytes='+str(before.st_size))
        raw=stream.read(length+1);after=os.fstat(stream.fileno())
        need(all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),'Code cache changed during read')
    return check_bytes(raw,pin,length)

def fetch(name,commit,pin,length,opener=None):
    need(re.fullmatch(r'[A-Za-z0-9_]+\.py',name) and re.fullmatch('[0-9a-f]{40}',commit)
         and re.fullmatch('[0-9a-f]{64}',pin) and 0<length<1024**2,'Invalid fixed source request')
    locations=[('api-raw',f'https://api.github.com/repos/{REPOSITORY}/contents/{PREFIX}{name}?ref={commit}'),
               ('raw',f'https://raw.githubusercontent.com/{REPOSITORY}/{commit}/{PREFIX}{name}')]
    errors=[]
    for kind,url in locations:
        try:
            headers={'User-Agent':'aenv-pinned-measurement','Accept-Encoding':'identity','Accept':'application/vnd.github.raw+json' if kind=='api-raw' else 'text/plain'}
            if opener is not None:
                request=urllib.request.Request(url,headers=headers)
                with opener.open(request,timeout=20) as response:body=response.read(length*2+16385)
            else:
                command=['curl','--fail','--location','--silent','--show-error','--connect-timeout','10','--max-time','30','--max-filesize',str(length*2+16384)]
                for key,value in headers.items():command+=['--header',key+': '+value]
                reply=subprocess.run(command+[url],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
                if reply.returncode:raise urllib.error.URLError('curl exit '+str(reply.returncode))
                body=reply.stdout
            if kind=='api':
                need(len(body)<=length*2+16384,'Oversized GitHub response')
                value=json.loads(body);need(value.get('encoding')=='base64','Unexpected GitHub encoding')
                raw=base64.b64decode(value['content'])
            else:raw=body
        except (urllib.error.URLError,TimeoutError,OSError,subprocess.TimeoutExpired,json.JSONDecodeError,KeyError) as error:
            errors.append({'endpoint':kind,'errorType':type(error).__name__,'httpStatus':getattr(error,'code',None)})
            continue
        return check_bytes(raw,pin,length)
    raise RuntimeError('Pinned GitHub source unavailable: '+json.dumps(errors)+'; no pipeline phase started')

def ensure_code(name,commit,pin,length):
    need(ROOT.resolve(strict=True)==ROOT,'Agent directory redirected')
    path=ROOT/name
    if path.exists() or path.is_symlink():return path,read_cached(path,pin,length)
    raw=fetch(name,commit,pin,length)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fchmod(stream.fileno(),0o600);os.fsync(stream.fileno())
    return path,raw

def online_command(phase,node,context,release,adapter_sha,adapter_bytes):
    need(re.fullmatch('[0-9a-f]{40}',release) and re.fullmatch('[0-9a-f]{64}',adapter_sha)
         and type(adapter_bytes) is int and 0<adapter_bytes<=65536,'Online release pin missing')
    data=json.dumps(context,sort_keys=True,separators=(',',':')).encode()
    need(len(data)<=16*1024**2,'Private context exceeds relay budget')
    capsule='\n'.join(textwrap.wrap(base64.b64encode(zlib.compress(data,9)).decode(),100))
    host={'a':'server1','b':'agent1'}[node]
    # Bootstrap downloads the small public adapter; the adapter reuses/fetches
    # the fixed public pipeline. The capsule is never part of an HTTP call.
    return f'''python3 -I -B - <<'ONLINE_MEASUREMENT_RELAY'
import base64,hashlib,json,os,platform,stat,subprocess,sys,zlib
from pathlib import Path
assert os.getuid()==os.geteuid()==0 and platform.node()=={host!r},'Root on {host} required'
data=zlib.decompress(base64.b64decode("""{capsule}"""))
assert hashlib.sha256(data).hexdigest()=={hashlib.sha256(data).hexdigest()!r}
root=Path('/home/jwk/agent');assert root.resolve(strict=True)==root
p=root/{NAME!r};pin={adapter_sha!r};size={adapter_bytes};release={release!r}
if p.exists() or p.is_symlink():
 assert not p.is_symlink() and p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as stream:
  meta=os.fstat(stream.fileno());assert stat.S_ISREG(meta.st_mode) and meta.st_uid in (0,1204) and meta.st_mode&0o022==0 and meta.st_size==size, f'Code cache metadata differs: {{p}} uid={{meta.st_uid}} mode={{oct(stat.S_IMODE(meta.st_mode))}} bytes={{meta.st_size}}'
  raw=stream.read(size+1)
else:
 raw=None
 urls=[('api-raw',f'https://api.github.com/repos/{REPOSITORY}/contents/{PREFIX}{NAME}?ref={{release}}'),('raw',f'https://raw.githubusercontent.com/{REPOSITORY}/{{release}}/{PREFIX}{NAME}')]
 for kind,url in urls:
  try:
   accept='application/vnd.github.raw+json' if kind=='api-raw' else 'text/plain'
   reply=subprocess.run(['curl','--fail','--location','--silent','--show-error','--connect-timeout','10','--max-time','30','--max-filesize',str(size*2+16384),'--header','Accept: '+accept,'--header','Accept-Encoding: identity','--header','User-Agent: aenv-pinned-online-bootstrap',url],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
   if reply.returncode:continue
   raw=reply.stdout
   break
  except (OSError,subprocess.TimeoutExpired):pass
 assert raw is not None,'GitHub download failed; no measurement phase started'
 assert len(raw)==size and hashlib.sha256(raw).hexdigest()==pin,'Downloaded adapter checksum mismatch'
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fchmod(stream.fileno(),0o600);os.fsync(stream.fileno())
assert len(raw)==size and hashlib.sha256(raw).hexdigest()==pin
scope={{'__name__':'verified_online_transport','__file__':str(p)}}
exec(compile(raw,str(p),'exec'),scope)
raise SystemExit(scope['run_online']({phase!r},json.loads(data),release,pin,size))
ONLINE_MEASUREMENT_RELAY'''

def run_online(phase,context,release,adapter_sha,adapter_bytes):
    need(os.getuid()==os.geteuid()==0,'Root execution required')
    node={'server1':'a','agent1':'b'}[os.uname().nodename]
    need(phase in ('original-a','original-b','full-a','full-b') and phase.endswith('-'+node),'Measurement phase/node required')
    read_cached(Path(__file__),adapter_sha,adapter_bytes)
    path,raw=ensure_code(PIPELINE_NAME,PIPELINE_COMMIT,PIPELINE_SHA,PIPELINE_BYTES)
    pipeline=types.ModuleType('unchanged_pinned_pipeline');pipeline.__file__=str(path)
    exec(compile(raw,str(path),'exec'),pipeline.__dict__)
    pipeline.relay=lambda next_phase,next_node,next_context,source=None:online_command(next_phase,next_node,next_context,release,adapter_sha,adapter_bytes)
    if phase.startswith('original-'):prepare_original_template(pipeline,node)
    print('ONLINE_PINNED_MEASUREMENT_PIPELINE_READY',flush=True)
    return pipeline.run(phase,context)


import argparse,hashlib,json,os,stat,subprocess,time,types
from pathlib import Path
ROOT=Path('/home/jwk/agent')
D=ROOT/'deployments/agentenv-direct-ub-deletefix-v1'
PAIR=D/'acceptance/exit-pair-v1'
MEASURE=D/'comparison/deletefix-full-v1'
RELEASE=None
SHA=None
SIZE=None

def need(ok,why):
    if not ok:raise RuntimeError(why)

def document(path,limit=16*1024**2):
    need(path.resolve(strict=True)==path and path.is_relative_to(ROOT),'Input path redirected')
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0,1204) and before.st_size<=limit,'Input metadata differs')
        raw=stream.read(limit+1);after=os.fstat(stream.fileno())
        need((before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Input changed during read')
    return json.loads(raw)

def decide(markers):
    if markers['fullReceipt']:return 'local-both-completed'
    if markers['originalReceipt']:return 'original-completed'
    if any(markers[k] for k in ('lock','run','originalDirectory','failureOriginal','failureFull')):
        return 'existing-attempt-no-restart'
    return 'start-original'

def stage_online(pipeline,online,phase,node,context):
    command=online.online_command(phase,node,context,RELEASE,SHA,SIZE)
    # Keep the old offline handoffs as evidence; never overwrite them merely
    # because the online transport has a different representation.
    path=ROOT/('next-measure-cli-ready-'+phase+'-'+pipeline.RUN+'.sh')
    pipeline.put(path,(command+'\n').encode(),1204,1205)
    return '# Saved on this node: '+str(path)+'\n'+command

def online_module():
    module=types.ModuleType('resourcefix_online_transport')
    module.__dict__.update(globals())
    return module


def main():
    global RELEASE,SHA,SIZE
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');parser.add_argument('--release');args=parser.parse_args()
    if not args.run:print(json.dumps({'status':'PLAN_ONLY','scope':'B original start or report existing attempt, after actual accepted pair'}));return 0
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='agent1','B/agent1 root required')
    need(ROOT.resolve(strict=True)==ROOT,'Agent directory redirected')
    need(isinstance(args.release,str) and re.fullmatch('[0-9a-f]{40}',args.release),'Fixed public release required')
    RELEASE=args.release
    entry=Path(__file__).read_bytes();SHA=hashlib.sha256(entry).hexdigest();SIZE=len(entry)
    online=online_module();path,raw=online.ensure_code(online.PIPELINE_NAME,online.PIPELINE_COMMIT,online.PIPELINE_SHA,online.PIPELINE_BYTES)
    pipeline=types.ModuleType('unchanged_measurement_pipeline');pipeline.__file__=str(path)
    exec(compile(raw,str(path),'exec'),pipeline.__dict__)
    pipeline.relay=lambda phase,node,context,source=None:online.online_command(phase,node,context,RELEASE,SHA,SIZE)
    pipeline.staged_relay=lambda phase,node,context:stage_online(pipeline,online,phase,node,context)
    pair=document(PAIR/'accepted-pair-bundle.json');ledger=document(PAIR/'allocation-ledger.json')
    comparison=pipeline.loaded('comparison');verifier=comparison.module('pair_verify')
    accepted=verifier.verify(pair,comparison.PAIR_SHA)
    need(document(PAIR/'pair-verification.json')==accepted,'Saved pair acceptance differs')
    context={'bundle':pair,'allocationLedger':ledger}
    markers={'lock':(MEASURE/'controller.lock').exists(),'run':(MEASURE/'run.json').exists(),
             'originalDirectory':(MEASURE/'original').exists(),'originalReceipt':(MEASURE/'original/receipt.json').exists(),
             'fullReceipt':(MEASURE/'full/receipt.json').exists(),'failureOriginal':(MEASURE/'failure-original.json').exists(),
             'failureFull':(MEASURE/'failure-full.json').exists()}
    action=decide(markers)
    print('RESOURCE_SCHEMA_FIXED cpu_count memory_mib disk_size_mib; complete resource identity retained',flush=True)
    print('B_MEASUREMENT_STATE '+json.dumps({'action':action,'markers':markers,'pairVerified':True}),flush=True)
    if action=='existing-attempt-no-restart':
        for name in ('run.json','original/replay.json','full/replay.json','failure-original.json','failure-full.json'):
            path=MEASURE/name
            if path.exists():
                value=document(path)
                keys=('status','phase','completedCommands','nonzeroCommands','pendingCommands','errorType','reason')
                print(json.dumps({'file':name,**{k:value[k] for k in keys if k in value}},indent=2),flush=True)
        print('EXISTING_B_MEASUREMENT_PRESERVED_NO_RESTART',flush=True);return 0
    if action in ('original-completed','local-both-completed'):
        aggregate=pipeline.loaded('aggregate');modules={name:aggregate.dependency(name) for name in ('pair','replay','sampler','admission')}
        reservation=modules['sampler'].ub_reservation(ledger)
        original=pipeline.phase_files(comparison,'original')
        aggregate.phase(original,'b','original',accepted,pair,reservation,modules)
        if action=='local-both-completed':
            aggregate.phase(pipeline.phase_files(comparison,'full'),'b','full',accepted,pair,reservation,modules)
            package={'version':1,'node':'b','runId':pipeline.RUN,'pairBundle':pair,'allocationLedger':ledger,
                     'phases':{name:pipeline.phase_files(comparison,name) for name in ('original','full')}}
            modules['replay'].compare_completed(package['phases']['original']['replay'],package['phases']['full']['replay'])
            output=ROOT/('deletefix-comparison-'+pipeline.RUN+'-b.json');raw=pipeline.canonical(package);pipeline.put(output,raw,1204,1205)
            print('COMPARISON_NODE_PACKAGE '+json.dumps({'node':'b','path':str(output),'bytes':len(raw),
                  'sha256':hashlib.sha256(raw).hexdigest(),'bothLocalVariantsCompleted':True}),flush=True);return 0
        original_a=online.online_command('original-a','a',context,RELEASE,SHA,SIZE)
        full_a=online.online_command('full-a','a',{**context,'peerOriginal':original['receipt']},RELEASE,SHA,SIZE)
        choice=('(\nset -eu\ntest "$(id -u)" = 0\ntest "$(hostname)" = server1\n'
                'm=/home/jwk/agent/deployments/agentenv-direct-ub-deletefix-v1/comparison/deletefix-full-v1\n'
                'if [ -e "$m/controller.lock" ]; then\n echo "A has an existing measurement lock; no restart"\n'
                'elif [ -f "$m/full/receipt.json" ]; then\n echo "A already completed both groups; return its data package"\n'
                'elif [ -f "$m/original/receipt.json" ]; then\n'+full_a+'\n'
                'elif [ ! -e "$m/run.json" ] && [ ! -e "$m/original" ] && [ ! -e "$m/failure-original.json" ]; then\n'+original_a+'\n'
                'else\n echo "A has an existing incomplete measurement; preserve it, no restart"\nfi\n)')
        output=ROOT/('next-measure-cli-ready-advance-a-'+pipeline.RUN+'.sh');pipeline.put(output,(choice+'\n').encode(),1204,1205)
        print('BEGIN_NEXT_A_MEASUREMENT_COMMAND');print(choice);print('END_NEXT_A_MEASUREMENT_COMMAND',flush=True)
        print('Saved A continuation: '+str(output),flush=True);return 0
    # No journal, lock, phase directory or persisted failure exists. The pinned
    # controller still performs its complete read-only admission before POST.
    prepare_original_template(pipeline,'b')
    pipeline.next_command('NEXT_A_ORIGINAL_COMMAND','original-a','a',context)
    print('Wait for B MEASUREMENT_PHASE_READY below, then run the A original block on A/root.',flush=True)
    try:return pipeline.measure('b','original',context)
    except Exception as error:
        result={'status':'STOPPED_B_MEASUREMENT_START_PRESERVE_STATE','errorType':type(error).__name__,
                'reason':str(error),'automaticCleanup':False,'originalExperimentStateNotReset':True}
        output=ROOT/('B-measurement-prepared-failure-'+str(os.getpid())+'-'+str(time.time_ns())+'.json')
        pipeline.put(output,pipeline.canonical(result))
        print(json.dumps({**result,'diagnostic':str(output)},indent=2),flush=True);return 1

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
    for p in (src,repo,repo/'catalog/records',repo/'managed-layers',repo/'snapshots'):
        prep_need(p.resolve(strict=True)==p and p.is_dir() and p.stat().st_uid==1204,'Repository layout differs: '+str(p))
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
                    'missingFiles':missing,'validated':validated,'originalRuntime':context,'createdNs':time.time_ns(),
                    'payloadChecks':'O_DIRECT SHA256; no buffered fallback','publication':'hard links; catalog last; no aliases',
                    'automaticCleanup':False}
            pipeline.put(receipt_dir/'intent.json',pipeline.canonical(intent))
            snapshot_dir=repo/'snapshots'/sid
            if not snapshot_dir.exists():snapshot_dir.mkdir(mode=0o700);os.chown(snapshot_dir,1204,1205)
            prep_need(snapshot_dir.resolve(strict=True)==snapshot_dir and snapshot_dir.stat().st_uid==1204,'Snapshot directory differs')
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


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED_MEASUREMENT_START_PREFLIGHT','errorType':type(error).__name__,'reason':str(error),'automaticCleanup':False}),flush=True)
        raise SystemExit(1)
