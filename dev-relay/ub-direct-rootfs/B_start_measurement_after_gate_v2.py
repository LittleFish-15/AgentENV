"""Online transport for the resource-schema-corrected measurement pipeline.

Only public code is fetched. Private context stays in human-relayed capsules.
"""
import base64,hashlib,json,os,re,stat,subprocess,textwrap,types,urllib.error,urllib.parse,urllib.request,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
REPOSITORY='LittleFish-15/AgentENV'
PREFIX='dev-relay/ub-direct-rootfs/'
NAME='B_start_measurement_after_gate_v2.py'
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
    path=ROOT/('next-measure-resourcefix-'+phase+'-'+pipeline.RUN+'.sh')
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
        output=ROOT/('next-measure-resourcefix-advance-a-'+pipeline.RUN+'.sh');pipeline.put(output,(choice+'\n').encode(),1204,1205)
        print('BEGIN_NEXT_A_MEASUREMENT_COMMAND');print(choice);print('END_NEXT_A_MEASUREMENT_COMMAND',flush=True)
        print('Saved A continuation: '+str(output),flush=True);return 0
    # No journal, lock, phase directory or persisted failure exists. The pinned
    # controller still performs its complete read-only admission before POST.
    pipeline.next_command('NEXT_A_ORIGINAL_COMMAND','original-a','a',context)
    print('Wait for B MEASUREMENT_PHASE_READY below, then run the A original block on A/root.',flush=True)
    try:return pipeline.measure('b','original',context)
    except Exception as error:
        result={'status':'STOPPED_B_MEASUREMENT_START_PRESERVE_STATE','errorType':type(error).__name__,
                'reason':str(error),'automaticCleanup':False,'originalExperimentStateNotReset':True}
        output=ROOT/('B-measurement-resourcefix-failure-'+str(os.getpid())+'-'+str(time.time_ns())+'.json')
        pipeline.put(output,pipeline.canonical(result))
        print(json.dumps({**result,'diagnostic':str(output)},indent=2),flush=True);return 1

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED_MEASUREMENT_START_PREFLIGHT','errorType':type(error).__name__,'reason':str(error),'automaticCleanup':False}),flush=True)
        raise SystemExit(1)
