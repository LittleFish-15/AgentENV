"""Human-relayed exit gate -> true original/full two-node first-template data.

No network transport is provisioned. Each generated command is explicitly run
on its named node. B original starts only after the fresh pair gate passes.
"""
import argparse,base64,hashlib,json,os,stat,sys,textwrap,threading,time,types,uuid,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
D=ROOT/'deployments/agentenv-direct-ub-deletefix-v1'
RUN='9c8f00d962c848c4b07e089bd69c5476'

def need(ok,why):
    if not ok:raise RuntimeError(why)

def raw_component(name):
    row=COMPONENTS[name];raw=zlib.decompress(base64.b64decode(row['z64'],validate=True))
    need(hashlib.sha256(raw).hexdigest()==row['sha256'],'Pinned component differs: '+name)
    return raw

def put(path,raw,uid=0,gid=0):
    need(path.is_relative_to(ROOT) and path.parent.resolve(strict=True)==path.parent and not path.is_symlink(),'Input/output path redirected')
    if path.exists():
        meta=path.stat();need(stat.S_ISREG(meta.st_mode) and meta.st_uid==uid and meta.st_nlink==1
              and not meta.st_mode&0o022 and path.read_bytes()==raw,'Existing input/output differs; preserve it')
        return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fchown(stream.fileno(),uid,gid);os.fchmod(stream.fileno(),0o600);os.fsync(stream.fileno())

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def loaded(name):
    raw=raw_component(name);path=ROOT/COMPONENTS[name]['filename'];put(path,raw)
    value=types.ModuleType('pipeline_'+name);value.__file__=str(path)
    exec(compile(raw,str(path),'exec'),value.__dict__);return value

def relay(phase,node,context,source=None):
    raw=Path(__file__).read_bytes() if source is None else source;data=canonical(context)
    code64='\n'.join(textwrap.wrap(base64.b64encode(zlib.compress(raw,9)).decode(),100))
    data64='\n'.join(textwrap.wrap(base64.b64encode(zlib.compress(data,9)).decode(),100))
    host={'a':'server1','b':'agent1'}[node]
    return f'''python3 -I -B - <<'DELETEFIX_MEASUREMENT_PIPELINE'
import base64,hashlib,json,os,platform,stat,sys,zlib
from pathlib import Path
assert os.getuid()==os.geteuid()==0 and platform.node()=={host!r},'Root on {host} required'
raw=zlib.decompress(base64.b64decode("""{code64}"""))
data=zlib.decompress(base64.b64decode("""{data64}"""))
assert hashlib.sha256(raw).hexdigest()=={hashlib.sha256(raw).hexdigest()!r}
assert hashlib.sha256(data).hexdigest()=={hashlib.sha256(data).hexdigest()!r}
root=Path('/home/jwk/agent');assert root.resolve(strict=True)==root
entry=root/'AB_deletefix_measurement_pipeline_v1.py'
if entry.exists():
 meta=entry.lstat();assert stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and meta.st_nlink==1 and meta.st_mode&0o022==0 and entry.read_bytes()==raw
else:
 fd=os.open(entry,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
print('DELETEFIX_MEASUREMENT_PIPELINE_VERIFIED',flush=True)
scope={{'__name__':'verified_pipeline','__file__':str(entry)}}
exec(compile(raw,str(entry),'exec'),scope)
raise SystemExit(scope['run']({phase!r},json.loads(data)))
DELETEFIX_MEASUREMENT_PIPELINE'''

def staged_relay(phase,node,context):
    command=relay(phase,node,context)
    path=ROOT/('next-'+phase+'-'+RUN+'.sh')
    put(path,(command+'\n').encode(),1204,1205)
    return '# This complete command is also saved on the current node: '+str(path)+'\n'+command

def next_command(label,phase,node,context):
    command=staged_relay(phase,node,context)
    print('BEGIN_'+label,flush=True);print(command);print('END_'+label,flush=True)

def measurement_inputs(context,node):
    folder=ROOT/'r'/('deletefix-measure-inputs-'+node+'-'+RUN[:8]);folder.mkdir(mode=0o700,exist_ok=True)
    need(folder.resolve(strict=True)==folder and folder.stat().st_uid==0 and not folder.stat().st_mode&0o077,'Input directory differs')
    pair=folder/'pair-bundle.json';ledger=folder/'allocation-ledger.json'
    put(pair,canonical(context['bundle']));put(ledger,canonical(context['allocationLedger']))
    return folder,pair,ledger

def phase_files(comp,variant):
    out=comp.WORK/variant
    return {key:json.loads((out/name).read_bytes()) for key,name in (
        ('receipt','receipt.json'),('replay','replay.json'),('bindings','bindings.json'),
        ('baseline','baseline.json'),('final','final-before-release.json'),('beforeGuestCreate','before-guest-create.json'))}

def progress_loop(path,stop,node,variant):
    last=None;last_emit=0
    while not stop.wait(5):
        try:
            if path.exists() and path.stat().st_size<=16*1024**2:
                state=json.loads(path.read_bytes());jobs=state.get('jobs',[])
                value=(sum(len(j.get('results',[])) for j in jobs),sum(j.get('expectedCommands',0) for j in jobs),state.get('status'))
            else:value=(None,None,'preparing')
            now=time.monotonic()
            if value!=last or now-last_emit>=20:
                print('MEASUREMENT_PROGRESS '+json.dumps({'node':node,'variant':variant,'completedCommands':value[0],
                      'expectedCommands':value[1],'state':value[2]}),flush=True);last=value;last_emit=now
        except (OSError,ValueError):
            # Optional console progress never changes persisted replay outcomes.
            continue

def measure(node,variant,context):
    comp=loaded('comparison');aggregate=loaded('aggregate')
    folder,pair,ledger=measurement_inputs(context,node)
    peer_path=None
    if variant=='full':
        need('peerOriginal' in context,'Peer original completion required')
        peer_path=folder/'peer-original.json';put(peer_path,canonical(context['peerOriginal']))
    args=types.SimpleNamespace(node=node,phase=variant,run_id=RUN,templates=1,pair_bundle=pair,
                              allocation_ledger=ledger,peer_original=peer_path,run=True)
    controller=comp.Comparison(args)
    print('MEASUREMENT_PHASE_READY '+json.dumps({'node':node,'variant':variant,'guests':2,
          'commandsPerGuest':len(controller.steps[0]),'output':str(comp.WORK/variant)}),flush=True)
    stop=threading.Event();thread=threading.Thread(target=progress_loop,args=(comp.WORK/variant/'replay.json',stop,node,variant),daemon=True)
    thread.start()
    try:receipt=controller.run()
    finally:stop.set();thread.join(timeout=2)
    modules={name:aggregate.dependency(name) for name in ('pair','replay','sampler','admission')}
    accepted=modules['pair'].verify(context['bundle'],aggregate.EXIT_CONTROLLER_PIN)
    reservation=modules['sampler'].ub_reservation(context['allocationLedger'])
    value=phase_files(comp,variant)
    summary=aggregate.phase(value,node,variant,accepted,context['bundle'],reservation,modules)
    comp.save(comp.WORK/variant/'phase-summary.json',summary)
    print('BEGIN_MEASUREMENT_PHASE_RESULT')
    print(json.dumps({'node':node,'variant':variant,'status':receipt['status'],
        'guests':summary['guests'],'completedCommands':summary['completedCommands'],'nonzeroCommands':summary['nonzeroCommands'],
        'elapsedSeconds':summary['elapsedSeconds'],'restoreSeconds':summary['restoreSeconds'],
        'hostCachedDeltaBytes':summary['hostCachedDeltaBytes'],'hostCachedDeltaSinceBeforeCreateBytes':summary['hostCachedDeltaSinceBeforeCreateBytes'],
        'fileResidentDeltaBytes':summary['fileResidentDeltaBytes'],'fileResidentDeltaSinceBeforeCreateBytes':summary['fileResidentDeltaSinceBeforeCreateBytes'],
        'baselineProcessPssBytesByRole':summary['baseline']['processPssBytesByRole'],
        'finalProcessPssBytesByRole':summary['final']['processPssBytesByRole'],
        'uniqueRetainedUBReservation':reservation,'netSavingsBytes':None,'outputDirectory':str(comp.WORK/variant)},indent=2))
    print('END_MEASUREMENT_PHASE_RESULT',flush=True)
    other='b' if node=='a' else 'a'
    if variant=='original':
        print('Wait until BOTH original phases have completed before executing the next full-phase command.',flush=True)
        next_command('NEXT_'+other.upper()+'_FULL_COMMAND','full-'+other,other,{**context,'peerOriginal':receipt})
    else:
        package={'version':1,'node':node,'runId':RUN,'pairBundle':context['bundle'],'allocationLedger':context['allocationLedger'],
                 'phases':{name:phase_files(comp,name) for name in ('original','full')}}
        path=ROOT/('deletefix-comparison-'+RUN+'-'+node+'.json');raw=canonical(package);put(path,raw,1204,1205)
        print('COMPARISON_NODE_PACKAGE '+json.dumps({'node':node,'path':str(path),'bytes':len(raw),
              'sha256':hashlib.sha256(raw).hexdigest(),'readableBy':'jwk','bothLocalVariantsCompleted':True}),flush=True)
    return 0

def run(phase,context):
    need(os.getuid()==os.geteuid()==0,'Root execution required')
    node={'server1':'a','agent1':'b'}[os.uname().nodename]
    need(phase in ('ready-a','ready-b','release-a','finish-b','original-a','original-b','full-a','full-b')
         and phase.endswith('-'+node),'Wrong phase/node')
    try:
        if phase.startswith(('original-','full-')):return measure(node,phase.split('-')[0],context)
        exit_pair=loaded('exit_pair')
        # Transport callback only. The exit controller, mutation gates and
        # receipts retain their pinned source identity and semantics.
        exit_pair.relay_command=lambda next_phase,next_node,history,peer=None,source=None:staged_relay(next_phase,next_node,{'history':history,'peer':peer})
        folder=ROOT/'r'/('deletefix-pipeline-'+node+'-'+RUN[:8]);folder.mkdir(mode=0o700,exist_ok=True)
        need(folder.resolve(strict=True)==folder and folder.stat().st_uid==0 and not folder.stat().st_mode&0o077,'Pipeline input directory differs')
        history=folder/(phase+'-history.json');put(history,canonical(context['history']))
        argv=[exit_pair.__file__,phase,'--history',str(history),'--run']
        if context.get('peer') is not None:
            peer=folder/(phase+'-peer.json');put(peer,canonical(context['peer']));argv+=['--peer',str(peer)]
        sys.argv=argv;code=exit_pair.main()
        if code or phase!='finish-b':return code
        completed={'bundle':json.loads((exit_pair.WORK/'accepted-pair-bundle.json').read_bytes()),
                   'allocationLedger':json.loads((exit_pair.WORK/'allocation-ledger.json').read_bytes())}
        # Pair gate has passed. Emit A's original start command BEFORE B's run,
        # so the user may start A in its own existing terminal while B runs.
        print('Pair gate passed. Copy the A original command to A/root; B original starts below.',flush=True)
        next_command('NEXT_A_ORIGINAL_COMMAND','original-a','a',completed)
        return measure('b','original',completed)
    except Exception as error:
        print(json.dumps({'status':'STOPPED_MEASUREMENT_PIPELINE_PRESERVE_STATE','phase':phase,
                          'errorType':type(error).__name__,'reason':str(error),'automaticCleanup':False},indent=2),flush=True)
        return 1

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--phase');parser.add_argument('--context',type=Path)
    parser.add_argument('--run',action='store_true');args=parser.parse_args()
    if not args.run:
        print(json.dumps({'status':'PLAN_ONLY','scope':'fresh exit gate then first-template original/full on two nodes',
                          'guestsPerNodePerVariant':2,'globalCacheEviction':False,'automaticPeerTransport':False}))
    else:
        need(args.phase and args.context and args.context.is_relative_to(ROOT)
             and args.context.resolve(strict=True)==args.context and args.context.stat().st_size<=16*1024**2,'Explicit bounded context required')
        raise SystemExit(run(args.phase,json.loads(args.context.read_bytes())))
