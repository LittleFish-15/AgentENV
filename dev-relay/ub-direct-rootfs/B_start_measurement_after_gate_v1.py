"""Start B original only if no measurement attempt exists; export A online start."""
import argparse,hashlib,json,os,stat,subprocess,time,types
from pathlib import Path
ROOT=Path('/home/jwk/agent')
D=ROOT/'deployments/agentenv-direct-ub-deletefix-v1'
PAIR=D/'acceptance/exit-pair-v1'
MEASURE=D/'comparison/deletefix-full-v1'
RELEASE='43b4746d6e46f02417f58d2f602216dcc79dcdce'
NAME='AB_deletefix_measurement_online_v3.py'
SHA='6037ae279285d87d06f3d7c97f0fabe4cf04f44e2a05a3ee2eb7397ef6182c16'
SIZE=8654

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

def online_module():
    path=ROOT/NAME
    if not path.exists() and not path.is_symlink():
        url=f'https://api.github.com/repos/LittleFish-15/AgentENV/contents/dev-relay/ub-direct-rootfs/{NAME}?ref={RELEASE}'
        response=subprocess.run(['curl','--fail','--location','--silent','--show-error','--connect-timeout','10','--max-time','30',
            '--max-filesize',str(SIZE),'--header','Accept: application/vnd.github.raw+json','--header','Accept-Encoding: identity',
            '--header','User-Agent: aenv-measurement-resume',url],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
        need(response.returncode==0,'Pinned online code download failed; no measurement started')
        raw=response.stdout;need(len(raw)==SIZE and hashlib.sha256(raw).hexdigest()==SHA,'Online code checksum differs')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fchmod(out.fileno(),0o600);os.fsync(out.fileno())
    need(path.resolve(strict=True)==path and not path.is_symlink(),'Online cache redirected')
    meta=path.stat();need(stat.S_ISREG(meta.st_mode) and meta.st_uid in (0,1204) and not meta.st_mode&0o022 and meta.st_size==SIZE,'Online cache metadata differs')
    raw=path.read_bytes();need(hashlib.sha256(raw).hexdigest()==SHA,'Online cache checksum differs')
    module=types.ModuleType('pinned_online_v3');module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__);return module

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');args=parser.parse_args()
    if not args.run:print(json.dumps({'status':'PLAN_ONLY','scope':'B original start or report existing attempt, after actual accepted pair'}));return 0
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='agent1','B/agent1 root required')
    need(ROOT.resolve(strict=True)==ROOT,'Agent directory redirected')
    online=online_module();path,raw=online.ensure_code(online.PIPELINE_NAME,online.PIPELINE_COMMIT,online.PIPELINE_SHA,online.PIPELINE_BYTES)
    pipeline=types.ModuleType('unchanged_measurement_pipeline');pipeline.__file__=str(path)
    exec(compile(raw,str(path),'exec'),pipeline.__dict__)
    pipeline.relay=lambda phase,node,context,source=None:online.online_command(phase,node,context,RELEASE,SHA,SIZE)
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
        pipeline.next_command('NEXT_A_FULL_COMMAND','full-a','a',{**context,'peerOriginal':original['receipt']})
        print('B original completed. Run A full only after A original has also completed.',flush=True);return 0
    # No journal, lock, phase directory or persisted failure exists. The pinned
    # controller still performs its complete read-only admission before POST.
    pipeline.next_command('NEXT_A_ORIGINAL_COMMAND','original-a','a',context)
    print('Wait for B MEASUREMENT_PHASE_READY below, then run the A original block on A/root.',flush=True)
    try:return pipeline.measure('b','original',context)
    except Exception as error:
        result={'status':'STOPPED_B_MEASUREMENT_START_PRESERVE_STATE','errorType':type(error).__name__,
                'reason':str(error),'automaticCleanup':False,'originalExperimentStateNotReset':True}
        output=ROOT/('B-measurement-start-failure-'+str(os.getpid())+'-'+str(time.time_ns())+'.json')
        pipeline.put(output,pipeline.canonical(result))
        print(json.dumps({**result,'diagnostic':str(output)},indent=2),flush=True);return 1

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED_MEASUREMENT_START_PREFLIGHT','errorType':type(error).__name__,'reason':str(error),'automaticCleanup':False}),flush=True)
        raise SystemExit(1)
