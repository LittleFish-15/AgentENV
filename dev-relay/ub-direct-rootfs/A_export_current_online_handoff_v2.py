"""Export the existing A phase as an API-first online handoff; no Guest mutation."""
import argparse,hashlib,json,os,re,stat,subprocess,types
from pathlib import Path
ROOT=Path('/home/jwk/agent')
TRANSPORT_NAME='AB_deletefix_measurement_online_v3.py'
TRANSPORT_SHA='6037ae279285d87d06f3d7c97f0fabe4cf04f44e2a05a3ee2eb7397ef6182c16'
TRANSPORT_BYTES=8654

def need(ok,why):
    if not ok:raise RuntimeError(why)

def read_code(path,length,pin):
    need(path.resolve(strict=True)==path and not path.is_symlink(),'Code path redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0,1204) and not before.st_mode&0o022 and before.st_size==length,
             'Code metadata differs: '+str(path))
        raw=stream.read(length+1);after=os.fstat(stream.fileno())
        need(all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),'Code changed during read')
    need(len(raw)==length and hashlib.sha256(raw).hexdigest()==pin,'Code checksum differs')
    return raw

def transport(release):
    path=ROOT/TRANSPORT_NAME
    if not path.exists() and not path.is_symlink():
        url=f'https://api.github.com/repos/LittleFish-15/AgentENV/contents/dev-relay/ub-direct-rootfs/{TRANSPORT_NAME}?ref={release}'
        reply=subprocess.run(['curl','--fail','--location','--silent','--show-error','--connect-timeout','10','--max-time','30',
            '--max-filesize',str(TRANSPORT_BYTES),'--header','Accept: application/vnd.github.raw+json',
            '--header','Accept-Encoding: identity','--header','User-Agent: aenv-online-stage-export',url],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
        need(reply.returncode==0,'curl failed while fetching online transport, exit='+str(reply.returncode)+'; no Guest action')
        raw=reply.stdout
        need(len(raw)==TRANSPORT_BYTES and hashlib.sha256(raw).hexdigest()==TRANSPORT_SHA,'Downloaded transport checksum differs')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fchmod(stream.fileno(),0o600);os.fsync(stream.fileno())
    raw=read_code(path,TRANSPORT_BYTES,TRANSPORT_SHA)
    value=types.ModuleType('pinned_online_v2');value.__file__=str(path)
    exec(compile(raw,str(path),'exec'),value.__dict__);return value

def choose_stage(files,life):
    if files['measurementStarted']:return 'measurement-attempt-present'
    if files['aExitEnvelope'] and files['releaseReceipt']:
        need(life.get('phase')=='quiesced' and life.get('sandboxIds')==life.get('openRequests')==[]
             and life.get('outcomeUncertain') is False,'A release journal is not complete')
        return 'finish-b'
    need(not files['exitIntent'] and not files['releaseReceipt'],'Existing partial exit; preserve it, do not issue another phase')
    need(files['readyEnvelope'] and life.get('openRequests')==[] and life.get('outcomeUncertain') is False
         and len(life.get('sandboxIds',[]))==1,'No uniquely owned ready A Guest')
    return 'ready-b'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release',required=True);parser.add_argument('--export',action='store_true');args=parser.parse_args()
    need(re.fullmatch('[0-9a-f]{40}',args.release),'Full fixed release commit required')
    if not args.export:
        print(json.dumps({'status':'PLAN_ONLY','scope':'inspect existing A state and export online next command; no Guest mutation'}));return 0
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='server1','A/server1 root only')
    need(ROOT.resolve(strict=True)==ROOT,'Agent directory redirected')
    result={'status':'A_HANDOFF_EXPORT_PREFLIGHT','GuestCreated':False,'GuestDeleted':False,
            'servicesChanged':False,'existingJournalChanged':False}
    try:
        online=transport(args.release)
        path,raw=online.ensure_code(online.PIPELINE_NAME,online.PIPELINE_COMMIT,online.PIPELINE_SHA,online.PIPELINE_BYTES)
        pipeline=types.ModuleType('pinned_pipeline');pipeline.__file__=str(path)
        exec(compile(raw,str(path),'exec'),pipeline.__dict__)
        control=pipeline.loaded('exit_pair');ready=control.module('ready');cont=control.module('continue');verify=control.module('verify')
        work=control.WORK;need(work.resolve(strict=True)==work,'No saved fresh A attempt at expected path')
        import fcntl
        fd=os.open(work/'run.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            meta=os.fstat(fd);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and meta.st_nlink==1,'Pair lock differs')
            fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
            life,life_sha=cont.document(work/'state.json')
            flags={'readyEnvelope':(work/'ready-envelope.json').exists(),'exitIntent':(work/'exit-intent.json').exists(),
                   'releaseReceipt':(work/'release-receipt.json').exists(),'aExitEnvelope':(work/'a-exit-envelope.json').exists(),
                   'measurementStarted':(pipeline.D/'comparison/deletefix-full-v1').exists()}
            result['savedState']={'phase':life.get('phase'),'sandboxIds':life.get('sandboxIds'),
                 'openRequestCount':len(life.get('openRequests',[])),'outcomeUncertain':life.get('outcomeUncertain'),'files':flags}
            phase=choose_stage(flags,life)
            if phase=='measurement-attempt-present':
                result.update(status='MEASUREMENT_ATTEMPT_EXISTS_DO_NOT_RESTART_PAIR',
                    outputDirectory=str(pipeline.D/'comparison/deletefix-full-v1'),
                    savedNextCommands=[str(p) for p in ROOT.glob('next-*-'+pipeline.RUN+'.sh')])
            else:
                history=cont.load(work/'historical-isolation.json');local=cont.load(work/'ready-envelope.json')
                pin=pipeline.COMPONENTS['exit_pair']['sha256']
                control.validate_ready(local,'a',verify,history,pin)
                runtime=ready.ReadyRun()
                need(runtime.n=='a' and runtime.server==local['readyReport']['serverIdentity']
                     and runtime.provider==local['readyReport']['provider'],'A Runtime/provider changed since ready')
                need(life['runId']==local['readyReceipt']['runId'],'A lifecycle run differs')
                if phase=='ready-b':
                    need(life['sandboxIds']==[local['readyReceipt']['sandboxId']],'A saved Guest differs')
                    def no_write(_):raise RuntimeError('Read-only export cannot rewrite lifecycle')
                    runtime.case=runtime.engine.Cohort.recovery(runtime.api,life,no_write)
                    binding=runtime.observe(local['readyReceipt']['sandboxId'])
                    cont.binding_stable(local['readyReport']['binding'],binding)
                    peer=local;result['currentAFC']=binding['fcIdentity'];result['currentABindingVerified']=True
                else:
                    peer=cont.load(work/'a-exit-envelope.json')
                    need(peer['controllerSha256']==pin and peer['kind']=='a-exit-envelope'
                         and verify.fingerprint(peer['aReady'])==verify.fingerprint(local),'Saved A exit envelope differs')
                    verify.released(peer['release'],'a',local['readyReport'],local['readyReceipt'],pin)
                    need(peer['release']['journal']==life,'Saved release/lifecycle differs')
                    status=cont.provider_status(runtime)
                    need(status['activeLeases']==status['activePayloadResponses']==0
                         and runtime.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'A no longer has an empty completed exit state')
                need(cont.document(work/'state.json')[1]==life_sha,'A lifecycle changed during export')
                command=online.online_command(phase,'b',{'history':history,'peer':peer},args.release,TRANSPORT_SHA,TRANSPORT_BYTES)
                target=ROOT/('next-online-'+phase+'-'+pipeline.RUN+'.sh');pipeline.put(target,(command+'\n').encode(),1204,1205)
                result.update(status='A_EXISTING_PHASE_EXPORTED_FOR_B_ONLINE',nextPhase=phase,nextNode='b',
                              commandFile=str(target),commandBytes=len(command.encode()),
                              commandSha256=hashlib.sha256((command+'\n').encode()).hexdigest())
        finally:os.close(fd)
        print('BEGIN_A_CURRENT_HANDOFF_REPORT');print(json.dumps(result,indent=2));print('END_A_CURRENT_HANDOFF_REPORT',flush=True)
        if result['status']=='A_EXISTING_PHASE_EXPORTED_FOR_B_ONLINE':
            print('BEGIN_NEXT_B_ONLINE_COMMAND');print(command);print('END_NEXT_B_ONLINE_COMMAND',flush=True)
        return 0
    except Exception as error:
        result.update(status='STOPPED_CURRENT_HANDOFF_EXPORT_NO_GUEST_ACTION',errorType=type(error).__name__,reason=str(error))
        print(json.dumps(result,indent=2),flush=True);return 1

if __name__=='__main__':raise SystemExit(main())
