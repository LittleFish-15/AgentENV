"""Continue exactly the recorded B SIGTERM timeout; never restart its old Guest."""
import argparse,base64,hashlib,json,os,stat,subprocess,sys,time,types,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
PAIR=ROOT/'deployments/agentenv-direct-ub-guest-v1/acceptance/direct-pair-v1'
PRIOR=PAIR/'b-deletefix-recovery-v1/progress.json'
WORK=PAIR/'b-deletefix-force-resume-v1'
UNIT='jwk-aenv-direct-ub-guest-v1-node-b.service'

def need(ok,why):
    if not ok:raise RuntimeError(why)

def reviewed_timeout(prior):
    return (prior.get('node')=='b' and prior.get('status')=='STOPPED_B_RECOVERY_PRESERVE_STATE'
        and prior.get('reason')=='B old processes/cgroup did not exit; no forced kill or deployment'
        and prior.get('deleteIntents')==[]
        and prior.get('signalIntents')==[{'role':'old-server','pid':2723514,'signal':'SIGTERM'}]
        and prior.get('oldServer',{}).get('startTicks')=='62254196'
        and prior.get('oldDaemon',{}).get('startTicks')=='62254283'
        and 'stageIntent' not in prior)

def process_snapshot(identity):
    proc=Path('/proc')/str(identity['pid'])
    try:
        fields=(proc/'stat').read_text().rsplit(')',1)[1].split()
        need(fields[19]==identity['startTicks'],'Old PID reused; do not signal')
        try:wait=(proc/'wchan').read_text().strip()
        except OSError:wait=None
        return {'pid':identity['pid'],'startTicks':fields[19],'state':fields[0],'waitChannel':wait}
    except (FileNotFoundError,ProcessLookupError):return None

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true')
    parser.add_argument('--allow-owned-unit-sigkill',action='store_true');args=parser.parse_args()
    if not args.run:
        print(json.dumps({'status':'PLAN_ONLY','scope':'continue known B SIGTERM timeout; explicit flag permits only old unit SIGKILL, then unchanged cleanup/staging'}));return 0
    need(args.allow_owned_unit_sigkill,'Explicit scoped force-stop flag required')
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='agent1','B/agent1 root only')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()=='e5aaa223-c78c-4eac-816e-7d98e0cca1c1','B boot changed')
    os.umask(0o077)
    raw=zlib.decompress(base64.b64decode(ORIGINAL_Z64,validate=True))
    need(hashlib.sha256(raw).hexdigest()==ORIGINAL_SHA,'Original B recovery changed')
    old=types.ModuleType('pinned_B_recovery');old.__file__='<pinned-B-recovery>'
    exec(compile(raw,old.__file__,'exec'),old.__dict__);old.WORK=WORK
    exec(compile(FINISH_SOURCE,'<reviewed-post-exit-continuation>','exec'),old.__dict__)
    deploy_path=ROOT/'AB_deploy_direct_deletefix_v2.py'
    deploy,deploy_raw=old.embedded('new_deploy',old.DEPLOY_Z64,old.DEPLOY_SHA,deploy_path)
    deploy.candidate_artifacts('b')
    controller,_=old.embedded('controller',old.CONTINUE_Z64,old.CONTINUE_SHA)
    ready,_=old.embedded('ready',old.READY_Z64,old.READY_SHA)
    helpers,_=old.embedded('recovery_helpers',old.RECOVERY_Z64,old.RECOVERY_SHA);helpers.RECOVERY=WORK
    prior,prior_sha=controller.document(PRIOR)
    need(reviewed_timeout(prior),'Not the known pre-device/pre-deployment timeout')
    need(PAIR.resolve(strict=True)==PAIR and PAIR.stat().st_uid==0,'Pair directory changed')
    import fcntl
    lock=os.open(PAIR/'run.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    fds={};made=False
    result={'status':'B_FORCE_RESUME_PREFLIGHT','node':'b','oldOriginalBContinuityProven':False,
        'oldPairLifecycleAccepted':False,'normalOldGuestDeletePassed':False,'oldJournalRewritten':False,
        'providerRetired':False,'newGuestCreated':False,'kernelModuleChanged':False,'automaticRetry':False,
        'signalIntents':[],'deleteIntents':[],'previousRecoverySha256':prior_sha}
    try:
        meta=os.fstat(lock);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and meta.st_nlink==1,'Lock changed')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(not WORK.exists() and not WORK.is_symlink(),'Prior force-resume preserved; do not repeat')
        docs={name:controller.document(PAIR/name) for name in prior['oldDocumentHashes']}
        need({k:v[1] for k,v in docs.items()}==prior['oldDocumentHashes'],'Original B journal changed')
        origin=docs['report.json'][0]
        need(origin['sandboxId']=='01a17ae4-2ff5-7122-a016-2099215c53e8' and origin['node']=='b','Wrong B cohort')
        need(origin['serverIdentity']==prior['oldServer'] and origin['binding']['daemonIdentity']==prior['oldDaemon'],
             'Timed-out process identities differ from original B receipt')
        deploy_old_path=old.OLD/'libexec/direct_guest_runtime.py';old_bytes=deploy_old_path.read_bytes()
        need(hashlib.sha256(old_bytes).hexdigest()==ready.DEPLOY_SHA,'Old B deployment source changed')
        old_deploy=types.ModuleType('old_B_deploy');old_deploy.__file__=str(deploy_old_path)
        exec(compile(old_bytes,str(deploy_old_path),'exec'),old_deploy.__dict__)
        definition=old_deploy.load(old.OLD/'guest-definition.json');m=old_deploy.make_module(definition)
        need(deploy.check_provider('b')==origin['provider'],'Provider changed')
        runtime=types.SimpleNamespace(n='b',deploy=old_deploy,m=m,provider=origin['provider'],original_units=prior['preservedUnits'])
        need(deploy.preserve_units(m,'b')==runtime.original_units,'Unrelated service changed')
        need(not ready.find_processes(Path(origin['binaries']['firecracker']['path']),old.GROUP),'Live B Guest present; no force stop')
        pidfds=deploy.PidfdOps();pidfds.self_check()
        original_identities={'server':prior['oldServer'],'daemon':prior['oldDaemon']}
        result['beforeProcesses']={}
        for name,identity in original_identities.items():
            observed=process_snapshot(identity);result['beforeProcesses'][name]=observed
            if observed:
                need(ready.process(identity['pid'],Path(identity['executable']),old.GROUP)==identity,'Old process ownership changed')
        members=helpers.group_pids(old.GROUP)
        need(runtime.provider['providerProcess']['pid'] not in members,'Provider belongs to old service; no force stop')
        if result['beforeProcesses']['daemon']:
            need(helpers.daemon_devices(prior['oldDaemon']['pid'])<=old.IDS,'Old daemon owns unexpected devices')
        new_runtime,new_fc,new_unit=deploy.location('b')
        need(all(not p.exists() and not p.is_symlink() for p in (deploy.D,new_runtime,new_fc)),'New deployment already exists')
        need(m.properties(new_unit).get('LoadState')=='not-found','New B unit already exists')
        proxy=old_deploy.load(old_deploy.location('b')[0]/'host-proxy.json')
        if Path('/proc',str(proxy['pid'])).exists():
            identity=m.process_identity(proxy['pid'])
            need(identity['start_ticks']==proxy['start_ticks'] and identity['uid']==[1204]*4 and m.owns_listener(proxy['pid']), 'Old proxy changed')
            fds['proxy']=pidfds.open(proxy['pid'])
            need(m.process_identity(proxy['pid'])['start_ticks']==proxy['start_ticks'],'Proxy changed during capture')
        captured={int(k):v for k,v in prior['capturedCharacterIdentities'].items()};need(set(captured)==old.IDS,'Captured device IDs differ')
        binary=zlib.decompress(base64.b64decode(old.HELPER_Z64,validate=True))
        need(hashlib.sha256(binary).hexdigest()==old.HELPER_SHA,'B helper changed')
        WORK.mkdir(mode=0o700);made=True;result['outputDirectory']=str(WORK)
        helpers.checkpoint(result)
        if members or any(result['beforeProcesses'].values()):
            need(m.properties(UNIT).get('ControlGroup')==old.GROUP,'Old unit cgroup changed')
            need(int(m.properties(UNIT).get('MainPID','0')) in (0,2723514),'Old unit main process replaced; no force stop')
            result['signalIntents'].append({'unit':UNIT,'signal':'SIGKILL','scope':'all members of this dedicated unit'})
            helpers.checkpoint(result)
            result['systemctlResults']=[]
            for command in (['/usr/bin/systemctl','kill','--kill-who=all','--signal=SIGKILL',UNIT],
                            ['/usr/bin/systemctl','stop','--no-block',UNIT]):
                reply=subprocess.run(command,capture_output=True,text=True,timeout=15)
                result['systemctlResults'].append({'operation':command[1],'exitCode':reply.returncode,'stderr':reply.stderr[:2000]})
                helpers.checkpoint(result)
                if reply.returncode:
                    need(not helpers.group_pids(old.GROUP)
                         and not any(process_snapshot(x) for x in original_identities.values())
                         and m.properties(UNIT).get('LoadState')=='not-found',
                         'Scoped systemctl failed while old unit/resources remain')
        deadline=time.monotonic()+30
        while True:
            result['lastProcesses']={name:process_snapshot(identity) for name,identity in original_identities.items()}
            result['lastUnit']=m.properties(UNIT);result['remainingCgroupPids']=helpers.group_pids(old.GROUP)
            blocks=[str(p) for i in old.IDS for p in (Path(f'/dev/ublkb{i}'),Path(f'/sys/class/block/ublkb{i}')) if p.exists() or p.is_symlink()]
            result['remainingBlockPaths']=blocks
            if not any(result['lastProcesses'].values()) and not result['remainingCgroupPids'] and not blocks:break
            need(time.monotonic()<deadline,'B process/cgroup/block remains after scoped force stop; preserve state')
            time.sleep(.25)
        need(controller.document(PRIOR)[1]==prior_sha,'Previous recovery record changed')
        old.finish(runtime,fds,pidfds,proxy,captured,helpers,deploy,binary,result,docs,new_unit,deploy_path,deploy_raw,controller)
    except Exception as error:
        result.update(status='STOPPED_B_FORCE_RESUME_PRESERVE_STATE',errorType=type(error).__name__,reason=str(error))
        if made:helpers.checkpoint(result)
    finally:
        for fd in fds.values():os.close(fd)
        os.close(lock)
    print('BEGIN_B_FORCE_RESUME_REPORT');print(json.dumps(result,indent=2));print('END_B_FORCE_RESUME_REPORT')
    return 0 if result['status']=='B_OLD_COHORT_RECOVERED_DELETEFIX_HEALTHY_NO_GUEST' else 1

if __name__=='__main__':raise SystemExit(main())
