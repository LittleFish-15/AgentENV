"""Continue the original B Guest after evidenced A recovery; never replace it."""
import argparse,base64,fcntl,hashlib,json,os,re,stat,sys,time,types,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
D=ROOT/'deployments/agentenv-direct-ub-guest-v1'
PAIR=D/'acceptance/direct-pair-v1'
WORK=PAIR/'post-a-recovery-v1'
SID='01a17ae4-2ff5-7122-a016-2099215c53e8'
RUN='ca0e30a36541483eaa26ff38ead95f8f'


def need(ok,why):
    if not ok:raise RuntimeError(why)


def embedded(name,encoded,pin):
    raw=zlib.decompress(base64.b64decode(encoded,validate=True))
    need(hashlib.sha256(raw).hexdigest()==pin,'Embedded source differs')
    module=types.ModuleType(name);module.__file__='<'+name+'>'
    exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


def context_contract(context,owner,manifest):
    cleanup=context['aRecovery']['reports']['cleanup'];smoke=context['aSmoke']
    need(cleanup['status']=='A_REVIEWED_DEAD_UBLK_DEVICES_REMOVED'
         and cleanup['deletedConfirmed']==[12,13] and cleanup['oldJournalRewritten'] is False,
         'A original failed-run recovery not confirmed')
    after=cleanup['after'];resources=after['resources']
    need(resources['processes']==[] and resources['unit']['MainPID']=='0'
         and all(v is None for v in resources['devices'].values()) and resources['sysfsRemaining']==[],
         'A original resources not confirmed absent')
    need(smoke['status']=='A_DELETEFIX_REAL_GUEST_READ_AND_NORMAL_DELETE_PASSED'
         and smoke['ordinaryDeletePassed'] is True and smoke['guestExitConfirmed'] is True
         and smoke['privateRootfsDeviceRemoved'] is True and smoke['localUBReadersReleased'] is True
         and smoke['forcedCleanupUsed'] is False and smoke['sharedObjectsRetired'] is False,
         'A subsequent regression did not finish normally')
    need(smoke['journal']['sandboxIds']==[] and smoke['journal']['openRequests']==[]
         and smoke['journal']['outcomeUncertain'] is False and smoke['deleteHttpStatus'] in (200,204),
         'A regression requests unresolved')
    for provider in (after['provider'],smoke['providerAfter']):
        need(provider['ownerId']==owner and provider['manifestSha256']==manifest
             and provider['activeLeases']==provider['activePayloadResponses']==0,'A shared base/reader context differs')


def old_process(identity,cgroup):
    pid=identity['pid'];proc=Path('/proc')/str(pid)
    try:
        ticks=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
        if ticks!=identity['startTicks']:return {'state':'original-exited-pid-reused','pid':pid,'observedStartTicks':ticks}
        executable=os.readlink(proc/'exe')
        groups=[line.split(':',2)[2] for line in (proc/'cgroup').read_text().splitlines()]
        need(executable==identity['executable'] and any(g==cgroup or g.startswith(cgroup+'/') for g in groups),
             'Original process executable/cgroup changed')
        need((proc/'stat').read_text().rsplit(')',1)[1].split()[19]==ticks,'Process changed during observation')
        return {'state':'same-incarnation','pid':pid,'startTicks':ticks,'executable':executable}
    except (FileNotFoundError,ProcessLookupError):return {'state':'not-observed','pid':pid}


def owned_memory_ids(log,sid,template):
    key=str(D/'state/snapshot-local-cache/runtime'/template/'memory/image.json')
    found=set()
    for line in re.sub(r'\x1b\[[0-9;]*m','',log).splitlines():
        if sid in line and 'created or acquired shared read-only ublk device' in line and 'key='+key in line:
            match=re.search(r'\bdev_id=(\d+)\b',line)
            if match:found.add(int(match[1]))
    return sorted(found)


def main(context=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');parser.add_argument('--context',type=Path)
    args=parser.parse_args()
    if not args.run:
        print(json.dumps({'status':'PLAN_ONLY','scope':'original B only: identity, optional actual Guest read and new UB events after A recovery; no create/delete/deploy'}));return 0
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='agent1','B/agent1 root only')
    ready=embedded('original_ready',READY_Z64,READY_SHA)
    cont=embedded('original_continuation',CONTINUE_Z64,CONTINUE_SHA)
    if context is None:
        need(args.context is not None,'Explicit returned A context required');context=cont.load(args.context)
    need(PAIR.resolve(strict=True)==PAIR and PAIR.stat().st_uid==0,'Original B pair path differs')
    lock=os.open(PAIR/'run.lock',os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    result={'status':'B_POST_A_RECOVERY_PREFLIGHT','node':'b','originalGuestId':SID,'originalRunId':RUN,
            'newGuestCreated':False,'servicesChanged':False,'SDKAllocationCalled':False,'sharedObjectsRetired':False,
            'originalPairJournalRewritten':False,'oldAOrdinaryDeletePassed':False,
            'twoNodeFinalAcceptance':False,'comparisonExecuted':False,'netSavingsBytes':None}
    made=False
    try:
        meta=os.fstat(lock);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and meta.st_nlink==1,'Original pair lock changed')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(not WORK.exists() and not WORK.is_symlink(),'Prior B continuation preserved; do not repeat')
        docs={n:cont.document(PAIR/n) for n in ('report.json','state.json','pair-phases.json','ready-receipt.json')}
        report=docs['report.json'][0];life=docs['state.json'][0];phase=docs['pair-phases.json'][0];local=docs['ready-receipt.json'][0]
        need(report['node']=='b' and report['pairRunId']==RUN and report['sandboxId']==SID
             and life['runId']==RUN and life['sandboxIds']==[SID] and life['openRequests']==[]
             and not life['outcomeUncertain'] and phase['phase']=='peer-isolated'
             and 'pending' not in phase and 'error' not in phase,'Original B phase/journal differs')
        need(phase['baseVerification']['status']=='CURRENT_UB_STORED_BASE_CONTENT_VERIFIED','Original base verification missing')
        context_contract(context,local['ownerId'],local['manifestSha256'])
        deploy_path=D/'libexec/direct_guest_runtime.py';raw=deploy_path.read_bytes()
        need(hashlib.sha256(raw).hexdigest()==ready.DEPLOY_SHA,'Original B deployment source differs')
        deploy=types.ModuleType('retained_B_deploy');deploy.__file__=str(deploy_path)
        exec(compile(raw,str(deploy_path),'exec'),deploy.__dict__)
        need(deploy.node()=='b' and deploy.check_provider('b')==report['provider'],'B provider incarnation changed')
        definition=deploy.load(D/'guest-definition.json');module=deploy.make_module(definition)
        result['oldUnit']=module.properties(module.UNIT)
        group='/system.slice/'+module.UNIT
        result['processes']={name:old_process(identity,group) for name,identity in (
            ('server',report['serverIdentity']),('daemon',report['binding']['daemonIdentity']),('fc',report['binding']['fcIdentity']))}
        result['providerStatus']=cont.provider_status(types.SimpleNamespace(n='b',deploy=deploy))
        root_id=int(re.fullmatch(r'/dev/ublkb(\d+)',report['binding']['rootfsDevice'])[1])
        try:
            memory_ids=owned_memory_ids(deploy.read(D/'logs/server.log',4*1024**2).decode('utf-8','replace'),SID,deploy.TEMPLATE)
        except (OSError,RuntimeError) as error:
            # Optional future cleanup evidence cannot block the actual read.
            # No memory-device cleanup is performed by this entry.
            memory_ids=[];result['memoryIdentityUnavailable']=type(error).__name__+': '+str(error)
        result['oldDeviceIds']={'rootfs':root_id,'memoryFromCreationLog':memory_ids}
        result['devicePresence']={str(i):{kind:Path(path).exists() for kind,path in
            [('block',f'/dev/ublkb{i}'),('char',f'/dev/ublkc{i}'),('sysfs',f'/sys/class/ublk-char/ublkc{i}')]} for i in {root_id,*memory_ids}}
        WORK.mkdir(mode=0o700);made=True;result['outputDirectory']=str(WORK)
        result['aContextSha256']=hashlib.sha256(json.dumps(context,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        ready.save(WORK/'a-context.json',context);ready.save(WORK/'result.json',result)
        if result['processes']['fc']['state']!='same-incarnation':
            result.update(status='ORIGINAL_B_GUEST_NOT_LIVE_CONTINUITY_NOT_PROVEN',postAExitReadPassed=False,
                scope='original B FC not observed or PID reused; cannot reconstruct its continuous survival; no replacement or command attempted')
        else:
            runtime=ready.ReadyRun();runtime.ready_module=ready
            need(runtime.server==report['serverIdentity'] and runtime.provider==report['provider'],'Original B Runtime changed')
            # Read-only API recovery object. No create/delete/fork/capture method
            # is called. Original journals stay byte-identical.
            def refuse_journal_mutation(_):
                raise RuntimeError('Post-exit read cannot mutate the original cohort journal')
            runtime.case=runtime.engine.Cohort.recovery(runtime.api,life,refuse_journal_mutation)
            binding=runtime.observe(SID);cont.binding_stable(report['binding'],binding)
            cont.WORK=WORK
            before=cont.traced(runtime,binding,time.monotonic_ns())
            result['readIntent']={'sandboxId':SID,'startedNs':time.time_ns(),'guestTimeoutSeconds':300,'cliTimeoutSeconds':330}
            ready.save(WORK/'result.json',result)
            print('PHASE=original-B-read-after-A-exit',flush=True)
            value=cont.command(runtime,SID,'b-after-a-recovery')
            need(value==local['base'],'Original B content differs from verified base')
            after_binding=runtime.observe(SID);cont.binding_stable(binding,after_binding)
            after=cont.traced(runtime,after_binding,time.monotonic_ns())
            increment=cont.new_backend_reads(before,after);runtime.guard()
            result.update(status='ORIGINAL_B_SURVIVED_A_RECOVERY_NEW_UB_READ_PASSED',postAExitReadPassed=True,
                base=value,binding=after_binding,beforeRead=before,afterRead=after,newBackendRequests=increment,
                scope='same original B Guest read unchanged data through new UB backend events after A recovered exit; B release and final aggregation remain pending')
        need({n:cont.document(PAIR/n)[1] for n in docs}=={n:v[1] for n,v in docs.items()},'Original B journal changed during observation')
    except Exception as error:
        result.update(status='STOPPED_B_POST_A_RECOVERY_PRESERVE_STATE',errorType=type(error).__name__,reason=str(error),automaticCleanup=False)
    finally:
        if made:ready.save(WORK/'result.json',result)
        os.close(lock)
    print('BEGIN_B_POST_A_RECOVERY_REPORT');print(json.dumps(result,indent=2));print('END_B_POST_A_RECOVERY_REPORT')
    return 0 if result['status']=='ORIGINAL_B_SURVIVED_A_RECOVERY_NEW_UB_READ_PASSED' else 1


if __name__=='__main__':raise SystemExit(main())
