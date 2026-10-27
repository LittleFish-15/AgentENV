"""Recover only the evidenced old B cohort and stage the existing fixed daemon."""
import argparse,base64,fcntl,hashlib,json,os,select,shutil,signal,stat,subprocess,sys,time,types,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
OLD=ROOT/'deployments/agentenv-direct-ub-guest-v1'
PAIR=OLD/'acceptance/direct-pair-v1'
WORK=PAIR/'b-deletefix-recovery-v1'
GROUP='/system.slice/jwk-aenv-direct-ub-guest-v1-node-b.service'
IDS={0,1}


def need(ok,why):
    if not ok:raise RuntimeError(why)


def embedded(name,encoded,pin,path=None):
    raw=zlib.decompress(base64.b64decode(encoded,validate=True))
    need(hashlib.sha256(raw).hexdigest()==pin,'Embedded source differs: '+name)
    module=types.ModuleType(name);module.__file__=str(path or ('<'+name+'>'))
    exec(compile(raw,module.__file__,'exec'),module.__dict__);return module,raw


def capture_chars():
    result={}
    for number in sorted(IDS):
        path=Path('/dev')/('ublkc'+str(number));meta=path.lstat()
        need(stat.S_ISCHR(meta.st_mode) and os.minor(meta.st_rdev)==number,'B character node differs: '+str(path))
        major=os.major(meta.st_rdev);sec,nsec=divmod(meta.st_ctime_ns,10**9)
        need(Path(f'/sys/class/ublk-char/ublkc{number}/dev').read_text().strip()==f'{major}:{number}','B sysfs identity differs')
        result[number]={'major':major,'inode':meta.st_ino,'ctimeSeconds':sec,'ctimeNanoseconds':nsec}
    return result


def residual_chars(captured):
    remaining=[]
    for number in sorted(IDS):
        for path in (Path(f'/dev/ublkb{number}'),Path(f'/sys/class/block/ublkb{number}')):
            need(not path.exists() and not path.is_symlink(),'B block device still present after process exit: '+str(path))
        path=Path(f'/dev/ublkc{number}');sysfs=Path(f'/sys/class/ublk-char/ublkc{number}')
        if not path.exists() and not path.is_symlink():
            need(not sysfs.exists() and not sysfs.is_symlink(),'Character sysfs remains without node');continue
        meta=path.lstat();expected=captured[number]
        need(stat.S_ISCHR(meta.st_mode) and os.minor(meta.st_rdev)==number
             and os.major(meta.st_rdev)==expected['major'] and meta.st_ino==expected['inode']
             and meta.st_ctime_ns==expected['ctimeSeconds']*10**9+expected['ctimeNanoseconds'],
             'B character device incarnation changed; no deletion')
        remaining.append(number)
    return remaining


def parse_health(text):
    begin='BEGIN_DIRECT_GUEST_RUNTIME_REPORT\n';end='\nEND_DIRECT_GUEST_RUNTIME_REPORT'
    need(text.count(begin)==text.count(end)==1,'Health report framing differs')
    value=json.loads(text.split(begin,1)[1].split(end,1)[0])
    need(value['status']=='DIRECT_GUEST_RUNTIME_HEALTHY_NO_GUEST_YET' and value['CLI_list_count']==0,
         'Fixed B health/inventory failed')
    return value


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true')
    if not parser.parse_args().run:
        print(json.dumps({'status':'PLAN_ONLY','scope':'B only; verify transferred fixed daemon first, graceful old-unit exit, optional reviewed DEAD0/1 deletion, isolated D2 staging; retain UB'}));return 0
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='agent1','B/agent1 root only')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()=='e5aaa223-c78c-4eac-816e-7d98e0cca1c1','B boot changed')
    os.umask(0o077)
    deploy_path=ROOT/'AB_deploy_direct_deletefix_v2.py'
    deploy,deploy_raw=embedded('fixed_B_deploy',DEPLOY_Z64,DEPLOY_SHA,deploy_path)
    candidate=ROOT/'uvm-ublk-daemon-private-delete-v1'
    need(candidate.exists(),'Transfer the fixed daemon to '+str(candidate)+' as jwk before running; no service changed')
    meta=candidate.lstat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1 and not meta.st_mode&0o022,
         'Transferred daemon must be a single ordinary jwk-owned non-writable-by-others file; uid='+str(meta.st_uid))
    deploy.candidate_artifacts('b')  # Exact ELF, length and SHA before any stop.
    need(shutil.disk_usage(ROOT).free>=8*1024**3,'Need 8GiB staging reserve before stopping old B')
    binary=zlib.decompress(base64.b64decode(HELPER_Z64,validate=True))
    need(hashlib.sha256(binary).hexdigest()==HELPER_SHA and Path('/lib/ld-linux-aarch64.so.1').is_file(),
         'B helper/installed loader differs; no service changed')
    ready,_=embedded('retained_ready',READY_Z64,READY_SHA)
    controller,_=embedded('retained_controller',CONTINUE_Z64,CONTINUE_SHA)
    helpers,_=embedded('recovery_helpers',RECOVERY_Z64,RECOVERY_SHA);helpers.RECOVERY=WORK
    pidfds=deploy.PidfdOps();pidfds.self_check()
    need(PAIR.resolve(strict=True)==PAIR and PAIR.stat().st_uid==0,'B pair directory changed')
    lock=os.open(PAIR/'run.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    fds={};made=False
    result={'status':'B_RECOVERY_PREFLIGHT','node':'b','oldOriginalBContinuityProven':False,
            'oldPairLifecycleAccepted':False,'normalOldGuestDeletePassed':False,'oldJournalRewritten':False,
            'providerRetired':False,'SDKAllocationCalled':False,'kernelModuleChanged':False,'newGuestCreated':False,
            'servicesChangeAttempted':False,'signalIntents':[],'deleteIntents':[],'automaticRetry':False}
    try:
        meta=os.fstat(lock);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and meta.st_nlink==1,'B pair lock changed')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(not WORK.exists() and not WORK.is_symlink(),'Previous B recovery preserved; do not repeat')
        prior=controller.load(PAIR/'post-a-recovery-v1/result.json')
        need(prior['status']=='ORIGINAL_B_GUEST_NOT_LIVE_CONTINUITY_NOT_PROVEN'
             and prior['oldDeviceIds']=={'rootfs':0,'memoryFromCreationLog':[1]}
             and prior['processes']['fc']['state']=='not-observed','Not the reviewed original B exit')
        docs={name:controller.document(PAIR/name) for name in ('report.json','state.json','pair-phases.json','ready-receipt.json')}
        origin,life,phase=[docs[name][0] for name in ('report.json','state.json','pair-phases.json')]
        need(origin['node']=='b' and origin['sandboxId']=='01a17ae4-2ff5-7122-a016-2099215c53e8','Wrong B Guest')
        helpers.expected_phase('b',life,phase,origin['sandboxId'])
        runtime=ready.ReadyRun();runtime.guard()
        need(runtime.n=='b' and runtime.server==origin['serverIdentity'] and runtime.provider==origin['provider'],'B Runtime/provider changed')
        need(runtime.server['pid']==2723514 and runtime.server['startTicks']=='62254196','B server incarnation differs')
        need(not ready.find_processes(Path(origin['binaries']['firecracker']['path']),GROUP),'B has a live Guest; do not stop')
        daemon=ready.process(2723962,OLD/'bin/uvm-ublk-daemon',GROUP)
        need(daemon==origin['binding']['daemonIdentity'] and daemon['startTicks']=='62254283','B old daemon changed')
        owned=helpers.owned_device_ids(runtime.deploy.read(OLD/'logs/server.log',4*1024**2).decode('utf-8','replace'),
            origin['sandboxId'],origin['binding']['rootfsDevice'],runtime.deploy.TEMPLATE)
        need(owned==IDS and helpers.daemon_devices(daemon['pid'])==IDS,'B daemon owns unexpected devices')
        captured=capture_chars();result['capturedCharacterIdentities']=captured
        provider_before=controller.provider_status(runtime)
        need(provider_before['activePayloadResponses']==0,'B payload read in flight; do not stop')
        need(runtime.provider['providerProcess']['pid'] not in helpers.group_pids(GROUP),'Provider belongs to old unit; do not stop')
        new_runtime,new_fc,new_unit=deploy.location('b')
        need(all(not p.exists() and not p.is_symlink() for p in (deploy.D,new_runtime,new_fc)),'New B deployment already exists')
        need(runtime.m.properties(new_unit).get('LoadState')=='not-found','New B unit already exists')
        proxy=runtime.deploy.load(runtime.deploy.location('b')[0]/'host-proxy.json')
        proxy_identity=runtime.m.process_identity(proxy['pid'])
        need(proxy_identity['start_ticks']==proxy['start_ticks'] and proxy_identity['uid']==[1204]*4
             and runtime.m.owns_listener(proxy['pid']),'B old proxy identity differs')
        for name,identity in (('server',runtime.server),('daemon',daemon)):
            fds[name]=pidfds.open(identity['pid'])
            need(ready.process(identity['pid'],Path(identity['executable']),GROUP)==identity,'Process changed before pidfd capture')
        fds['proxy']=pidfds.open(proxy['pid'])
        need(runtime.m.process_identity(proxy['pid'])['start_ticks']==proxy['start_ticks'],'Proxy changed before pidfd capture')
        result.update(oldServer=runtime.server,oldDaemon=daemon,providerBefore=provider_before,
                      oldDocumentHashes={k:v[1] for k,v in docs.items()},preservedUnits=runtime.original_units)
        WORK.mkdir(mode=0o700);made=True;result['outputDirectory']=str(WORK)
        for name,row in docs.items():
            with (WORK/('before-'+name)).open('x') as out:json.dump(row[0],out,indent=2)
        # Preserve still-present private upper/config evidence before old service
        # destructors run. Missing files after the prior FC exit are recorded NA.
        evidence={'image.json':Path(origin['binding']['imageConfigPath'])}
        evidence.update({'upper.'+key:Path(row['path']) for key,row in origin['binding']['upper'].items()})
        result['oldUpperEvidence']={}
        for name,path in evidence.items():
            need(path.is_relative_to(runtime.deploy.location('b')[1]),'Old upper evidence path outside dedicated FC directory')
            if not path.exists():result['oldUpperEvidence'][name]={'NA':'already absent'};continue
            data=runtime.deploy.read(path,64*1024**2)
            with (WORK/('before-'+name)).open('xb') as out:out.write(data);out.flush();os.fsync(out.fileno())
            result['oldUpperEvidence'][name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        helpers.checkpoint(result);runtime.guard()
        result['servicesChangeAttempted']=True;result['signalIntents'].append({'role':'old-server','pid':2723514,'signal':'SIGTERM'})
        helpers.checkpoint(result);pidfds.send(fds['server'],signal.SIGTERM)
        deadline=time.monotonic()+90
        while not (helpers.exited(fds['server']) and helpers.exited(fds['daemon']) and not helpers.group_pids(GROUP)):
            need(time.monotonic()<deadline,'B old processes/cgroup did not exit; no forced kill or deployment');time.sleep(.25)
        need(int(runtime.m.properties(runtime.m.UNIT).get('MainPID','0'))==0,'B old main process remains')
        result['oldProcessesExited']=True
        need(deploy.check_provider('b')==runtime.provider,'B provider changed')
        provider=controller.provider_status(runtime)
        need(provider['activeLeases']==provider['activePayloadResponses']==0,'B local UB readers remain; preserve them')
        result['providerAfterOldExit']=provider
        remaining=residual_chars(captured);result['stoppedCharacterDevices']=remaining;helpers.checkpoint(result)
        if remaining:
            path=WORK/'reviewed-B-dead-ublk'
            with path.open('xb') as out:out.write(binary);out.flush();os.fsync(out.fileno())
            path.chmod(0o500)
            def execute(mode,number):
                identity=captured[number];label=mode+'-'+str(number)
                result['pendingHelper']={'mode':mode,'device':number};helpers.checkpoint(result)
                argv=[str(path),mode,str(number),*(str(identity[key]) for key in ('major','inode','ctimeSeconds','ctimeNanoseconds'))]
                with (WORK/(label+'.log')).open('xb') as out:
                    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=out,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':'/root'})
                    result['pendingHelper']['pid']=child.pid;helpers.checkpoint(result)
                    try:code=child.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        try:child.wait(timeout=5)
                        except subprocess.TimeoutExpired:pass
                        raise RuntimeError('B helper timed out; kernel completion unknown, no retry')
                raw=(WORK/(label+'.log')).read_bytes();need(len(raw)<=32768,'B helper output oversized')
                text=raw.decode('utf-8','replace');result.setdefault('helperResults',{})[label]={'exitCode':code,'output':text};helpers.checkpoint(result)
                need(code==0,'B helper refused/failed: '+label)
                rows=[json.loads(line) for line in text.splitlines() if line.startswith('{')]
                need(any(row.get('phase')=='kernel-info' and all(row.get(k)==v for k,v in
                         {'id':number,'state':0,'serverPid':-1,'uid':1204,'gid':1205}.items()) for row in rows),'B kernel state differs')
                if mode=='delete-reviewed-dead':need({'phase':'delete-ack','id':number} in rows,'B delete ACK absent')
                result.pop('pendingHelper');helpers.checkpoint(result)
            for number in remaining:execute('inspect',number)
            for number in remaining:
                need(number in residual_chars(captured) and not helpers.group_pids(GROUP),'B device/process changed')
                result['deleteIntents'].append(number);helpers.checkpoint(result);execute('delete-reviewed-dead',number)
        deadline=time.monotonic()+5
        while not helpers.devices_absent(IDS):
            need(time.monotonic()<deadline,'B devices not confirmed removed');time.sleep(.2)
        result['oldDevicesRemoved']=[0,1];helpers.checkpoint(result)
        if not helpers.exited(fds['proxy']):
            need(runtime.m.process_identity(proxy['pid'])['start_ticks']==proxy['start_ticks'] and runtime.m.owns_listener(proxy['pid']),'Old B proxy changed')
            result['signalIntents'].append({'role':'old-proxy','pid':proxy['pid'],'signal':'SIGTERM'});helpers.checkpoint(result)
            pidfds.send(fds['proxy'],signal.SIGTERM)
        deadline=time.monotonic()+10
        while not helpers.exited(fds['proxy']):
            need(time.monotonic()<deadline,'Old B proxy exit unconfirmed');time.sleep(.2)
        need(deploy.preserve_units(runtime.m,'b')==runtime.original_units and deploy.check_provider('b')==runtime.provider,'Unrelated services/provider changed')
        need(all(controller.document(PAIR/name)[1]==row[1] for name,row in docs.items()),'Old B journal changed')
        helpers.install_owner_code(deploy_path,deploy_raw)
        result['stageIntent']=str(deploy.D);helpers.checkpoint(result)
        prepared=deploy.as_owner(['/usr/bin/python3','-I','-B',str(deploy_path),'prepare','--run'],300)
        (WORK/'prepare.log').write_text(prepared.stdout+prepared.stderr);need(prepared.returncode==0,'B preparation failed; preserve prepare.log')
        result['activationIntent']=new_unit;helpers.checkpoint(result);result['activation']=deploy.activate()
        health=deploy.as_owner(['/usr/bin/python3','-I','-B',str(deploy_path),'health','--run'],180)
        (WORK/'health.log').write_text(health.stdout+health.stderr);need(health.returncode==0,'B health failed; preserve new unit and health.log')
        result['health']=parse_health(health.stdout)
        need(deploy.check_provider('b')==runtime.provider and deploy.preserve_units(runtime.m,'b')==runtime.original_units,'Retained provider/services changed during staging')
        need(all(controller.document(PAIR/name)[1]==row[1] for name,row in docs.items()),'Old journal rewritten during staging')
        result.update(status='B_OLD_COHORT_RECOVERED_DELETEFIX_HEALTHY_NO_GUEST',ordinaryUserHealthPassed=True,
                      newDeployment=str(deploy.D),newDaemonSha256=deploy.BINARIES['uvm-ublk-daemon'])
        helpers.checkpoint(result)
    except Exception as error:
        result.update(status='STOPPED_B_RECOVERY_PRESERVE_STATE',errorType=type(error).__name__,reason=str(error))
        if made:helpers.checkpoint(result)
    finally:
        for fd in fds.values():os.close(fd)
        os.close(lock)
    print('BEGIN_B_RECOVERY_STAGE_REPORT');print(json.dumps(result,indent=2));print('END_B_RECOVERY_STAGE_REPORT')
    return 0 if result['status']=='B_OLD_COHORT_RECOVERED_DELETEFIX_HEALTHY_NO_GUEST' else 1


if __name__=='__main__':raise SystemExit(main())
