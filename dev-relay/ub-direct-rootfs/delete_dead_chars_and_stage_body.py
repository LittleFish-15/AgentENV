"""Delete only the two reviewed stopped A ublk objects, then resume fixed staging."""
import argparse, base64, fcntl, hashlib, json, os, platform, stat, subprocess, sys, time, types, zlib
from pathlib import Path

ROOT=Path('/home/jwk/agent')
PAIR=ROOT/'deployments/agentenv-direct-ub-guest-v1/acceptance/direct-pair-v1'
PRIOR=PAIR/'post-force-b8b5891eb7c74ea380994a79849ba3c9/report.json'
WORK=PAIR/'dead-char-delete-v1'


def need(ok,why):
    if not ok:raise RuntimeError(why)


def known_remainder(snapshot, remaining):
    unit=snapshot['unit']
    if unit['MainPID']!='0' or unit['ActiveState'] not in ('inactive','failed') or unit.get('Job'):return False
    if snapshot['processes']:return False
    for name,row in snapshot['devices'].items():
        if name.startswith('ublkb') and row is not None:return False
        if name.startswith('ublkc'):
            number=int(name[5:])
            if number in remaining:
                if row != {'major':242,'minor':number,'expectedIdentity':True}:return False
            elif row is not None:return False
    return set(snapshot['sysfsRemaining'])=={f'/sys/class/ublk-char/ublkc{i}' for i in remaining}


def run_helper(path,mode,number,record,post):
    label=mode+'-'+str(number);output=WORK/(label+'.log')
    record['pendingHelper']={'mode':mode,'device':number,'log':str(output)}
    post.write_report(WORK,record)
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':'/root'}
    with output.open('xb') as stream:
        child=subprocess.Popen([str(path),mode,str(number)],stdin=subprocess.DEVNULL,stdout=stream,stderr=stream,env=env)
        record['pendingHelper']['pid']=child.pid;post.write_report(WORK,record)
        try:code=child.wait(timeout=20)
        except subprocess.TimeoutExpired:
            # This is our unreaped child, not a numeric-PID selection of another
            # service. Unknown kernel completion remains journalled, never retried.
            child.kill()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:pass
            raise RuntimeError('Helper timeout; kernel deletion outcome unknown; preserve pendingHelper')
    raw=output.read_bytes();need(len(raw)<=32768,'Helper output budget exceeded')
    text=raw.decode('utf-8','replace');record.setdefault('helperResults',{})[label]={'exitCode':code,'output':text}
    post.write_report(WORK,record)
    need(code==0,'Helper refused/failed: '+label+'; see helperResults and private log')
    rows=[json.loads(line) for line in text.splitlines() if line.startswith('{')]
    info=[row for row in rows if row.get('phase')=='kernel-info']
    need(len(info)==1 and all(info[0].get(k)==v for k,v in
         {'id':number,'state':0,'serverPid':-1,'uid':1204,'gid':1205}.items()),'Kernel info receipt mismatch')
    if mode=='delete-reviewed-dead':
        need(sum(row=={'phase':'delete-ack','id':number} for row in rows)==1,'Kernel DELETE acknowledgment missing')
    record.pop('pendingHelper');post.write_report(WORK,record)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true')
    if not parser.parse_args().run:
        print(json.dumps({'status':'PLAN_ONLY','scope':'A stopped ublk12/13 GET_DEV_INFO then one DEL_DEV each; confirmed disappearance then fixed-daemon staging; no module/SDK/Guest operation'}));return 0
    need(os.getuid()==os.geteuid()==0 and platform.node()=='server1','A/server1 root only')
    os.umask(0o077)
    need(ROOT.resolve(strict=True)==ROOT and PAIR.resolve(strict=True)==PAIR and PAIR.stat().st_uid==0,'Pair path changed')
    raw=zlib.decompress(base64.b64decode(POST_Z64,validate=True));need(hashlib.sha256(raw).hexdigest()==POST_SHA,'Pinned post-force v2 changed')
    post=types.ModuleType('reviewed_post_force_v2');post.__file__='<embedded-post-force-v2>'
    exec(compile(raw,post.__file__,'exec'),post.__dict__)
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==post.BOOT,'Boot changed')
    deploy_raw=zlib.decompress(base64.b64decode(post.DEPLOY_Z64,validate=True))
    deploy=post.load_code('reviewed_deploy',deploy_raw,post.DEPLOY_SHA,ROOT/'AB_deploy_direct_deletefix_v2.py')
    controller_path=ROOT/'actual_guest_pair_continue_v2.py'
    controller=post.load_code('reviewed_controller',post.root_controller_bytes(controller_path),
        '6c01a15e36a056b29a400e52f33f38981ff0abf3ca939185e6a4074dd9fda1fa',controller_path)
    runtime=types.SimpleNamespace(n='a',deploy=deploy)
    result={'status':'DEAD_CHAR_PREFLIGHT','node':'a','normalGuestDeletePassed':False,'oldPairLifecycleAccepted':False,
            'oldJournalRewritten':False,'sharedObjectsRetired':False,'kernelModuleChanged':False,'GuestCreated':False,
            'automaticRetry':False,'deleteIntents':[],'deletedConfirmed':[]}
    made=False;lock=os.open(PAIR/'run.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        meta=os.fstat(lock);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and meta.st_nlink==1,'Lock changed')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(not WORK.exists() and not WORK.is_symlink(),'Prior deletion attempt preserved; do not repeat')
        prior,prior_sha=controller.document(PRIOR)
        need(prior['status']=='STOPPED_POST_FORCE_PRESERVE_STATE' and prior['node']=='a'
             and prior['reason']=='Owned ublk devices remain; kernel deletion has not been confirmed'
             and prior['servicesChangeAttempted'] is False and prior['signalIntents']==[]
             and known_remainder(prior['oldResources'],{12,13}),'Not the reviewed stopped-device receipt')
        docs={n:controller.document(PAIR/n) for n in ('report.json','state.json','pair-phases.json')}
        need({n:r[1] for n,r in docs.items()}==prior['oldDocumentHashes'],'Old journal changed')
        origin=docs['report.json'][0]
        provider=deploy.check_provider('a');need(provider==origin['provider'],'Provider incarnation changed')
        definition=deploy.load(post.OLD/'guest-definition.json');m=deploy.make_module(definition)
        preserved=deploy.preserve_units(m,'a')
        def guard(remaining):
            observed=post.snapshot();need(known_remainder(observed,remaining),'Old unit/device incarnation changed')
            need(deploy.check_provider('a')==provider,'Provider changed')
            status=controller.provider_status(runtime)
            need(status['activeLeases']==status['activePayloadResponses']==0,'Local provider readers remain')
            holders=post.device_holders();need(holders['complete'] and holders['matches']==[],'Device holders exist or observation incomplete')
            need(deploy.preserve_units(m,'a')==preserved,'Unrelated service changed')
            need({n:controller.document(PAIR/n)[1] for n in docs}==prior['oldDocumentHashes'],'Old journal changed')
            return {'resources':observed,'provider':status,'holders':holders}
        result['before']=guard({12,13});result['priorReceiptSha256']=prior_sha
        need(Path('/lib/ld-linux-aarch64.so.1').is_file(),'Existing AArch64 dynamic loader missing; no libraries installed')
        binary=zlib.decompress(base64.b64decode(HELPER_Z64,validate=True))
        need(len(binary)==HELPER_BYTES and hashlib.sha256(binary).hexdigest()==HELPER_SHA,'Fixed ARM64 helper changed')
        WORK.mkdir(mode=0o700);made=True;result['outputDirectory']=str(WORK)
        helper=WORK/'aenv-reviewed-dead-ublk'
        with helper.open('xb') as stream:stream.write(binary);stream.flush();os.fsync(stream.fileno())
        helper.chmod(0o500);result['helperSha256']=HELPER_SHA;post.write_report(WORK,result)
        # Inspect BOTH devices before any mutation. No STOP_DEV, module unload,
        # forced deletion or not-found-as-success shortcut is used.
        for number in (12,13):run_helper(helper,'inspect',number,result,post)
        remaining={12,13}
        for number in (12,13):
            result['lastGuard']=guard(remaining)
            result['deleteIntents'].append(number);post.write_report(WORK,result)
            run_helper(helper,'delete-reviewed-dead',number,result,post)
            remaining.remove(number)
            deadline=time.monotonic()+5
            while not known_remainder(post.snapshot(),remaining):
                need(time.monotonic()<deadline,'Kernel ack received but device disappearance not confirmed')
                time.sleep(.2)
            result['deletedConfirmed'].append(number);post.write_report(WORK,result)
        result['after']=guard(set())
        result['status']='A_REVIEWED_DEAD_UBLK_DEVICES_REMOVED';post.write_report(WORK,result)
    except Exception as error:
        result.update(status='STOPPED_DEAD_CHAR_DELETE_PRESERVE_STATE',errorType=type(error).__name__,reason=str(error))
        if made:post.write_report(WORK,result)
    finally:os.close(lock)
    print('BEGIN_DEAD_CHAR_DELETE_REPORT');print(json.dumps(result,indent=2));print('END_DEAD_CHAR_DELETE_REPORT',flush=True)
    if result['status']!='A_REVIEWED_DEAD_UBLK_DEVICES_REMOVED':return 1
    # Reuse the unchanged v2 reader/proxy/staging gates after releasing the pair
    # lock. Old failed DELETE is never converted into a successful Guest exit.
    sys.argv=['post_force_v2','--run']
    return post.main()


if __name__=='__main__':raise SystemExit(main())
