"""A fixed-daemon regression: actual restore, UB read, ordinary API DELETE."""
import argparse,base64,fcntl,hashlib,json,os,re,sys,time,types,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
D=ROOT/'deployments/agentenv-direct-ub-deletefix-v1'
WORK=D/'acceptance/deletefix-smoke-v1'


def need(ok,why):
    if not ok:raise RuntimeError(why)


def embedded(name,data,pin):
    raw=zlib.decompress(base64.b64decode(data,validate=True))
    need(hashlib.sha256(raw).hexdigest()==pin,'Embedded code differs: '+name)
    value=types.ModuleType(name);value.__file__='<'+name+'>'
    exec(compile(raw,value.__file__,'exec'),value.__dict__);return value


def device_paths(number):
    return [Path('/dev')/('ublk'+kind+str(number)) for kind in ('b','c')]+[
        Path('/sys/class/block')/('ublkb'+str(number)),Path('/sys/class/ublk-char')/('ublkc'+str(number))]


def absent(number):return all(not p.exists() and not p.is_symlink() for p in device_paths(number))


def memory_id(text,sid,template):
    text=re.sub(r'\x1b\[[0-9;]*m','',text)
    key=str(D/'state/snapshot-local-cache/runtime'/template/'memory/image.json')
    values=set()
    for line in text.splitlines():
        if sid in line and 'created or acquired shared read-only ublk device' in line and 'key='+key in line:
            match=re.search(r'\bdev_id=(\d+)\b',line)
            need(match is not None,'Memory device creation lacks ID');values.add(int(match[1]))
    need(len(values)==1,'Cannot identify this Guest shared memory device')
    return values.pop()


def memory_release_evidence(text,number,gone):
    if gone:return {'deviceId':number,'state':'removed','guestReferenceReleased':True}
    text=re.sub(r'\x1b\[[0-9;]*m','',text)
    rows=[line for line in text.splitlines() if re.search(r'\bdev_id='+str(number)+r'\b',line)]
    released=any('releasing shared device (refcount reached 0)' in line for line in rows)
    placeholder=any('device returned to idle pool on placeholder' in line for line in rows)
    if released and placeholder:return {'deviceId':number,'state':'idle-on-placeholder','guestReferenceReleased':True,
        'scope':'existing shared-memory device pool retained; not a UB rootfs reader, not zero-cost'}
    return None


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true')
    if not parser.parse_args().run:
        print(json.dumps({'status':'PLAN_ONLY','scope':'A only, one fresh Guest restore/read/normal DELETE; preserved full UB base; no service deployment or kernel cleanup'}));return 0
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='server1','A/server1 root only')
    ready=embedded('fixed_ready',READY_Z64,READY_SHA)
    ready.D=D;ready.WORK=WORK;ready.DEPLOY_SHA='b879e57841935e4516a28badf7e7f32ccaf53c94e5f6721ef7b803afb489ac65'
    ready.PAIR_RUN_ID='94cdf2e7927e466e80a3c0e0853d87a4'
    continuation=embedded('fixed_continuation',CONTINUE_Z64,CONTINUE_SHA)
    runtime=ready.ReadyRun()
    need(runtime.n=='a' and runtime.server['pid']==85472 and runtime.server['startTicks']=='86348532',
         'Not the newly confirmed A Runtime; no Guest created')
    need(runtime.deploy.CORE_COMMIT=='d97d2388e6985e7d28faa3746b91fe54c18aaf60'
         and runtime.binaries['uvm-ublk-daemon']['sha256']=='5291c267777cd91c4b853c6d40720e8d87200b2a0162024782534c4126cba726',
         'Fixed daemon/source differs')
    before=continuation.provider_status(runtime)
    need(before['activeLeases']==before['activePayloadResponses']==0,'Local UB readers already present')
    # run() retains the established create journal, 300/330 command deadlines,
    # exact process/image binding and real required-UB trace contract unchanged.
    report=runtime.run()
    if report['status']!='DIRECT_UB_ONE_REAL_GUEST_READY_RETAINED':
        print('BEGIN_DELETEFIX_GUEST_SMOKE_REPORT');print(json.dumps(report,indent=2));print('END_DELETEFIX_GUEST_SMOKE_REPORT');return 1
    result={'status':'DELETEFIX_GUEST_SMOKE_DELETE_PENDING','read':report,'providerBefore':before,
            'twoNodeGuestAccepted':False,'comparisonExecuted':False,'netSavingsBytes':None,
            'sharedObjectsRetired':False,'servicesChanged':False,'forcedCleanupUsed':False}
    lock=os.open(WORK/'run.lock',os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(continuation.load(WORK/'state.json')==runtime.case.state,'Guest journal changed before DELETE')
        sid=report['sandboxId'];binding=runtime.observe(sid)
        continuation.binding_stable(report['binding'],binding)
        root_id=int(re.fullmatch(r'/dev/ublkb(\d+)',binding['rootfsDevice'])[1])
        mem_id=memory_id(runtime.deploy.read(D/'logs/server.log',4*1024**2).decode('utf-8','replace'),sid,runtime.deploy.TEMPLATE)
        need(root_id!=mem_id,'Rootfs and shared memory alias')
        daemon_log=D/'logs/ublk-daemon.log';log_meta=daemon_log.stat();log_offset=log_meta.st_size
        result.update(rootfsDeviceId=root_id,memoryDeviceId=mem_id)
        ready.save(WORK/'smoke-report.json',result)
        original_call=runtime.api.call
        def audited_call(method,route,*args,**kwargs):
            value=original_call(method,route,*args,**kwargs)
            if method=='DELETE' and route=='/sandboxes/'+sid:
                ready.save(WORK/'delete-api-response.json',{'status':value[0],'body':value[1]})
                result['deleteHttpStatus']=value[0]
            return value
        runtime.api.call=audited_call
        result['deleteIntent']={'sandboxId':sid,'startedNs':time.time_ns()};ready.save(WORK/'smoke-report.json',result)
        print('PHASE=normal-runtime-delete',flush=True)
        runtime.case.delete(sid)
        need(result.get('deleteHttpStatus') in (200,204),'Normal DELETE did not return 200/204')
        deadline=time.monotonic()+10
        while True:
            runtime.guard()
            try:alive=runtime.rt.ticks(binding['fcIdentity']['pid'])==binding['fcIdentity']['startTicks']
            except FileNotFoundError:alive=False
            provider=continuation.provider_status(runtime)
            current=daemon_log.stat()
            need(current.st_ino==log_meta.st_ino and current.st_size>=log_offset and current.st_size-log_offset<=2*1024**2,'Daemon release log rotated/oversized')
            with daemon_log.open('rb') as stream:stream.seek(log_offset);tail=stream.read(2*1024**2).decode('utf-8','replace')
            memory=memory_release_evidence(tail,mem_id,absent(mem_id))
            if not alive and absent(root_id) and memory and provider['activeLeases']==provider['activePayloadResponses']==0:
                need(runtime.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Inventory not empty after DELETE')
                break
            need(time.monotonic()<deadline,'Guest/private device/memory reference/UB permit release not confirmed; preserve result')
            time.sleep(.2)
        need(runtime.case.state['sandboxIds']==[] and runtime.case.state['openRequests']==[], 'Delete journal incomplete')
        result.update(status='A_DELETEFIX_REAL_GUEST_READ_AND_NORMAL_DELETE_PASSED',
            guestExitConfirmed=True,privateRootfsDeviceRemoved=True,memoryRelease=memory,
            localUBReadersReleased=True,providerAfter=provider,ordinaryDeletePassed=True,
            scope='one A real Guest regression; peer survival, two-node acceptance and original/full comparison remain pending')
    except Exception as error:
        result.update(status='STOPPED_DELETEFIX_GUEST_SMOKE_PRESERVE_STATE',errorType=type(error).__name__,
                      reason=str(error),automaticCleanup=False)
    finally:
        result['journal']=runtime.case.state
        ready.save(WORK/'smoke-report.json',result);os.close(lock)
    print('BEGIN_DELETEFIX_GUEST_SMOKE_REPORT');print(json.dumps(result,indent=2));print('END_DELETEFIX_GUEST_SMOKE_REPORT')
    return 0 if result['status']=='A_DELETEFIX_REAL_GUEST_READ_AND_NORMAL_DELETE_PASSED' else 1


if __name__=='__main__':raise SystemExit(main())
