"""Fresh normal exit pair; retained write isolation remains a separate run."""
import argparse,base64,copy,fcntl,hashlib,json,os,re,subprocess,sys,textwrap,time,types,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
D=ROOT/'deployments/agentenv-direct-ub-deletefix-v1'
WORK=D/'acceptance/exit-pair-v1'

def need(ok,why):
    if not ok:raise RuntimeError(why)

def module(name):
    row=MODULES[name];raw=zlib.decompress(base64.b64decode(row['z64'],validate=True))
    need(hashlib.sha256(raw).hexdigest()==row['sha256'],'Embedded component differs')
    value=types.ModuleType('exit_'+name);value.__file__=str(WORK/(name+'.py'))
    exec(compile(raw,value.__file__,'exec'),value.__dict__);return value

def self_sha():return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

def relay_command(phase,node,history,peer=None,source=None):
    source=Path(__file__).read_bytes() if source is None else source
    data=json.dumps({'history':history,'peer':peer},sort_keys=True,separators=(',',':')).encode()
    code64='\n'.join(textwrap.wrap(base64.b64encode(zlib.compress(source,9)).decode(),100))
    data64='\n'.join(textwrap.wrap(base64.b64encode(zlib.compress(data,9)).decode(),100))
    host={'a':'server1','b':'agent1'}[node]
    return f'''python3 -I -B - <<'DELETEFIX_EXIT_PAIR_RELAY'
import base64,hashlib,json,os,platform,stat,sys,zlib
from pathlib import Path
assert os.getuid()==os.geteuid()==0 and platform.node()=={host!r}, 'Run as root on {host}'
raw=zlib.decompress(base64.b64decode("""{code64}"""))
data=zlib.decompress(base64.b64decode("""{data64}"""))
assert hashlib.sha256(raw).hexdigest()=={hashlib.sha256(source).hexdigest()!r}
assert hashlib.sha256(data).hexdigest()=={hashlib.sha256(data).hexdigest()!r}
root=Path('/home/jwk/agent');assert root.resolve(strict=True)==root
folder=root/'r/exit-pair-relay-{node}-e846ec'
folder.mkdir(mode=0o700,exist_ok=True)
assert folder.resolve(strict=True)==folder and folder.stat().st_uid==0 and folder.stat().st_mode&0o077==0
def put(path,content):
 assert path.parent.resolve(strict=True)==path.parent and not path.is_symlink()
 if path.exists():
  m=path.stat();assert stat.S_ISREG(m.st_mode) and m.st_uid==0 and m.st_nlink==1 and m.st_mode&0o022==0 and path.read_bytes()==content
 else:
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as out:out.write(content);out.flush();os.fsync(out.fileno())
entry=root/'AB_deletefix_exit_pair_v1.py';put(entry,raw)
context=json.loads(data);history=folder/'{phase}-history.json';put(history,json.dumps(context['history'],sort_keys=True).encode())
args=[str(entry),{phase!r},'--history',str(history),'--run']
if context['peer'] is not None:
 peer=folder/'{phase}-peer.json';put(peer,json.dumps(context['peer'],sort_keys=True).encode());args+=['--peer',str(peer)]
print('DELETEFIX_EXIT_PAIR_RELAY_VERIFIED',flush=True)
sys.argv=args
exec(compile(raw,str(entry),'exec'),{{'__name__':'__main__','__file__':str(entry)}})
DELETEFIX_EXIT_PAIR_RELAY'''

def allocation_ledger(runtime):
    need(runtime.n=='a','Only exporter A supplies the unique reservation ledger')
    path=ROOT/'AB_direct_full_host_v1.py';raw=runtime.deploy.read(path,128*1024)
    need(len(raw)==81083 and hashlib.sha256(raw).hexdigest()=='de7d33573d8ae46d37c08e811973deab20d16cf855adf256f9b7b6f25bbb7cc0',
         'Retained read-only mapping collector differs')
    source=types.ModuleType('retained_mapping_collector');source.__file__=str(path)
    exec(compile(raw,str(path),'exec'),source.__dict__)
    evidence=source.root_evidence('a')
    need(evidence['ownerId']==runtime.deploy.OWNER and evidence['manifestSha256']==runtime.deploy.MANIFEST
         and evidence['allocationCalls']==8,'Exporter mapping identity differs')
    regions={r['device']:r for r in evidence['regions']};rows=[]
    expected={r['objectName']:r['mappingBytes'] for r in runtime.index['replicas']}
    need(len(evidence['objectMappings'])==len(expected)==8,'Exporter object count differs')
    for obj in evidence['objectMappings']:
        need(expected[obj['objectName']]==obj['mappingBytes'],'Exporter mapped size differs')
        parts=[]
        for segment in obj['segments']:
            region=regions[segment['device']];size=int(region['size'],0)
            need(region['type']=='export' and size>=segment['bytes'],'Exporter region type/size differs')
            parts.append({'role':'export','exportNode':'a','exportBootId':runtime.provider['providerProcess']['bootId'],
                          'exportRegionId':segment['device'],'bytes':size})
        rows.append({'objectName':obj['objectName'],'regions':parts})
    ledger={'version':1,'mode':'full-stored','presence':'retained','ownerId':runtime.deploy.OWNER,
            'manifestSha256':runtime.deploy.MANIFEST,'objects':rows,
            'source':'read-only retained provider mappings and current export sysfs; no payload reread',
            'observedUnixNs':time.time_ns()}
    cost=module('sampler').ub_reservation(ledger)
    need(cost['uniqueExportRegions']==19 and cost['reportedReservationBytesCountedOnce']==2432*1024**2,'Retained reservation differs')
    return ledger

def completed_smoke_contract(report,life,global_state,server):
    need(report['status']=='A_DELETEFIX_REAL_GUEST_READ_AND_NORMAL_DELETE_PASSED'
         and report['ordinaryDeletePassed'] is True and report['forcedCleanupUsed'] is False
         and report['read']['serverIdentity']==server and report['deleteHttpStatus'] in (200,204)
         and report['guestExitConfirmed'] is True and report['privateRootfsDeviceRemoved'] is True
         and report['localUBReadersReleased'] is True,'A previous smoke not confirmed complete')
    need(life==report['journal'] and life['runId']=='94cdf2e7927e466e80a3c0e0853d87a4'
         and life['sandboxIds']==life['openRequests']==[] and life['outcomeUncertain'] is False,'A previous journal differs')
    ops=life['operations'];sid=report['read']['sandboxId']
    need(len(ops)==2 and ops[0]['kind']=='create' and ops[0]['httpStatus']==201 and ops[0]['ack']['sandboxIds']==[sid]
         and ops[1]['kind']=='delete' and ops[1]['route']=='/sandboxes/'+sid and ops[1]['httpStatus']==report['deleteHttpStatus'],
         'A previous request ACKs incomplete')
    need(global_state['version']==1 and global_state['phase']=='active'
         and global_state['directPairRunId']==life['runId'] and global_state['sandboxIds']==global_state['openRequests']==[]
         and global_state['outcomeUncertain'] is False,'Global state not the completed A smoke')

def close_completed_smoke(runtime,ready,cont,release):
    global_state=runtime.deploy.load(D/'guest-cohort-state.json')
    if runtime.engine.quiescent(global_state):return
    need(runtime.n=='a','Unknown non-quiescent B cohort; preserve it')
    base=D/'acceptance/deletefix-smoke-v1'
    report=cont.load(base/'smoke-report.json');life=cont.load(base/'state.json')
    completed_smoke_contract(report,life,global_state,runtime.server)
    need(report['read']['binaries']==runtime.binaries and report['read']['provider']==runtime.provider
         and report['read']['coreCommit']==runtime.deploy.CORE_COMMIT,'Completed smoke deployment context differs')
    # The successful smoke already confirmed removal. A numeric device ID may
    # since have been reused; do not inspect/delete an unrelated replacement.
    fc=report['read']['binding']['fcIdentity']
    try:live=runtime.rt.ticks(fc['pid'])==fc['startTicks']
    except FileNotFoundError:live=False
    need(not live and runtime.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Previous Guest still present')
    status=cont.provider_status(runtime);need(status['activeLeases']==status['activePayloadResponses']==0,'Previous readers remain')
    ready.save(base/'completion-for-next-run.json',{'status':'COMPLETED_SMOKE_ACKS_AND_RELEASE_RECONCILED',
        'sourceReportSha256':hashlib.sha256((base/'smoke-report.json').read_bytes()).hexdigest(),
        'oldRunId':life['runId'],'previousReportAndJournalUnchanged':True})
    closed={**global_state,'phase':'quiesced'}
    ready.save(D/'guest-cohort-state.json',closed,1204,1205)

def normal_release(runtime,origin,ready,cont,release):
    sid=origin['sandboxId'];binding=runtime.observe(sid);cont.binding_stable(origin['binding'],binding)
    root_id=int(re.fullmatch(r'/dev/ublkb(\d+)',binding['rootfsDevice'])[1])
    mem_id=release.memory_id(runtime.deploy.read(D/'logs/server.log',4*1024**2).decode('utf-8','replace'),sid,runtime.deploy.TEMPLATE)
    need(root_id!=mem_id,'Device roles alias')
    log=D/'logs/ublk-daemon.log';before=log.stat();offset=before.st_size
    observed={};original=runtime.api.call
    def call(method,route,*args,**kwargs):
        response=original(method,route,*args,**kwargs)
        if method=='DELETE' and route=='/sandboxes/'+sid:
            observed['httpStatus']=response[0]
            ready.save(WORK/'normal-delete-response.json',{'status':response[0],'body':response[1]})
        return response
    runtime.api.call=call;runtime.case.delete(sid)
    need(observed.get('httpStatus') in (200,204),'Fresh normal DELETE not acknowledged')
    deadline=time.monotonic()+10
    while True:
        runtime.guard()
        try:live=runtime.rt.ticks(binding['fcIdentity']['pid'])==binding['fcIdentity']['startTicks']
        except FileNotFoundError:live=False
        provider=cont.provider_status(runtime);current=log.stat()
        need(current.st_ino==before.st_ino and offset<=current.st_size<=offset+2*1024**2,'Release log rotated/oversized')
        with log.open('rb') as stream:stream.seek(offset);tail=stream.read(2*1024**2).decode('utf-8','replace')
        memory=release.memory_release_evidence(tail,mem_id,release.absent(mem_id))
        if not live and release.absent(root_id) and memory and provider['activeLeases']==provider['activePayloadResponses']==0:
            need(runtime.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Inventory remains after normal delete');break
        need(time.monotonic()<deadline,'Fresh release not confirmed; no forced cleanup');time.sleep(.2)
    need(runtime.case.state['sandboxIds']==runtime.case.state['openRequests']==[],'Fresh lifecycle not empty')
    runtime.case.state['phase']='quiesced';runtime.case.state['lifecyclePassed']=True;runtime.persist(runtime.case.state)
    return {'deleteHttpStatus':observed['httpStatus'],'guestExitConfirmed':True,'privateRootfsDeviceRemoved':True,
        'localReaderLeasesReleased':True,'memoryRelease':memory,'providerStatus':provider,
        'sharedObjectsRetired':False,'forcedCleanupUsed':False,'bindingEvidence':binding,
        'journal':copy.deepcopy(runtime.case.state)}

def prepare_fresh_private_read(binding,memory_device_id,ready):
    """Invalidate only this validation Guest's private Host block-device cache.

    The Guest command already uses O_DIRECT. This prevents a Host ublk cache
    hit from hiding the backing read. It is not used in either measured group.
    """
    device=Path(binding['rootfsDevice']);meta=device.stat()
    need(binding['requiredUB'] is True and binding['upperPrivateVerified'] is True
         and re.fullmatch('/dev/ublkb[0-9]+',str(device)) is not None,'Private rootfs binding required')
    need(int(str(device).removeprefix('/dev/ublkb'))!=memory_device_id,'Rootfs and shared memory device alias; no cache action')
    request={'path':str(device),'major':binding['rootfsDeviceMajor'],'minor':binding['rootfsDeviceMinor'],
             'inode':meta.st_ino,'scope':'only fresh B validation Guest private rootfs block cache; not Guest memory or global cache'}
    ready.save(WORK/'private-rootfs-flush-intent.json',request)
    code='''import fcntl,json,os,stat,sys
p=sys.argv[1];major,minor,inode=map(int,sys.argv[2:])
assert os.geteuid()==0
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
try:
 m=os.fstat(fd)
 assert stat.S_ISBLK(m.st_mode) and (os.major(m.st_rdev),os.minor(m.st_rdev),m.st_ino)==(major,minor,inode)
 assert fcntl.ioctl(fd,0x1261)==0 # Linux BLKFLSBUF: sync then invalidate this block device only.
 assert os.stat(p).st_ino==inode
 print(json.dumps({'status':'PRIVATE_ROOTFS_BLOCK_CACHE_FLUSHED','device':p,'major':major,'minor':minor,'inode':inode}))
finally:os.close(fd)
'''
    outpath=WORK/'private-rootfs-flush.log'
    with outpath.open('xb') as out:
        child=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',code,str(device),str(request['major']),str(request['minor']),str(request['inode'])],
            stdin=subprocess.DEVNULL,stdout=out,stderr=out,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        request['helperPid']=child.pid;ready.save(WORK/'private-rootfs-flush-intent.json',request)
        try:rc=child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            child.kill()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:pass
            raise RuntimeError('Private validation-device flush unconfirmed; preserve Guest and intent')
    raw=outpath.read_bytes();need(rc==0 and len(raw)<=8192,'Private validation-device flush failed; no global-cache fallback')
    result=json.loads(raw)
    need(result=={'status':'PRIVATE_ROOTFS_BLOCK_CACHE_FLUSHED','device':str(device),'major':request['major'],
                 'minor':request['minor'],'inode':request['inode']},'Private flush receipt differs')
    ready.save(WORK/'private-rootfs-flush-result.json',result)
    return result

def envelope(ready,runtime,report,history,verify):
    return {'version':1,'kind':'exit-pair-ready','controllerSha256':self_sha(),'node':runtime.n,
        'readyReport':report,'readyReceipt':json.loads((WORK/'ready-receipt.json').read_bytes()),
        'baseCommand':json.loads((WORK/'command-result.json').read_bytes()),'boundReplicas':runtime.index['replicas'],
        'historicalIsolationSha256':verify.fingerprint(history)}

def validate_ready(value,node,verify,history,pin):
    need(value['version']==1 and value['kind']=='exit-pair-ready' and value['node']==node
         and value['controllerSha256']==pin and value['historicalIsolationSha256']==verify.fingerprint(history),'Peer envelope differs')
    verify.ready_report(value['readyReport'],node)
    historical=verify.historical_isolation(history);report=value['readyReport'];receipt=value['readyReceipt']
    need(receipt['sandboxId']==report['sandboxId'] and receipt['runId']==report['pairRunId']
         and receipt['runId']=='e846ecf57f8f48b8871514a9badca2d0'
         and receipt['node']==node and receipt['base']==report['base']
         and report['provider']['ownerId']==receipt['ownerId'] and report['provider']['manifestSha256']==receipt['manifestSha256'],
         'Peer ready identity differs')
    need(all(receipt[k]==historical[k] for k in ('ownerId','manifestSha256','templateId','base'))
         and verify.normalized_replicas(value['boundReplicas'])==historical['replicas'],'Peer shared generation differs')
    need(value['baseCommand']['exitCode']==0 and value['baseCommand']['timedOut'] is False
         and value['baseCommand']['result']==receipt['base'],'Peer base command failed')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=('ready-a','ready-b','release-a','finish-b'))
    parser.add_argument('--history',type=Path,required=True);parser.add_argument('--peer',type=Path)
    parser.add_argument('--run',action='store_true');args=parser.parse_args()
    if not args.run:print(json.dumps({'status':'PLAN_ONLY','scope':'one fresh Guest per node; original isolation retained separately; no service changes'}));return 0
    ready=module('ready');cont=module('continue');release=module('release');verify=module('verify')
    cont.D=D;cont.WORK=WORK
    runtime=ready.ReadyRun();runtime.ready_module=ready
    need(runtime.n==('a' if args.phase.endswith('-a') else 'b'),'Wrong node for phase')
    history=cont.load(args.history);verified_history=verify.historical_isolation(history)
    need(verify.normalized_replicas(runtime.index['replicas'])==verified_history['replicas'],'Live objects differ from retained isolation')
    pin=self_sha();peer=cont.load(args.peer) if args.peer else None
    if args.phase.startswith('ready-'):
        if runtime.n=='b':
            need(peer is not None,'A actual ready receipt required');validate_ready(peer,'a',verify,history,pin)
        close_completed_smoke(runtime,ready,cont,release)
        ledger=allocation_ledger(runtime) if runtime.n=='a' else peer['allocationLedger']
        report=runtime.run()
        if report['status']!='DIRECT_UB_ONE_REAL_GUEST_READY_RETAINED':
            print(json.dumps(report,indent=2));return 1
        value=envelope(ready,runtime,report,history,verify)
        value['allocationLedger']=ledger
        if peer:
            need(peer['readyReceipt']['runId']==value['readyReceipt']['runId'],'Different fresh pair run')
            need(peer['readyReceipt']['sandboxId']!=value['readyReceipt']['sandboxId'],'Same Guest ID across nodes')
            value['peerReadySha256']=verify.fingerprint(peer);ready.save(WORK/'peer-ready.json',peer)
        ready.save(WORK/'historical-isolation.json',history);ready.save(WORK/'ready-envelope.json',value)
        print('BEGIN_DELETEFIX_EXIT_PAIR_READY');print(json.dumps(value,indent=2));print('END_DELETEFIX_EXIT_PAIR_READY')
        next_phase,next_node=('ready-b','b') if runtime.n=='a' else ('release-a','a')
        print('BEGIN_NEXT_'+next_node.upper()+'_COMMAND');print(relay_command(next_phase,next_node,history,value));print('END_NEXT_'+next_node.upper()+'_COMMAND')
        return 0
    need(peer is not None,'Actual peer phase receipt required')
    lock=os.open(WORK/'run.lock',os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    result={};started=False
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(not (WORK/'exit-intent.json').exists(),'Existing exit attempt preserved; do not repeat')
        local=cont.load(WORK/'ready-envelope.json');validate_ready(local,runtime.n,verify,history,pin)
        need(verify.fingerprint(cont.load(WORK/'historical-isolation.json'))==verify.fingerprint(history),'History changed')
        report=local['readyReport'];initial=local['readyReceipt']
        need(report['serverIdentity']==runtime.server and report['provider']==runtime.provider,'Runtime changed since ready')
        runtime.case=runtime.engine.Cohort.recovery(runtime.api,cont.load(WORK/'state.json'),runtime.persist)
        need(runtime.case.state['sandboxIds']==[initial['sandboxId']] and runtime.case.state['openRequests']==[], 'Fresh cohort unresolved')
        if runtime.n=='a':
            validate_ready(peer,'b',verify,history,pin)
            need(peer['peerReadySha256']==verify.fingerprint(local),'B was not created against this A')
            need(verify.fingerprint(peer['allocationLedger'])==verify.fingerprint(local['allocationLedger']),'B reservation context differs')
        else:
            need(peer['kind']=='a-exit-envelope' and peer['controllerSha256']==pin
                 and verify.fingerprint(peer['bReady'])==verify.fingerprint(local),'A exit belongs to another B')
            validate_ready(peer['aReady'],'a',verify,history,pin)
            verify.released(peer['release'],'a',peer['aReady']['readyReport'],peer['aReady']['readyReceipt'],pin)
            need(peer['release']['peerReadyReportSha256']==verify.fingerprint(report),'A exit did not observe this B ready')
        ready.save(WORK/'exit-intent.json',{'phase':args.phase,'peerSha256':verify.fingerprint(peer),'startedNs':time.time_ns()});started=True
        result={'version':1,'kind':runtime.n+'-released','node':runtime.n,'runId':initial['runId'],
            'sandboxId':initial['sandboxId'],'controllerSha256':pin,'coreCommit':runtime.deploy.CORE_COMMIT,
            'readyReportSha256':verify.fingerprint(report),'readyReceiptSha256':verify.fingerprint(initial),
            'serverIdentity':runtime.server,'binaries':runtime.binaries,'unit':runtime.m.UNIT,'apiPort':runtime.definition['apiPort']}
        if runtime.n=='a':
            result.update(peerReadyReportSha256=verify.fingerprint(peer['readyReport']),peerReadyReceiptSha256=verify.fingerprint(peer['readyReceipt']))
        else:
            binding=runtime.observe(initial['sandboxId']);cont.binding_stable(report['binding'],binding)
            memory_device_id=release.memory_id(runtime.deploy.read(D/'logs/server.log',4*1024**2).decode('utf-8','replace'),initial['sandboxId'],runtime.deploy.TEMPLATE)
            result['postExitReadPreparation']=prepare_fresh_private_read(binding,memory_device_id,ready)
            before=cont.traced(runtime,binding,time.monotonic_ns())
            value=cont.command(runtime,initial['sandboxId'],'b-after-a-exit')
            need(value==initial['base'],'B content changed after A exit')
            after_binding=runtime.observe(initial['sandboxId']);cont.binding_stable(binding,after_binding)
            after=cont.traced(runtime,after_binding,time.monotonic_ns())
            result.update(peerReleaseSha256=verify.fingerprint(peer['release']),beforePostExitRead=before,afterPeerExitRead=after,
                          newBackendRequests=cont.new_backend_reads(before,after))
        result.update(normal_release(runtime,report,ready,cont,release));ready.save(WORK/'release-receipt.json',result)
        if runtime.n=='a':
            out={'version':1,'kind':'a-exit-envelope','controllerSha256':pin,'aReady':local,'bReady':peer,'release':result}
            ready.save(WORK/'a-exit-envelope.json',out)
            print('BEGIN_DELETEFIX_A_EXIT');print(json.dumps(out,indent=2));print('END_DELETEFIX_A_EXIT')
            print('BEGIN_NEXT_B_COMMAND');print(relay_command('finish-b','b',history,out));print('END_NEXT_B_COMMAND')
        else:
            a=peer['aReady'];bundle={'version':1,'kind':'deletefix-composite-pair-v1','historicalIsolation':history,
                'readyReports':{'a':a['readyReport'],'b':report},'readyReceipts':{'a':a['readyReceipt'],'b':initial},
                'boundReplicas':{'a':a['boundReplicas'],'b':local['boundReplicas']},
                'exitReceipts':{'a-released':peer['release'],'b-released':result},
                'commandResults':{'a':{'base-read':a['baseCommand']},'b':{'base-read':local['baseCommand'],
                    'b-after-a-exit':cont.load(WORK/'b-after-a-exit-result.json')}}}
            accepted=verify.verify(bundle,pin);ready.save(WORK/'accepted-pair-bundle.json',bundle);ready.save(WORK/'pair-verification.json',accepted)
            ready.save(WORK/'allocation-ledger.json',a['allocationLedger'])
            print('BEGIN_DELETEFIX_EXIT_PAIR_COMPLETED');print(json.dumps({'accepted':accepted,'bundle':bundle,'allocationLedger':a['allocationLedger']},indent=2));print('END_DELETEFIX_EXIT_PAIR_COMPLETED')
        return 0
    except Exception as error:
        failed={'status':'STOPPED_DELETEFIX_EXIT_PAIR_PRESERVE_STATE','phase':args.phase,'errorType':type(error).__name__,
                'reason':str(error),'intentPersisted':started,'partialReceipt':result,'automaticCleanup':False}
        ready.save(WORK/'failure.json',failed);print(json.dumps(failed,indent=2));return 1
    finally:os.close(lock)

if __name__=='__main__':raise SystemExit(main())
