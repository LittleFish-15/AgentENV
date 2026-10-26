"""Continue the fixed real-Guest pair using explicit peer receipts.

No network coordination is provisioned. This controller uses only the local
Runtime API and the local provider status socket. Uncertain phases cannot be
repeated. Shared bases are retained, never retired by Guest release.
"""
import argparse,fcntl,hashlib,json,os,re,stat,subprocess,sys,time,types,uuid
from pathlib import Path
ROOT=Path('/home/jwk/agent')
D=ROOT/'deployments/agentenv-direct-ub-guest-v1'
WORK=D/'acceptance/direct-pair-v1'
READY_SHA='145ddd8b86c3cb8a1d1cb61278b01cbf0039668827a83e340e550f11e7c53c30'

def need(ok,reason):
    if not ok:raise RuntimeError(reason)

def document(path,limit=2*1024**2):
    need(path.resolve(strict=True)==path and path.is_relative_to(ROOT),'Redirected/outside receipt')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        meta=os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid in (0,1204) and meta.st_size<=limit,'Unexpected receipt type/owner/size')
        raw=stream.read(limit+1)
        after=os.fstat(stream.fileno())
        need((meta.st_dev,meta.st_ino,meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Receipt changed during read')
    need(len(raw)<=limit,'Receipt oversized')
    return json.loads(raw),hashlib.sha256(raw).hexdigest()

def load(path,limit=2*1024**2):return document(path,limit)[0]

def peer_contract(local,peer,kind):
    need(peer.get('version')==1 and peer.get('kind')==kind
         and peer.get('node')==('b' if local['node']=='a' else 'a'),'Peer role/phase differs')
    for key in ('runId','ownerId','manifestSha256','templateId','base'):
        need(peer.get(key)==local.get(key),'Peer context differs: '+key)
    need(isinstance(peer.get('sandboxId'),str) and re.fullmatch('[A-Za-z0-9_-]{1,128}',peer['sandboxId']), 'Peer Guest identity missing')
    need(peer['sandboxId']!=local['sandboxId'],'Peer cannot be the local Guest')
    if kind!='ready':
        need(isinstance(peer.get('written'),dict) and peer['written']['path']==local['base']['path']
             and re.fullmatch('[0-9a-f]{64}',peer['written'].get('sha256',''))
             and peer['written']['sha256']!=local['base']['sha256'],'Peer write evidence missing')
    if kind=='a-released':
        need(peer.get('guestExitConfirmed') is True and peer.get('deviceExitConfirmed') is True
             and peer.get('localReaderLeasesReleased') is True,'Peer release evidence incomplete')

def changed_upper(before,after):
    changed=False
    for name in ('data','index'):
        a,b=before[name],after[name]
        need(all(a[key]==b[key] for key in ('path','dev','inode')),'Private upper identity changed')
        changed|=a['bytes']!=b['bytes'] or a['mtimeNs']!=b['mtimeNs']
    need(changed,'Private upper has no observed change')

def binding_stable(before,after):
    for key in ('fcIdentity','daemonIdentity','imageConfigSha256','rootfsDevice'):
        need(before[key]==after[key],'Guest/backend identity changed during phase: '+key)

def new_backend_reads(before,after):
    need(before['source']==after['source'] and before['trace']==after['trace'], 'Read trace incarnation changed')
    need(after['requests']>before['requests'] and after['bytesIncludingRepeatedReads']>before['bytesIncludingRepeatedReads'],
         'No new B UB backend read after A exit; cached success cannot pass')
    return after['requests']-before['requests']

def provider_status(runtime):
    # Ordinary UID is required by the existing provider's SO_PEERCRED check.
    path=str(ROOT/'r'/('uf-'+runtime.n+'-v1')/'p/control.sock')
    code='''import json,socket,struct,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(sys.argv[1])
pid,uid,gid=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
assert uid==1204
def exact(n):
 b=bytearray()
 while len(b)<n:
  v=s.recv(n-len(b));assert v;b.extend(v)
 return bytes(b)
data=b'{"operation":"status"}'
s.sendall(struct.pack('>I',len(data))+data)
n=struct.unpack('>I',exact(4))[0];assert 0<n<=16384
value=json.loads(exact(n));s.close();print(json.dumps(value))
'''
    result=runtime.deploy.as_owner(['/usr/bin/python3','-I','-B','-c',code,path],15)
    need(result.returncode==0,'Provider status failed; no lease release inferred')
    reply=json.loads(result.stdout)
    need(reply.get('ownerId')==runtime.deploy.OWNER and reply.get('manifestSha256')==runtime.deploy.MANIFEST
         and reply.get('source')=='ub-direct-stored','Provider status identity differs')
    return reply

BASE_CHECK_CODE=r'''import hashlib,json,os,socket,stat,struct,sys,time
from pathlib import Path
path=Path(sys.argv[1]);pin=sys.argv[2]
assert os.getuid()==os.geteuid()==1204 and path.resolve(strict=True)==path
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
with os.fdopen(fd,'rb') as stream:
 meta=os.fstat(stream.fileno());assert stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_size<=1048576
 raw=stream.read(1048577)
assert hashlib.sha256(raw).hexdigest()==pin
index=json.loads(raw);rows=index['replicas']
assert index['version']==1 and index['state']=='ready' and len(rows)==8
assert len({r['objectName'] for r in rows})==8 and sum(r['fileBytes'] for r in rows)<=2*1024**3
magic=b'AENVUB1\0';deadline=time.monotonic()+300;result=[]
for row in rows:
 assert row['allowRepositoryFallback'] is False
 name=row['objectName'].encode();assert len(name)==37
 digest=bytes.fromhex(row['layerDigest'].removeprefix('sha256:'));assert len(digest)==32
 generation=bytes.fromhex(row['generation']);assert len(generation)==16
 request=magic+struct.pack('>H',len(name))+name+generation+struct.pack('>QQ',row['fileBytes'],row['mappingBytes'])+digest
 assert len(request)==111
 with socket.socket(socket.AF_UNIX) as stream:
  stream.settimeout(10);stream.connect(row['brokerSocket'])
  assert struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]==1204
  def exact(n):
   out=bytearray()
   while len(out)<n:
    remaining=deadline-time.monotonic();assert remaining>0
    stream.settimeout(min(10,remaining));chunk=stream.recv(n-len(out));assert chunk;out.extend(chunk)
   return bytes(out)
  def response(expected):
   header=exact(16);assert header[:8]==magic and struct.unpack('>II',header[8:])==(0,expected)
  stream.sendall(request);response(0);h=hashlib.sha256();offset=0
  while offset<row['fileBytes']:
   count=min(1048576,row['fileBytes']-offset)
   stream.sendall(struct.pack('>QI',offset,count));response(count);h.update(exact(count));offset+=count
  assert h.digest()==digest
 result.append({'objectName':row['objectName'],'generation':row['generation'],'bytes':offset,'sha256':'sha256:'+h.hexdigest()})
print(json.dumps({'status':'CURRENT_UB_STORED_BASE_CONTENT_VERIFIED','layers':result,'bytesVerified':sum(r['bytes'] for r in result),'sourceFileReads':False,'SDKAllocationCalled':False}))
'''

def verify_base(runtime):
    result=runtime.deploy.as_owner(['/usr/bin/python3','-I','-B','-c',BASE_CHECK_CODE,
                                  runtime.provider['path'],runtime.provider['sha256']],310)
    need(result.returncode==0,'Current UB base checksum not verified; retain private logs/state')
    value=json.loads(result.stdout)
    need(value.get('status')=='CURRENT_UB_STORED_BASE_CONTENT_VERIFIED'
         and len(value.get('layers',[]))==len(runtime.refs),'Base verification reply incomplete')
    expected={(r['objectName'],r['generation'],r['layerDigest'],r['fileBytes']) for r in runtime.index['replicas']}
    actual={(r['objectName'],r['generation'],r['sha256'],r['bytes']) for r in value['layers']}
    need(actual==expected,'Base checksum receipt differs from actual pinned objects')
    return value

def command(runtime,sid,label,write=False):
    need(runtime.case.owned(sid) is not None,'Owned Guest missing')
    marker='DIRECT_UB_END_'+uuid.uuid4().hex
    shell=runtime.replay.shell_command(runtime.pair.guest_command(runtime.case.run_id,write),marker)
    runtime.ready_module.save(WORK/(label+'-intent.json'),{'label':label,'sandboxId':sid,'write':write,
        'guestTimeoutSeconds':300,'cliTimeoutSeconds':330,'startedNs':time.time_ns()})
    env=runtime.m.environment();env.update(XDG_CONFIG_HOME=str(D/'cli/config'),XDG_CACHE_HOME=str(D/'cli/cache'))
    outpath=WORK/(label+'.stdout');errpath=WORK/(label+'.stderr')
    args=['/usr/bin/setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all','--ambient-caps=-all',
          '--bounding-set=-all','--no-new-privs',str(D/'bin/aenv'),'exec',sid,'/bin/bash','-c',shell]
    child=None;start=time.monotonic()
    try:
        with outpath.open('xb') as out,errpath.open('xb') as err:
            child=subprocess.Popen(args,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
            while child.poll() is None:
                need(time.monotonic()-start<330,'CLI exceeded 330 seconds; outcome retained')
                need(outpath.stat().st_size+errpath.stat().st_size<=4*1024**2,'Command output budget exceeded')
                time.sleep(.2)
        need(child.returncode==0,'CLI transport failed; outcome retained')
        need(outpath.stat().st_size+errpath.stat().st_size<=4*1024**2,'Completed command output budget exceeded')
        text=outpath.read_text(errors='replace')
        exits=re.findall(r'(?m)^'+marker+r' ([0-9]+)\s*$',text)
        need(len(exits)==1 and exits[0]=='0','Guest command failed; inspect private output')
        value=runtime.pair.file_result({'exitCode':0,'timedOut':False,'stdout':text})
        runtime.ready_module.save(WORK/(label+'-result.json'),{'result':value,'exitCode':0,'timedOut':False,'seconds':time.monotonic()-start})
        return value
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)

def traced(runtime,binding,through):
    daemon=binding['daemonIdentity']
    path=D/'logs/rootfs-access'/('uvm-ublk-daemon-'+str(daemon['pid'])+'.jsonl')
    status=path.with_suffix('.status.json')
    for _ in range(25):
        row=load(status)
        if isinstance(row.get('drained_through_ns'),int) and row['drained_through_ns']>=through:break
        time.sleep(.2)
    return runtime.ready_module.trace_summary(path,status,daemon['pid'],Path(binding['imageConfigPath']),runtime.refs,through)

def release_guest(runtime,sid,binding):
    need(runtime.case.state['sandboxIds']==[sid] and not runtime.case.state['openRequests'],'Unresolved or additional Guests; no delete')
    runtime.case.delete(sid)
    deadline=time.monotonic()+10
    fc=binding['fcIdentity'];device=Path(binding['rootfsDevice'])
    while True:
        runtime.guard()
        try:alive=runtime.rt.ticks(fc['pid'])==fc['startTicks']
        except FileNotFoundError:alive=False
        status=provider_status(runtime)
        if not alive and not device.exists() and status['activeLeases']==0 and status['activePayloadResponses']==0:
            need(runtime.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Runtime inventory not empty after release')
            return {'guestExitConfirmed':True,'deviceExitConfirmed':True,'localReaderLeasesReleased':True,
                    'providerRetained':True,'sharedBaseRetired':False,'providerStatus':status}
        need(time.monotonic()<deadline,'Guest/device/read permits not confirmed released; preserve pending phase')
        time.sleep(.2)

def run(phase,peer_path):
    need(os.getuid()==os.geteuid()==0 and sys.platform=='linux','Root target execution required')
    path=ROOT/'AB_actual_ub_guest_ready_v1.py'
    need(path.resolve(strict=True)==path,'Ready controller redirected')
    raw=path.read_bytes();need(hashlib.sha256(raw).hexdigest()==READY_SHA,'Ready controller differs')
    module=types.ModuleType('verified_ready');module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    runtime=module.ReadyRun();runtime.ready_module=module
    lock=os.open(WORK/'run.lock',os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    try:
        report=load(WORK/'report.json');local=load(WORK/'ready-receipt.json')
        need(report['status']=='DIRECT_UB_ONE_REAL_GUEST_READY_RETAINED'
             and report['serverIdentity']==runtime.server and report['provider']==runtime.provider
             and report['coreCommit']==runtime.deploy.CORE_COMMIT,'Original ready context differs')
        need(local['node']==runtime.n and local['runId']==module.PAIR_RUN_ID,'Wrong pair context')
        runtime.case=runtime.engine.Cohort.recovery(runtime.api,load(WORK/'state.json'),runtime.persist)
        sid=local['sandboxId'];binding=report['binding']
        need(runtime.case.run_id==module.PAIR_RUN_ID and not runtime.case.state['openRequests'],'Unresolved API request; no new phase')
        journal_path=WORK/'pair-phases.json'
        journal=load(journal_path) if journal_path.exists() else {'phase':'ready','events':[]}
        transitions={'write-a':('a','ready','ready','a-written'),
                     'check-b':('b','ready','a-written','peer-isolated'),
                     'release-a':('a','a-written','peer-isolated','a-released'),
                     'survive-release-b':('b','peer-isolated','a-released','b-released')}
        node,start,peer_kind,end=transitions[phase]
        need(runtime.n==node and journal['phase']==start and 'pending' not in journal,'Wrong/uncertain phase; do not repeat')
        peer,peer_hash=document(peer_path,65536);peer_contract(local,peer,peer_kind)
        if phase in ('release-a','survive-release-b'):
            need(peer['written']==journal['written'],'Peer checked another A write')
            need(peer.get('baseContentVerified') is True,'Peer lacks base checksum verification')
        before=runtime.observe(sid)
        need(before['fcIdentity']==binding['fcIdentity'] and before['imageConfigSha256']==binding['imageConfigSha256'],'Actual binding changed')
        intent={'phase':phase,'peerSha256':peer_hash,'startedNs':time.time_ns()}
        journal['pending']=intent
        module.save(journal_path,journal)
        try:
            result={**local,'kind':end,'sharedBaseRetired':False,'baseChecksumVerificationPending':True,
                    'controllerSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    'peerReceiptSha256':runtime.pair.fingerprint(peer),
                    'readyReceiptSha256':runtime.pair.fingerprint(local),
                    'readyReportSha256':runtime.pair.fingerprint(report),
                    'coreCommit':runtime.deploy.CORE_COMMIT,'binaries':runtime.binaries,
                    'serverIdentity':runtime.server,'unit':runtime.m.UNIT,
                    'apiPort':runtime.definition['apiPort'],'bindingEvidence':before,
                    'boundReplicas':runtime.index['replicas']}
            if phase=='write-a':
                value=command(runtime,sid,'a-private-write',True)
                need(value['path']==local['base']['path'] and value['sha256']!=local['base']['sha256'],'A write did not change selected file')
                after=runtime.observe(sid);binding_stable(before,after);changed_upper(before['upper'],after['upper'])
                journal['written']=value;result.update(written=value,upperBefore=before['upper'],upperAfter=after['upper'])
            elif phase=='check-b':
                need(command(runtime,sid,'b-after-a-write')==local['base'],'B observed A modified value')
                binding_stable(before,runtime.observe(sid))
                verified=verify_base(runtime)
                journal.update(written=peer['written'],baseVerification=verified)
                result.update(written=peer['written'],baseVerification=verified,baseContentVerified=True,baseChecksumVerificationPending=False)
            elif phase=='release-a':
                result.update(written=journal['written'],baseContentVerified=True,baseVerification=peer['baseVerification'],baseChecksumVerificationPending=False)
                result.update(release_guest(runtime,sid,binding))
            else:
                trace_before=traced(runtime,before,time.monotonic_ns())
                need(command(runtime,sid,'b-after-a-exit')==local['base'],'B content changed after A exit')
                after=runtime.observe(sid);binding_stable(before,after);trace_after=traced(runtime,after,time.monotonic_ns())
                delta=new_backend_reads(trace_before,trace_after)
                need(peer['baseVerification']==journal['baseVerification'],'Base verification chain differs')
                result.update(written=peer['written'],beforePostExitRead=trace_before,afterPeerExitRead=trace_after,newBackendRequests=delta,
                              baseContentVerified=True,baseVerification=journal['baseVerification'],baseChecksumVerificationPending=False)
                result.update(release_guest(runtime,sid,binding))
            runtime.guard()
            module.save(WORK/(end+'-receipt.json'),result)
            journal['events'].append({'phase':phase,'finishedNs':time.time_ns()});journal['phase']=end;del journal['pending']
            module.save(journal_path,journal)
            return {'status':'DIRECT_UB_PAIR_PHASE_COMPLETED','phase':phase,'receipt':result,
                    'twoNodeFinalAcceptance':False,'scope':'final pair aggregation still required; shared bases retained for comparison'}
        except Exception as error:
            journal['phase']=start;journal['pending']=intent
            journal['error']={'type':type(error).__name__,'reason':str(error)[:1000]}
            module.save(journal_path,journal)
            return {'status':'STOPPED_DIRECT_UB_PAIR_PHASE_PRESERVE_STATE','phase':phase,'error':journal['error'],
                    'pending':journal['pending'],'automaticCleanup':False,'providerRetained':True}
    finally:os.close(lock)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=('write-a','check-b','release-a','survive-release-b'))
    parser.add_argument('--peer',type=Path,required=True);parser.add_argument('--run',action='store_true');args=parser.parse_args()
    if not args.run:print(json.dumps({'status':'PLAN_ONLY','phase':args.phase,'remoteExecution':False}));return 0
    report=run(args.phase,args.peer)
    print('BEGIN_DIRECT_UB_PAIR_PHASE_REPORT');print(json.dumps(report,indent=2));print('END_DIRECT_UB_PAIR_PHASE_REPORT')
    return 0 if report['status']=='DIRECT_UB_PAIR_PHASE_COMPLETED' else 1

if __name__=='__main__':
    try:code=main()
    except Exception as error:
        print(json.dumps({'status':'STOPPED_DIRECT_UB_PAIR_PREFLIGHT','type':type(error).__name__,'reason':str(error)[:1000],'automaticCleanup':False}));code=1
    raise SystemExit(code)
