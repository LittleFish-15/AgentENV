"""Retire the known disposable 64MiB generation with B's SDK lock fenced.

The user runs this on A. It contacts only the configured B over authenticated
SSH, never probes a network range. No SDK allocation, new Guest, permissions or
old-service restart. Only the pinned legacy publisher can delete its own object.
An uncertain retirement is preserved and must be reconciled, never resent.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

ROOT=Path('/home/jwk/agent')
SELF=ROOT/'legacy_provider_handoff.py'
A_WORK=ROOT/'r/legacy-a-v4'
B_WORK=ROOT/'r/legacy-b-v4'
A_PROVIDER=ROOT/'r/pm-a-v1/native-session/provider'
B_PROVIDER=ROOT/'r/pm-b-v1/pair-v1/provider'
OLD_SHA='7dd6d01e04adb7506b35ccca850d57f6cf21d086cb3615f4f6b109cf041e3640'
OLD_SCRIPT_SHA='ac0d70cf685fc9c87e73901703e29d34dd91dc0473b3d2814a27c2efba2cab2b'
NEXT_ENTRY_SHA='8a903602d647ecfef0d1ce775b10140048e740793c8c4e99950ad2c08c7c51d2'


def need(ok,reason):
    if not ok:raise RuntimeError(reason)


def canonical(value):return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()


def read(path):
    path=Path(path);need(path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Receipt path redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204 and 0<before.st_size<=1024**2,'Unexpected receipt')
        data=stream.read(1024**2+1);after=os.fstat(stream.fileno())
    stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(stamp(before)==stamp(after) and len(data)==before.st_size,'Receipt changed')
    return json.loads(data)


def save(path,value):
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    with temporary.open('xb') as stream:stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)


def account(node):
    need(sys.platform=='linux' and socket.gethostname()==('server1' if node=='node-a' else 'agent1'),'Use intended node')
    need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Use ordinary experiment user')
    fields=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)
    need(all(int(fields[k].strip(),16)==0 for k in ('CapInh','CapPrm','CapEff','CapAmb')),'Zero capabilities required')
    need(ROOT.resolve(strict=True)==ROOT and ROOT.stat().st_uid==1204,'Workspace changed')
    os.umask(0o077)


def lock_sdk(node):
    import fcntl
    path=ROOT/'relay'/('ub-layer-sdk-'+node+'.lock')
    need(path.resolve(strict=True)==path,'Existing SDK lock required')
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        meta=os.fstat(fd);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1,'SDK lock identity differs')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return fd
    except BaseException:os.close(fd);raise


def next_ready(node):
    session=ROOT/('r/up-a-v4' if node=='node-a' else 'r/up-b-v4')
    path=session/'provider-entry.py'
    need(path.resolve(strict=True)==path and path.stat().st_uid==1204 and 0<path.stat().st_size<=512*1024,
         'Prepare the next real-rootfs provider before retiring the old test object')
    raw=path.read_bytes();need(hashlib.sha256(raw).hexdigest()==NEXT_ENTRY_SHA,'Next provider release is not the reviewed candidate')
    scope={'__name__':'verified_next_provider','__file__':str(path)}
    exec(compile(raw,str(path),'exec'),scope)
    # This only checks fixed sources, compiled adapter and installed SDK hashes;
    # it does not construct an SDK backend or call serve.
    _,_,report=scope['prepared'](node)
    need(report.get('role')==('publish' if node=='node-a' else 'import'),'Wrong next provider role')
    return report


def validate_manifest(value):
    need(digest(value)==OLD_SHA and value.get('version')==1 and value.get('mode')=='pmem'
         and value.get('readers')==['node-b'] and len(value.get('replicas',[]))==1,'Only pinned legacy generation is in scope')
    replica=value['replicas'][0]
    need(replica['mappingBytes']==67108864 and replica['identity']['bytes']==67108864,'Only the old 64MiB test object is in scope')


def validate_b_release(manifest,state,receipt):
    validate_manifest(manifest)
    expected={'version':1,'ownerId':manifest['ownerId'],'readerId':'node-b','manifestSha256':'sha256:'+OLD_SHA,'state':'released'}
    need(receipt==expected and state.get('state')=='released' and state.get('objects')==[]
         and state.get('ownerId')==manifest['ownerId'] and state.get('manifestSha256')=='sha256:'+OLD_SHA
         and state.get('finalize_acknowledged') is True and state.get('base_post_sha256_verified') is True,
         'Latest B pair import is not explicitly released')


def validate_a_release(manifest,state):
    validate_manifest(manifest)
    objects=state.get('objects',[])
    need(state.get('state')=='released' and state.get('ownerId')==manifest['ownerId']
         and state.get('manifestSha256')=='sha256:'+OLD_SHA and len(objects)==1
         and state.get('finalize_acknowledged') is True and state.get('base_post_sha256_verified') is True,
         'Legacy owner release/finalization/integrity is incomplete')
    need(objects[0].get('replica')==manifest['replicas'][0] and objects[0].get('creation_confirmed') is True
         and objects[0].get('delete_acknowledged') is True,'Owned deletion acknowledgement missing')


def validate_a_serving(manifest,state):
    validate_manifest(manifest)
    objects=state.get('objects',[])
    need(state.get('state')=='serving' and state.get('ownerId')==manifest['ownerId']
         and state.get('manifestSha256')=='sha256:'+OLD_SHA and len(objects)==1
         and objects[0].get('replica')==manifest['replicas'][0]
         and objects[0].get('creation_confirmed') is True and objects[0].get('delete_acknowledged') is False,
         'Legacy owner is not confirmed unchanged and serving')


def send(stream,value):
    data=canonical(value);need(len(data)<=65536,'Oversized handoff message');stream.sendall(struct.pack('>I',len(data))+data)


def receive(stream):
    def exact(n):
        data=b''
        while len(data)<n:
            part=stream.recv(n-len(data));need(bool(part),'Handoff peer closed');data+=part
        return data
    size=struct.unpack('>I',exact(4))[0];need(0<size<=65536,'Oversized handoff response')
    return json.loads(exact(size))


def same_uid(stream):
    _,uid,_=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));need(uid==1204,'Unexpected control peer')


def apply_fence_request(state,request,manifest):
    need(request.get('nonce')==state['nonce'],'Wrong transition nonce')
    operation=request.get('operation')
    if operation=='status':return state,False
    if operation=='authorize':
        need(state['phase'] in ('fenced','authorized'),'Fence is not available for retirement')
        return dict(state,phase='authorized'),False
    if operation=='complete':
        need(state['phase'] in ('authorized','complete'),'No authorized retirement to complete')
        validate_a_release(manifest,request['ownerState'])
        return dict(state,phase='complete',ownerStateSha256=digest(request['ownerState'])),True
    if operation=='cancel':
        need(state['phase']=='fenced','Cannot cancel after retirement authorization; reconcile A first')
        return dict(state,phase='cancelled'),True
    if operation=='declined':
        need(state['phase']=='authorized' and request.get('retireReply',{}).get('state')=='refused','No explicit refusal to reconcile')
        validate_a_serving(manifest,request['ownerState'])
        return dict(state,phase='cancelled',reason='legacy_refused'),True
    raise RuntimeError('Unknown fence operation')


def fence_worker(nonce):
    account('node-b');need(re.fullmatch('[0-9a-f]{32}',nonce),'Invalid transition nonce')
    need(not B_WORK.exists() and B_WORK.parent.resolve(strict=True)==B_WORK.parent,'Prior B fence preserved')
    candidate=next_ready('node-b')
    sdk=lock_sdk('node-b')
    try:
        manifest=read(B_PROVIDER/'replicas.json');receipt=read(B_PROVIDER/'release.json');owner=read(B_PROVIDER/'owner.json')
        validate_b_release(manifest,owner,receipt)
        B_WORK.mkdir(mode=0o700)
        state={'version':1,'nonce':nonce,'phase':'fenced','manifest':manifest,'release':receipt,'ownerState':owner,
               'nextContentIdentity':candidate['contentIdentity'],
               'pid':os.getpid(),'startTicks':Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19],
               'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'SDK_called':False}
        save(B_WORK/'state.json',state)
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(B_WORK/'control.sock'));os.chmod(B_WORK/'control.sock',0o600);listener.listen(2)
            while True:
                stream,_=listener.accept()
                terminal=False
                with stream:
                    stream.settimeout(15)
                    try:
                        same_uid(stream);request=receive(stream)
                        updated,done=apply_fence_request(state,request,manifest)
                        save(B_WORK/'state.json',updated);state=updated
                        terminal=done
                        send(stream,state)
                    except Exception as error:
                        try:send(stream,{'phase':'refused','reason':str(error)[:500]})
                        except OSError:pass
                if terminal:return
    finally:os.close(sdk)


def b_command(operation,nonce,expected_sha):
    account('node-b')
    need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==expected_sha,'Remote handoff helper differs')
    if operation=='start':
        need(not B_WORK.exists(),'Prior B transition preserved; use status/resume')
        log=ROOT/'relay'/('legacy-b-v4-'+nonce+'.log')
        with log.open('xb') as output:
            child=subprocess.Popen(['/usr/bin/python3','-I','-B',str(SELF),'worker-b','--nonce',nonce,'--run'],
                stdin=subprocess.DEVNULL,stdout=output,stderr=output,start_new_session=True)
        for _ in range(100):
            need(child.poll() is None,'B fence exited; inspect its bounded local log')
            if (B_WORK/'control.sock').exists():break
            time.sleep(.1)
        else:raise RuntimeError('B fence did not become ready; preserve its process and journal')
        operation='status'
    request={'operation':operation,'nonce':nonce}
    if operation in ('complete','declined'):
        data=sys.stdin.buffer.read(65537);need(len(data)<=65536,'Oversized completion receipt')
        payload=json.loads(data)
        if operation=='complete':request['ownerState']=payload
        else:
            request['ownerState']=payload['ownerState'];request['retireReply']=payload['retireReply']
    prior=read(B_WORK/'state.json')
    if prior['phase']=='complete' and operation in ('status','complete'):
        need(prior['nonce']==nonce,'Transition nonce differs')
        if operation=='complete':
            validate_a_release(prior['manifest'],request['ownerState'])
            need(digest(request['ownerState'])==prior['ownerStateSha256'],'Completed receipt differs')
        return prior
    if prior['phase']=='cancelled' and operation=='declined':
        need(prior['nonce']==nonce and prior.get('reason')=='legacy_refused','Different cancelled transition')
        validate_a_serving(prior['manifest'],request['ownerState'])
        need(request['retireReply'].get('state')=='refused','Explicit refusal required')
        return prior
    need(prior['phase'] in ('fenced','authorized') and prior['nonce']==nonce,'B fence state differs')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==prior['boot'],'B fence boot changed')
    need(Path('/proc/'+str(prior['pid'])+'/stat').read_text().rsplit(')',1)[1].split()[19]==prior['startTicks'],'B fence process changed')
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(20);stream.connect(str(B_WORK/'control.sock'));same_uid(stream);send(stream,request);reply=receive(stream)
    if reply.get('phase') in ('complete','cancelled'):
        for _ in range(100):
            try:
                fd=lock_sdk('node-b');os.close(fd);break
            except BlockingIOError:time.sleep(.05)
        else:raise RuntimeError('B fence has not released SDK lock; do not start new SDK work')
    return reply


def remote(operation,nonce,owner=None):
    pin=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    # All remote argv fields are fixed words or validated hex; no user strings
    # are interpolated into a remote shell command.
    command=['/usr/bin/ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','jwk@agent1',
             '/usr/bin/python3','-I','-B',str(SELF),'control-b','--operation',operation,'--nonce',nonce,'--expected-sha',pin,'--run']
    result=subprocess.run(command,input=canonical(owner) if owner is not None else b'',capture_output=True,timeout=30)
    need(result.returncode==0 and len(result.stdout)<=65536,'B fence command failed; logs withheld, no retirement retry')
    return json.loads(result.stdout)


def finish_a(state,manifest):
    # Holding this exact shared SDK mutex proves the old publisher finished
    # finalization and left its critical section; no new SDK calls are made.
    sdk=lock_sdk('node-a')
    try:
        owner=read(A_PROVIDER/'owner.json');validate_a_release(manifest,owner)
        save(A_WORK/'owner-release.json',owner)
        reply=remote('complete',state['nonce'],owner)
        need(reply.get('phase')=='complete' and reply.get('nonce')==state['nonce'],'B completion unconfirmed')
        state.update(phase='complete',ownerStateSha256=digest(owner),B_fence_complete=True)
        save(A_WORK/'state.json',state)
        return {'status':'LEGACY_OWNED_GENERATION_RETIRED_SDK_LOCKS_AVAILABLE','nonce':state['nonce'],
                'SDK_called_by_this_process':False,'SDK_cleanup_called_by_legacy_owner':True,
                'deletedLogicalBytes':67108864,'newAllocationPerformed':False,'servicesRestarted':False}
    finally:os.close(sdk)


def transition_a(resume=False):
    account('node-a');manifest=read(A_PROVIDER/'replicas.json');validate_manifest(manifest)
    if resume:
        state=read(A_WORK/'state.json')
        need(state['phase'] in ('preparing','retire_intent','retire_acknowledged','retire_refused','complete'),'Only recorded retirement can be reconciled')
        if state['phase']=='retire_refused':return finish_refusal(state,manifest)
        if state['phase']=='complete':
            validate_a_release(manifest,read(A_WORK/'owner-release.json'))
            return {'status':'LEGACY_GENERATION_PREVIOUSLY_RETIRED_LOCK_AVAILABILITY_NOT_RECHECKED',
                    'nonce':state['nonce'],'newAllocationPerformed':False,'retireResent':False}
        if state['phase']!='preparing':return finish_a(state,manifest) # Never resends retire.
    else:
        need(not A_WORK.exists() and A_WORK.parent.resolve(strict=True)==A_WORK.parent,'Existing A transition preserved; use resume-a')
    need(hashlib.sha256((ROOT/'native_pmem_provider.py').read_bytes()).hexdigest()==OLD_SCRIPT_SHA,'Legacy publisher script differs')
    owner=read(A_PROVIDER/'owner.json')
    validate_a_serving(manifest,owner)
    candidate=next_ready('node-a')
    if not resume:
        A_WORK.mkdir(mode=0o700);state={'version':1,'nonce':uuid.uuid4().hex,'phase':'preparing','manifestSha256':OLD_SHA,
                                      'nextContentIdentity':candidate['contentIdentity']}
        save(A_WORK/'state.json',state)
    proof=remote('status' if resume else 'start',state['nonce'])
    need(proof.get('phase') in ('fenced','authorized'),'B is not fenced')
    validate_b_release(manifest,read_owner_from_proof(proof),proof['release'])
    need(proof['manifest']==manifest and proof['nonce']==state['nonce'],'B generation/transition differs')
    need(proof.get('nextContentIdentity')==candidate['contentIdentity'],'A and B prepared different next rootfs content')
    # The remote worker retains the SDK mutex while the receipt travels.
    peer_path=A_WORK/'b-release.json';save(peer_path,proof['release'])
    proof=remote('authorize',state['nonce']);need(proof.get('phase')=='authorized','B authorization not confirmed')
    state['phase']='retire_intent';save(A_WORK/'state.json',state)
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(120);stream.connect(str(A_PROVIDER/'control.sock'));same_uid(stream)
        send(stream,{'operation':'retire','peerReceipts':[str(peer_path)]})
        result=receive(stream)
    if result.get('state')=='refused':
        state.update(phase='retire_refused',retireReply=result);save(A_WORK/'state.json',state)
        return finish_refusal(state,manifest)
    need(result=={'state':'released'},'Legacy retirement refused/unconfirmed; B fence retained for reconciliation')
    state['phase']='retire_acknowledged';save(A_WORK/'state.json',state)
    for _ in range(100):
        try:return finish_a(state,manifest)
        except BlockingIOError:time.sleep(.1)
    raise RuntimeError('A publisher has not released its SDK lock; B fence retained')


def read_owner_from_proof(proof):
    # The actual owner journal is carried by the lock-holding worker.
    return proof['ownerState']


def finish_refusal(state,manifest):
    owner=read(A_PROVIDER/'owner.json');validate_a_serving(manifest,owner)
    reply=remote('declined',state['nonce'],{'ownerState':owner,'retireReply':state['retireReply']})
    need(reply.get('phase')=='cancelled' and reply.get('reason')=='legacy_refused','B refusal reconciliation is incomplete')
    state['B_fence_cancelled']=True;save(A_WORK/'state.json',state)
    return {'status':'LEGACY_RETIREMENT_REFUSED_OLD_OWNER_PRESERVED','nonce':state['nonce'],
            'retireReply':state['retireReply'],'B_fence_cancelled':True,'newAllocationPerformed':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('transition-a','resume-a','worker-b','control-b'))
    parser.add_argument('--nonce');parser.add_argument('--operation',choices=('start','status','authorize','complete','cancel','declined'))
    parser.add_argument('--expected-sha');parser.add_argument('--run',action='store_true');args=parser.parse_args()
    if not args.run:print(json.dumps({'status':'PLAN_ONLY','mode':args.mode,'SDK_called':False}));return 0
    if args.mode in ('transition-a','resume-a'):result=transition_a(args.mode=='resume-a')
    else:
        need(re.fullmatch('[0-9a-f]{32}',args.nonce or ''),'Explicit transition nonce required')
        if args.mode=='worker-b':fence_worker(args.nonce);return 0
        need(re.fullmatch('[0-9a-f]{64}',args.expected_sha or '') and args.operation,'Pinned remote helper required')
        result=b_command(args.operation,args.nonce,args.expected_sha)
    print(json.dumps(result))
    if args.mode in ('transition-a','resume-a'):
        return 0 if result['status'] in ('LEGACY_OWNED_GENERATION_RETIRED_SDK_LOCKS_AVAILABLE',
             'LEGACY_GENERATION_PREVIOUSLY_RETIRED_LOCK_AVAILABILITY_NOT_RECHECKED') else 1
    return 1 if result.get('phase')=='refused' else 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED_LEGACY_HANDOFF_PRESERVE_JOURNALS_AND_FENCE','errorType':type(error).__name__,
                          'reason':str(error)[:800],'newAllocationPerformed':False}));raise SystemExit(1)
