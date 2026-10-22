"""Stop this experiment and explicitly release B before A. Preserve all evidence."""
import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import select
import shlex
import signal
import socket
import stat
import subprocess
import time
import uuid

ROOT=Path('/home/jwk/agent')
H=ROOT/'lazy-four'
WORK=ROOT/'r/lazy-four-rollout-v1'
D=ROOT/'deployments/agentenv-lazy-four-32ce41c'
ENTRY_SHA='4f39e88e30c342c8f270fe01d8b2e0f80181d40289e83489ad4ba2f2d69efc7b'
A_SCOPE_SHA='5ad512921795a7ff9c3f6c601b1a1c59f05db170a4018007d69395d61cc30f60'


def need(ok,message):
    if not ok:raise RuntimeError(message)


def read(path,owner=1204,limit=16*1024**2):
    need(path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Unexpected cleanup evidence path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==owner and before.st_size<=limit,'Unexpected cleanup input')
        if owner==0:
            need(not before.st_mode&0o022 and before.st_nlink in (1,2),'Root acknowledgement is writable or unexpectedly linked')
        raw=stream.read(limit+1);after=os.fstat(stream.fileno())
    need(len(raw)<=limit and (before.st_ino,before.st_size,before.st_mtime_ns)==
         (after.st_ino,after.st_size,after.st_mtime_ns),'Cleanup input changed')
    return raw


def ticks(pid):
    return Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]


def unit_state(unit):
    r=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,MainPID,User,Group'],
                     capture_output=True,text=True,timeout=15)
    value=dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
    need(r.returncode==0 or value.get('LoadState')=='not-found','Cannot read exact experiment unit')
    return value


def validate_a_ack(value,nonce,sequence,operation):
    expected={'runtime-stop':'own-runtime-and-proxy-stopped','finish':'supervision-completed'}
    need(operation in expected and value.get('status')=='ROOT_OPERATION_COMPLETED'
         and value.get('nonce')==nonce and value.get('sequence')==sequence and value.get('operation')==operation
         and value.get('result',{}).get('state')==expected[operation],
         'Fresh root cleanup acknowledgement differs or failed; preserve remaining state')


def recovered_a_request(operation):
    """Ignore re-owned ready.json. Accept only new root-owned cleanup replies.

    The exact scope digest and last completed sequence were returned by the
    operator. Neither the contents nor the PID of A's ready file authorize an
    operation. This code never changes ownership or relaxes root reply checks.
    """
    import fcntl
    need(operation in ('runtime-stop','finish') and os.getuid()==os.geteuid()==1204
         and socket.gethostname()=='server1','Only A cleanup operations are allowed')
    raw=read(WORK/'root-scope.json')
    need(hashlib.sha256(raw).hexdigest()==A_SCOPE_SHA,'Previously reviewed A supervision scope changed')
    scope=json.loads(raw)
    need(scope['node']=='node-a' and scope['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
         'A node or boot changed')
    mailbox=WORK/'root-mailbox'
    need(mailbox.resolve(strict=True)==mailbox and mailbox.stat().st_uid==1204,'Unexpected cleanup mailbox')
    lock=os.open(mailbox/'channel.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        meta=os.fstat(lock);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1,'Unexpected channel mutex')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        previous=json.loads(read(mailbox/'client-state.json'))
        expected_previous=632 if operation=='runtime-stop' else 633
        need(previous=={'completed':expected_previous},'Root request sequence advanced or is uncertain; do not replay')
        if operation=='finish':
            prior=json.loads(read(mailbox/'0633.reply.json',owner=0,limit=65536))
            validate_a_ack(prior,scope['nonce'],633,'runtime-stop')
        sequence=expected_previous+1
        request=mailbox/f'{sequence:04d}.request.json'
        response=mailbox/f'{sequence:04d}.reply.json'
        need(not request.exists() and not request.is_symlink() and not response.exists() and not response.is_symlink(),
             'Prior request/reply exists; no resend')
        def atomic(path,value):
            temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
            with temporary.open('x') as output:
                json.dump(value,output);output.flush();os.fsync(output.fileno())
            os.replace(temporary,path)
        atomic(request,{'nonce':scope['nonce'],'sequence':sequence,'operation':operation})
        deadline=time.monotonic()+240
        while not response.exists():
            need(time.monotonic()<deadline,'Root cleanup acknowledgement pending; retain request, do not resend')
            time.sleep(.5)
        # A user-owned historical receipt is never accepted as new root proof.
        value=json.loads(read(response,owner=0,limit=65536))
        validate_a_ack(value,scope['nonce'],sequence,operation)
        atomic(mailbox/'client-state.json',{'completed':sequence})
        return value
    finally:os.close(lock)


def inspect_node(node):
    need(os.getuid()==os.geteuid()==1204 and socket.gethostname()==('server1' if node=='node-a' else 'agent1'),
         'Use declared ordinary jwk node')
    report=json.loads(read(WORK/('lazy-'+node+'.json')))
    state=json.loads(read(D/'cohort-state.json'))
    need(report.get('ownedGuestsReleased') is True and report.get('outcomeUncertain') is False
         and report.get('remainingSandboxIds')==[] and state.get('phase')=='quiesced'
         and state.get('sandboxIds')==state.get('openRequests')==[] and state.get('outcomeUncertain') is False
         and state.get('fourRunId')==report.get('runId'),'Guest cleanup not confirmed; no forced termination')
    session=ROOT/('r/lazy4-a-v1' if node=='node-a' else 'r/lazy4-b-v1')
    owner=json.loads(read(session/'provider/owner.json'))
    reference=report['admissionSample']['provider']
    need(owner.get('cacheId')==reference['cacheId'] and owner.get('pool')==reference['pool']
         and owner.get('role')==('publish' if node=='node-a' else 'import'),'Provider is not this measured generation')
    runtime=unit_state('jwk-aenv-lazy-four-32ce41c-'+node+'.service')
    if runtime.get('ActiveState')=='active':
        pid=int(runtime['MainPID'])
        need(runtime.get('User')==runtime.get('Group')=='jwk' and pid==report['context']['runtimePid']
             and ticks(pid)==report['context']['runtimeTicks'],'Measured Runtime identity changed')
    else:need(runtime.get('MainPID')=='0','Unexpected remaining Runtime process')
    if node=='node-a':
        raw=read(WORK/'root-scope.json')
        need(hashlib.sha256(raw).hexdigest()==A_SCOPE_SHA,'Previously reviewed A root scope changed')
        root_pid=root_ticks=None # Do not trust the PID in a re-owned ready file.
    else:
        ready=json.loads(read(WORK/'root-mailbox/ready.json',0))
        scope=json.loads(read(WORK/'root-scope.json'))
        need(ready['nonce']==scope['nonce'],'Root supervisor identity differs')
        root_pid=ready['pid']
        try:root_ticks=ticks(root_pid)
        except FileNotFoundError:root_ticks=None
    return {'node':node,'guestsReleased':True,'runtime':runtime,
            'providerUnit':unit_state('jwk-ub-lazy-four-'+node+'-v1.service'),
            'provider':{k:owner.get(k) for k in ('state','cacheId','pool','role','deleteAcknowledged','finalizeAcknowledged')},
            'rootPid':root_pid,'rootTicks':root_ticks,'metadataSocketPresent':(session/'metadata.sock').exists()}


def validate_pair(a,b):
    need(a['guestsReleased'] and b['guestsReleased'] and a['provider']['cacheId']==b['provider']['cacheId']
         and a['provider']['pool']==b['provider']['pool'],'Nodes do not identify the same owned pool')
    need(a['provider']['state']==b['provider']['state']=='serving','Expected the preserved serving generation; inspect partial cleanup before retry')


def released(value,node):
    p=value['provider']
    return p.get('state')=='released' and p.get('finalizeAcknowledged') is True and (node=='node-b' or p.get('deleteAcknowledged') is True)


def coordinator():
    path=H/'lazy_four_rollout.py';raw=read(path)
    need(hashlib.sha256(raw).hexdigest()==ENTRY_SHA,'Use the exact measured coordinator')
    scope={'__name__':'verified_cleanup_transport','__file__':str(path)}
    exec(compile(raw,str(path),'exec'),scope)
    for name in ('lazy_four_provider.py','lazy_four_root_client.py','lazy_four_transport.py'):
        need(hashlib.sha256(read(H/name)).hexdigest()==scope['PUBLIC_PINS'][name],'Measured cleanup helper changed')
    original=scope['root_command']
    scope['root_command']=lambda node,operation: recovered_a_request(operation) if node=='node-a' else original(node,operation)
    return scope


def remote_inspect(scope):
    functions=(need,read,ticks,unit_state,inspect_node)
    code="import hashlib,json,os,socket,stat,subprocess\nfrom pathlib import Path\nROOT=Path('/home/jwk/agent');WORK=ROOT/'r/lazy-four-rollout-v1';D=ROOT/'deployments/agentenv-lazy-four-32ce41c'\n"
    code+='\n\n'.join(inspect.getsource(fn) for fn in functions)
    code+="\nprint(json.dumps(inspect_node('node-b')))\n"
    result=subprocess.run(scope['SSH']+[shlex.join(['/usr/bin/python3','-I','-B','-c',code])],
                          stdin=subprocess.DEVNULL,capture_output=True,timeout=90)
    need(result.returncode==0 and len(result.stdout)<=65536,'B current cleanup evidence unavailable; do not guess')
    return json.loads(result.stdout)


def stop_metadata(scope):
    receipt=json.loads(read(WORK/'metadata-transport.json'))
    pid=receipt['pid'];need(type(pid) is int and pid>1,'Invalid owned transport PID')
    need(receipt['scriptSha256']==scope['PUBLIC_PINS']['lazy_four_transport.py'],'Recorded metadata helper differs')
    try:handle=os.pidfd_open(pid)
    except ProcessLookupError:return {'leaderAlreadyExited':True,'unknownProcessesSignalled':False}
    try:
        proc=Path('/proc',str(pid))
        need(ticks(pid)==receipt['startTicks'],'Transport PID reused; no signal')
        need(proc.stat().st_uid==1204 and (proc/'cmdline').read_bytes().split(b'\0')==
             [b'/usr/bin/python3',b'-I',b'-B',os.fsencode(H/'lazy_four_transport.py'),b'owner-a',b''],
             'Transport command differs; no signal')
        children=(proc/'task'/str(pid)/'children').read_text().split()
        need(len(children)<=1,'Unexpected transport child processes; preserved')
        signalled=[]
        for child in children:
            child_pid=int(child);child_fd=os.pidfd_open(child_pid)
            try:
                child_proc=Path('/proc',child)
                parent=int((child_proc/'stat').read_text().rsplit(')',1)[1].split()[1])
                args=[os.fsdecode(x) for x in (child_proc/'cmdline').read_bytes().split(b'\0') if x]
                need(parent==pid and child_proc.stat().st_uid==1204 and args[:-1]==scope['SSH']
                     and receipt['scriptSha256'] in args[-1] and str(H/'lazy_four_transport.py') in args[-1],
                     'Only the exact owned metadata SSH child may be stopped')
                signal.pidfd_send_signal(child_fd,signal.SIGTERM);signalled.append(child_pid)
                child_poll=select.poll();child_poll.register(child_fd,select.POLLIN)
                need(bool(child_poll.poll(10000)),'Owned SSH child exit unconfirmed; no forced kill')
            finally:os.close(child_fd)
        poll=select.poll();poll.register(handle,select.POLLIN)
        if not poll.poll(15000):
            signal.pidfd_send_signal(handle,signal.SIGTERM)
            need(bool(poll.poll(10000)),'Metadata leader exit unconfirmed; no forced kill')
        return {'ownedLeaderExited':True,'ownedSshChildrenSignalled':signalled,'unknownProcessesSignalled':False}
    finally:os.close(handle)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');args=p.parse_args()
    if not args.run:print('STOP_PLAN_ONLY');return
    need(os.getuid()==os.geteuid()==1204 and socket.gethostname()=='server1','Run on A as ordinary jwk')
    os.umask(0o077)
    scope=coordinator();a,b=inspect_node('node-a'),remote_inspect(scope);validate_pair(a,b)
    path=WORK/'stop-and-release-v1.json'
    need(not path.exists() and not path.is_symlink(),'Prior cleanup receipt exists; do not blindly resend operations')
    result={'status':'STOPPING_OWN_EXPERIMENT','before':{'A':a,'B':b},'steps':[],
            'furtherTestsRequested':False,'reportsAndSnapshotsPreserved':True,'sshConfigurationPreserved':True}
    def save():scope['save'](path,result)
    def action(name,fn):
        row={'name':name,'state':'intent_recorded_before_action'};result['steps'].append(row);save()
        print('STOP_PHASE='+name,flush=True)
        value=fn();row.update(state='acknowledged',result=value);save();return value
    def retire(node):
        command=scope['remote_command'](['b-retire']) if node=='node-b' else ['/usr/bin/python3','-I','-B',str(H/'lazy_four_provider.py'),'retire','--node','node-a','--run']
        log=WORK/('stop-retire-'+node+'.log')
        with log.open('xb') as output:
            r=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,timeout=180)
        current=remote_inspect(scope) if node=='node-b' else inspect_node(node)
        need(r.returncode==0 and released(current,node),'Provider retirement unresolved; preserve metadata transport and inspect own log')
        return current['provider']
    try:
        save()
        action('stop-runtime-a',lambda:scope['root_command']('node-a','runtime-stop'))
        action('stop-runtime-b',lambda:scope['root_command']('node-b','runtime-stop'))
        action('release-b-reader',lambda:retire('node-b'))
        action('release-a-pool',lambda:retire('node-a'))
        action('finish-root-b',lambda:scope['root_command']('node-b','finish'))
        action('finish-root-a',lambda:scope['root_command']('node-a','finish'))
        action('stop-owned-metadata-transport',lambda:stop_metadata(scope))
        deadline=time.monotonic()+30
        while True:
            after={'A':inspect_node('node-a'),'B':remote_inspect(scope)}
            done=all(value['runtime'].get('MainPID')=='0' and value['providerUnit'].get('MainPID')=='0' for value in after.values())
            done=done and after['B']['rootTicks']!=result['before']['B']['rootTicks']
            if done and not after['B']['metadataSocketPresent']:break
            need(time.monotonic()<deadline,'Process exit is not yet confirmed; retain receipts')
            time.sleep(1)
        result.update(status='OWN_LAZY_EXPERIMENT_STOPPED_AND_UB_RELEASED',after=after,
                      aRootFinishProof='fresh root-owned sequence634 reply; re-owned ready PID not used as proof',
                      confirmation='Guest journals empty; own Runtime/provider processes exited; B finalized before A deletion; both root supervisors acknowledged finish')
        save()
    except BaseException as error:
        result.update(status='CLEANUP_STOPPED_PRESERVE_REMAINING_STATE',errorType=type(error).__name__,
                      reason=str(error)[:600] if isinstance(error,RuntimeError) else 'Inspect stop step receipts and logs')
        save()
        raise
    finally:
        print('BEGIN_OWN_LAZY_STOP_REPORT');print(json.dumps(result,indent=2));print('END_OWN_LAZY_STOP_REPORT')


if __name__=='__main__':main()
