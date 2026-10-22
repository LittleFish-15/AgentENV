"""Root-owned replies outside user-owned deployment trees; requests stay separate."""
import json
import os
from pathlib import Path
import re
import stat

RECEIPT_BASE = Path('/run/agentenv-lazy-four')


def receipt_directory(nonce):
    if not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{32}',nonce):
        raise RuntimeError('Invalid root receipt generation')
    return RECEIPT_BASE/nonce


def trusted_receipt_directory(directory):
    if directory.parent!=RECEIPT_BASE or receipt_directory(directory.name)!=directory:
        raise RuntimeError('Receipt outside exact generation')
    for path in (RECEIPT_BASE.parent,RECEIPT_BASE,directory):
        meta=path.lstat()
        if (path.resolve(strict=True)!=path or not stat.S_ISDIR(meta.st_mode)
                or meta.st_uid!=0 or stat.S_IMODE(meta.st_mode)&0o022
                or not stat.S_IMODE(meta.st_mode)&0o001):
            raise RuntimeError('Root receipt hierarchy is not root-owned and protected')


def create_receipt_directory(nonce):
    if os.geteuid()!=0:raise RuntimeError('Only root creates receipt generations')
    parent=RECEIPT_BASE.parent
    meta=parent.lstat()
    if parent.resolve(strict=True)!=parent or meta.st_uid!=0 or not stat.S_ISDIR(meta.st_mode) or stat.S_IMODE(meta.st_mode)&0o022:
        raise RuntimeError('Unexpected root receipt parent')
    try:
        RECEIPT_BASE.mkdir(mode=0o755)
        os.chmod(RECEIPT_BASE,0o755)  # Root's restrictive umask must not block the reader.
    except FileExistsError:pass
    base=RECEIPT_BASE.lstat()
    if RECEIPT_BASE.resolve(strict=True)!=RECEIPT_BASE or base.st_uid!=0 or not stat.S_ISDIR(base.st_mode) or stat.S_IMODE(base.st_mode)&0o022 or not stat.S_IMODE(base.st_mode)&0o001:
        raise RuntimeError('Unexpected root receipt base')
    directory=receipt_directory(nonce)
    directory.mkdir(mode=0o755)  # Never reuse an existing root session, even empty.
    os.chmod(directory,0o755)
    trusted_receipt_directory(directory)
    return directory


def read_root_receipt(path,nonce):
    directory=receipt_directory(nonce)
    if path.parent!=directory or not re.fullmatch(r'(ready|[0-9]{4,5}\.reply)\.json',path.name):
        raise RuntimeError('Unexpected root receipt name or generation')
    trusted_receipt_directory(directory)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink not in (1,2) or stat.S_IMODE(before.st_mode)&0o022 or before.st_size>1024**2:
            raise RuntimeError('Unexpected root receipt file')
        raw=stream.read(1024**2+1);after=os.fstat(stream.fileno())
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or len(raw)!=before.st_size:
        raise RuntimeError('Root receipt changed while reading')
    value=json.loads(raw)
    if not isinstance(value,dict) or value.get('nonce')!=nonce:raise RuntimeError('Root receipt nonce differs')
    return value


def validate_root_result(value,nonce,sequence,operation):
    if (value.get('nonce')!=nonce or value.get('sequence')!=sequence or value.get('operation')!=operation
            or value.get('status') not in ('ROOT_OPERATION_COMPLETED','ROOT_OPERATION_STOPPED_PRESERVE_STATE')):
        raise RuntimeError('Root operation outcome is unconfirmed; preserve request')
    return value['status']=='ROOT_OPERATION_COMPLETED'

"""Fixed-operation root supervisor for one prepared two-round experiment.

The operator starts this once per node with a pinned scope file. Requests are
enum operations, never shell text or source code. Services always run as jwk.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import subprocess
import time

ROOT=Path('/home/jwk/agent')
D=ROOT/'deployments/agentenv-lazy-four-32ce41c'
WORK=ROOT/'r/lazy-four-rollout-v2'
OPS=('runtime-off','runtime-stop','provider-start','runtime-lazy','observe','finish')


def need(ok,reason):
    if not ok:raise RuntimeError(reason)


def read(path,limit=2*1024**2,owner=1204):
    need(path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Redirected/out-of-scope supervisor input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==owner and before.st_nlink==1 and before.st_size<=limit,'Unexpected supervisor input')
        raw=stream.read(limit+1);after=os.fstat(stream.fileno())
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(raw)==before.st_size,'Supervisor input changed')
        return raw


def fields(unit):
    result=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,MainPID,User,Group,WorkingDirectory'],
                          capture_output=True,text=True,timeout=15)
    value=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    need(result.returncode==0 or value.get('LoadState')=='not-found','Cannot inspect exact unit')
    return value


def ticks(pid):
    return Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]


def service_identity(unit):
    value=fields(unit);pid=int(value.get('MainPID','0'))
    return [value.get('LoadState'),value.get('ActiveState'),pid,ticks(pid) if pid>1 else None]


def no_guests(port):
    state=json.loads(read(D/'cohort-state.json'))
    need(state.get('phase') in ('prepared','quiesced') and state.get('sandboxIds')==[]
         and state.get('openRequests')==[] and state.get('outcomeUncertain') is False,'Cohort not explicitly quiescent')
    key=read(D/'config/api-key',1024).decode().strip()
    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
    try:
        connection.request('GET','/v2/sandboxes?limit=1',headers={'X-API-Key':key})
        response=connection.getresponse();raw=response.read(65537)
        need(response.status==200 and len(raw)<=65536 and json.loads(raw)==[] and not response.getheader('X-Next-Token'),
             'Inventory nonempty or uncertain; service preserved')
    finally:connection.close()


def original_idle():
    # Read-only exclusion of a concurrent original Guest batch. Never stop it.
    key=read(ROOT/'deployments/agentenv-ae9c626-baseline/config/api-key',1024).decode().strip()
    connection=http.client.HTTPConnection('127.0.0.1',18080,timeout=10)
    try:
        connection.request('GET','/v2/sandboxes?limit=1',headers={'X-API-Key':key})
        response=connection.getresponse();raw=response.read(65537)
        need(response.status==200 and len(raw)<=65536 and json.loads(raw)==[] and not response.getheader('X-Next-Token'),
             'Original Guest batch is active/uncertain; do not overlap formal rounds')
    finally:connection.close()


def verify_pins(pins):
    need(isinstance(pins,dict) and 8<=len(pins)<=512,'Unexpected prepared input count')
    for name,pin in pins.items():
        path=Path(name)
        need(path.is_relative_to(D) or path.is_relative_to(ROOT/'r/lazy4-a-v2') or path.is_relative_to(ROOT/'r/lazy4-b-v2')
             or path in (ROOT/'lazy-four-v2/ram_observer.py',ROOT/'lazy-four-v2/four_runtime.py'),
             'Pin outside exact experiment')
        need(re.fullmatch('[0-9a-f]{64}',pin) and path.resolve(strict=True)==path,'Malformed/redirected pin')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            m=os.fstat(stream.fileno())
            need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_size<=512*1024**2,'Unexpected pinned input')
            need(hashlib.file_digest(stream,'sha256').hexdigest()==pin,'Prepared executable/input changed')
            after=os.fstat(stream.fileno())
            need((m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),
                 'Pinned input changed while checking')


def validate_request(value,nonce,sequence):
    need(set(value)=={'nonce','sequence','operation'} and value['nonce']==nonce and value['sequence']==sequence
         and value['operation'] in OPS,'Unexpected root operation; no arbitrary commands accepted')
    return value['operation']


class Supervisor:
    def __init__(self,scope):
        self.scope=scope;self.node=scope['node']
        need(self.node in ('node-a','node-b'),'Unexpected node')
        need(os.geteuid()==0 and socket.gethostname()==('server1' if self.node=='node-a' else 'agent1'),'Use intended root terminal')
        need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==scope['bootId'],'Boot changed')
        need(re.fullmatch('[0-9a-f]{32}',scope['nonce']),'Invalid supervision nonce')
        for name,number in (('jwk','1204'),):
            need(subprocess.check_output(['/usr/bin/id','-u',name],text=True).strip()==number,'User differs')
        need(subprocess.check_output(['/usr/bin/id','-g','jwk'],text=True).strip()=='1205','Group differs')
        for name,gid in (('kvm','36'),('aenv','982'),('ubsmd','984')):
            need(subprocess.check_output(['/usr/bin/getent','group',name],text=True).split(':')[2]==gid,'Required group differs')
        self.unit='jwk-aenv-lazy-four-32ce41c-'+self.node+'.service'
        self.provider_unit='jwk-ub-lazy-four-'+self.node+'-v2.service'
        self.session=ROOT/('r/lazy4-a-v2' if self.node=='node-a' else 'r/lazy4-b-v2')
        self.runtime=ROOT/('r/lazy-four-a-v1' if self.node=='node-a' else 'r/lazy-four-b-v1')
        self.expected_old={'jwk-aenv-ae9c626-'+self.node+'.service','jwk-aenv-ub-b019f27-'+self.node+'.service',
                           'jwk-aenv-native-fe63038-'+self.node+'.service','ubsmd.service','ubse.service'}
        need(set(scope['oldServices'])==self.expected_old,'Existing service scope incomplete')
        self.check_old()
        need(fields(self.unit).get('LoadState')=='not-found' and fields(self.provider_unit).get('LoadState')=='not-found',
             'Prior new unit preserved; supervisor cannot resume blindly')
        verify_pins(scope['pins'])
        definition=json.loads(read(D/'definition-native.json'))
        need(definition['node']==self.node and definition.get('rootfsBinding') is None,'Ordinary isolated service required')
        self.port=definition['apiPort'];need(type(self.port) is int and 18082<=self.port<=18089,'Unexpected API port')
        self.runtime_identity=None;self.provider_started=False;self.off_stopped=False;self.lazy_started=False

    def observe(self):
        import types
        need(self.runtime_identity is not None and service_identity(self.unit)==self.runtime_identity,'Own Runtime changed before observation')
        original_idle()
        modules=[]
        for name in ('ram_observer','four_runtime'):
            path=ROOT/'lazy-four'/(name+'.py');raw=read(path)
            need(hashlib.sha256(raw).hexdigest()==self.scope['pins'][str(path)],'Read-only observer changed')
            m=types.ModuleType('root_'+name);m.__file__=str(path)
            exec(compile(raw,str(path),'exec'),m.__dict__);modules.append(m)
        observer,rt=modules
        mode='lazy' if self.lazy_started else 'off'
        saved=json.loads(read(D/'four-cohort'/mode/'state.json'))
        need(saved['context']['runtimePid']==self.runtime_identity[2] and saved['context']['runtimeTicks']==self.runtime_identity[3]
             and saved['context']['bootId']==self.scope['bootId'] and set(saved['cases'])=={'0','1','2','3'},'Cohort process/scope changed')
        api=rt.Api(D,self.unit,self.port)
        seed_raw=read(D/'rootfs-inputs.json')
        need(hashlib.sha256(seed_raw).hexdigest()==self.scope['pins'][str(D/'rootfs-inputs.json')],'Seed receipt changed')
        seed=json.loads(seed_raw);rt.configure(self.node,mode,seed,observer)
        jobs=[]
        for index,case in saved['cases'].items():
            need(not case['openRequests'] and len(case['sandboxIds'])==2,'Exactly two acknowledged Guests per template required')
            for slot,sid in enumerate(case['sandboxIds']):
                need(re.fullmatch('[A-Za-z0-9_-]{1,128}',sid),'Invalid Guest ID')
                code,body=api.call('GET','/sandboxes/'+sid)
                need(code==200 and body.get('metadata',{}).get('cow_batch')==case['runId']
                     and body['metadata'].get('cow_four_index')==index,'Guest ownership changed')
                jobs.append({'sandboxId':sid,'templateIndex':int(index),'slot':slot})
        bindings=rt.verify_bindings(api,observer,D,jobs,seed,mode)
        ram=observer.collect_ram(D,api.pid,api.ticks,[j['sandboxId'] for j in jobs])
        provider=None
        if self.provider_started:
            p=fields(self.provider_unit);pid=int(p.get('MainPID','0'))
            need(p.get('ActiveState')=='active' and p.get('User')==p.get('Group')=='jwk' and pid>1,'Provider process changed')
            start=ticks(pid)
            provider={'pid':pid,'startTicks':start,'wholeProcess':observer.whole_process_metrics(pid,start)}
        return {'state':'scoped-readonly-observation','bindingEvidence':bindings,'ram':ram,
                'runtimeCharge':rt.cgroup_memory(api.cgroup),'providerProcess':provider,'noMemoryContentRead':True}

    def check_old(self):
        need(all(service_identity(unit)==state for unit,state in self.scope['oldServices'].items()),
             'Existing service changed; preserve experiment state')

    def start_runtime(self,lazy):
        need(self.runtime_identity is None and fields(self.unit).get('LoadState')=='not-found','Own Runtime already exists')
        need(not self.lazy_started and (self.off_stopped and self.provider_started if lazy else not self.off_stopped),
             'Unexpected round ordering')
        original_idle()
        verify_pins(self.scope['pins'])
        seed=json.loads(read(D/'rootfs-inputs.json'))
        need(seed['status']=='ORDINARY_FOUR_SNAPSHOTS_SEEDED_NOT_GUEST_ACCEPTANCE' and seed['node']==self.node
             and len(seed['templates'])==4,'Ordinary four-template seed required')
        for template in seed['templates']:
            need(re.fullmatch('[0-9a-f-]{36}',template['templateId']),'Invalid template ID')
            path=D/'state/snapshot-store/repository/catalog/records'/(template['templateId']+'.json')
            need(hashlib.sha256(read(path)).hexdigest()==template['catalogSha256'],'Snapshot record changed')
        arguments=['inside']
        if lazy:
            owner=json.loads(read(self.session/'provider/owner.json'))
            need(owner.get('state')=='serving' and owner.get('mode')=='stored-lazy','Lazy provider not serving')
            raw=read(self.session/'provider/runtime-index.json')
            value=json.loads(raw);need(value['version']==1 and value['state']=='ready' and value['replicas'],'Lazy index not ready')
            arguments=['inside-lazy',hashlib.sha256(raw).hexdigest()]
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            probe.bind(('127.0.0.1',self.port));probe.listen(1)
        command=['/usr/bin/systemd-run','--unit='+self.unit,'--collect','--property=Description=AgentENV ordinary/lazy four-template experiment',
            '--property=User=jwk','--property=Group=jwk','--property=SupplementaryGroups=kvm aenv',
            '--property=CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN','--property=AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN',
            '--property=NoNewPrivileges=yes','--property=RestrictSUIDSGID=yes','--property=PrivateNetwork=yes','--property=PrivateMounts=yes',
            '--property=Type=exec','--property=Restart=no','--property=KillMode=control-group','--property=TimeoutStopSec=90s',
            '--property=LimitNOFILE=65536','--property=LimitMEMLOCK=2147483648','--property=WorkingDirectory='+str(D),
            '--property=StandardOutput=null','--property=StandardError=null',
            '/usr/bin/python3','-I','-B',str(D/'libexec/lazy-v2/native_service.py'),*arguments]
        subprocess.run(command,check=True,timeout=30)
        state=service_identity(self.unit);need(state[1]=='active' and state[2]>1,'Own Runtime did not start')
        self.runtime_identity=state
        if lazy:self.lazy_started=True
        return {'state':'runtime-started','variant':'lazy' if lazy else 'off','unit':self.unit,'process':state}

    def stop_runtime(self):
        need(self.runtime_identity is not None and service_identity(self.unit)==self.runtime_identity,'Own Runtime identity changed')
        import fcntl
        lock=os.open(D/'cohort.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            m=os.fstat(lock);need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_nlink==1,'Unexpected cohort mutex')
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            no_guests(self.port)
            proxy=json.loads(read(self.runtime/'host-proxy.json'))
            pid=proxy['pid'];need(type(pid) is int and pid>1 and ticks(pid)==proxy['start_ticks'],'Proxy identity changed')
            proc=Path('/proc',str(pid));status=dict(x.split(':',1) for x in (proc/'status').read_text().splitlines() if ':' in x)
            need([int(x) for x in status['Uid'].split()]==[1204]*4
                 and all(int(status[x].strip(),16)==0 for x in ('CapInh','CapPrm','CapEff','CapAmb')),'Unexpected proxy privilege')
            need((proc/'cmdline').read_bytes().split(b'\0')==[b'/usr/bin/python3',b'-I',b'-B',
                 os.fsencode(D/'libexec/lazy-v2/native_service.py'),b'proxy-host',b''],'Unexpected proxy command')
            handle=os.pidfd_open(pid)
            try:
                need(ticks(pid)==proxy['start_ticks'],'Proxy changed after pidfd acquisition')
                subprocess.run(['/usr/bin/systemctl','stop',self.unit],check=True,timeout=120)
                deadline=time.monotonic()+15
                while fields(self.unit).get('LoadState')!='not-found' and time.monotonic()<deadline:time.sleep(.25)
                need(fields(self.unit).get('LoadState')=='not-found','Own Runtime stop/collection incomplete')
                signal.pidfd_send_signal(handle,signal.SIGTERM)
                poll=select.poll();poll.register(handle,select.POLLIN)
                need(bool(poll.poll(10000)),'Host proxy exit unconfirmed; no forced kill')
            finally:os.close(handle)
            self.runtime_identity=None;self.off_stopped=True
        finally:os.close(lock)
        return {'state':'own-runtime-and-proxy-stopped','otherServicesUnchanged':True}

    def start_provider(self):
        need(self.off_stopped and self.runtime_identity is None and not self.provider_started,'Provider starts only after baseline fully stops')
        verify_pins(self.scope['pins'])
        need(fields(self.provider_unit).get('LoadState')=='not-found' and not (self.session/'provider').exists(),'Prior provider generation preserved')
        command=['/usr/bin/systemd-run','--unit='+self.provider_unit,'--collect','--property=Description=Bounded lazy rootfs UB cache',
                 '--property=User=jwk','--property=Group=jwk','--property=SupplementaryGroups=ubsmd',
                 '--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=NoNewPrivileges=yes',
                 '--property=RestrictSUIDSGID=yes','--property=Type=exec','--property=Restart=no','--property=KillMode=control-group',
                 '--property=TimeoutStopSec=90s','--property=LimitNOFILE=4096','--property=LimitCORE=0','--property=LimitMEMLOCK=671088640',
                 '--property=MemoryMax=1610612736','--property=UMask=0077','--property=StandardOutput=null','--property=StandardError=null',
                 '/usr/bin/python3','-I','-B',str(self.session/'provider-entry.py'),'serve','--node',self.node,'--run']
        subprocess.run(command,check=True,timeout=30)
        self.provider_started=True
        return {'state':'provider-submitted','unit':self.provider_unit,'capabilities':0}

    def execute(self,operation):
        self.check_old()
        if operation=='runtime-off':result=self.start_runtime(False)
        elif operation=='runtime-lazy':result=self.start_runtime(True)
        elif operation=='runtime-stop':result=self.stop_runtime()
        elif operation=='provider-start':result=self.start_provider()
        elif operation=='observe':result=self.observe()
        else:
            need(self.runtime_identity is None,'Stop own Runtime before ending supervisor')
            if self.provider_started:
                journal=json.loads(read(self.session/'provider/owner.json'))
                need(journal.get('state')=='released' and journal.get('finalizeAcknowledged') is True,'Provider release unresolved')
            result={'state':'supervision-completed'}
        self.check_old()
        return result


def reply(path,value):
    trusted_receipt_directory(path.parent)
    need(not path.exists() and not path.is_symlink(),'Existing root receipt preserved')
    temporary=path.with_name(path.name+'.root-partial')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'w') as output:
        os.fchmod(output.fileno(),0o644)
        json.dump(value,output);output.flush();os.fsync(output.fileno())
    os.link(temporary,path) # Publish complete JSON without replacing an existing receipt.
    temporary.unlink()
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scope',type=Path,required=True);p.add_argument('--sha256',required=True)
    a=p.parse_args();raw=read(a.scope,262144)
    need(hashlib.sha256(raw).hexdigest()==a.sha256,'Reviewed root scope changed')
    scope=json.loads(raw);supervisor=Supervisor(scope)
    mailbox=WORK/'root-mailbox';need(mailbox.resolve(strict=True)==mailbox and mailbox.stat().st_uid==1204,'Unexpected mailbox')
    receipts=create_receipt_directory(scope['nonce'])
    reply(receipts/'ready.json',{'status':'LAZY_ROOT_SUPERVISOR_READY','nonce':scope['nonce'],'pid':os.getpid()})
    deadline=time.monotonic()+21600
    cleanup_only=False
    for sequence in range(1,10001):
        path=mailbox/f'{sequence:04d}.request.json'
        last=time.monotonic()
        while not path.exists():
            need(time.monotonic()<deadline,'Supervisor deadline; services/journals preserved')
            if time.monotonic()-last>=60:
                print('ROOT_SUPERVISOR_WAITING sequence='+str(sequence),flush=True);last=time.monotonic()
            time.sleep(.5)
        operation=validate_request(json.loads(read(path,4096)),scope['nonce'],sequence)
        try:
            need(not cleanup_only or operation in ('runtime-stop','observe','finish'),'Earlier operation failed; only inspection and cleanup remain')
            result=supervisor.execute(operation)
            value={'status':'ROOT_OPERATION_COMPLETED','operation':operation,'sequence':sequence,'nonce':scope['nonce'],'result':result}
        except Exception as error:
            cleanup_only=True
            value={'status':'ROOT_OPERATION_STOPPED_PRESERVE_STATE','operation':operation,'sequence':sequence,'nonce':scope['nonce'],
                   'errorType':type(error).__name__,'reason':str(error)[:500] if isinstance(error,RuntimeError) else 'Inspect retained logs'}
            reply(receipts/f'{sequence:04d}.reply.json',value)
            print(json.dumps(value),flush=True)
            continue
        reply(receipts/f'{sequence:04d}.reply.json',value)
        if operation!='observe':print(json.dumps(value),flush=True)
        if operation=='finish':return


if __name__=='__main__':main()
