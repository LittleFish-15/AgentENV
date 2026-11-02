"""Ordinary-UID stored-lower broker inheriting exact readonly DAX descriptors.

The root mount owner keeps its UB lease and file descriptors until this child
explicitly stops, or an explicit retirement reconciliation observes exit 0.
This module does not allocate UB, mount filesystems or invoke SDK functions.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import threading
import uuid

from . import contract, fsdax, host_dax, stored, demand_wire, host_pmem_cache

MAX_MESSAGE=1024*1024


def send(stream,value):
    data=contract.canonical(value)
    if len(data)>MAX_MESSAGE:raise ValueError('Rootfs control message too large')
    stream.sendall(struct.pack('>I',len(data))+data)


def receive(stream):
    size=struct.unpack('>I',contract.receive(stream,4))[0]
    if not 0<size<=MAX_MESSAGE:raise ValueError('Invalid rootfs control frame')
    return json.loads(contract.receive(stream,size))


def validate(config,control_fd=None):
    if (set(config)!={'version','uid','gid','parentPid','device','socket','files','payloadResponses'}
            or type(config['version']) is not int or config['version'] not in (1,2)
            or any(type(config[k]) is not int or config[k]<=0 for k in ('uid','gid','parentPid','device'))
            or type(config['payloadResponses']) is not int or not 1<=config['payloadResponses']<=8
            or not isinstance(config['files'],list) or not 1<=len(config['files'])<=64):
        raise ValueError('Invalid inherited DAX broker contract')
    replicas=[];fds=[]
    for item in config['files']:
        if set(item)!={'fd','replica'} or type(item['fd']) is not int or item['fd']<=2 or item['fd']==control_fd:
            raise ValueError('Invalid inherited descriptor')
        r=(demand_wire.Layer(**item['replica']) if config['version']==2 else stored.Replica(**item['replica'])).validate()
        if r.brokerSocket!=config['socket'] or (config['version']==1 and r.allowRepositoryFallback):
            raise ValueError('Socket/fallback does not match inherited publication')
        if config['version']==2 and r.stablePmem is None:
            raise ValueError('Stable inherited broker requires exact image layouts')
        replicas.append(r);fds.append(item['fd'])
    if (len(set(fds))!=len(fds) or len({r.objectName for r in replicas})!=len(replicas)
            or len({r.layerDigest for r in replicas})!=len(replicas)):
        raise ValueError('Duplicate inherited file or lower identity')
    return replicas


def child(control_fd,pin):
    contract.linux_only()
    stream=socket.socket(fileno=control_fd)
    config=receive(stream)
    if hashlib.sha256(contract.canonical(config)).hexdigest()!=pin:
        raise ValueError('Inherited config hash differs')
    replicas=validate(config,control_fd)
    peer,uid,_=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    if peer!=config['parentPid'] or uid!=0 or os.getuid()!=config['uid'] or os.getgid()!=config['gid']:
        raise PermissionError('Inherited root controller/ordinary broker identity differs')
    status=Path('/proc/self/status').read_text()
    for name in ('CapInh','CapPrm','CapEff','CapAmb'):
        if int(next(line.split()[1] for line in status.splitlines() if line.startswith(name+':')),16):
            raise PermissionError('Inherited DAX broker must have no capabilities')
    mappings=[]
    try:
        for item,r in zip(config['files'],replicas):
            reader=host_dax.StableDaxMapping if config['version']==2 else host_dax.StoredDaxMapping
            mappings.append(reader.from_fd(item['fd'],r,config['device']))
        broker_type=demand_wire.Broker if config['version']==2 else stored.Broker
        broker=broker_type(replicas,mappings,max_payload_responses=config['payloadResponses'])
        broker.start(config['socket'])
    except Exception as error:
        for mapping in mappings:mapping.close()
        send(stream,{'state':'startup_failed','configSha256':pin,'reason':str(error)})
        stream.close()
        return 2
    send(stream,{'state':'serving','configSha256':pin,'fileCount':len(mappings),
                 'files':[m.observed for m in mappings],'payloadCache':False})
    while True:
        try:request=receive(stream)
        except (EOFError,OSError):
            # Lost controller is not permission to retire live readers. The
            # service owner must reconcile this exact process and mount.
            threading.Event().wait()
            raise RuntimeError('Unreachable controller-disconnect path')
        if (not isinstance(request,dict) or set(request)!={'operation','requestId','configSha256'}
                or request['configSha256']!=pin or not isinstance(request['requestId'],str)):
            raise ValueError('Invalid rootfs control request')
        operation=request['operation']
        if operation=='status':
            with broker.condition:
                result={'state':'serving','activeLeases':broker.active,'readRequests':broker.reads,
                        'readBytes':broker.bytes,'activePayloadResponses':broker.active_payloads,
                        'peakPayloadResponses':broker.peak_payloads,'payloadFailures':broker.payload_failures}
        elif operation=='retire':
            try:
                result={'state':'released',**host_dax.close_publication(broker,mappings)}
            except RuntimeError as error:result={'state':'busy','reason':str(error)}
        else:raise ValueError('Unknown rootfs control operation')
        result.update(requestId=request['requestId'],configSha256=pin)
        try:send(stream,result)
        except OSError:
            if result['state']!='released':continue
        if result['state']=='released':
            stream.close()
            return 0


class Worker:
    """Root-side owner. Unknown child outcome remains a retained consumer."""
    def __init__(self,session,files,uid,gid,socket_path,save,payload_responses=2,stable=None,child_package=None):
        if (os.getuid()!=0 or os.geteuid()!=0 or session.status is None
                or session.record['phase'] not in ('mounted_pending_file_verification','local_read_verified')):
            raise ValueError('An active root-owned mounted session is required')
        self.session,self.files,self.uid,self.gid=session,files,uid,gid
        self.socket_path,self.save,self.limit=socket_path,save,payload_responses
        self.stable=stable
        self.child_package=child_package
        self.fds=[];self.process=None;self.control=None;self.attempted=False;self.retired=False
        self.record={'state':'not_started','retireIntent':False};self.pin=None
        session.retain_consumer(self)

    def mark(self,state,**values):
        self.record.update(state=state,**values);self.save(dict(self.record))

    def start(self):
        if self.attempted:raise RuntimeError('DAX broker launch already attempted')
        self.attempted=True
        if not isinstance(self.files,list) or not 1<=len(self.files)<=64:
            raise ValueError('Expected bounded lower list')
        mount=self.session.work/'mount'
        device=os.makedev(self.session.status.major,self.session.status.minor)
        directory=os.open(mount,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        peer=None
        try:
            rows=[];names=set()
            for item in self.files:
                if set(item)!={'name','replica'}:raise ValueError('Unexpected lower contract fields')
                name=item['name']
                if (not isinstance(name,str) or name in ('','.','..') or '/' in name or '\\' in name
                        or '\0' in name or name in names):raise ValueError('Lower name must be a unique direct child')
                names.add(name)
                r=stored.Replica(**item['replica']).validate()
                fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
                self.fds.append(fd)
                observed=fsdax.validate_fd(fd,r.fileBytes)
                if observed['device']!=device:raise ValueError('Lower is outside the mounted UB image')
                if self.stable is not None:
                    layout={'imageSha256':self.stable['imageSha256'],'imageBytes':self.stable['imageBytes'],
                            'logicalBytes':demand_wire.DEVICE_BYTES,'loadBytes':demand_wire.LOAD_BYTES,
                            'extents':host_pmem_cache.file_layout(fd,r.fileBytes,self.stable['imageBytes'])}
                    r=demand_wire.Layer(r.brokerSocket,r.objectName,r.generation,r.layerDigest,r.fileBytes,
                        r.mappingBytes,self.stable['manifestSha256'],self.stable.get('requestTimeoutMs',30000),layout).validate()
                rows.append({'fd':fd,'replica':asdict(r)})
            config={'version':2 if self.stable is not None else 1,'uid':self.uid,'gid':self.gid,'parentPid':os.getpid(),
                    'device':device,'socket':self.socket_path,'files':rows,'payloadResponses':self.limit}
            validate(config)
            self.pin=hashlib.sha256(contract.canonical(config)).hexdigest()
            self.control,peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
            self.control.settimeout(600)
            self.mark('launch_intent',configSha256=self.pin,fileCount=len(rows))
            package=str(Path(__file__).resolve().parents[1])
            if self.child_package is not None:
                candidate=Path(self.child_package)
                if not candidate.is_absolute() or candidate.resolve(strict=True)!=candidate:
                    raise ValueError('Ordinary broker package path redirected')
                # Both copies must be the same reviewed package, not arbitrary child code.
                current=Path(__file__).resolve().parent
                for path in current.glob('*.py'):
                    if hashlib.sha256(path.read_bytes()).digest()!=hashlib.sha256((candidate/'aenv_ub_provider'/path.name).read_bytes()).digest():
                        raise ValueError('Ordinary broker package differs from root package')
                package=str(candidate)
            bootstrap="import sys,runpy;p=sys.argv.pop(1);sys.path.insert(0,p);sys.argv[0]='host_dax_worker';runpy.run_module('aenv_ub_provider.host_dax_worker',run_name='__main__')"
            argv=[sys.executable,'-I','-B','-c',bootstrap,package,'--control-fd',str(peer.fileno()),'--config-sha256',self.pin]
            self.process=subprocess.Popen(argv,pass_fds=(*self.fds,peer.fileno()),
                user=self.uid,group=self.gid,extra_groups=[],umask=0o077,
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
            peer.close();peer=None
            self.mark('started_pending_validation',pid=self.process.pid)
            send(self.control,config)
            result=receive(self.control)
            if result.get('state')=='startup_failed' and result.get('configSha256')==self.pin:
                if self.process.wait(timeout=10)!=2:raise RuntimeError('Startup failure exit not confirmed')
                self.close_fds();self.retired=True
                self.mark('startup_failed_closed',reason=result.get('reason'),exitCode=2)
                raise RuntimeError('DAX broker startup failed: '+str(result.get('reason')))
            if (result.get('state')!='serving' or result.get('configSha256')!=self.pin
                    or result.get('fileCount')!=len(rows) or self.process.poll() is not None):
                raise RuntimeError('Broker startup not confirmed')
            self.mark('serving',fileEvidence=result['files'],inheritedFiles=rows)
            index=({'version':3,'state':'metadata_ready','mode':'host-dax-stable-demand',
                    'replicas':[row['replica'] for row in rows]} if self.stable is not None
                   else stored.index_for([stored.Replica(**row['replica']) for row in rows]))
            return {'index':index,
                    'pid':self.process.pid,'files':result['files'],'configSha256':self.pin}
        except BaseException:
            if self.process is None:
                self.close_fds();self.retired=True
                self.mark('not_started_closed')
            elif not self.retired:self.mark('start_unconfirmed_preserve_mount')
            raise
        finally:
            os.close(directory)
            if peer is not None:peer.close()

    def request(self,operation):
        if self.retired or self.process is None or self.process.poll() is not None:
            raise RuntimeError('No confirmed live broker control; preserve mount')
        request_id=uuid.uuid4().hex
        send(self.control,{'operation':operation,'requestId':request_id,'configSha256':self.pin})
        result=receive(self.control)
        if result.get('requestId')!=request_id or result.get('configSha256')!=self.pin:
            raise ValueError('Control reply identity differs')
        return result

    def retire(self):
        if self.retired:return dict(self.record)
        if self.process is None and self.record['state']=='not_started':
            self.close_fds();self.retired=True
            self.mark('not_started_closed')
            return dict(self.record)
        self.mark('retire_intent',retireIntent=True)
        result=self.request('retire')
        if result.get('state')!='released':
            self.mark('busy_preserve_mount',reply=result)
            raise RuntimeError('Broker readers remain; retain mount and SDK lease')
        if self.process.wait(timeout=10)!=0:raise RuntimeError('Broker exit not successful')
        self.close_fds();self.retired=True
        self.mark('released',reply=result,exitCode=0)
        return dict(self.record)

    def reconcile_retirement(self):
        """Explicit lost-ack reconciliation, never implicit on process death."""
        if not self.record['retireIntent'] or self.process is None or self.process.poll()!=0:
            raise RuntimeError('No attributable successful retirement exit; preserve mount')
        self.close_fds();self.retired=True
        self.mark('released_reconciled_exit',exitCode=0,replyAcknowledged=False)

    def close_fds(self):
        for fd in self.fds:os.close(fd)
        self.fds=[]
        if self.control is not None:self.control.close();self.control=None


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control-fd',type=int,required=True)
    parser.add_argument('--config-sha256',required=True)
    args=parser.parse_args();return child(args.control_fd,args.config_sha256)


if __name__=='__main__':raise SystemExit(main())
