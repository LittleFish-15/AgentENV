"""Root mount owner plus ordinary-UID DAX lower broker for existing UB images.

Only local view/consumer lifecycle is implemented here. SDK publication and
cross-node retirement receipts remain with the external experiment owner.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import stat
import uuid

from . import contract, host_dax_worker, host_pmem_cli, host_pmem_lease, stored
from .host_pmem_session import MountedSession
from .io import read_json


def plan(config):
    extra={'files','brokerSocket','brokerGid','runtimeIndex','payloadResponses'}
    common={key:value for key,value in config.items() if key not in extra}
    if 'testFile' in common:raise ValueError('Rootfs config derives its verification from exact lower identities')
    if not extra.issubset(config) or not isinstance(config['files'],list) or not 1<=len(config['files'])<=64:
        raise ValueError('Expected a bounded rootfs lower catalog')
    if (type(config['brokerGid']) is not int or config['brokerGid']<=0
            or type(config['payloadResponses']) is not int or not 1<=config['payloadResponses']<=8):
        raise ValueError('Invalid ordinary broker identity/response limit')
    replicas=[];names=[]
    for item in config['files']:
        if not isinstance(item,dict) or set(item)!={'name','replica'}:
            raise ValueError('Rootfs file requires immutable name and replica')
        name=item['name']
        if not isinstance(name,str) or name in ('','.','..') or any(c in name for c in ('/','\\','\0')):
            raise ValueError('Rootfs lower must be a direct file in the mounted image')
        r=stored.Replica(**item['replica']).validate()
        if r.brokerSocket!=config['brokerSocket'] or r.allowRepositoryFallback:
            raise ValueError('Required DAX broker socket/fallback differs')
        names.append(name);replicas.append(r)
    if len(set(names))!=len(names) or len({r.layerDigest for r in replicas})!=len(replicas) or len({r.objectName for r in replicas})!=len(replicas):
        raise ValueError('Duplicate lower or replica identity')
    if sum(r.fileBytes for r in replicas)>config['source']['bytes']:
        raise ValueError('Selected lower data exceeds its container')
    first=replicas[0]
    common['testFile']={'name':names[0],'bytes':first.fileBytes,'sha256':first.layerDigest[7:]}
    host_pmem_cli.plan(common)
    index=Path(config['runtimeIndex'])
    if not index.is_absolute() or index in (Path(config['releaseReceipt']),Path(config['workDir'])):
        raise ValueError('Runtime index needs a distinct absolute path')
    return {'state':'host_pmem_rootfs_plan_no_action','configSha256':hashlib.sha256(contract.canonical(config)).hexdigest(),
            'files':len(replicas),'logicalFileBytes':sum(r.fileBytes for r in replicas),
            'containerBytes':config['source']['bytes'],'GuestCreated':False,'SDKAllocationIncluded':False}


def write_index(path,value,expected=None):
    """Publish only in a root-owned readable directory, preserving strangers."""
    path=Path(path);parent=path.parent;info=parent.stat()
    if (parent.resolve(strict=True)!=parent or info.st_uid!=0 or info.st_mode&0o022
            or not stat.S_ISDIR(info.st_mode)):
        raise ValueError('Runtime index requires a root-owned staging parent')
    if path.exists() or path.is_symlink():
        info=path.lstat()
        if (expected is None or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022
                or (info.st_dev,info.st_ino)!=tuple(expected)):
            raise ValueError('Existing runtime index is not this publication')
    elif expected is not None:raise ValueError('Owned runtime index disappeared')
    temp=parent/(path.name+'.'+uuid.uuid4().hex+'.next')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(contract.canonical(value)+b'\n');stream.flush();os.fchmod(stream.fileno(),0o644);os.fsync(stream.fileno())
    if expected is None:
        # An independently created index must win over this publication rather
        # than being overwritten between the existence check and rename.
        os.link(temp,path)
        temp.unlink()
    else:os.replace(temp,path)
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    info=path.stat();return [info.st_dev,info.st_ino]


def serve(config,pin):
    if (os.getuid()!=0 or os.geteuid()!=0 or platform.release()!=config['kernelRelease']
            or Path('/sys/module/obmm/srcversion').read_text().strip()!=config['moduleSrcversion']
            or Path('/sys/module/obmm/parameters/pmem_ro_enable').read_text().strip()!='Y'):
        raise RuntimeError('Exact root/kernel/candidate context required')
    sock_parent=Path(config['brokerSocket']).parent
    info=sock_parent.stat()
    if sock_parent.resolve(strict=True)!=sock_parent or info.st_uid!=config['ownerUid'] or info.st_mode&0o022:
        raise ValueError('Broker socket needs a non-writable-by-others ordinary-owner directory')
    # Avoid mounting anything when a runtime index already exists.
    output=Path(config['runtimeIndex'])
    if output.exists() or output.is_symlink():raise ValueError('Runtime index exists; preserve previous publication')
    session=MountedSession(config['workDir'],config['source'],config['ownerUid'],config['ownerPid'],
                           config['ownerStartTicks'],config['publication'])
    session.update('configSha256',pin)
    session.update('helper',{'pid':os.getpid(),'startTicks':host_pmem_lease.process_ticks(os.getpid())})
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    endpoint=session.work/'root-control.sock';endpoint_identity=None
    worker=None;index=None;index_identity=None
    try:
        listener.bind(str(endpoint));os.chmod(endpoint,0o600);listener.listen(2)
        info=endpoint.stat();endpoint_identity=(info.st_dev,info.st_ino)
        try:
            session.start()
            worker=host_dax_worker.Worker(session,config['files'],config['ownerUid'],config['brokerGid'],
                config['brokerSocket'],lambda value:session.update('rootfsBroker',value),config['payloadResponses'])
            ready=worker.start();index=ready['index']
            index_identity=write_index(output,index)
            session.update('runtimeIndex',{'path':str(output),'identity':index_identity,'state':'ready'})
            session.update('phase','rootfs_broker_ready')
            print(json.dumps({'state':'rootfs_broker_ready','files':ready['files'],'brokerPid':ready['pid'],
                'runtimeIndex':str(output),'GuestCreated':False,'twoNodeAccepted':False}),flush=True)
        except Exception as error:
            session.update('rootfsFailure',{'reason':str(error)})
            print(json.dumps({'state':'rootfs_stopped_preserve_resources','reason':str(error)}),flush=True)
        while True:
            channel,_=listener.accept()
            with channel:
                channel.settimeout(10);completed=False
                try:
                    host_pmem_cli.root_peer(channel)
                    request=contract.receive_json(channel)
                    if (set(request)!={'operation','configSha256'} or request['configSha256']!=pin
                            or request['operation'] not in ('status','retire','reconcile-broker')):
                        raise ValueError('Invalid rootfs controller request')
                    if request['operation']=='status':
                        broker=worker.request('status') if worker is not None and not worker.retired else None
                        reply={'state':session.record['phase'],'broker':broker,
                               'volume':asdict(session.control.query(session.status.uuid)) if session.status is not None else None}
                    else:
                        if worker is not None and not worker.retired:
                            if request['operation']=='reconcile-broker':worker.reconcile_retirement()
                            else:worker.retire()
                        if index_identity is not None:
                            index_identity=write_index(output,{**index,'state':'retired'},index_identity)
                            session.update('runtimeIndex',{'path':str(output),'identity':index_identity,'state':'retired'})
                        session.retire();session.export_release(config['releaseReceipt'])
                        reply={'state':'local_resources_released','receipt':config['releaseReceipt'],
                               'sharedBackingReleaseAuthorized':False}
                        completed=True
                except Exception as error:reply={'state':'refused_preserve_resources','reason':str(error)}
                try:contract.send_json(channel,reply)
                except OSError:pass
                if completed:return
    finally:
        listener.close()
        if endpoint_identity is not None and endpoint.exists():
            info=endpoint.lstat()
            if (info.st_dev,info.st_ino)==endpoint_identity:endpoint.unlink()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('plan','serve','status','retire','reconcile-broker'))
    parser.add_argument('--config',required=True);parser.add_argument('--expected-config-sha256');parser.add_argument('--approval')
    args=parser.parse_args();config=read_json(args.config);result=plan(config);pin=result['configSha256']
    if args.mode=='plan':print(json.dumps(result));return 0
    if args.expected_config_sha256!=pin:raise ValueError('Exact reviewed rootfs configuration required')
    if args.mode=='serve':
        if args.approval!='CREATE_READONLY_ROOTFS_HOST_PMEM':raise ValueError('Rootfs local view approval required')
        serve(config,pin);return 0
    result=host_pmem_cli.request_action(config,pin,args.mode)
    print(json.dumps(result))
    return 1 if result.get('state')=='refused_preserve_resources' else 0


if __name__=='__main__':raise SystemExit(main())
