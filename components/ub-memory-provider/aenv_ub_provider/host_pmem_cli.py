"""Local Host pmem gate: plan, foreground serve, explicit root retirement.

The experiment wrapper must first obtain module/UB-operation approval and start
an ordinary, receipt-guarded SDK owner. This command never loads a module,
allocates UB, starts Guests or retires the SDK owner.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import struct

from . import contract, host_pmem_guard, host_pmem_lease
from .host_pmem_session import MountedSession
from .io import read_json


def plan(config):
    required={'version','workDir','source','ownerUid','ownerPid','ownerStartTicks','publication',
              'releaseReceipt','testFile','kernelRelease','moduleSrcversion'}
    if set(config)!=required or type(config['version']) is not int or config['version']!=1:
        raise ValueError('Unknown Host pmem gate configuration')
    host_pmem_guard.publication_binding(config['publication'],config['source'])
    if (type(config['ownerUid']) is not int or config['ownerUid']<=0
            or type(config['ownerPid']) is not int or config['ownerPid']<=0
            or not isinstance(config['ownerStartTicks'],str) or not config['ownerStartTicks'].isdecimal()
            or not isinstance(config['kernelRelease'],str) or not config['kernelRelease']
            or not isinstance(config['moduleSrcversion'],str)
            or re.fullmatch('[A-F0-9]{24}',config['moduleSrcversion']) is None):
        raise ValueError('Exact owner/kernel/module identity required')
    work=Path(config['workDir']);receipt=Path(config['releaseReceipt'])
    if (not work.is_absolute() or not receipt.is_absolute() or work==receipt
            or len(os.fsencode(work/'root-control.sock'))>=108):
        raise ValueError('Invalid work/receipt path or UNIX socket length')
    test=config['testFile']
    if (set(test)!={'name','bytes','sha256'} or not isinstance(test['name'],str)
            or test['name'] in ('','.','..') or any(c in test['name'] for c in ('/','\\','\0'))
            or type(test['bytes']) is not int or not 0<test['bytes']<=config['source']['bytes']
            or not isinstance(test['sha256'],str) or re.fullmatch('[0-9a-f]{64}',test['sha256']) is None):
        raise ValueError('Invalid bounded DAX test file')
    return {'configSha256':hashlib.sha256(contract.canonical(config)).hexdigest(),
            'state':'host_pmem_plan_no_action','sourceBytes':config['source']['bytes'],
            'SDKAllocationIncluded':False,'moduleChangeIncluded':False,'GuestCreated':False,
            'twoNodeAccepted':False,'netSavingsBytes':None}


def root_peer(stream, pid=None):
    actual_pid,uid,_=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    if uid!=0 or (pid is not None and actual_pid!=pid):
        raise PermissionError('Unexpected root control peer')
    return actual_pid


def serve(config, pin):
    if os.getuid()!=0 or os.geteuid()!=0 or platform.release()!=config['kernelRelease']:
        raise RuntimeError('Exact root/kernel context required')
    if (Path('/sys/module/obmm/srcversion').read_text().strip()!=config['moduleSrcversion']
            or Path('/sys/module/obmm/parameters/pmem_ro_enable').read_text().strip()!='Y'):
        raise RuntimeError('Approved candidate is not enabled; no automatic module switch')
    session=MountedSession(config['workDir'],config['source'],config['ownerUid'],config['ownerPid'],
                           config['ownerStartTicks'],config['publication'])
    session.update('configSha256',pin)
    session.update('helper',{'pid':os.getpid(),'startTicks':host_pmem_lease.process_ticks(os.getpid())})
    control=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    endpoint=session.work/'root-control.sock'
    endpoint_identity=None
    try:
        control.bind(str(endpoint));os.chmod(endpoint,0o600);control.listen(2)
        observed=endpoint.stat();endpoint_identity=(observed.st_dev,observed.st_ino)
        try:
            session.start()
            test=config['testFile'];session.verify(test['name'],test['bytes'],test['sha256'])
        except Exception as error:
            print(json.dumps({'state':'host_pmem_stopped_preserve_resources','reason':str(error),
                              'workDir':str(session.work),'explicitRetirementAvailable':True}),flush=True)
        else:
            print(json.dumps({'state':'host_pmem_local_read_verified_holding',
                              'workDir':str(session.work),'twoNodeAccepted':False}),flush=True)
        # Keep the SDK lease and mount alive while the other node is tested.
        # Only an explicit authenticated local request initiates cleanup.
        while True:
            stream,_=control.accept()
            with stream:
                stream.settimeout(10)
                completed=False
                try:
                    root_peer(stream)
                    request=contract.receive_json(stream)
                    if (not isinstance(request,dict) or set(request)!={'operation','configSha256'}
                            or request['configSha256']!=pin or request['operation'] not in ('retire','verify')):
                        raise ValueError('Unexpected control request')
                    if request['operation']=='verify':
                        test=config['testFile']
                        verified=session.verify(test['name'],test['bytes'],test['sha256'])
                        reply={'state':'local_read_verified','verification':verified}
                    else:
                        session.retire()
                        session.export_release(config['releaseReceipt'])
                        reply={'state':'local_resources_released','receipt':config['releaseReceipt'],
                               'SDKOwnerRetired':False,'sharedBackingReleaseAuthorized':False}
                        completed=True
                except Exception as error:
                    reply={'state':'retirement_refused_preserve_resources','reason':str(error)}
                try:contract.send_json(stream,reply)
                except OSError:pass  # A lost reply does not undo a durable release.
                if completed:
                    print(json.dumps(reply),flush=True)
                    return
    finally:
        control.close()
        if endpoint_identity is not None and endpoint.exists():
            now=endpoint.lstat()
            if (now.st_dev,now.st_ino)==endpoint_identity:
                endpoint.unlink()


def request_action(config,pin,operation='retire'):
    if os.getuid()!=0 or os.geteuid()!=0:
        raise RuntimeError('Retirement requires root')
    work=Path(config['workDir']);info=work.lstat()
    if (work.resolve(strict=True)!=work or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=0 or info.st_mode&0o077):
        raise ValueError('Unsafe root transaction directory')
    record=read_json(work/'host-pmem-session.json')
    if (record['configSha256']!=pin or record['source']!=config['source']
            or record['bootId']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
        raise ValueError('Root transaction identity changed')
    if record['phase']=='local_resources_released':
        if operation!='retire':
            raise RuntimeError('Cannot verify a retired local view')
        # Export may have failed after cleanup; require the exact same receipt.
        return host_pmem_guard.write_release(config['releaseReceipt'],record)
    helper=record['helper']
    if host_pmem_lease.process_ticks(helper['pid'])!=helper['startTicks']:
        raise RuntimeError('Helper identity changed; preserve orphan journal, no implicit adoption')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
        stream.settimeout(60)
        stream.connect(str(work/'root-control.sock'))
        root_peer(stream,helper['pid'])
        if host_pmem_lease.process_ticks(helper['pid'])!=helper['startTicks']:
            raise RuntimeError('Helper changed during control connect')
        contract.send_json(stream,{'operation':operation,'configSha256':pin})
        return contract.receive_json(stream)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('plan','serve','verify','retire'))
    parser.add_argument('--config',required=True)
    parser.add_argument('--expected-config-sha256')
    parser.add_argument('--approval')
    args=parser.parse_args()
    config=read_json(args.config);summary=plan(config);pin=summary['configSha256']
    if args.mode=='plan':
        print(json.dumps(summary));return 0
    if args.expected_config_sha256!=pin:
        raise ValueError('Require the reviewed exact configuration SHA256')
    if args.mode=='serve':
        if args.approval!='CREATE_READONLY_HOST_PMEM_VIEW':
            raise ValueError('Explicit Host pmem view/mount approval required')
        serve(config,pin);return 0
    result=request_action(config,pin,args.mode);print(json.dumps(result))
    return 0 if result.get('state') in ('local_resources_released','released','local_read_verified') else 1


if __name__=='__main__':
    raise SystemExit(main())
