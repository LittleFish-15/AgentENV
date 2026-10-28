"""Explicitly retire A after its real B release receipt; retain static artifacts.

No allocation, module/service change, process kill or removal of artifacts.
The root inspection and human-relayed B receipt supply runtime identities.
No field report or actual object identities are embedded in this source.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

SDK_SHA='88686bc4e869c6442eb7d88128a2d3efd82468696c489734fc80b4692ac60223'
HOST_SHA='de7d33573d8ae46d37c08e811973deab20d16cf855adf256f9b7b6f25bbb7cc0'
ROOT=Path('/home/jwk/agent')


def need(value,reason):
    if not value:raise RuntimeError(reason)


def read_inspection(path,pin):
    need(path.is_absolute() and path.is_relative_to(ROOT/'r') and path.resolve(strict=True)==path,'Unexpected inspection path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077
             and 0<info.st_size<=1024**2,'Inspection ownership/type/size differs')
        data=stream.read(1024**2+1)
    need(hashlib.sha256(data).hexdigest()==pin,'Exact returned inspection differs')
    value=json.loads(data)
    need(value['status']=='UB_ROOTFS_CLOSE_SCOPE_READ_ONLY' and value['node']=='a','Expected A inspection')
    need(value['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Boot changed')
    return value


def inactive_consumers():
    result={}
    for name in ('jwk-aenv-direct-ub-deletefix-v1-node-a.service','jwk-aenv-direct-ub-guest-v1-node-a.service'):
        r=subprocess.run(['systemctl','show',name,'--property=LoadState,ActiveState,MainPID,Job'],
                         capture_output=True,text=True,timeout=15,check=True)
        value=dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)
        need(value.get('ActiveState')=='inactive' and value.get('MainPID')=='0'
             and value.get('Job') in ('','0'),'A related consumer unit is active or unknown: '+name)
        result[name]=value
    return result


CHILD=r'''
import hashlib,json,os,stat,sys
from pathlib import Path
expected=json.loads(sys.argv[1])
p=Path('/home/jwk/agent/AB_direct_full_host_v1.py')
assert os.getuid()==os.geteuid()==1204 and p.resolve(strict=True)==p
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as f:
 m=os.fstat(f.fileno());assert stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_size==81083
 raw=f.read(81084)
assert hashlib.sha256(raw).hexdigest()=='de7d33573d8ae46d37c08e811973deab20d16cf855adf256f9b7b6f25bbb7cc0'
s={'__name__':'verified_retire_only','__file__':str(p)}
exec(compile(raw,str(p),'exec'),s)
s['ordinary']('a');work=s['paths']('a')
assert s['stable'](work)==expected['process'], 'Provider identity changed; no retirement'
current=s['control'](work,{'operation':'status'})
assert current.get('ownerId')==expected['ownerId'] and current.get('manifestSha256')==expected['manifestSha256'], 'Object generation differs'
assert current.get('activeLeases')==0 and current.get('activePayloadResponses')==0, 'Readers remain; no retirement'
sys.argv=[str(p),'retire','--node','a','--capsule',expected['peerCapsule'],'--run']
raise SystemExit(s['main']())
'''


def expected_identity(inspection):
    provider=inspection['provider'];owner=provider['p/owner.json']['value']
    need(owner['role']=='publish' and owner['state']=='serving','A owner not confirmed serving in inspection')
    need(provider['status']['available'] is True,'No inspected provider control status')
    status=provider['status']['value']
    need(status['ownerId']==owner['ownerId'] and status['manifestSha256']==owner['manifestSha256'],
         'Inspection object identities differ')
    return {'process':provider['provider-process.json']['value'],
            'ownerId':owner['ownerId'],'manifestSha256':owner['manifestSha256']}


def validate_peer(peer,expected):
    need(set(peer)=={'version','ownerId','readerId','manifestSha256','state'}
         and type(peer['version']) is int and peer['version']==1
         and peer['state']=='released' and peer['readerId']=='full-b-v1'
         and peer['ownerId']==expected['ownerId']
         and peer['manifestSha256']==expected['manifestSha256'],
         'B release does not match this A owner generation')


def read_owner_allocation():
    path=ROOT/'r/uf-a-v1/p/stored-owner.json'
    need(path.resolve(strict=True)==path,'Redirected allocation journal')
    with path.open('rb') as stream:
        meta=os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and 0<meta.st_size<=2*1024**2,'Allocation journal differs')
        value=json.loads(stream.read(2*1024**2+1))
    rows=value.get('objects',[])
    need(value.get('state')=='freed' and value.get('finalize_acknowledged') is True
         and len(rows)==8 and all(r.get('creation_confirmed') is True and r.get('delete_acknowledged') is True for r in rows),
         'SDK global deletion/finalization not fully confirmed')
    return {'state':'freed','objectsDeletedAndAcknowledged':len(rows),'finalizeAcknowledged':True,
            'obmmGlobalReferenceClearance':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retire-a',action='store_true')
    parser.add_argument('--peer-capsule')
    parser.add_argument('--inspection');parser.add_argument('--inspection-sha256')
    args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0,'Expected root')
    node={'server1':'a','agent1':'b'}[os.uname().nodename]
    report={'node':node,'status':'OWNER_RETIRE_PLAN_NO_ACTION','moduleChanged':False,'servicesChanged':False,
            'retireCommandAttempted':False,'globalObjectDeletionRequested':False,'twoNodeAccepted':False}
    try:
        if args.retire_a:
            need(node=='a' and args.inspection and args.inspection_sha256 and args.peer_capsule,'Explicit A inspection and real B receipt required')
            inspection=read_inspection(Path(args.inspection),args.inspection_sha256)
            expected=expected_identity(inspection)
            need(len(args.peer_capsule)<=16384,'Peer capsule too large')
            peer=json.loads(base64.b64decode(args.peer_capsule,validate=True))
            validate_peer(peer,expected)
            expected['peerCapsule']=args.peer_capsule
            report['consumerUnits']=inactive_consumers()
            argv=['setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all',
                  '--ambient-caps=-all','--bounding-set=-all','--no-new-privs',
                  '/usr/bin/python3','-I','-B','-c',CHILD,json.dumps(expected)]
            report['retireCommandAttempted']=True
            report['globalObjectDeletionRequested']=True
            result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=660)
            matches=re.findall(r'BEGIN_DIRECT_FULL_HOST_REPORT\s*(\{.*?\})\s*END_DIRECT_FULL_HOST_REPORT',result.stdout,re.S)
            report['retireExitCode']=result.returncode
            if matches:report['providerRetirement']=json.loads(matches[-1])
            need(result.returncode==0 and report.get('providerRetirement',{}).get('state')=='released',
                 'Retirement not confirmed; preserve state. '+result.stderr[-1500:])
            report['status']='A_GLOBAL_RELEASE_ACKNOWLEDGED_MODULES_UNCHANGED'
            allocation=read_owner_allocation()
            report['allocationRelease']=allocation
            report['obmmAfter']={'referenceCount':Path('/sys/module/obmm/refcnt').read_text().strip(),
                'regionDevices':sorted(p.name for p in Path('/sys/devices/obmm').glob('obmm_shmdev*')),
                'clearance':'Observation only; both nodes recheck at activation'}
    except Exception as error:
        report.update(status='STOPPED_OWNER_RETIRE_PRESERVE_STATE',reason=str(error))
    print('BEGIN_HOST_PMEM_OWNER_RETIRE')
    print(json.dumps(report,indent=2))
    print('END_HOST_PMEM_OWNER_RETIRE')
    return 1 if report['status'].startswith('STOPPED') else 0


if __name__=='__main__':raise SystemExit(main())
