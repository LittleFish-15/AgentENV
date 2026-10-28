"""Inspect SDK bytes on A/B; explicitly retire only B's existing import.

No allocation, module/service change, process kill or removal of artifacts.
The inspected root receipt supplies runtime identities; no field report is
embedded in this source. A retains global objects until actual B release.
"""
import argparse
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


def sdk_details():
    source=Path('/usr/lib64/libubsm_sdk.so')
    resolved=source.resolve(strict=True)
    fd=os.open(resolved,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        result={'path':str(source),'resolvedPath':str(resolved),'uid':info.st_uid,'gid':info.st_gid,
                'mode':oct(stat.S_IMODE(info.st_mode)),'bytes':info.st_size,
                'regularFile':stat.S_ISREG(info.st_mode),'expectedSha256':SDK_SHA}
        checks={'regularFile':stat.S_ISREG(info.st_mode),'rootOwner':info.st_uid==0,
                'notGroupOrWorldWritable':not bool(info.st_mode&0o022),
                'withinOriginal64MiBBound':0<info.st_size<=64*1024**2}
        result['originalGuardChecks']=checks
        if stat.S_ISREG(info.st_mode) and 0<info.st_size<=512*1024**2:
            digest=hashlib.sha256()
            for data in iter(lambda:stream.read(1024**2),b''):digest.update(data)
            after=os.fstat(stream.fileno())
            result['identityStable']=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==(
                after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            result['sha256']=digest.hexdigest()
            result['matchesPinnedBytes']=result['identityStable'] and result['sha256']==SDK_SHA
        else:result.update(sha256=None,matchesPinnedBytes=None)
        result['guardPassed']=all(checks.values()) and result['matchesPinnedBytes'] is True
        return result


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
    need(value['status']=='UB_ROOTFS_CLOSE_SCOPE_READ_ONLY' and value['node']=='b','Expected B inspection')
    need(value['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Boot changed')
    return value


def inactive_consumers():
    result={}
    for name in ('jwk-aenv-direct-ub-deletefix-v1-node-b.service','jwk-aenv-direct-ub-guest-v1-node-b.service'):
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
s['ordinary']('b');work=s['paths']('b')
assert s['stable'](work)==expected['process'], 'Provider identity changed; no retirement'
current=s['control'](work,{'operation':'status'})
assert current.get('ownerId')==expected['ownerId'] and current.get('manifestSha256')==expected['manifestSha256'], 'Object generation differs'
assert current.get('activeLeases')==0 and current.get('activePayloadResponses')==0, 'Readers remain; no retirement'
sys.argv=[str(p),'retire','--node','b','--run']
raise SystemExit(s['main']())
'''


def expected_identity(inspection):
    provider=inspection['provider'];owner=provider['p/owner.json']['value']
    need(owner['role']=='import' and owner['state']=='serving','B import not confirmed serving in inspection')
    need(provider['status']['available'] is True,'No inspected provider control status')
    status=provider['status']['value']
    need(status['ownerId']==owner['ownerId'] and status['manifestSha256']==owner['manifestSha256'],
         'Inspection object identities differ')
    return {'process':provider['provider-process.json']['value'],
            'ownerId':owner['ownerId'],'manifestSha256':owner['manifestSha256']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retire-b',action='store_true')
    parser.add_argument('--inspection');parser.add_argument('--inspection-sha256')
    args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0,'Expected root')
    node={'server1':'a','agent1':'b'}[os.uname().nodename]
    report={'node':node,'status':'SDK_FILE_DETAILS_READ_ONLY','moduleChanged':False,'servicesChanged':False,
            'retireCommandAttempted':False,'globalObjectDeletionRequested':False,'twoNodeAccepted':False}
    try:
        try:report['sdk']=sdk_details()
        except Exception as error:report['sdk']={'available':False,'reason':str(error)}
        if args.retire_b:
            need(node=='b' and args.inspection and args.inspection_sha256,'Explicit B inspection binding required')
            inspection=read_inspection(Path(args.inspection),args.inspection_sha256)
            expected=expected_identity(inspection)
            report['consumerUnits']=inactive_consumers()
            argv=['setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all',
                  '--ambient-caps=-all','--bounding-set=-all','--no-new-privs',
                  '/usr/bin/python3','-I','-B','-c',CHILD,json.dumps(expected)]
            report['retireCommandAttempted']=True
            result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=660)
            matches=re.findall(r'BEGIN_DIRECT_FULL_HOST_REPORT\s*(\{.*?\})\s*END_DIRECT_FULL_HOST_REPORT',result.stdout,re.S)
            report['retireExitCode']=result.returncode
            if matches:report['providerRetirement']=json.loads(matches[-1])
            need(result.returncode==0 and report.get('providerRetirement',{}).get('state')=='released',
                 'Retirement not confirmed; preserve state. '+result.stderr[-1500:])
            report['status']='B_IMPORT_RELEASE_ACKNOWLEDGED_A_MUST_RETAIN_UNTIL_RELAY'
    except Exception as error:
        report.update(status='STOPPED_SDK_CHECK_OR_IMPORT_RETIRE_PRESERVE_STATE',reason=str(error))
    print('BEGIN_HOST_PMEM_SDK_AND_RETIRE')
    print(json.dumps(report,indent=2))
    print('END_HOST_PMEM_SDK_AND_RETIRE')
    return 1 if report['status'].startswith('STOPPED') else 0


if __name__=='__main__':raise SystemExit(main())
