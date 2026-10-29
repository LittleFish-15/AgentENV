"""Read-only ublk ownership diagnostics for C T1 prerequisites. Never open device data or stop anything."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

SCOPE='C_T1_READONLY_UBLK_OWNERSHIP_BEFORE_PERMISSION_CHANGES'
PARENT=Path('/var/lib/agentenv-c-rootfs-preflight-v1')


def need(ok,message):
    if not ok:raise RuntimeError(message)


def device_metadata(path):
    s=path.lstat()
    return {'path':str(path),'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),
            'inode':s.st_ino,'rdev':s.st_rdev,'symlink':path.is_symlink()}


def snapshot():
    names={p.name for p in Path('/dev').iterdir() if re.fullmatch('ublk[bc][0-9]+',p.name)}
    roots=[p for p in Path('/sys/class').glob('*/ublkc*') if re.fullmatch('ublkc[0-9]+',p.name)]
    roots += [p for p in Path('/sys/class/block').glob('ublkb*') if re.fullmatch('ublkb[0-9]+',p.name)]
    names.update(p.name for p in roots)
    need(len(names)<=128,'Device diagnostic bound exceeded')
    devices=[device_metadata(Path('/dev')/name) for name in sorted(names) if (Path('/dev')/name).exists()]
    sysfs=[]
    for path in roots:
        row={'path':str(path),'resolved':str(path.resolve()),'attributes':{}}
        for field in ('dev','size','pid','ublksrv_pid','owner_uid','owner_gid','state','flags','uevent'):
            value=path/field
            if value.is_file():
                try:
                    with value.open('rb') as stream:raw=stream.read(8193)
                    row['attributes'][field]=raw[:8192].decode('utf-8','replace')
                    if len(raw)>8192:row['attributes'][field+'Truncated']=True
                except OSError:row['attributes'][field]=None
        sysfs.append(row)
    before={row['path']:row for row in devices};matches=[];denied=vanished=visited=0;complete=True
    end=time.monotonic()+10
    targets=set(before)|{'/dev/ublk-control'}
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():continue
        if time.monotonic()>end:complete=False;break
        try:
            start=(proc/'stat').read_text().rsplit(')',1)[1].split()[19];hits=[]
            for fd in (proc/'fd').iterdir():
                visited+=1
                if visited>65536 or time.monotonic()>end:complete=False;break
                try:link=os.readlink(fd)
                except FileNotFoundError:continue
                if link in targets:hits.append({'fd':fd.name,'device':link})
            if hits:
                status=(proc/'status').read_text().splitlines()
                uids=next(line.split()[1:] for line in status if line.startswith('Uid:'))
                finish=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
                matches.append({'pid':int(proc.name),'comm':(proc/'comm').read_text().strip(),'uids':uids,
                    'startTicks':start,'identityStable':start==finish,'cgroup':(proc/'cgroup').read_text(), 'fds':hits})
        except FileNotFoundError:vanished+=1
        except PermissionError:denied+=1;complete=False
        if visited>65536:break
    after={row['path']:device_metadata(Path(row['path'])) for row in devices if Path(row['path']).exists()}
    return {'devices':devices,'sysfs':sysfs,'fdHolders':matches,'deviceMetadataStable':before==after,
            'scanComplete':complete,'deniedProcesses':denied,'vanishedProcesses':vanished,'fdsVisited':visited,
            'scope':'Conventional FD ownership only. No holder does not prove no kernel references.',
            'deviceDataOpened':False,'servicesChanged':False,'permissionsChanged':False,'SDK_called':False,
            'Guest_created':False,'moduleChanged':False}


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('activate',));p.add_argument('--approval',required=True)
    args=p.parse_args()
    need(os.getuid()==os.geteuid()==0 and args.approval=='C_NATIVE_ADAPTER_BUILD_OBMM_SWITCH_EXPLICIT_RESTORE',
         'C root queued diagnostic required')
    need(PARENT.resolve()==PARENT and PARENT.stat().st_uid==0,'C preflight report parent untrusted')
    expected=json.loads((PARENT/'receipt.json').read_bytes())
    need(expected['machineId']==Path('/etc/machine-id').read_text().strip()
         and expected['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'C identity changed')
    row=snapshot();row.update(scope=SCOPE,status='C_UBLK_OWNERSHIP_INSPECTED_NO_ACTION',
        experimentDirectoryExists=Path('/var/lib/agentenv-hpc1').exists())
    target=PARENT/'maintenance-activate-v1.json'
    if target.exists():
        previous=target.read_bytes();backup=PARENT/'maintenance-activate-before-ublk-diagnostic.json'
        need(not backup.exists(),'Prior diagnostic exists; preserve, do not repeat')
        with backup.open('xb') as stream:stream.write(previous);stream.flush();os.fsync(stream.fileno())
    temporary=PARENT/'ublk-diagnostic-v1.next.json'
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    with os.fdopen(fd,'wb') as stream:
        os.fchown(stream.fileno(),0,1205);os.fchmod(stream.fileno(),0o640)
        stream.write((json.dumps(row,indent=2)+'\n').encode());stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,target)
    print(json.dumps({'status':row['status'],'devices':[d['path'] for d in row['devices']],
                      'holdersFound':len(row['fdHolders']),'scanComplete':row['scanComplete']}))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'C_READONLY_UBLK_DIAGNOSTIC_STOPPED','reason':str(error)}));raise SystemExit(1)
