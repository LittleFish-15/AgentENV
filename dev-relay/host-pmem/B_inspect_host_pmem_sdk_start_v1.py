"""Inspect the exact failed B SDK unit; no start/stop/import/retire operation.

Bounded raw logs remain root-private. Terminal output filters likely secrets.
Missing state or an exited process never proves that no import occurred.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

BASE=Path('/var/lib/agentenv-hpmem-demo-v2/node-b')
PREP=Path('/home/jwk/agent/r/hpmem-b-v1')
UNIT='aenv-hpmem-v2-node-b-sdk.service'


def need(value,reason):
    if not value:raise RuntimeError(reason)


def regular(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        info=os.fstat(f.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid in (0,1204) and 0<=info.st_size<=limit,'Unexpected diagnostic file')
        return f.read(limit+1)


def public_lines(raw):
    lines=raw.decode(errors='replace').splitlines()[-55:]
    result=[]
    for line in lines:
        if re.search(r'(?i)password|secret|api.?key|token.?id|credential|access.?key',line):
            result.append('[sensitive diagnostic line retained only in private log]')
        else:result.append(line[:1500])
    return result


def run(args,limit):
    r=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=20)
    return r.returncode,r.stdout[-limit:],r.stderr[-4096:]


def inspect():
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='agent1','Expected B root')
    info=BASE.lstat()
    need(BASE.resolve(strict=True)==BASE and stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077,'Unsafe root transaction directory')
    raw=regular(BASE/'workflow.json',1024**2);state=json.loads(raw)
    need(state['node']=='node-b' and state['phase']=='sdk_start_intent','State changed; do not inspect a different stage')
    out=BASE/('sdk-start-inspection-'+str(time.time_ns()));out.mkdir(mode=0o700)
    report={'status':'HOST_PMEM_B_SDK_START_INSPECTED_NO_ACTION','node':'node-b','phase':state['phase'],
            'workflowSha256':hashlib.sha256(raw).hexdigest(),'outputDirectory':str(out),
            'startRetried':False,'SDKCalledByInspector':False,'servicesChanged':False,'moduleChanged':False,
            'importOutcome':'unconfirmed; inspect owner journal and service evidence',
            'workflowEpoch':state['epoch'],'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    def save(name,data):
        fd=os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    keys='LoadState,ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus,InvocationID,User,Group,SupplementaryGroups,WorkingDirectory,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic'
    rc,stdout,stderr=run(['systemctl','show',UNIT,'--no-pager','--property='+keys],32768)
    save('unit.txt',stdout+b'\nSTDERR\n'+stderr)
    report['unit']={'exitCode':rc,'properties':dict(line.split('=',1) for line in stdout.decode(errors='replace').splitlines() if '=' in line),'stderr':public_lines(stderr)}
    rc,stdout,stderr=run(['journalctl','--unit='+UNIT,'--no-pager','--output=cat','--lines=70'],65536)
    save('journal-tail.txt',stdout+b'\nSTDERR\n'+stderr)
    report['journal']={'exitCode':rc,'tail':public_lines(stdout),'stderr':public_lines(stderr)}
    log=PREP/'sdk.log'
    try:
        fd=os.open(log,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno());need(stat.S_ISREG(info.st_mode) and info.st_uid in (0,1204),'Unexpected SDK log')
            f.seek(max(0,info.st_size-65536));data=f.read(65536)
        save('sdk-tail.txt',data);report['sdkLog']={'present':True,'tail':public_lines(data)}
    except FileNotFoundError:report['sdkLog']={'present':False}
    for name in ('owner.json','replicas.json','release.json'):
        try:
            data=regular(PREP/'provider'/name,1024**2);value=json.loads(data);save(name,data)
            summary={key:value[key] for key in ('state','role','mode','ownerId','manifestSha256','errorType','reason','cleanupError',
                'finalize_acknowledged','base_post_sha256_verified','importObject','imports') if key in value}
            report[name]={'present':True,'sha256':hashlib.sha256(data).hexdigest(),'summary':summary}
        except FileNotFoundError:report[name]={'present':False}
    report['obmm']={'referenceCount':Path('/sys/module/obmm/refcnt').read_text().strip(),
                   'regionDevices':sorted(p.name for p in Path('/sys/devices/obmm').glob('obmm_shmdev*'))}
    save('report.json',(json.dumps(report,indent=2)+'\n').encode())
    return report


if __name__=='__main__':
    try:
        report=inspect();code=0
    except Exception as error:
        report={'status':'HOST_PMEM_B_INSPECTION_STOPPED_NO_ACTION','reason':str(error)};code=1
    print('BEGIN_HOST_PMEM_B_SDK_START_INSPECTION');print(json.dumps(report,indent=2));print('END_HOST_PMEM_B_SDK_START_INSPECTION')
    raise SystemExit(code)
