"""Read-only reconciliation of one unacknowledged original Guest creation.

No new Guest request, SDK call, service stop, permission or pending-journal change.
Reports remain in the private relay. Never infer non-creation from an empty list.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

SCOPE='C_T1_SMOKE_READONLY_CREATE_RECONCILIATION'
PARENT=Path('/var/lib/agentenv-c-rootfs-preflight-v1')
ROOT=Path('/var/lib/agentenv-hpc1')
WORK=Path('/home/jwk/agent/r/hpc1')
DRIVER=Path('/var/lib/agentenv-root-relay/jobs/root-c-t1-scoped-004/driver.py')
DRIVER_SHA='9de59dfe89ba543498d168be57128769fb7e6fadfa9ac7d9c779675f40e657ea'
RUN_ID_SHA='e422d6cc93fea8dc0e5796f4b1d6661944ba2489c6abb065eef63e8987d9f9ae'

def need(value,message):
    if not value:raise RuntimeError(message)

def trusted(path,limit):
    need(path.resolve()==path,'Private path redirected')
    info=path.stat()
    need(info.st_uid==0 and not info.st_mode&0o022 and stat.S_ISREG(info.st_mode) and info.st_size<=limit,'Private evidence differs')
    return path.read_bytes()

def redact(value,secret):
    if isinstance(value,dict):
        return {key:('[REDACTED]' if re.search('token|secret|password|api.?key|authorization',key,re.I)
                     else redact(item,secret)) for key,item in value.items()}
    if isinstance(value,list):return [redact(item,secret) for item in value]
    if isinstance(value,str):
        if secret:value=value.replace(secret,'[REDACTED]')
        value=re.sub(r'(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+',r'\1[REDACTED]',value)
        value=re.sub(r'(?i)((?:api[_-]?key|access[_-]?token|envdAccessToken|password|authorization)["\s:=]+)[^"\s,}]+',r'\1[REDACTED]',value)
    return value

def log_tail(path,secret):
    if not path.exists():return {'present':False}
    need(path.resolve()==path and stat.S_ISREG(path.stat().st_mode),'Log path redirected')
    with path.open('rb') as stream:
        total=os.fstat(stream.fileno()).st_size;stream.seek(max(0,total-49152));raw=stream.read(49152)
    lines=[]
    for line in raw.decode('utf-8','replace').splitlines():
        try:lines.append(redact(json.loads(line),secret))
        except ValueError:lines.append(redact(line,secret))
    return {'present':True,'bytesOnDisk':total,'tailOnly':total>49152,'tail':lines}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('activate',));parser.add_argument('--approval')
    args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0 and args.approval=='C_NATIVE_ADAPTER_BUILD_OBMM_SWITCH_EXPLICIT_RESTORE','Fixed C root diagnostic required')
    identity=json.loads(trusted(PARENT/'receipt.json',524288))
    need(identity['machineId']==Path('/etc/machine-id').read_text().strip()
         and identity['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'C context differs')
    raw=trusted(DRIVER,131072);need(hashlib.sha256(raw).hexdigest()==DRIVER_SHA,'Fixed failed driver differs')
    spec=importlib.util.spec_from_file_location('failed_demo',DRIVER);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    journal_path=ROOT/'journal.json';before=trusted(journal_path,524288);state=json.loads(before)
    need(hashlib.sha256(state['runId'].encode()).hexdigest()==RUN_ID_SHA and state['phase']=='stopped_preserve_resources'
         and state['unknownCreate']=={'attempt':0,'variant':'original'} and not state['SDK_called'],'Unexpected pending state; no action')
    unit_row=state['units']['original'];status=m.unit(unit_row['name'])
    row={'scope':SCOPE,'status':'C_T1_CREATE_RECONCILIATION_READONLY_COLLECTED',
         'runId':state['runId'],'pendingCreate':state['unknownCreate'],'unit':status,
         'GuestCreationOutcome':'Unconfirmed; empty inventory alone never clears pending',
         'SDKCalledByDiagnostic':False,'GuestRequestedByDiagnostic':False,'permissionsChanged':False,
         'servicesChanged':False,'pendingCleared':False,'logs':{}}
    key=(WORK/'original/state/secrets/api-key').read_text().strip()
    need(32<=len(key)<=256,'API key format differs')
    for label,path in (('runtime',ROOT/'original.log'),('ublk',WORK/'original/logs/ublk.log'),('permissions',ROOT/'ublk-permissions.jsonl')):
        row['logs'][label]=log_tail(path,key)
    active=status['ActiveState']=='active' and status['MainPID']==str(unit_row['pid']) and m.ticks(unit_row['pid'])==unit_row['ticks'] and status['Description']==unit_row['description']
    row['ownedRuntimeIdentityStable']=active
    if active:
        demo=m.Demo(state,{},None)
        row['cli']={}
        for label,args in (('inventory',['list','--output','json']),('startHelp',['start','--help'])):
            try:
                result=demo.cli('original',args,30)
                value={'exitCode':result.returncode}
                for field,data in (('stdout',result.stdout),('stderr',result.stderr)):
                    need(len(data)<=65536,'Read-only CLI output exceeds bound')
                    try:value[field]=redact(json.loads(data),key)
                    except ValueError:value[field]=redact(data.decode('utf-8','replace'),key)
                row['cli'][label]=value
            except Exception as error:row['cli'][label]={'error':redact(str(error),key)}
    owned=[];denied=0;complete=True;end=time.monotonic()+8
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():continue
        if time.monotonic()>end:complete=False;break
        try:
            cgroup=(proc/'cgroup').read_text()
            if not any(line.split(':',2)[2].endswith('/'+unit_row['name']) for line in cgroup.splitlines()):continue
            start=m.ticks(int(proc.name))
            owned.append({'pid':int(proc.name),'ticks':start,'comm':(proc/'comm').read_text().strip(),
                          'executable':os.readlink(proc/'exe'),'stable':m.ticks(int(proc.name))==start})
        except (FileNotFoundError,ProcessLookupError):continue
        except PermissionError:denied+=1;complete=False
    row.update(ownedProcesses=owned,ownedProcessScanComplete=complete,processScanDenied=denied)
    row['ublkInventory']=m.ublk_devices()
    row['ublkOwners']=[]
    need(hashlib.sha256(trusted(ROOT/'ublk-owner-query',65536)).hexdigest()==
         '0aaedab15e5171d40722dc3ac0b02f4378e7750b406c8b2dbeba4386b4e52b04','Read-only device query helper changed')
    for name in row['ublkInventory']:
        if not name.startswith('ublkc'):continue
        need(len(row['ublkOwners'])<64,'Device query bound exceeded')
        result=m.command([str(ROOT/'ublk-owner-query'),name[5:]],2)
        row['ublkOwners'].append({'device':name,'exitCode':result.returncode,
            'info':json.loads(result.stdout) if result.returncode==0 else None})
    row['journalUnchanged']=trusted(journal_path,524288)==before
    need(row['journalUnchanged'],'Pending journal changed concurrently; do not reconcile from this capture')
    target=PARENT/'maintenance-activate-v1.json';backup=PARENT/'maintenance-activate-before-create-reconciliation.json'
    need(not backup.exists(),'Previous reconciliation preserved; do not repeat')
    m.write(backup,trusted(target,524288))
    payload=(json.dumps(redact(row,key),ensure_ascii=False,indent=2)+'\n').encode()
    need(len(payload)<=384*1024,'Diagnostic report exceeds bound')
    temporary=PARENT/'create-reconciliation.next.json';m.write(temporary,payload,gid=1205,mode=0o640)
    os.replace(temporary,target)
    print(json.dumps({'status':row['status'],'ownedRuntimeIdentityStable':active,
                      'journalUnchanged':row['journalUnchanged'],'pendingCleared':False}))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'C_T1_READONLY_RECONCILIATION_STOPPED','errorType':type(error).__name__,'reason':str(error)}))
        raise SystemExit(1)
