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

SCOPE='C_T1_READONLY_NC_ALLOCATION_REJECTION_EVIDENCE'
PARENT=Path('/var/lib/agentenv-c-rootfs-preflight-v1')
ROOT=Path('/var/lib/agentenv-hpc2')
WORK=Path('/home/jwk/agent/r/hpc1')
DRIVER=Path('/var/lib/agentenv-root-relay/jobs/root-c-t1-scoped-004/driver.py')
DRIVER_SHA='9de59dfe89ba543498d168be57128769fb7e6fadfa9ac7d9c779675f40e657ea'
RUN_ID_SHA='c9f8715145a4be23c6d59f6d6e15c7bfb8152d135ff322a9cc7cf31f1f1e87c3'

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

def target_lines(text,name):
    lines=text.splitlines();selected=set()
    for i,line in enumerate(lines):
        if name in line:
            selected.update(range(max(0,i-2),min(len(lines),i+3)))
    return [lines[i][:4096] for i in sorted(selected)[:120]]

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('activate',));parser.add_argument('--approval');args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0 and args.approval=='C_NATIVE_ADAPTER_BUILD_OBMM_SWITCH_EXPLICIT_RESTORE','C root read-only evidence required')
    expected=json.loads(trusted(PARENT/'receipt.json',524288))
    need(expected['machineId']==Path('/etc/machine-id').read_text().strip() and expected['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'C context changed')
    need(hashlib.sha256(trusted(DRIVER,131072)).hexdigest()==DRIVER_SHA,'Pinned read-only helpers changed')
    spec=importlib.util.spec_from_file_location('helpers',DRIVER);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    path=WORK/'sdk-owner/owner.json';s=path.stat()
    need(path.resolve()==path and s.st_uid==1204 and not s.st_mode&0o022 and s.st_size<=131072,'Owner journal untrusted')
    raw=path.read_bytes();owner=json.loads(raw)
    need(owner['state']=='unresolved_create' and owner['reason']=='SDK allocate failed: rc=6025'
         and owner['finalize_acknowledged'] is True and len(owner['objects'])==1,'Allocation outcome differs; no action')
    obj=owner['objects'][0];name=obj['replica']['objectName']
    need(re.fullmatch('aenv_[0-9a-f]{32}',name) and obj['allocation_attempted'] and not obj['creation_confirmed'],'Object intent differs')
    feature=Path('/sys/bus/ub/ub_feature')
    with feature.open('rb') as stream:feature_raw=stream.read(16385)
    need(len(feature_raw)<=16384,'Feature report exceeds bound')
    key=(WORK/'original/state/secrets/api-key').read_text().strip()
    row={'scope':SCOPE,'status':'C_NC_ALLOCATION_REJECTION_EVIDENCE_COLLECTED_NO_ACTION',
         'bootId':expected['bootId'],'ubFeature':feature_raw.decode('utf-8','replace'),
         'request':{'objectName':name,'logicalBytes':obj['replica']['mappingBytes'],'region':'default',
                    'flagsHex':'0x6','flags':['UBSM_FLAG_NONCACHE','UBSM_FLAG_WR_DELAY_COMP']},
         'ownerJournalSha256':hashlib.sha256(raw).hexdigest(),'ownerStatePreserved':True,
         'SDKCalledByDiagnostic':False,'allocationRetried':False,'pendingCleared':False,
         'servicesChanged':False,'permissionsChanged':False,'matchingLogs':[],
         'units':{u:m.unit(u) for u in ('ubse.service','ubsmd.service')}}
    # Only this allocation's time window; keep matching object lines plus context.
    result=m.command([m.tool('journalctl'),'-u','ubse.service','-u','ubsmd.service','--no-pager','-o','cat',
        '--since','@'+str(int(s.st_mtime)-120),'--until','@'+str(int(s.st_mtime)+120),'-n','400'],30)
    text=result.stdout[-2*1024**2:].decode('utf-8','replace')
    row['matchingLogs'].append({'source':'service-journal','exitCode':result.returncode,
        'truncated':len(result.stdout)>2*1024**2,'lines':redact(target_lines(text,name),key)})
    budget=16*1024**2;paths=[]
    for folder in (Path('/var/log/ubsm'),Path('/var/log/ubse')):
        if folder.is_dir() and folder.resolve()==folder:
            paths.extend(p for p in folder.iterdir() if not p.is_symlink() and p.is_file()
                and '.log' in p.name and p.stat().st_mtime>=s.st_mtime-120)
    paths=sorted(paths,key=lambda p:p.stat().st_mtime,reverse=True)[:16]
    for log in paths:
        if budget<=0:break
        take=min(2*1024**2,budget);budget-=take
        with log.open('rb') as stream:
            total=os.fstat(stream.fileno()).st_size;stream.seek(max(0,total-take));chunk=stream.read(take)
        matches=target_lines(chunk.decode('utf-8','replace'),name)
        row['matchingLogs'].append({'source':str(log),'bytesOnDisk':total,'tailOnly':total>take,'lines':redact(matches,key)})
    row['ownerStatePreserved']=path.read_bytes()==raw
    need(row['ownerStatePreserved'],'Owner journal changed while reading')
    row['matchingEvidenceFound']=any(x['lines'] for x in row['matchingLogs'])
    row['interpretationBoundary']='Current boot capability and matching logs only; no assumption of permanent hardware incapability or global object absence'
    target=PARENT/'maintenance-activate-v1.json';backup=PARENT/'maintenance-activate-before-nc-rejection.json'
    need(not backup.exists(),'Prior capability evidence preserved; no automatic repeat')
    m.write(backup,trusted(target,524288))
    payload=(json.dumps(redact(row,key),ensure_ascii=False,indent=2)+'\n').encode();need(len(payload)<=384*1024,'Evidence exceeds bound')
    temporary=PARENT/'nc-rejection.next.json';m.write(temporary,payload,gid=1205,mode=0o640);os.replace(temporary,target)
    print(json.dumps({'status':row['status'],'matchingEvidenceFound':row['matchingEvidenceFound'],'allocationRetried':False}))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'C_NC_READONLY_EVIDENCE_STOPPED','reason':str(error)}));raise SystemExit(1)
