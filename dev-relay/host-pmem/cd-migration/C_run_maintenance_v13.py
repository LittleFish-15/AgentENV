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

SCOPE='C_T1_READONLY_SDK_PUBLICATION_RECONCILIATION'
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

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('activate',));parser.add_argument('--approval');args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0 and args.approval=='C_NATIVE_ADAPTER_BUILD_OBMM_SWITCH_EXPLICIT_RESTORE','C root read-only task required')
    identity=json.loads(trusted(PARENT/'receipt.json',524288))
    need(identity['machineId']==Path('/etc/machine-id').read_text().strip() and identity['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'C context changed')
    raw=trusted(DRIVER,131072);need(hashlib.sha256(raw).hexdigest()==DRIVER_SHA,'Pinned helper driver differs')
    spec=importlib.util.spec_from_file_location('read_functions',DRIVER);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    before=trusted(ROOT/'journal.json',524288);state=json.loads(before)
    need(hashlib.sha256(state['runId'].encode()).hexdigest()==RUN_ID_SHA and state['sdkLaunchAttempted']
         and state['unknownCreate'] is False and state['units']['original']['stopped'] is True
         and state['guests']['original']==[] and 'publication' not in state and 'view' not in state['units'],
         'Unexpected pending publication state; no action')
    key=(WORK/'original/state/secrets/api-key').read_text().strip()
    need(32<=len(key)<=256,'Local redaction key format differs')
    row={'scope':SCOPE,'status':'C_T1_SDK_PUBLICATION_INSPECTED_NO_ACTION','runId':state['runId'],
         'SDKCalledByDiagnostic':False,'GuestRequestedByDiagnostic':False,'servicesChanged':False,
         'permissionsChanged':False,'allocationRetried':False,'pendingCleared':False,
         'unit':m.unit(state['units']['sdk']['name']),'sdkLog':log_tail(ROOT/'sdk.log',key),'ownerFiles':{}}
    owner=WORK/'sdk-owner'
    for name in ('owner.json','replicas.json','release.json','stored-owner.json'):
        path=owner/name
        if not path.exists():row['ownerFiles'][name]={'present':False};continue
        meta=path.stat()
        need(owner.resolve()==owner and owner.stat().st_uid==1204 and not owner.stat().st_mode&0o077
             and path.resolve()==path and meta.st_uid==1204 and not meta.st_mode&0o022
             and stat.S_ISREG(meta.st_mode) and meta.st_size<=131072,'Owner journal untrusted or too large')
        data=path.read_bytes()
        row['ownerFiles'][name]={'present':True,'sha256':hashlib.sha256(data).hexdigest(),'data':redact(json.loads(data),key)}
    row['ownerDirectoryPresent']=owner.exists()
    row['kernel']={'obmmReferences':Path('/sys/module/obmm/refcnt').read_text().strip(),
        'regionDevices':[p.name for p in Path('/dev').glob('obmm_shmdev*')],
        'scope':'Observation only, not proof that global allocations are absent'}
    row['viewDirectoryPresent']=(ROOT/'view').exists()
    row['journalUnchanged']=trusted(ROOT/'journal.json',524288)==before
    need(row['journalUnchanged'],'Controller journal changed during collection')
    target=PARENT/'maintenance-activate-v1.json';backup=PARENT/'maintenance-activate-before-sdk-inspection.json'
    need(not backup.exists(),'Previous SDK inspection preserved; do not repeat')
    m.write(backup,trusted(target,524288))
    payload=(json.dumps(redact(row,key),ensure_ascii=False,indent=2)+'\n').encode()
    need(len(payload)<=384*1024,'Read-only report exceeds limit')
    temporary=PARENT/'sdk-inspection.next.json';m.write(temporary,payload,gid=1205,mode=0o640);os.replace(temporary,target)
    print(json.dumps({'status':row['status'],'journalUnchanged':True,'allocationRetried':False}))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'C_SDK_READONLY_INSPECTION_STOPPED','reason':str(error)}));raise SystemExit(1)
