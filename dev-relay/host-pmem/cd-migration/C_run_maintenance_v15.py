"""Restore only owned temporary device ACLs after SDK process exit.

The global UB creation remains unresolved. No SDK call, object deletion,
service stop, group removal or module operation is performed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

ROOT=Path('/var/lib/agentenv-hpc2')
WORK=Path('/home/jwk/agent/r/hpc1')
PARENT=Path('/var/lib/agentenv-c-rootfs-preflight-v1')
SCOPE='C_T1_LOCAL_ACL_RESTORE_KEEP_UNRESOLVED_UB_OBJECT'
ALLOWED=('/dev/obmm','/dev/ublk-control')

def need(ok,message):
    if not ok:raise RuntimeError(message)

def trusted(path,limit=524288):
    s=path.stat()
    need(path.resolve()==path and s.st_uid==0 and not s.st_mode&0o022 and stat.S_ISREG(s.st_mode) and s.st_size<=limit,'Untrusted local recovery input')
    return path.read_bytes()

def validate_backup(path,raw):
    need(path in ALLOWED,'ACL target not in owned allowlist')
    files=[line[len('# file: '):] for line in raw.decode().splitlines() if line.startswith('# file: ')]
    need(files==[path],'ACL backup target differs or has multiple files')

def restore_one(m,api,item,record):
    path=item['path'];need(path in ALLOWED,'Unknown ACL target')
    s=Path(path).lstat()
    need(stat.S_ISCHR(s.st_mode) and s.st_ino==item['inode'] and s.st_rdev==item['rdev'],'Device identity changed; preserve ACL')
    need(item['backup']=='acl-'+Path(path).name+'.txt','Unexpected ACL backup name')
    backup=ROOT/item['backup'];original=trusted(backup,16384);validate_backup(path,original)
    current=m.checked([m.tool('getfacl'),'-p',path])
    entry={'path':path,'originalSha256':hashlib.sha256(original).hexdigest(),'restored':False}
    record['acl'].append(entry)
    if current!=original:
        need(hashlib.sha256(current).hexdigest()==item['appliedAclSha256'],'ACL changed outside this task; preserve it')
        entry['restoreIntent']=True;api.atomic(ROOT/'local-acl-recovery.json',record)
        m.checked([m.tool('setfacl'),'--restore='+str(backup)])
    need(m.checked([m.tool('getfacl'),'-p',path])==original,'ACL restoration not confirmed')
    entry['restored']=True;api.atomic(ROOT/'local-acl-recovery.json',record)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('activate',));parser.add_argument('--approval');args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0 and args.approval=='C_NATIVE_ADAPTER_BUILD_OBMM_SWITCH_EXPLICIT_RESTORE','Approved C local recovery required')
    expected=json.loads(trusted(PARENT/'receipt.json'))
    need(expected['machineId']==Path('/etc/machine-id').read_text().strip() and expected['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'C identity changed')
    driver=Path('/var/lib/agentenv-root-relay/jobs/root-c-t1-scoped-004/driver.py')
    need(hashlib.sha256(trusted(driver,131072)).hexdigest()=='9de59dfe89ba543498d168be57128769fb7e6fadfa9ac7d9c779675f40e657ea','Fixed helpers differ')
    spec=importlib.util.spec_from_file_location('helpers',driver);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    recovery=Path('/var/lib/agentenv-root-relay/jobs/root-c-t1-group-006/driver.py')
    need(hashlib.sha256(trusted(recovery,131072)).hexdigest()=='f830e1b3d1086c4b04e9922ff0dbc7461beb3c72e3122251bd6636a81cdbfbb2','Group identity helper differs')
    spec=importlib.util.spec_from_file_location('group_helpers',recovery);g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
    state_raw=trusted(ROOT/'journal.json');state=json.loads(state_raw)
    need(state['unknownCreate'] is False and state['guests']['original']==[] and state['units']['original']['stopped'] is True
         and 'publication' not in state and 'view' not in state['units'],'Unexpected consumers/publication; no ACL action')
    owner_path=WORK/'sdk-owner/owner.json';s=owner_path.stat()
    need(owner_path.resolve()==owner_path and s.st_uid==1204 and not s.st_mode&0o022 and s.st_size<=131072,'Owner journal differs')
    owner_raw=owner_path.read_bytes();owner=json.loads(owner_raw)
    need(hashlib.sha256(owner_raw).hexdigest()=='8872de656db8e27d420a5626a120011acc3fa7ee23108c2ca3885803d76759b4'
         and owner['state']=='unresolved_create' and owner['finalize_acknowledged'] is True,'SDK outcome changed; preserve')
    for label in ('original','sdk'):
        row=m.unit(state['units'][label]['name'])
        need(row['MainPID']=='0' and row['ActiveState'] in ('inactive','failed') and row['Job'] in ('','0'),'Owned process not fully exited')
    need(not g.process_rows(m,gid=state['reservedRuntimeGid']),'Reserved group has processes')
    need(not (ROOT/'view').exists() and Path('/sys/module/obmm/refcnt').read_text().strip()=='0'
         and not list(Path('/dev').glob('obmm_shmdev*')),'Local UB consumers may remain; preserve')
    need(sorted(x['path'] for x in state['acl'])==sorted(ALLOWED),'Unexpected ACL list')
    ns={'__name__':'root_transport'};exec(compile(trusted(Path('/var/lib/agentenv-root-relay/root-relay.py'),262144),'<transport>','exec'),ns);api=ns['api_module']()
    need(not (ROOT/'local-acl-recovery.json').exists(),'Prior local recovery intent exists; inspect it, do not overwrite')
    record={'scope':SCOPE,'status':'C_LOCAL_ACCESS_RECOVERY_STARTED','acl':[],
        'globalObjectState':'unresolved_create','globalObjectDeletionAcknowledged':False,'globalObjectAbsentProven':False,
        'SDKCalled':False,'servicesChanged':False,'moduleChanged':False,'groupRemoved':False,'pendingCleared':False}
    api.atomic(ROOT/'local-acl-recovery.json',record)
    target=PARENT/'maintenance-activate-v1.json';backup=PARENT/'maintenance-activate-before-local-acl-recovery.json'
    need(not backup.exists(),'Previous evidence backup exists; preserve');m.write(backup,trusted(target))
    try:
        for item in state['acl']:restore_one(m,api,item,record)
        need(trusted(ROOT/'journal.json')==state_raw and owner_path.read_bytes()==owner_raw,'Global/controller journal changed concurrently')
        record.update(status='C_LOCAL_ACCESS_RESTORED_GLOBAL_UB_INTENT_PRESERVED',localAclRestored=True,ownerJournalUnchanged=True)
    except BaseException as error:
        record.update(status='C_LOCAL_ACCESS_RECOVERY_STOPPED_PRESERVE_STATE',reason=str(error));raise
    finally:
        api.atomic(ROOT/'local-acl-recovery.json',record);api.atomic(target,record);os.chmod(target,0o640)
        print(json.dumps(record))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'C_LOCAL_ACL_RECOVERY_STOPPED','reason':str(error)}));raise SystemExit(1)
