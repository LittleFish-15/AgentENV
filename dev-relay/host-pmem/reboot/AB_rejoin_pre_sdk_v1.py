"""Explicit new transaction only when the previous run never attempted maintenance or publication."""
import fcntl,hashlib,json,os,platform,sys,types
from pathlib import Path
B=Path('/var/lib/agentenv-hpab-services-v1')
PIN='1f388bb505c655bfd0b494f20f4ab13ad7e2b3ab57f34cbf525e72b350e89358'
def main():
    assert os.getuid()==os.geteuid()==0
    p=B/'entry.py';raw=p.read_bytes();assert p.resolve()==p and p.stat().st_uid==0 and hashlib.sha256(raw).hexdigest()==PIN
    m=types.ModuleType('approved');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
    api=m.module('api');node={'server1':'node-a','agent1':'node-b'}[platform.node()]
    token=json.loads(m.read(m.CREDS,8192,owners=(1204,)))
    client=api.GitHub(token['controlToken']);client.private_repo(m.CONTROL,1438089258)
    code,data,_=client.contents(m.CONTROL,'reboot-recovery/'+m.SESSION+'/pre-sdk-rejoin-v1.json','main')
    assert code==200;spec=json.loads(data);auth=spec['approval']
    assert spec['repairSha256']==hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    assert auth['entrySha256']==PIN and auth['nodes'][node]['identity']==m.identity()
    m.put(B/'recover-pre-sdk.py',Path(__file__).read_bytes(),mode=0o600)
    m.put(B/'recover-pre-sdk.sh',b'#!/bin/bash\nset -eu\nexec /usr/bin/python3 -I -B /var/lib/agentenv-hpab-services-v1/recover-pre-sdk.py\n',mode=0o700)
    import time
    assert api.timestamp(auth['notBefore'])<=time.time()<api.timestamp(auth['expiresAt'])
    fd=os.open(B/'private/operation.lock',os.O_RDWR|os.O_NOFOLLOW)
    with os.fdopen(fd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        jp=B/'private/journal.json';j=json.loads(m.read(jp));old=json.loads(m.read(B/'private/approval.json'))
        if j['runId']!=auth['runId']:
            assert j['runId']==spec['previousRunId'] and j['entrySha256']==PIN
            assert not j['units'] and j['SDK_called'] is False and not j.get('terminal')
            assert set(j['steps'])<= {'export_code','compile_helpers','lookup_old'}
            assert j['steps']['export_code']['state']=='done'
            assert not Path('/var/lib/agentenv-hpab-module-v1').exists()
            assert Path('/sys/module/obmm/srcversion').read_text().strip()=='B2D1EBF7E6C2BB3EF877E36'
            assert Path('/sys/module/obmm/refcnt').read_text().strip()=='0'
            assert not list(Path('/dev').glob('obmm_shmdev*'))
            archive=B/'private'/('archive-'+spec['previousRunId']);m.folder(archive,mode=0o700)
            m.put(archive/'journal.json',m.read(jp),mode=0o600)
            m.put(archive/'approval.json',m.read(B/'private/approval.json'),mode=0o600)
            original=json.loads(m.read(Path(old['nodes'][node]['planPath'])))
            assert api.digest(api.encoded(original))==old['nodes'][node]['planSha256']
            plan=dict(original,identity=m.identity())
            assert api.digest(api.encoded(plan))==auth['nodes'][node]['planSha256']
            m.put(Path(auth['nodes'][node]['planPath']),api.encoded(plan),mode=0o600)
            fresh={'version':1,'node':node,'runId':auth['runId'],'identity':m.identity(),
                'entrySha256':PIN,'steps':{'export_code':j['steps']['export_code']},'units':{},
                'phase':'new_boot_pre_sdk_recovery','SDK_called':False,'Guest_created':False,
                'logicalUbBytes':m.BYTES,'physicalHardQuota':False,'netSavingsBytes':None,
                'previousTransactionArchive':str(archive)}
            tmp=B/'private/rejoin-journal.next';m.put(tmp,m.wire(fresh)+b'\n',mode=0o600);os.replace(tmp,jp)
        else:assert j['identity']==m.identity()
        tmp=B/'private/rejoin-approval.next';m.put(tmp,api.encoded(auth),mode=0o600);os.replace(tmp,B/'private/approval.json')
        sync=os.open(jp.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(sync);os.close(sync)
    print('PRE_SDK_REBOOT_RECOVERY_BOUND_CONTINUING',flush=True)
    os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(p),'start'])
if __name__=='__main__':main()
