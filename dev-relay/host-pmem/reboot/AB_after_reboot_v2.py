"""Fixed manual A/B reboot inspection and private upload; never restarts SDK or services."""
import hashlib,json,os,platform,stat,sys,types,uuid
from pathlib import Path
B=Path('/var/lib/agentenv-hpab-services-v1')
PINS={'b072e78f6cd206537a1b06dd1b4efbfaa98fbe38213a3cc944e900764abae927',
      '1f388bb505c655bfd0b494f20f4ab13ad7e2b3ab57f34cbf525e72b350e89358'}

def main():
    assert os.getuid()==os.geteuid()==0 and sys.argv[1:] in ([],['--install'])
    os.umask(0o077)
    p=B/'entry.py';st=p.lstat()
    assert p.resolve()==p and stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022 and st.st_size<=256*1024
    raw=p.read_bytes();pin=hashlib.sha256(raw).hexdigest();assert pin in PINS
    m=types.ModuleType('known_entry');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
    api=m.module('api');auth=json.loads(m.read(B/'private/approval.json',owners=(0,)))
    node={'server1':'node-a','agent1':'node-b'}[platform.node()];current=m.identity();old=auth['nodes'][node]['identity']
    assert current['machineId']==old['machineId'] and current['hostname']==old['hostname']
    if sys.argv[1:]==['--install']:
        data=Path(__file__).read_bytes()
        target=B/'after-reboot.py'
        if target.exists() and m.read(target)!=data:
            prior=m.read(target,owners=(0,))
            assert hashlib.sha256(prior).hexdigest()=='6878a0d3accacfc5ba61d3fad2c5a1adc737afb5055b1c20bd2dd8a2442177aa'
            m.put(B/'after-reboot-v1.backup.py',prior,mode=0o600)
            temp=B/'after-reboot-v2.next';m.put(temp,data,mode=0o600);os.replace(temp,target)
        else:m.put(target,data,mode=0o600)
        m.put(B/'after-reboot.sh',b'#!/bin/bash\nset -eu\numask 077\nexec /usr/bin/python3 -I -B /var/lib/agentenv-hpab-services-v1/after-reboot.py\n',mode=0o700)
    journal=json.loads(m.read(B/'private/journal.json',owners=(0,)))
    units=set(['ubse.service','ubsmd.service'])
    units.update(r['name'] for r in journal.get('units',{}).values())
    assert len(units)<=16
    fields=('identity','runId','entrySha256','phase','steps','units','SDK_called','terminal','sdkReleased','publicationNotAttempted','failure')
    report={'schema':1,'status':'AB_POST_REBOOT_INSPECTED_NO_ACTION','node':node,'identity':current,
        'priorApprovedIdentity':old,'bootChanged':current['bootId']!=old['bootId'],
        'entrySha256':pin,'runId':auth['runId'],'oldJournal':{k:journal[k] for k in fields if k in journal},
        'units':{name:m.props(name) for name in sorted(units)},'modules':{},
        'SDKCalled':False,'servicesChanged':False,'moduleChanged':False,'oldJournalChanged':False,
        'sharedObjectReleaseInferred':False}
    for name in ('obmm','ublk_drv'):
        r={}
        for field in ('srcversion','refcnt','parameters/pmem_ro_enable'):
            try:r[field]=Path('/sys/module',name,field).read_text().strip()
            except OSError as e:r[field]={'unavailable':type(e).__name__}
        report['modules'][name]=r
    runtime=journal.get('units',{}).get('runtime')
    if runtime:
        import tomllib
        plan=json.loads(m.read(Path(auth['nodes'][node]['planPath'])))
        credentials=Path(plan['workDirectory'])/'active/cli/aenv/credentials'
        secrets=[]
        if credentials.exists():secrets.append(tomllib.loads(m.read(credentials).decode())['api_key'])
        details=m.cmd([m.tool('systemctl'),'show',runtime['name'],'--no-pager',
            '--property=ExecStart,ExecStartPre,ExecMainCode,ExecMainStatus,Result,InvocationID,User,Group,SupplementaryGroups'],check=False)
        log=m.cmd([m.tool('journalctl'),'-b','-u',runtime['name'],'--no-pager','-n','60','-o','short-precise'],check=False)
        report['runtimeDiagnostics']={'unit':runtime['name'],'propertiesExit':details.returncode,
            'properties':api.redact(details.stdout[:32768],secrets).decode(errors='replace'),
            'journalExit':log.returncode,'journal':api.redact(log.stdout[:65536],secrets).decode(errors='replace'),
            'journalTruncated':len(log.stdout)>65536}
    report['regionDeviceNames']=[p.name for p in Path('/dev').glob('obmm_shmdev*')]
    ident='reboot-'+uuid.uuid4().hex
    target=B/'private'/(ident+'.json');api.atomic(target,report)
    tokens=json.loads(m.read(m.CREDS,8192,owners=(1204,)))
    client=api.GitHub(tokens['resultToken']);client.private_repo(m.RESULTS,1438089386)
    key='hpab-reboots/'+m.SESSION+'/'+node+'/'+ident+'.json'
    client.immutable_result(m.RESULTS,1438089386,'main',key,api.encoded(report))
    print('AB_POST_REBOOT_REPORT_UPLOADED_NO_SERVICES_CHANGED node='+node)

if __name__=='__main__':
    try:main()
    except Exception as e:
        print('AB_POST_REBOOT_STOPPED_PRESERVE_STATE errorType='+type(e).__name__)
        raise SystemExit(1)
