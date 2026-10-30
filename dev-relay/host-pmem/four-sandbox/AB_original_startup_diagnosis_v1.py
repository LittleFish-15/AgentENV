"""Read the failed original service startup only. No start/stop/Guest actions."""
import hashlib,json,os,stat,subprocess,sys,types
from pathlib import Path
BASE=Path('/home/jwk/root/original-t1')
PIN='78dc13208bda586473d01416426b8023d75a5a080c12623efb15fc07f883f61b'

def main():
    entry=BASE/'original-entry.py';raw=entry.read_bytes()
    if os.geteuid()!=0 or entry.resolve()!=entry or entry.stat().st_uid!=0 or hashlib.sha256(raw).hexdigest()!=PIN:
        raise RuntimeError('Expected installed root original entry')
    m=types.ModuleType('original_diagnosis');m.__file__=str(entry);sys.modules[m.__name__]=m
    exec(compile(raw,str(entry),'exec'),m.__dict__)
    node={'server1':'node-a','agent1':'node-b'}.get(__import__('socket').gethostname());m.need(node,'Only A/B')
    work=BASE/node;started=json.loads(m.read(work/'started.json'))
    m.need(started['identity']==m.identity() and started['sourceSha256']==PIN,'Different startup identity')
    m.need(not (work/'cohort.json').exists(),'Guest phase exists; not this startup failure')
    units=json.loads(m.read(work/'units.json'));m.need(set(units)=={'runtime'},'Different unit transaction')
    unit=units['runtime'];m.need(unit['state']=='launch_intent' and unit['name']=='aenv-original-t1-'+node[-1]+'-runtime-1030r1.service','Not the acknowledged failed launch')
    api=m.load_module('startup_transport',m.decode(m.BUNDLED['API']))
    tokens=json.loads(m.read(Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json'),8192))
    result=api.GitHub(tokens['resultToken']);result.private_repo(m.RESULTS,1438089386)
    key=''
    for line in m.read(work/'runtime.env',16384).decode().splitlines():
        if line.startswith('AENV_API_KEY='):key=line.split('=',1)[1]
    def command(argv,limit):
        p=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=20)
        return {'exitCode':p.returncode,'stdout':api.redact(p.stdout[-limit:],[key,*tokens.values()]).decode(errors='replace'),
            'stderr':api.redact(p.stderr[-2048:],[key,*tokens.values()]).decode(errors='replace'),'truncated':len(p.stdout)>limit}
    report={'status':'ORIGINAL_STARTUP_INSPECTED_NO_ACTION','identity':m.identity(),'unit':unit,
        'properties':command(['systemctl','show',unit['name'],'--no-pager',
            '--property=MainPID,ActiveState,LoadState,Result,ExecMainCode,ExecMainStatus,ExecStart,ExecStartPre,User,Group,SupplementaryGroups,Description,ControlGroup'],4096),
        'journal':command(['journalctl','-b','-u',unit['name'],'--no-pager','-n','40','-o','short-precise'],8192),
        'paths':[],'servicesChanged':False,'GuestCreated':False,'SDKCalled':False}
    for p in [Path('/home/jwk'),Path('/home/jwk/root'),BASE,BASE/'public',BASE/'public'/('exec-'+node[-1]+'.py'),
              BASE/'public'/('runtime-'+node[-1]+'.toml'),Path('/home/jwk/root/orig-'+node[-1]),
              Path('/home/jwk/agent/deployments/agentenv-ae9c626-baseline/bin/server')]:
        try:
            st=p.stat();report['paths'].append({'path':str(p),'uid':st.st_uid,'gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode)),
                'size':st.st_size,'securityCapabilityPresent':bool(os.getxattr(p,'security.capability')) if p.is_file() else None})
        except OSError as e:
            if 'st' in locals() and p.exists():report['paths'].append({'path':str(p),'uid':p.stat().st_uid,'mode':oct(stat.S_IMODE(p.stat().st_mode)),'capabilityUnavailableErrno':e.errno})
            else:report['paths'].append({'path':str(p),'errno':e.errno})
    m.need(len(m.wire(report))<20*1024,'Diagnosis exceeds small upload bound')
    ctx=object.__new__(m.OriginalContext);ctx.node=node;ctx.pin=PIN;ctx.expected={'identity':m.identity()};ctx.work=work;ctx.results=result;ctx.transport=api
    ctx.event('startup-diagnosis-v1',report)
    print('ORIGINAL_STARTUP_DIAGNOSIS_UPLOADED_NO_SERVICES_CHANGED',flush=True)

if __name__=='__main__':main()
