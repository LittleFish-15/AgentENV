"""Check and start only the retained B original services; never recreate units."""
import fcntl,hashlib,http.client,json,os,platform,stat,subprocess,time,tomllib
from pathlib import Path
BASE=Path('/home/jwk/root/hpo-services-v1')
ACTIVE=Path('/home/jwk/agent/r/hpo-b-v1/active')
DEP=Path('/home/jwk/agent/deployments/agentenv-ae9c626-baseline')
OUT=Path('/home/jwk/root/b-original-check-start-20261109')
PINS={'bin/server':'0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff','bin/aenv':'ac2cf76020ce2ed0cf06f1105e06c34534a35ed8247fca0cb57e2d53269771e1','bin/uvm-ublk-daemon':'13bd2ac381cf877348a39c0b198e2061479ae237c0f54cbcbeae0ab14e700172','deps/firecracker/1.15.1-patch-v3/firecracker':'a64b8f068d47bd6ec85aa755b8f8863e16d0ae14be551376218fed401ee0bdf8'}
CONFIG_SHA='31bb09072bbfd74b2c2e41810cb19d4e118c0c56127283a1daff5fb041f5ee04'
REPORT={'status':'B_ORIGINAL_CHECKING','starts':[],'GuestCreated':False,'UBChanged':False,'compiled':False}
def need(ok,why):
    if not ok:raise RuntimeError(why)
def hashfile(p):
    with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def props(name):
    r=subprocess.run(['systemctl','show',name,'--no-pager','--property=LoadState,ActiveState,SubState,MainPID,Description,User,Group,ExecStart,ExecStartPre,ControlGroup,Result'],capture_output=True,text=True,timeout=15)
    need(r.returncode==0,'Cannot inspect '+name)
    return dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
def public(p):return {k:v for k,v in p.items() if k not in ('ExecStart','ExecStartPre')}
def save():
    temp=OUT/'report.next';temp.write_text(json.dumps(REPORT,indent=2),encoding='utf-8');os.chmod(temp,0o600);os.replace(temp,OUT/'report.json')
def health():
    c=http.client.HTTPConnection('127.0.0.1',18251,timeout=3)
    try:c.request('GET','/health');r=c.getresponse();r.read(4096);return r.status
    except (OSError,http.client.HTTPException):return None
    finally:c.close()
def main():
    os.umask(0o077)
    need(os.geteuid()==0 and platform.node()=='agent1','B root required')
    need(Path('/etc/machine-id').read_text().strip()=='ae1ee682fbf544ffb4828c403bf658f5','B machine identity differs')
    need(OUT.parent.resolve()==OUT.parent and not OUT.is_symlink(),'Output redirected')
    OUT.mkdir(mode=0o700,exist_ok=True);need(OUT.stat().st_uid==0 and not OUT.stat().st_mode&0o077,'Output permissions differ')
    need(not (OUT/'report.json').exists(),'Previous check preserved; collect before another attempt')
    REPORT['bootId']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    lock=os.open(BASE/'private/titanic-measure.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    j=json.loads((BASE/'private/journal.json').read_bytes())
    REPORT['previousBootId']=j['identity']['bootId'];REPORT['journalPhase']=j.get('phase')
    roles=('runtime','inside-proxy','host-proxy');before={}
    for label in roles:
        name='aenv-hpo-b-'+label+'-61103-v1.service'
        need(j['units'][label]['name']==name,'Owned unit journal differs')
        pr=props(name);before[label]=pr
    REPORT['before']={k:public(v) for k,v in before.items()};REPORT['healthBefore']=health()
    REPORT['unresolvedMarkerPresent']=(ACTIVE/'external-mutation-observed').exists();save()
    need(hashfile(BASE/'public/runtime.toml')==CONFIG_SHA,'Original config differs')
    cfg=tomllib.loads((BASE/'public/runtime.toml').read_text())
    need(not any('ub_rootfs' in k for k in cfg.get('snapshot',{})),'UB config found in original')
    for rel,pin in PINS.items():need(hashfile(DEP/rel)==pin,'Original binary differs: '+rel)
    for label,pr in before.items():
        need(pr.get('LoadState')=='loaded','Unit absent; explicit reconstruction required: '+label)
        need(pr['User'] in ('1204','jwk') and pr['Description']==j['units'][label]['description'],'Owned unit identity differs: '+label)
        command=pr['ExecStart']
        need(str(BASE/'public/runtime.toml') in command if label=='runtime' else str(BASE/'public/proxy.py') in command,'Unit command binding differs')
        need(pr['ActiveState'] in ('active','inactive','failed'),'Unit transitioning; preserve state')
    need(before['runtime']['ActiveState']=='active' or all(before[x]['ActiveState']!='active' for x in ('inside-proxy','host-proxy')),'Stale proxy namespace requires explicit recovery')
    if any(v['ActiveState']!='active' for v in before.values()):
        need(not REPORT['unresolvedMarkerPresent'],'Unresolved mutation marker; no service start')
        need(j['identity']['bootId']==REPORT['bootId'],'New boot requires original service reconstruction')
    for label in roles:
        name=j['units'][label]['name'];pr=props(name)
        if pr['ActiveState']!='active':
            REPORT['starts'].append({'unit':name,'state':'intent'});save()
            r=subprocess.run(['systemctl','start',name],capture_output=True,timeout=100)
            REPORT['starts'][-1].update(exitCode=r.returncode,state='returned');save()
            need(r.returncode==0,'Service start failed: '+label)
        if label=='runtime':
            pr=props(name);pid=int(pr['MainPID']);need(pid>0 and pr['ActiveState']=='active','Runtime process not active')
            need(hashfile(Path('/proc')/str(pid)/'exe')==PINS['bin/server'],'Live Runtime is not pinned original')
    end=time.monotonic()+45
    while time.monotonic()<end:
        if health()==204:break
        time.sleep(1)
    else:raise RuntimeError('Original API health not 204; preserve services and inspect')
    REPORT.update(status='B_ORIGINAL_AENV_HEALTHY',health=204,api='http://127.0.0.1:18251',cli=str(ACTIVE/'aenv-original'),after={x:public(props(j['units'][x]['name'])) for x in roles})
    save();print(json.dumps(REPORT,indent=2));print('B_ORIGINAL_AENV_HEALTHY')
if __name__=='__main__':
    try:main()
    except Exception as e:
        REPORT.update(status='B_ORIGINAL_STOPPED_PRESERVE_STATE',errorType=type(e).__name__,reason=str(e)[:500])
        if OUT.exists():
            # Never overwrite a previous invocation's report.
            p=OUT/('failure-'+str(time.time_ns())+'.json');p.write_text(json.dumps(REPORT,indent=2),encoding='utf-8')
        print(json.dumps(REPORT,indent=2));raise SystemExit(1)
