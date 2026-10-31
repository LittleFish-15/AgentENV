"""Finish only the failed read-only API bridge; retain SDK, DAX and Runtime."""
import asyncio,hashlib,http.client,json,os,platform,re,socket,sys,time,types
from pathlib import Path
BASE=Path('/home/jwk/root/hpra-v1')
RESUME=Path('/home/jwk/root/relay/jobs/locality-a-dax-resume-004/task.py')
RESUME_SHA='a562f3ddcfe66da36db91588cbb47a3f1d2cece79c1ad01288888f6af181b2c9'
OLD_GUARD="assert re.fullmatch('/home/jwk/agent/r/hpab-[ab]-v1/active/api.sock',cfg['socket'])"
NEW_GUARD="assert re.fullmatch(r'/home/jwk/agent/r/hpab-[ab]-v1/(?:active|rejoin-r1)/api\\.sock',cfg['socket'])"


def need(ok,why):
    if not ok:raise RuntimeError(why)


def patched_proxy(raw):
    text=raw.decode()
    need(text.count(OLD_GUARD)==1,'Unexpected bridge source; refuse a broad replacement')
    changed=text.replace(OLD_GUARD,NEW_GUARD).encode()
    compile(changed,'<readonly-rejoin-proxy>','exec')
    return changed


def proxy_error_matches(log):
    return 'AssertionError' in log and OLD_GUARD in log


def main():
    need(os.getuid()==os.geteuid()==0 and platform.node()=='server1','A root only')
    os.umask(0o077)
    # The unified entry already pins this source. Reuse the last checked
    # continuation's root-input and provider-package verification functions.
    need(RESUME.resolve()==RESUME and RESUME.stat().st_uid==0 and not RESUME.stat().st_mode&0o022,
         'Previous continuation path/owner differs')
    raw=RESUME.read_bytes();need(hashlib.sha256(raw).hexdigest()==RESUME_SHA,'Previous continuation changed')
    proof=types.ModuleType('checked_rejoin_continuation');proof.__file__=str(RESUME)
    sys.modules[proof.__name__]=proof;exec(compile(raw,str(RESUME),'exec'),proof.__dict__)
    spec=proof.decode_spec(sys.argv[1:])
    current={'hostname':platform.node(),'machineId':Path('/etc/machine-id').read_text().strip(),
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'kernel':platform.release(),'architecture':platform.machine()}
    need(current==spec['identity'],'A boot/identity changed')
    raw=proof.checked_read(proof.PREVIOUS)
    need(hashlib.sha256(raw).hexdigest()==proof.PREVIOUS_SHA,'Composed driver changed')
    old=types.ModuleType('checked_rejoin_driver');old.__file__=str(proof.PREVIOUS)
    sys.modules[old.__name__]=old;exec(compile(raw,str(proof.PREVIOUS),'exec'),old.__dict__)
    before=proof.checked_read(BASE/'private/state.json');state=json.loads(before)
    need(state['identity']==current and state['phase']=='stopped_preserve_state'
         and state['failure']['reason']=='Owned inside-proxy process changed'
         and all(state['steps'][k]['state']=='done' for k in ('sdk','view','provenance','runtime'))
         and state['steps']['proxies']=={'state':'intent'}
         and set(state['units'])=={'sdk','view','runtime','inside-proxy'},'Unexpected incomplete service state')
    ctx=old.Rejoin.__new__(old.Rejoin);ctx.spec=spec;ctx.node='node-a';ctx.n='a'
    ctx.auth={'runId':'hpra-20261031-v1'};ctx.work=Path(spec['workDirectory']);ctx.active=ctx.work/'rejoin-r1';ctx.state=state
    ctx.api=types.SimpleNamespace(digest=lambda b:hashlib.sha256(b).hexdigest(),
        encoded=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode())
    ctx.plan=json.loads(old.read(Path(spec['planPath'])))
    need(old.digest(Path(spec['planPath']))==spec['planSha256'],'Retained plan changed')
    pubraw=proof.checked_read(BASE/'public/publisher.json');ctx.publication=json.loads(pubraw)
    need('sha256:'+ctx.api.digest(pubraw)==spec['manifestSha256'],'Publication changed')
    ctx.candidate_live()
    for label in ('sdk','view','runtime'):
        bound=ctx.bound(label)
        need(bound['pid']==spec['expectedRetainedPids'][label],'Retained service PID differs')
    need(state['steps']['provenance']['result']['sharedGraph']['matched'] is True,'Source graph not confirmed')
    proof.install_parent_path(old)
    failed=state['units']['inside-proxy'];status=old.props(failed['name'])
    need(status['MainPID']=='0' and status['ActiveState'] in ('failed','inactive')
         and status['LoadState'] in ('loaded','not-found'),'Old bridge is still active or unknown')
    if status['LoadState']=='loaded':
        need(status['Description']==failed['description'] and status['User']=='1204' and status['Group']=='1205',
             'Failed bridge identity differs')
    source=proof.checked_read(BASE/'public/proxy.py')
    need(source==old.source('proxy'),'Original bridge code changed')
    config=json.loads(proof.checked_read(BASE/'public/proxy.json'))
    need(config=={'port':18231,'socket':str(ctx.active/'api.sock')},'Bridge configuration differs')
    need(not (ctx.active/'api.sock').exists() and not (ctx.active/'api.sock').is_symlink(),
         'Unconfirmed existing UNIX socket; do not unlink')
    for label in ('inside-proxy-r2','host-proxy'):
        name='aenv-hpra-a-'+label+'-'+ctx.auth['runId'][-8:]+'.service'
        need(old.props(name)['LoadState']=='not-found','Continuation bridge unit already exists')
    with socket.socket() as port:port.bind(('127.0.0.1',18231))
    journal=old.cmd([old.tool('journalctl'),'-b','-u',failed['name'],'-n','60','--no-pager','-o','cat'],30).stdout
    need(len(journal)<=64*1024,'Bridge failure journal exceeds bound')
    print('BEGIN_PROXY_FAILURE_DIAGNOSIS',flush=True)
    print(journal.decode(errors='replace'),flush=True)
    print('END_PROXY_FAILURE_DIAGNOSIS',flush=True)
    need(proxy_error_matches(journal.decode(errors='replace')),'Actual bridge failure does not match the scoped path assertion')
    need(not (BASE/'private/proxy-resume-r1-before.json').exists(),'Proxy continuation already attempted')
    old.put(BASE/'private/proxy-resume-r1-before.json',before,mode=0o600)
    old.put(BASE/'private/proxy-failure-before.txt',journal,mode=0o600)
    fixed=patched_proxy(source)
    old.put(BASE/'public/proxy-rejoin-r1.py',fixed)
    state['reconciledProxyFailure']={'failure':state.pop('failure'),'failedUnit':state['units'].pop('inside-proxy'),
        'previousStep':state['steps']['proxies'],'beforeStateSha256':ctx.api.digest(before),
        'originalProxySha256':ctx.api.digest(source),'fixedProxySha256':ctx.api.digest(fixed)}
    ctx.mark('proxy_path_assertion_confirmed_and_fixed_existing_services_retained')
    try:
        common=['User=1204','Group=1205','NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=']
        rt=ctx.bound('runtime')
        inside=ctx.launch('inside-proxy-r2',['/usr/bin/python3','-I','-B',str(BASE/'public/proxy-rejoin-r1.py'),
             'inside',str(BASE/'public/proxy.json')],common+['PrivateNetwork=yes','JoinsNamespaceOf='+rt['name']])
        end=time.monotonic()+15
        while not (ctx.active/'api.sock').exists() and time.monotonic()<end:
            ctx.bound('inside-proxy-r2');time.sleep(.2)
        need((ctx.active/'api.sock').exists(),'New bridge socket not ready')
        need(os.stat('/proc/'+str(inside['pid'])+'/ns/net').st_ino==os.stat('/proc/'+str(rt['pid'])+'/ns/net').st_ino,
             'Bridge does not share the retained Runtime network namespace')
        state['units']['inside-proxy']=state['units'].pop('inside-proxy-r2')
        ctx.mark('inside_proxy_ready_in_retained_runtime_namespace')
        ctx.launch('host-proxy',['/usr/bin/python3','-I','-B',str(BASE/'public/proxy-rejoin-r1.py'),
             'host',str(BASE/'public/proxy.json')],common)
        end=time.monotonic()+20
        while time.monotonic()<end:
            ctx.bound('host-proxy');ctx.bound('inside-proxy')
            try:
                c=http.client.HTTPConnection('127.0.0.1',18231,timeout=3);c.request('GET','/health')
                r=c.getresponse();body=r.read(4096);c.close()
                if r.status==204 and body==b'':break
            except OSError:pass
            time.sleep(.5)
        else:raise RuntimeError('Host bridge health not confirmed; backing retained')
        need(old.zero_caps(ctx.bound('host-proxy')['pid']) and old.zero_caps(ctx.bound('inside-proxy')['pid']),
             'Bridge capabilities differ')
        sourcebase=Path(ctx.plan['sourceDeployment'])
        library=str(sourcebase/'native/lib')+':'+str(sourcebase/'native/fallback/lib')
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/home/jwk','LANG':'C','LC_ALL':'C',
             'LD_LIBRARY_PATH':library,'XDG_CONFIG_HOME':str(ctx.active/'cli')}
        answer=old.cmd([ctx.plan['binaries']['bin/aenv']['path'],'list','--output','json'],30,owner=True,env=env)
        need(json.loads(answer.stdout)==[],'Runtime is not empty; preserve consumers')
        wrapper=('#!/bin/sh\nexport HOME=/home/jwk\nexport XDG_CONFIG_HOME='+str(ctx.active/'cli')+'\n'
            'export LD_LIBRARY_PATH='+library+'\nexec '+ctx.plan['binaries']['bin/aenv']['path']+' "$@"\n').encode()
        old.put(ctx.active/'aenv-host-dax',wrapper,1204,1205,0o700)
        state['steps']['proxies']={'state':'done','result':{'health':204,'api':'http://127.0.0.1:18231',
            'CLI':str(ctx.active/'aenv-host-dax'),'initialSandboxCount':0,'Guest_created':False,'guestCreationEnabled':False}}
        for label in ('sdk','view','runtime'):ctx.bound(label)
        ctx.mark('A_REJOINED_DAX_RUNTIME_HEALTHY_NO_GUEST')
        print('BEGIN_A_REJOIN_RESULT_JSON',flush=True);print(json.dumps(state,sort_keys=True),flush=True)
        print('END_A_REJOIN_RESULT_JSON',flush=True);print('A_REJOINED_DAX_RUNTIME_HEALTHY_NO_GUEST',flush=True)
        return 0
    except Exception as error:
        detail={'status':'A_PROXY_CONTINUATION_STOPPED_PRESERVE_STATE','errorType':type(error).__name__,
            'reason':str(error)[:1000],'SDKRestartAttempted':False,'DAXRestartAttempted':False,'RuntimeRestartAttempted':False}
        state['failure']=detail;ctx.mark('stopped_preserve_state')
        detail['units']={k:old.props(v['name']) for k,v in state['units'].items()}
        detail['proxyDiagnostics']={}
        for label in ('inside-proxy-r2','inside-proxy','host-proxy'):
            if label in state['units']:
                p=old.cmd([old.tool('journalctl'),'-b','-u',state['units'][label]['name'],'-n','35','--no-pager','-o','cat'],30,check=False)
                detail['proxyDiagnostics'][label]=p.stdout[-12000:].decode(errors='replace')
        print(json.dumps(detail,sort_keys=True),flush=True);return 1


if __name__=='__main__':
    try:code=main()
    except Exception as error:
        print(json.dumps({'status':'A_PROXY_REPAIR_STOPPED_BEFORE_BRIDGE_START','errorType':type(error).__name__,
            'reason':str(error)[:800],'SDKRestartAttempted':False,'DAXRestartAttempted':False,'RuntimeRestartAttempted':False}),flush=True)
        code=1
    raise SystemExit(code)
