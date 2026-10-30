"""One-time ordinary-user start.sh upgrade; explicit new-boot receipt/acceptance.

Never changes the original enrollment or historical job journals. No root/SDK
operations are implemented by this transport. Credentials stay at their old path.
"""
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
import types
import zlib

READINESS_Z64 = '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'
READINESS_SHA = 'cb9a321880327590b8114f9e2e28968a42b9a7ddd9fbc426118b5c3e95eca95d'
BASE = Path('/home/jwk/agent/github-relay')
PRIVATE = Path('/home/jwk/.local/state/agentenv-github-relay')
RUNNER_SHA = 'b958c459c09db2fe72d508762e8bdab06bd642bfc2f33c6723462ac45353fdcd'
SESSION = 'relay-20261029-0d032371'


def need(ok, reason):
    if not ok: raise RuntimeError(reason)


def payload():
    compressed=base64.b64decode(READINESS_Z64,validate=True)
    d=zlib.decompressobj();raw=d.decompress(compressed,32769)
    need(len(raw)<=32768 and d.eof and not d.unconsumed_tail and not d.unused_data,
         'Readiness expansion differs')
    need(hashlib.sha256(raw).hexdigest()==READINESS_SHA,'Readiness payload differs')
    m=types.ModuleType('embedded_readiness');m.__file__=str(BASE/'embedded-readiness.py')
    exec(compile(raw,m.__file__,'exec'),m.__dict__)
    return m


def context():
    need(sys.platform=='linux' and os.getuid()==os.geteuid()==1204 and os.getgid()==1205,
         'Use ordinary jwk UID1204/GID1205')
    need(os.environ.get('HOME')=='/home/jwk','Expected ordinary jwk HOME')
    os.umask(0o077)
    r=payload();p=BASE/('runner-'+RUNNER_SHA[:12]+'.py')
    need(hashlib.sha256(r.read(p,65536)).hexdigest()==RUNNER_SHA,'Pinned old runner differs')
    s=importlib.util.spec_from_file_location('pinned_epoch_api',p)
    api=importlib.util.module_from_spec(s);s.loader.exec_module(api)
    api.secure_dir(BASE);api.secure_dir(PRIVATE)
    config=api.load(PRIVATE/'config.json',True);current=api.identity()
    validate_physical(config,current)
    return api,r,config,current


def validate_physical(config,current):
    need(config.get('node') in ('node-a','node-b') and config.get('sessionId')==SESSION,
         'This upgrade is only for enrolled A/B')
    old=config['identity']
    for key in ('machineId','hostname','uid','gid','architecture'):
        need(current[key]==old[key],'Physical node/user changed; stop without re-enrollment')
    need(current['hostname']=={'node-a':'server1','node-b':'agent1'}[config['node']],
         'Node hostname differs')
    need(config['controlRepo']=='LittleFish-15/AgentENV-relay-control' and
         config['controlRepoId']==1438089258 and
         config['resultRepo']=='LittleFish-15/AgentENV-relay-results' and
         config['resultRepoId']==1438089386,'Repository binding differs')


def old_start():
    runner=str(BASE/('runner-'+RUNNER_SHA[:12]+'.py'))
    return ('#!/bin/bash\nset -eu\numask 077\n'
        'test "$(id -u)" -eq 1204 || { echo "Use ordinary jwk"; exit 1; }\n'
        '/usr/bin/python3 -I -B '+runner+' enroll --control-repo LittleFish-15/AgentENV-relay-control '
        '--result-repo LittleFish-15/AgentENV-relay-results\n'
        'exec /usr/bin/python3 -I -B '+runner+' run\n').encode()


def launcher(target):
    need(target.parent==BASE and target.name.startswith('reboot-start-') and target.suffix=='.py',
         'Unexpected launcher target')
    return ('#!/bin/bash\nset -eu\numask 077\n'
        'test "$(id -u)" -eq 1204 || { echo "Use ordinary jwk"; exit 1; }\n'
        'exec /usr/bin/python3 -I -B '+str(target)+'\n').encode()


def put_exact(path,raw,mode):
    need(path.parent.resolve(strict=True)==path.parent and not path.is_symlink(),'Redirected output')
    if path.exists():
        st=path.stat()
        need(st.st_uid==1204 and stat.S_ISREG(st.st_mode) and
             stat.S_IMODE(st.st_mode)==mode and path.read_bytes()==raw,'Existing entry differs; preserved')
        return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())


def install(r):
    raw=r.read(Path(__file__).resolve(),32768)
    pin=hashlib.sha256(raw).hexdigest()
    target=BASE/('reboot-start-'+pin[:16]+'.py')
    current=r.read(BASE/'start.sh',8192)
    expected=launcher(target)
    need(current in (old_start(),expected),'Existing start.sh differs; not overwritten')
    put_exact(BASE/'start.before-reboot-v1.sh',old_start(),0o700)
    put_exact(target,raw,0o600)
    if current!=expected:
        temporary=BASE/'start.reboot-v1.new'
        put_exact(temporary,expected,0o700)
        need(r.read(BASE/'start.sh',8192)==current,'Launcher changed; preserve new temporary')
        os.replace(temporary,BASE/'start.sh')
        fd=os.open(BASE,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    print('AB_FIXED_START_UPGRADED_NO_TOKENS_OR_SERVICES_CHANGED',flush=True)


def history(api):
    rows=[]
    jobs=PRIVATE/'jobs'
    if jobs.exists():
        api.secure_dir(jobs)
        for p in sorted(jobs.iterdir()):
            need(p.is_dir() and p.resolve()==p,'Historical job redirected')
            state=api.load(p/'state.json',True)
            rows.append({'jobId':p.name,'state':state['state'],
                         'stateSha256':api.digest(api.encoded(state))})
    need(len(rows)<=128,'Historical jobs exceed review bound')
    return rows


def validate_acceptance(api,a,request,now):
    keys={'schema','node','sessionId','identity','previousIdentity','receiptSha256',
          'requestSha256','wrapperSha256','notBefore','expiresAt','priorJobsReviewed'}
    need(set(a)==keys and a['schema']==1 and a['priorJobsReviewed'] is True,'Boot acceptance fields differ')
    for key in ('node','sessionId','identity','previousIdentity','receiptSha256','wrapperSha256'):
        need(a[key]==request[key],'Boot acceptance binding differs')
    need(a['requestSha256']==api.digest(api.encoded(request)),'Request receipt differs')
    need(api.timestamp(a['notBefore'])<=now<api.timestamp(a['expiresAt']) and
         api.timestamp(a['expiresAt'])-api.timestamp(a['notBefore'])<=48*3600,
         'Boot acceptance expired or unbounded')
    need(all(x['state']=='uploaded' for x in request['priorJobs']),
         'Old job outcome requires reconciliation; never clear unknown state')


def turn(api,r,config,current):
    if (PRIVATE/'stop.request').exists():
        print('RELAY_STOP_REQUESTED_NO_TASK_EXECUTED');return
    tokens=api.load(PRIVATE/'credentials.json',True)
    control,result=api.GitHub(tokens['controlToken']),api.GitHub(tokens['resultToken'])
    for client,kind in ((control,'control'),(result,'result')):
        client.private_repo(config[kind+'Repo'],config[kind+'RepoId'])
    # Reuse the published read-only inspection and immutable private receipt.
    receipt_path=BASE/'reboot-readiness-v1'/ (current['bootId']+'.json')
    if not receipt_path.exists():
        report=r.inspect(api,config)
        api.secure_dir(receipt_path.parent);api.atomic(receipt_path,report,replace=False)
    report=api.load(receipt_path,True)
    need(report['identity']==current and report['node']==config['node'],'Saved boot receipt differs')
    key='reboot-readiness/'+SESSION+'/'+config['node']+'/'+current['bootId']+'.json'
    result.immutable_result(config['resultRepo'],config['resultRepoId'],config['resultBranch'],key,api.encoded(report))
    wrapper_sha=api.digest(r.read(Path(__file__).resolve(),32768))
    request={'schema':1,'node':config['node'],'sessionId':SESSION,'identity':current,
        'previousIdentity':config['identity'],'receiptSha256':api.digest(api.encoded(report)),
        'wrapperSha256':wrapper_sha,'priorJobs':history(api)}
    request_key='reboot-requests/'+SESSION+'/'+config['node']+'/'+current['bootId']+'.json'
    result.immutable_result(config['resultRepo'],config['resultRepoId'],config['resultBranch'],request_key,api.encoded(request))
    code,raw,_=control.contents(config['controlRepo'],
        'reboot-acceptances/'+SESSION+'/'+config['node']+'/'+current['bootId']+'.json',config['controlBranch'])
    if code==404:
        print('AB_REBOOT_READINESS_UPLOADED_WAIT_FOR_CONTROLLER_NO_SERVICES_CHANGED',flush=True)
        return
    need(code==200,'Cannot read explicit boot acceptance')
    acceptance=json.loads(raw);validate_acceptance(api,acceptance,request,time.time())
    code,raw,_=control.contents(config['controlRepo'],'profiles/'+config['node']+'.json',config['controlBranch'])
    need(code==200,'Profile unavailable');profile=json.loads(raw)
    api.validate_profile(profile,current,RUNNER_SHA,time.time())
    need(profile['sessionId']==SESSION and profile['node']==config['node'],'Profile session differs')
    epochs=api.secure_dir(PRIVATE/'boot-epochs')
    epoch=api.secure_dir(epochs/current['bootId'])
    epoch_config=dict(config,**{k:profile[k] for k in ('protocol','node','sessionId','uid','gid',
        'hostname','machineId','runnerSha256','expiresAt','allowedOperations','allowedScopes','mode')})
    epoch_config['identity']=current
    api.atomic(epoch/'config.json',epoch_config)
    api.atomic(epoch/'boot-acceptance.json',acceptance)
    api.secure_dir(epoch/'jobs')
    registration={'protocol':api.VERSION,'node':config['node'],'sessionId':SESSION,
        'identity':current,'runnerSha256':RUNNER_SHA,'wrapperSha256':wrapper_sha,
        'allowedOperations':profile['allowedOperations'],'acceptanceSha256':api.digest(api.encoded(acceptance))}
    result.immutable_result(config['resultRepo'],config['resultRepoId'],config['resultBranch'],
        'registrations/'+SESSION+'/'+config['node']+'/epochs/'+current['bootId']+'.json',api.encoded(registration))
    code,raw,_=control.contents(config['controlRepo'],'queues/'+config['node']+'.json',config['controlBranch'])
    need(code==200,'Queue unavailable');queue=json.loads(raw)
    def fetch(job_id):
        code,raw,_=control.contents(config['controlRepo'],'jobs/'+job_id+'.json',config['controlBranch'])
        need(code==200,'Job unavailable');job=json.loads(raw)
        # No pre-reboot job can be replayed merely by accepting a new boot.
        need(job['kind']=='reviewed-python-v1' and job['input'].get('expectedIdentity')==current,
             'Task must explicitly bind the reviewed current boot')
        return job
    runner=api.Runner(epoch,epoch_config,control,result)
    outcome=api.manual_turn(runner,queue,fetch,current,time.time(),tuple(tokens.values()))
    api.atomic(epoch/'status.json',dict(outcome,node=config['node'],finishedAt=api.utc()))
    print(json.dumps(outcome,indent=2));print('RELAY_EXITED_WAIT_FOR_NEXT_USER_COMMAND',flush=True)


def main():
    api,r,config,current=context()
    need(sys.argv[1:] in ([],['--install']),'Only --install or the fixed invocation is supported')
    fd=os.open(PRIVATE/'runner.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        st=os.fstat(lock.fileno())
        need(st.st_uid==1204 and st.st_nlink==1 and stat.S_ISREG(st.st_mode) and
             not stat.S_IMODE(st.st_mode)&0o077,'Lock identity differs')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if sys.argv[1:]==['--install']:install(r)
        turn(api,r,config,current)


if __name__=='__main__':
    try:main()
    except Exception as error:
        print('AB_FIXED_START_STOPPED_PRESERVE_STATE errorType='+type(error).__name__,flush=True)
        raise SystemExit(1)
