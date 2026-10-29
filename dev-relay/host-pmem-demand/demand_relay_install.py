"""Install an independent manual demand-build lane, reusing existing tokens.

No existing relay entry, queue, credentials or services are modified. Private
repositories use a separate branch and session. No root or SDK operations.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import types
import urllib.request

BRANCH='demand-20261030'
SESSION='demand-core-20261030-v1'
RUNNER_BLOB='4fe2da5a6c3a84463605e4db884b1fc3d9ecd8f0'
RUNNER_SHA='b958c459c09db2fe72d508762e8bdab06bd642bfc2f33c6723462ac45353fdcd'
RUNNER_BYTES=31491


def need(value,reason):
    if not value:raise RuntimeError(reason)


def write_exact(path,data,mode):
    need(not path.is_symlink(),'New relay entry redirected')
    if path.exists():
        need(path.is_file() and path.read_bytes()==data,'Existing demand relay entry differs; preserved')
        return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())


def independent_config(old,profile,current):
    need(current==old['identity'],'Existing enrollment boot/identity changed; preserve')
    need(old['node'] in ('node-c','node-d'),'Build lane only supports workspace nodes; source nodes unchanged')
    need(profile['sessionId']==SESSION and profile['node']==old['node'],'Independent demand session differs')
    need(profile.get('allowedOperations')==['reviewed-python-v1']
         and profile.get('allowedScopes')==['workspace-files'],'Unexpected demand build scope')
    return dict(profile,identity=current,controlRepo=old['controlRepo'],controlRepoId=old['controlRepoId'],
        controlBranch=BRANCH,resultRepo=old['resultRepo'],resultRepoId=old['resultRepoId'],resultBranch=BRANCH)


def install():
    need(sys.platform=='linux' and sys.version_info>=(3,11),'Native Linux Python >=3.11 required')
    need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Use enrolled ordinary identity')
    os.umask(0o077)
    url='https://api.github.com/repos/LittleFish-15/AgentENV/git/blobs/'+RUNNER_BLOB
    request=urllib.request.Request(url,headers={'User-Agent':'AgentENV-independent-demand-lane'})
    with urllib.request.urlopen(request,timeout=45) as response:row=json.loads(response.read(65536))
    need(row.get('sha')==RUNNER_BLOB and row.get('encoding')=='base64' and row.get('size')==RUNNER_BYTES,
         'Pinned common runner metadata differs')
    raw=base64.b64decode(''.join(row['content'].split()),validate=True)
    need(len(raw)==RUNNER_BYTES and hashlib.sha256(raw).hexdigest()==RUNNER_SHA,'Pinned common runner SHA differs')
    # This is the same reviewed runner used by the full-mode manual exchange.
    module=types.ModuleType('demand_relay_protocol');module.__file__='pinned-relay-runner.py'
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    current=module.identity()
    previous=Path.home()/'.local/state/agentenv-github-relay'
    old=module.load(previous/'config.json',True)
    secrets=module.load(previous/'credentials.json',True)
    need(current==old['identity'],'Existing enrollment boot/identity changed; preserve')
    need(old['node'] in ('node-c','node-d'),'Build lane only supports workspace nodes; source nodes unchanged')
    control=module.GitHub(secrets['controlToken']);results=module.GitHub(secrets['resultToken'])
    control.private_repo(old['controlRepo'],old['controlRepoId'])
    results.private_repo(old['resultRepo'],old['resultRepoId'])
    code,data,_=control.contents(old['controlRepo'],'profiles/'+old['node']+'.json',BRANCH)
    need(code==200,'Demand profile not published; no target operation started')
    profile=json.loads(data)
    module.validate_profile(profile,current,RUNNER_SHA,__import__('time').time())
    need(profile['sessionId']==SESSION and profile['node']==old['node'],'Independent demand session differs')
    base=Path.home()/'agentenv-demand-relay';state=Path.home()/'.local/state/agentenv-demand-relay'
    module.secure_dir(base);module.secure_dir(state)
    config=independent_config(old,profile,current)
    if (state/'config.json').exists():
        existing=module.load(state/'config.json',True)
        need(existing['sessionId']==SESSION and existing['identity']==current,'Existing demand state requires reconciliation')
    if (state/'credentials.json').exists():
        need(module.load(state/'credentials.json',True)==secrets,'Credential rotation requires explicit reconciliation')
    else:module.atomic(state/'credentials.json',secrets,replace=False)
    module.atomic(state/'config.json',config)
    runner=base/('runner-'+RUNNER_SHA[:12]+'.py');write_exact(runner,raw,0o400)
    body=('#!/bin/bash\nset -eu\numask 077\nexec '+shlex.quote(sys.executable)+' -I -B '+shlex.quote(str(runner))+
          ' --state-dir '+shlex.quote(str(state))+' run\n').encode()
    entry=base/'start.sh';write_exact(entry,body,0o700)
    print('INDEPENDENT_DEMAND_ENTRY_READY=bash '+str(entry),flush=True)
    os.execv('/bin/bash',['bash',str(entry)])


if __name__=='__main__':
    try:install()
    except Exception as error:
        # Never stringify credential objects or server response bodies.
        print('DEMAND_RELAY_STOPPED_PRESERVE_STATE: '+type(error).__name__+': '+str(error),file=sys.stderr)
        raise SystemExit(1)
