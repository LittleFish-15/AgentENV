"""Pinned ordinary-user native core build. No SDK, service or Guest operations.

Designed for the manual private GitHub relay; execution never polls for work.
Artifacts and reports stay private. This is a build/debug prerequisite, not a
claim that the complete demand deployment or two-node hardware path passed.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time

CORE_COMMIT='8d83cfd17461fece060c38e3224867295e6b8640'
CORE_TREE='8f6272066c2d8becfdcf09220ab925c959704344'
REPO='https://github.com/LittleFish-15/AgentENV.git'


def need(value,reason):
    if not value:raise RuntimeError(reason)


def atomic(path,value):
    data=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    temporary=path.with_name(path.name+'.new')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)


def build(home,run=subprocess.run):
    need(sys.version_info>=(3,11),'Python >=3.11 required')
    need(platform.system()=='Linux' and platform.machine()=='aarch64','Native ARM64 Linux required')
    need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Ordinary enrolled build identity required')
    status=Path('/proc/self/status').read_text()
    for capability in ('CapInh','CapPrm','CapEff','CapAmb'):
        need(int(next(row.split()[1] for row in status.splitlines() if row.startswith(capability+':')),16)==0,
             'Build must have no capabilities')
    need(not list(Path('/sys/block').glob('ublkb*')),'BUILD_DEFERRED_ACTIVE_UBLK: preserve other experiments')
    home=Path(home).resolve(strict=True)
    root=home/'agentenv-demand-build'
    if not root.exists():root.mkdir(mode=0o700)
    need(root.resolve(strict=True)==root and root.stat().st_uid==1204 and not root.stat().st_mode&0o077,
         'Private isolated build root required')
    import fcntl
    lock=os.open(root/'build.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    directory=root/CORE_COMMIT[:12]
    if not directory.exists():directory.mkdir(mode=0o700)
    need(directory.resolve(strict=True)==directory,'Build directory redirected')
    env={key:os.environ[key] for key in ('HOME','LANG','LC_ALL') if key in os.environ}
    env.update(HOME=str(home),PATH=str(home/'.cargo/bin')+':/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
               CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(directory/'target'),PYTHONDONTWRITEBYTECODE='1',
               GIT_TERMINAL_PROMPT='0',GCM_INTERACTIVE='never')
    for tool in ('git','cargo','rustc','cc','c++','pkg-config','protoc'):
        need(shutil.which(tool,path=env['PATH']),'Missing native build prerequisite: '+tool)
    version=run(['rustc','--version'],env=env,capture_output=True,text=True,check=True,timeout=20).stdout
    match=re.match(r'rustc (\d+)\.(\d+)\.(\d+)',version)
    need(match and tuple(map(int,match.groups()))>=(1,91,1),'Native Rust >=1.91.1 required; nothing installed automatically')
    report={'state':'BUILD_INTENT','sourceCommit':CORE_COMMIT,'sourceTree':CORE_TREE,'SDK_called':False,
            'servicesChanged':False,'Guest_created':False,'twoNodeDemandAccepted':False,'commands':[]}
    receipt=directory/'native-build.json';atomic(receipt,report)
    source=directory/'source'
    def command(label,argv,cwd,timeout=1800):
        report['phase']=label;atomic(receipt,report);started=time.monotonic()
        log=directory/(label+'.log')
        with log.open('ab') as output:
            child=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            try:
                while child.poll() is None:
                    need(time.monotonic()-started<timeout,'Build command deadline: '+label)
                    need(log.stat().st_size<=32*1024**2,'Build command log limit: '+label)
                    time.sleep(0.5)
            except BaseException:
                # Only this build command's new process group, never a service
                # or another experiment. The outer relay may terminate us.
                try:os.killpg(child.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    child.wait(timeout=5)
                raise
        with log.open('rb') as stream:log_sha=hashlib.file_digest(stream,'sha256').hexdigest()
        report['commands'].append({'phase':label,'exitCode':child.returncode,'seconds':time.monotonic()-started,
            'logPath':str(log),'logSha256':log_sha,'logBytes':log.stat().st_size})
        atomic(receipt,report);need(child.returncode==0,'Native build phase failed: '+label)
        print('NATIVE_CORE_PHASE_PASSED='+label,flush=True)
    try:
        if not source.exists():
            source.mkdir(mode=0o700)
            command('git-init',['git','init','--quiet'],source,30)
            command('git-fetch-pinned',['git','fetch','--depth','1',REPO,CORE_COMMIT],source,300)
            command('git-checkout',['git','checkout','--detach','FETCH_HEAD'],source,60)
        need(source.resolve(strict=True)==source,'Source checkout redirected')
        for query,expected in (('HEAD',CORE_COMMIT),('HEAD^{tree}',CORE_TREE)):
            result=run(['git','rev-parse',query],cwd=source,env=env,capture_output=True,text=True,check=True,timeout=20)
            need(result.stdout.strip()==expected,'Pinned source identity differs')
        result=run(['git','status','--porcelain'],cwd=source,env=env,capture_output=True,text=True,check=True,timeout=20)
        need(not result.stdout.strip(),'Source checkout changed; preserve')
        provider=source/'components/ub-memory-provider'
        command('provider-tests',[sys.executable,'-B','-m','unittest','discover','-s','tests'],provider,180)
        command('actual-virtual-file-test',['cargo','test','--locked','-p','overlaybd','--features','io-uring,rootfs-read-trace',
                    '--lib','actual_virtual_file_uses_demand_wire_and_rejects_writes'],source)
        command('core-release-build',['cargo','build','--locked','--release','-p','agentenv','-p','uvm-ublk-daemon',
                    '--bin','server','--bin','uvm-ublk-daemon','--features','overlaybd/rootfs-read-trace'],source,3600)
        artifacts={}
        for name in ('server','uvm-ublk-daemon'):
            path=directory/'target/release'/name
            with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
            artifacts[name]={'path':str(path),'sha256':digest,'bytes':path.stat().st_size}
        report.update(state='DEMAND_NATIVE_CORE_BUILT_TESTED_NOT_DEPLOYED',artifacts=artifacts)
    except BaseException as error:
        report.update(state='STOPPED_NATIVE_CORE_BUILD_PRESERVE_OUTPUTS',reason=str(error))
        atomic(receipt,report);raise
    finally:
        atomic(receipt,report);fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)
        print('BEGIN_DEMAND_NATIVE_BUILD_REPORT',flush=True)
        print(json.dumps(report),flush=True)
        print('END_DEMAND_NATIVE_BUILD_REPORT',flush=True)
    return report


if __name__=='__main__':
    os.umask(0o077)
    def interrupted(*_):raise InterruptedError('Build relay interrupted; preserve outputs')
    signal.signal(signal.SIGTERM,interrupted)
    build(Path.home())
