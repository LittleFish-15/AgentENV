"""Pinned ordinary-user native core build. No SDK, service or Guest operations.

Designed for the manual private GitHub relay; execution never polls for work.
Artifacts and reports stay private. This is a build/debug prerequisite, not a
claim that the complete demand deployment or two-node hardware path passed.
"""
import hashlib
import argparse
import ast
import base64
import io
import tarfile
import urllib.request
import zlib
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

CORE_COMMIT='e823fa02c9d726b06bb4bcb3c3e4c7e26f4a480f'
CORE_TREE='5eba6550f378998ff733340ad28cf3b5d05e78ec'
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


def build(home,run=subprocess.run,image=None,image_sha=None):
    need(sys.version_info>=(3,11),'Python >=3.11 required')
    need(platform.system()=='Linux' and platform.machine()=='aarch64','Native ARM64 Linux required')
    need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Ordinary enrolled build identity required')
    status=Path('/proc/self/status').read_text()
    for capability in ('CapInh','CapPrm','CapEff','CapAmb'):
        need(int(next(row.split()[1] for row in status.splitlines() if row.startswith(capability+':')),16)==0,
             'Build must have no capabilities')
    # Compilation does not operate on existing ublk devices or services.
    home=Path(home).resolve(strict=True)
    root=home/'agent/builds/host-pmem-demand'
    if not root.exists():root.mkdir(mode=0o700,parents=True)
    need(root.resolve(strict=True)==root and root.stat().st_uid==1204 and not root.stat().st_mode&0o077,
         'Private isolated build root required')
    import fcntl
    lock=os.open(root/'build.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    directory=root/CORE_COMMIT[:12]
    if not directory.exists():directory.mkdir(mode=0o700)
    need(directory.resolve(strict=True)==directory,'Build directory redirected')
    env={key:os.environ[key] for key in ('HOME','LANG','LC_ALL','HTTPS_PROXY','HTTP_PROXY','NO_PROXY','https_proxy','http_proxy','no_proxy') if key in os.environ}
    env.update(HOME=str(home),PATH=str(home/'.cargo/bin')+':/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
               CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(directory/'target'),PYTHONDONTWRITEBYTECODE='1',
               GIT_TERMINAL_PROMPT='0',GCM_INTERACTIVE='never')
    # Reuse the already successful A/B native build toolchain/dependencies,
    # while keeping this branch's build output entirely separate.
    retained=home/'agent'
    rust=retained/'toolchains/agentenv-rust-1.99.0/rustup/toolchains/1.99.0-aarch64-unknown-linux-gnu/bin'
    native=retained/'deployments/agentenv-native-fe63038/native'
    if (rust/'cargo').is_file() and (rust/'rustc').is_file():
        env.update(PATH=str(rust)+':'+str(native/'bin')+':'+env['PATH'],
                   RUSTC=str(rust/'rustc'),RUSTDOC=str(rust/'rustdoc'))
    cargo_home=retained/'builds/agentenv-ub-build-v2/cargo'
    if cargo_home.is_dir():env['CARGO_HOME']=str(cargo_home)
    prior=retained/'builds/agentenv-native-fe63038/return.json'
    if prior.is_file():
        previous=json.loads(prior.read_text())
        need(previous.get('status')=='THREE_CORE_BINARIES_BUILT_STAGED_NOT_DEPLOYED','Prior native dependency receipt differs')
        for key,patterns in (('ROCKSDB_LIB_DIR',('librocksdb.*',)),('SNAPPY_LIB_DIR',('libsnappy.*',)),
                             ('LIBCLANG_PATH',('libclang.so*','libclang-*.so*'))):
            value=previous.get('explicitNativeBuildDirectories',{}).get(key)
            if value:
                path=Path(value)
                need(path.is_absolute() and path.resolve(strict=True)==path and path.is_dir()
                     and any(any(path.glob(pattern)) for pattern in patterns),'Retained native library path differs: '+key)
                env[key]=str(path)
    library_paths=[path for path in (native/'lib',native/'fallback/lib') if path.is_dir()]
    # Reuse the native libraries from the previously successful core build.
    if library_paths:env['LD_LIBRARY_PATH']=':'.join(map(str,library_paths))
    pkg_paths=[path for path in (native/'lib/pkgconfig',retained/'native/lib64/pkgconfig') if path.is_dir()]
    if pkg_paths:env['PKG_CONFIG_PATH']=':'.join(map(str,pkg_paths))
    for tool in ('git','cargo','rustc','cc','c++','pkg-config','protoc','make','gcc','ld','modinfo'):
        need(shutil.which(tool,path=env['PATH']),'Missing native build prerequisite: '+tool)
    version=run(['rustc','--version'],env=env,capture_output=True,text=True,check=True,timeout=20).stdout
    match=re.match(r'rustc (\d+)\.(\d+)\.(\d+)',version)
    need(match and tuple(map(int,match.groups()))>=(1,91,1),'Native Rust >=1.91.1 required; nothing installed automatically')
    temporary=home/'agent/r'/('dmb-'+CORE_COMMIT[:8]);temporary.mkdir(mode=0o700,parents=True,exist_ok=True)
    need(temporary.resolve(strict=True)==temporary and temporary.stat().st_uid==1204 and not temporary.stat().st_mode&0o077,'Private short test temporary directory required')
    env.update(TMPDIR=str(temporary),CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0',CARGO_PROFILE_RELEASE_DEBUG='0',CARGO_PROFILE_RELEASE_LTO='false',CMAKE_BUILD_PARALLEL_LEVEL='2')
    need(shutil.disk_usage(directory).free>=8*1024**3,'At least 8 GiB free space required for isolated build')
    report={'state':'BUILD_INTENT','sourceCommit':CORE_COMMIT,'sourceTree':CORE_TREE,'SDK_called':False,
            'servicesChanged':False,'Guest_created':False,'twoNodeDemandAccepted':False,'moduleLoaded':False,'commands':[],
            'identity':{'hostname':platform.node(),'kernel':platform.release(),'architecture':platform.machine(),
                        'machineId':Path('/etc/machine-id').read_text().strip(),
                        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}}
    receipt=directory/'native-build.json'
    if receipt.exists():
        need(not receipt.is_symlink() and receipt.stat().st_size<=2*1024**2,'Prior build report differs')
        prior_raw=receipt.read_bytes();need(json.loads(prior_raw)['sourceCommit']==CORE_COMMIT,'Prior build source differs')
        backup=directory/('native-build.previous-'+str(time.time_ns())+'.json')
        with backup.open('xb') as stream:stream.write(prior_raw)
        report['priorReport']={'path':str(backup),'sha256':hashlib.sha256(prior_raw).hexdigest()}
    atomic(receipt,report)
    source=directory/'source'
    def command(label,argv,cwd,timeout=1800):
        report['phase']=label;atomic(receipt,report);started=time.monotonic()
        log=directory/(label+'.log')
        inherited_group=os.environ.get('AENV_DEMAND_BUILD_GROUP')=='1'
        if inherited_group:need(os.getpid()==os.getpgrp(),'Build group ownership differs')
        with log.open('ab') as output:
            child=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                stdout=output,stderr=subprocess.STDOUT,start_new_session=not inherited_group)
            try:
                progress=0
                while child.poll() is None:
                    elapsed=time.monotonic()-started
                    if elapsed-progress>=20:
                        print('PROGRESS phase='+label+' elapsed_s='+str(int(elapsed)),flush=True);progress=elapsed
                    need(time.monotonic()-started<timeout,'Build command deadline: '+label)
                    need(log.stat().st_size<=32*1024**2,'Build command log limit: '+label)
                    need(shutil.disk_usage(directory).free>=2*1024**3,'Build disk reserve reached; preserve outputs')
                    time.sleep(0.5)
            except BaseException:
                # Only this build command's new process group, never a service
                # or another experiment. The outer relay may terminate us.
                group=os.getpgrp() if inherited_group else child.pid
                previous=signal.signal(signal.SIGTERM,signal.SIG_IGN) if inherited_group else None
                try:os.killpg(group,signal.SIGTERM)
                except ProcessLookupError:pass
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:os.killpg(group,signal.SIGKILL)
                    except ProcessLookupError:pass
                    child.wait(timeout=5)
                if previous is not None:signal.signal(signal.SIGTERM,previous)
                raise
        with log.open('rb') as stream:log_sha=hashlib.file_digest(stream,'sha256').hexdigest()
        report['commands'].append({'phase':label,'exitCode':child.returncode,'seconds':time.monotonic()-started,
            'logPath':str(log),'logSha256':log_sha,'logBytes':log.stat().st_size})
        if child.returncode:
            with log.open('rb') as tail:
                tail.seek(max(0,log.stat().st_size-12000));report['failureLogTail']=tail.read().decode(errors='replace')
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
        command('native-demand-core-tests',['cargo','test','--locked','-p','overlaybd','--features','io-uring,rootfs-read-trace',
                    '--lib','demand'],source)
        command('core-release-build',['cargo','build','--locked','--release','-p','agentenv','-p','uvm-ublk-daemon',
                    '--bin','server','--bin','uvm-ublk-daemon','--features','overlaybd/rootfs-read-trace'],source,3600)
        artifacts={}
        for name in ('server','uvm-ublk-daemon'):
            path=directory/'target/release'/name
            with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
            artifacts[name]={'path':str(path),'sha256':digest,'bytes':path.stat().st_size}
        report['artifacts']=artifacts;atomic(receipt,report)
        module=prepare_kernel_source(home,directory,source)
        headers=Path('/lib/modules')/platform.release()/'build'
        need((headers/'Module.symvers').is_file(),'Missing matching kernel build headers')
        command('native-obmm-kbuild',['make','-C',str(headers),'M='+str(module),'CC=gcc','LD=ld','-j2','modules'],module,1200)
        binary=module/'obmm.ko'
        info={name:run(['modinfo','-F',name,str(binary)],capture_output=True,text=True,check=True,timeout=20,env=env).stdout.strip()
              for name in ('vermagic','srcversion','depends','signer')}
        need(info['vermagic'].split()[0]==platform.release(),'Candidate kernel ABI differs')
        artifacts['obmm.ko']={'path':str(binary),'bytes':binary.stat().st_size,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),**info}
        report['kernelSymbolTableSha256']=hashlib.sha256((headers/'Module.symvers').read_bytes()).hexdigest()
        if image is not None:
            original=Path(image)
            need(original.is_absolute() and original.resolve(strict=True)==original and original.is_relative_to(home/'agent')
                 and original.suffix=='.ext4','Expected retained ext4 image under the ordinary workspace')
            manifest=directory/'stable-image-manifest.json'
            if manifest.exists():
                need(not manifest.is_symlink() and manifest.stat().st_size<=4*1024**2,'Existing manifest differs')
                prepared=json.loads(manifest.read_bytes());st=original.stat();identity=prepared['sourceIdentity']
                need((identity['device'],identity['inode'],identity['bytes'],identity['mtimeSeconds']*10**9+identity['mtimeNanos'],identity['ctimeSeconds']*10**9+identity['ctimeNanos'])
                     ==(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns),'Source changed since preparation; preserve prior manifest')
                document=prepared['document']
                need(document['layerDigest']=='sha256:'+image_sha.removeprefix('sha256:') and document['chunkBytes']==256*1024
                     and hashlib.sha256(json.dumps(document,sort_keys=True,separators=(',',':')).encode()).hexdigest()==prepared['sha256'],
                     'Existing trusted manifest differs')
                report['metadataPreparation']='REUSED_UNCHANGED_SOURCE_IDENTITY'
            else:
                command('prepare-stable-image-metadata',[artifacts['server']['path'],'--prepare-host-pmem-image',str(original),
                        '--host-pmem-image-sha256',image_sha,'--host-pmem-manifest',str(manifest)],source,300)
                report['metadataPreparation']='NATIVE_DIRECT_SCAN_COMPLETED'
            raw=manifest.read_bytes();need(len(raw)<=4*1024**2,'Manifest exceeds transfer bound')
            compressed=zlib.compress(raw,9);need(len(compressed)<=600*1024,'Compressed manifest exceeds transfer bound')
            report['preparedImage']={'path':str(manifest),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                                    'zlibBase64':base64.b64encode(compressed).decode()}
        report.update(state='DEMAND_NATIVE_CORE_AND_MODULE_BUILT_NOT_DEPLOYED',artifacts=artifacts)
    except BaseException as error:
        report.update(state='STOPPED_NATIVE_CORE_BUILD_PRESERVE_OUTPUTS',reason=str(error))
        atomic(receipt,report);raise
    finally:
        atomic(receipt,report);fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)
        print('BEGIN_DEMAND_NATIVE_BUILD_REPORT',flush=True)
        print(json.dumps(report),flush=True)
        print('END_DEMAND_NATIVE_BUILD_REPORT',flush=True)
    return report



BASE_ENTRY_SHA='e24b25c7733431e0c6d47de1d2094345de238d2a5b076781e618b4255590a2ca'
BASE_ENTRY_BLOB='60c3fcd037433796013fc2cd6337dd43c691a607'

def prepare_kernel_source(home,directory,source):
    entry=home/'agent/A_build_host_pmem_candidate_v1.py'
    if entry.is_file() and not entry.is_symlink():raw=entry.read_bytes()
    else:
        url='https://api.github.com/repos/LittleFish-15/AgentENV/git/blobs/'+BASE_ENTRY_BLOB
        with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'AgentENV-demand-native-build'}),timeout=30) as response:
            record=json.loads(response.read(512*1024))
        need(record.get('sha')==BASE_ENTRY_BLOB and record.get('encoding')=='base64','Baseline blob differs')
        raw=base64.b64decode(''.join(record['content'].split()),validate=True)
    need(len(raw)==164286 and hashlib.sha256(raw).hexdigest()==BASE_ENTRY_SHA,'Baseline source entry differs; never execute it')
    values={}
    for statement in ast.parse(raw).body:
        if isinstance(statement,ast.Assign):
            for target in statement.targets:
                if isinstance(target,ast.Name) and target.id in ('PAYLOAD','PAYLOAD_SHA','SOURCE_HASHES'):
                    values[target.id]=ast.literal_eval(statement.value)
    payload=base64.b64decode(values['PAYLOAD'],validate=True)
    need(hashlib.sha256(payload).hexdigest()==values['PAYLOAD_SHA'],'Baseline archive differs')
    module=directory/'kernel-obmm';module.mkdir(mode=0o700,exist_ok=True)
    replacements={'obmm_pmem_ro.c','obmm_pmem_uapi.h'}
    expected={p for p in values['SOURCE_HASHES'] if p.startswith('kernel-obmm/')}
    seen=set()
    with tarfile.open(fileobj=io.BytesIO(payload),mode='r:gz') as archive:
        for member in archive:
            if member.name not in expected:continue
            rel=Path(member.name).relative_to('kernel-obmm')
            need(member.isfile() and not rel.is_absolute() and '..' not in rel.parts,'Invalid baseline member')
            data=archive.extractfile(member).read()
            need(hashlib.sha256(data).hexdigest()==values['SOURCE_HASHES'][member.name],'Baseline source hash differs')
            seen.add(member.name)
            if rel.as_posix() in replacements:continue
            target=module/rel;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            if target.exists():need(not target.is_symlink() and target.read_bytes()==data,'Existing kernel source differs')
            else:
                with target.open('xb') as output:output.write(data)
    need(seen==expected,'Incomplete baseline kernel source')
    for name in replacements:
        data=(source/'components/obmm-host-pmem'/name).read_bytes();target=module/name
        if target.exists():need(not target.is_symlink() and target.read_bytes()==data,'Candidate source differs')
        else:
            with target.open('xb') as output:output.write(data)
    return module

if __name__=='__main__':
    os.umask(0o077)
    def interrupted(*_):raise InterruptedError('Build relay interrupted; preserve outputs')
    signal.signal(signal.SIGTERM,interrupted)
    if os.getuid()==0:
        need(platform.system()=='Linux','Root relay bootstrap requires Linux')
        tool=Path('/usr/bin/setpriv');need(tool.is_file() and tool.stat().st_uid==0 and not tool.stat().st_mode&0o022,'Trusted setpriv required')
        env={k:v for k,v in os.environ.items() if k in ('LANG','LC_ALL','HTTPS_PROXY','HTTP_PROXY','NO_PROXY','https_proxy','http_proxy','no_proxy')}
        env.update(AENV_DEMAND_BUILD_GROUP='1',HOME='/home/jwk',USER='jwk',LOGNAME='jwk',PATH='/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin')
        masked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM,signal.SIGINT})
        child=subprocess.Popen([str(tool),'--reuid=1204','--regid=1205','--clear-groups','--bounding-set=-all',
            '--inh-caps=-all','--ambient-caps=-all','--no-new-privs','/usr/bin/python3','-I','-B','-',*sys.argv[1:]],
            stdin=subprocess.PIPE,env=env,start_new_session=True)
        def stop_build(signum,*_):
            try:os.killpg(child.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=1)
            raise SystemExit(128+signum)
        signal.signal(signal.SIGTERM,stop_build);signal.signal(signal.SIGINT,stop_build)
        signal.pthread_sigmask(signal.SIG_SETMASK,masked)
        child.communicate(input=Path(__file__).read_bytes())
        raise SystemExit(child.returncode)
    if os.environ.get('AENV_DEMAND_BUILD_GROUP')=='1':
        signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM,signal.SIGINT})
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--image-sha')
    args=parser.parse_args();need(bool(args.image)==bool(args.image_sha),'Image and trusted digest must be supplied together')
    try:build(Path.home(),image=args.image,image_sha=args.image_sha)
    except Exception as error:
        print('DEMAND_BUILD_ENTRY_STOPPED '+json.dumps({'reason':str(error),'SDK_called':False,'moduleLoaded':False,'servicesChanged':False}),flush=True)
        raise SystemExit(1)
