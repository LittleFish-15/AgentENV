"""Root provisions build dependencies; all source/toolchain/build work runs as jwk."""
import hashlib,json,os,pathlib,platform,pwd,shutil,signal,stat,subprocess,tarfile,time
P=pathlib.Path
BASE=P('/data/jwk/aenv-y-20261107')
SOURCE=BASE/'source/AgentENV-5ca17126'
DELIVERY={'source_manifest': {'commit': '5ca17126c51ce1ac1cfaf31cf50d902ab54d55b7', 'tree': '1a9ffaf259f94adb770c6ecf4d3932d89a5ad248', 'files': 799, 'archive_sha256': 'bb4864908e66e61d3b4a35921210c78ce01e93d5e4fe25142e5ff0d8f2932c86', 'archive_bytes': 2302854, 'parts': [{'name': 'AgentENV-5ca17126-source.part001.bin', 'bytes': 716800, 'sha256': '7937ee18a86cf7606436d6478fb9a83159a087c26b99518cf8a42e6a073abb88', 'descriptor': {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-jwk-aenv-20261107/AgentENV-5ca17126-source.part001.bin', 'commit': '9e618b699294839c066834ac7cd8eb677ddd3e38', 'sha256': '7937ee18a86cf7606436d6478fb9a83159a087c26b99518cf8a42e6a073abb88', 'bytes': 716800, 'blob': '4b4e51a1b06ee3c3ec3487391dbb83736e49f829'}}, {'name': 'AgentENV-5ca17126-source.part002.bin', 'bytes': 716800, 'sha256': 'f295d448914acde0b65bc4c7593ff2a6310fee173b3171584a31eb2e34c86d52', 'descriptor': {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-jwk-aenv-20261107/AgentENV-5ca17126-source.part002.bin', 'commit': '9e618b699294839c066834ac7cd8eb677ddd3e38', 'sha256': 'f295d448914acde0b65bc4c7593ff2a6310fee173b3171584a31eb2e34c86d52', 'bytes': 716800, 'blob': '5c96eed2726c4afbf7dc47d8183e50bb94ace806'}}, {'name': 'AgentENV-5ca17126-source.part003.bin', 'bytes': 716800, 'sha256': 'a47c447e1a30d1cfe45224a3dff1c363da21a15f982d43a80b7521908efbc812', 'descriptor': {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-jwk-aenv-20261107/AgentENV-5ca17126-source.part003.bin', 'commit': '9e618b699294839c066834ac7cd8eb677ddd3e38', 'sha256': 'a47c447e1a30d1cfe45224a3dff1c363da21a15f982d43a80b7521908efbc812', 'bytes': 716800, 'blob': '2f32a2ba9f1fed782d387bc3cf022b7521476f76'}}, {'name': 'AgentENV-5ca17126-source.part004.bin', 'bytes': 152454, 'sha256': '7bbf8fe1a0b6e6f6806b37b36b73d9bbbefeacfb1b1ca0ea950da7ca9482aed2', 'descriptor': {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-jwk-aenv-20261107/AgentENV-5ca17126-source.part004.bin', 'commit': '9e618b699294839c066834ac7cd8eb677ddd3e38', 'sha256': '7bbf8fe1a0b6e6f6806b37b36b73d9bbbefeacfb1b1ca0ea950da7ca9482aed2', 'bytes': 152454, 'blob': 'edbc455b77a08a6c4abb66bca185db47cd7a005c'}}], 'commit_object': 'AgentENV-5ca17126.commit', 'commit_object_sha256': '89af7573580d415df022f197c8edf4cf9caf250632470d0eda667c21346b64f6', 'origin': 'https://gitcode.com/boostkit/AgentENV.git'}, 'commit_object': {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-jwk-aenv-20261107/AgentENV-5ca17126.commit', 'commit': '9e618b699294839c066834ac7cd8eb677ddd3e38', 'sha256': '89af7573580d415df022f197c8edf4cf9caf250632470d0eda667c21346b64f6', 'bytes': 1052, 'blob': '2eafd41594964e0ea69547c2555b1ed86ddb6030'}, 'startup_patch': {'blob': 'bd9c99c29ad1f5032d757a684da67664ec1108fe', 'bytes': 7035, 'commit': '1387b23851fa5c8fc19d9e206860d07786ada306', 'path': 'dev-relay/host-pmem/y-jwk-aenv-20261107/initial-pool.patch', 'repo': 'LittleFish-15/AgentENV', 'sha256': '9f73bc40e2ea3e6b9b8599b1e6c0c4f24cde4536917819fc8599cf0d6ffab8f6'}, 'rust': {'name': 'rust-1.91.1-x86_64-unknown-linux-gnu.tar.xz', 'url': 'https://static.rust-lang.org/dist/rust-1.91.1-x86_64-unknown-linux-gnu.tar.xz', 'sha256': 'db178028da493a663b2e344a142076fb0f72adea4120043983f488de9cf95214'}}
START=time.monotonic()
STATE={'schema':1,'action':'Y_DOWNLOAD_AND_BUILD','source_commit':'5ca17126c51ce1ac1cfaf31cf50d902ab54d55b7',
       'compiled':False,'service_started':False,'benchmark_executed':False,'stages':[]}
JWK=None

def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,why):
    if not ok:raise RuntimeError(why)
def owned_mkdir(path):
    need(path.parent.resolve()==path.parent and not path.is_symlink(),'Redirected build directory')
    if not path.exists():path.mkdir(mode=0o700);os.chown(path,JWK.pw_uid,JWK.pw_gid)
    st=path.stat();need(st.st_uid==JWK.pw_uid and stat.S_ISDIR(st.st_mode),'Unexpected build directory owner/type')
def save():
    target=BASE/'build-status.json'
    need(not target.is_symlink(),'Redirected status file')
    target.write_text(json.dumps(STATE,ensure_ascii=False,indent=2)+'\n')
    os.chown(target,JWK.pw_uid,JWK.pw_gid);os.chmod(target,0o600)
def user_environment():
    env={'HOME':JWK.pw_dir,'USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
       'PATH':str(BASE/'deps/rust-1.91.1/bin')+':/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
       'CARGO_HOME':str(BASE/'deps/cargo'),'CARGO_TARGET_DIR':str(BASE/'build/target'),
       'CARGO_BUILD_JOBS':'4','CARGO_INCREMENTAL':'0','CARGO_HTTP_SSL_VERIFY':'false',
       'CARGO_HTTP_TIMEOUT':'120','CARGO_HTTP_MULTIPLEXING':'false','CARGO_NET_RETRY':'2',
       'CARGO_NET_GIT_FETCH_WITH_CLI':'true','GIT_TERMINAL_PROMPT':'0',
       'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'http.sslVerify','GIT_CONFIG_VALUE_0':'false'}
    for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy'):
        if key in os.environ:env[key]=os.environ[key]
    return env
def available_memory():
    return next(int(x.split()[1])*1024 for x in P('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
def run(name,argv,seconds=900,user=True,cwd=BASE,input_bytes=None):
    need(time.monotonic()-START<10200,'Build task overall deadline reached')
    log=BASE/'build-logs'/(name+'.log')
    need(not log.exists() and not log.is_symlink(),'Existing stage log preserved; reconcile previous build before retry')
    stage={'name':name,'user':'jwk' if user else 'root','started_unix':time.time()};STATE['stages'].append(stage);save()
    print(json.dumps({'stage':name,'state':'started','user':stage['user']}),flush=True)
    if user:argv=['runuser','-u','jwk','--','nice','-n','15',*argv]
    env=user_environment() if user else dict(os.environ)
    begun=time.monotonic();reason=None
    with log.open('xb') as out:
        os.chown(log,JWK.pw_uid,JWK.pw_gid)
        proc=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                              stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
        if input_bytes is not None:proc.stdin.write(input_bytes);proc.stdin.close()
        last=begun
        while proc.poll() is None:
            now=time.monotonic()
            if now-begun>seconds or now-START>10300:reason='timeout'
            elif available_memory()<128*2**30:reason='available_memory_below_128GiB'
            if reason:
                os.killpg(proc.pid,signal.SIGTERM)
                try:proc.wait(timeout=10)
                except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
                break
            if now-last>=30:
                print(json.dumps({'stage':name,'elapsed_seconds':round(now-begun),'log_bytes':log.stat().st_size}),flush=True);last=now
            time.sleep(1)
    stage.update(exit_code=proc.returncode,elapsed_seconds=round(time.monotonic()-begun,3),stop_reason=reason);save()
    if proc.returncode!=0 or reason:
        with log.open('rb') as f:f.seek(max(0,log.stat().st_size-12000));tail=f.read()
        print(json.dumps({'stage':name,'tail':tail.decode(errors='replace')}),flush=True)
        raise RuntimeError('Build stage failed: '+name)
    return log.read_text(errors='replace')[-32000:] if log.stat().st_size<128*1024 else ''
def download(name,descriptor):
    target=BASE/'downloads'/name
    need(not target.exists(),'Existing delivery file preserved')
    url='https://api.github.com/repos/'+descriptor['repo']+'/contents/'+descriptor['path']+'?ref='+descriptor['commit']
    run('download-'+name,['curl','-k','-fL','--retry','2','--connect-timeout','10','--max-time','180',
         '--max-filesize',str(descriptor['bytes']),'-H','Accept: application/vnd.github.raw+json',url,'-o',str(target)],seconds=600)
    need(target.stat().st_size==descriptor['bytes'] and sha(target.read_bytes())==descriptor['sha256'],'Downloaded delivery digest differs')
    return target
def diagnostic(argv):
    try:
        r=subprocess.run(argv,capture_output=True,text=True,timeout=20)
        return {'code':r.returncode,'stdout':r.stdout[-8000:],'stderr':r.stderr[-1500:]}
    except (OSError,subprocess.TimeoutExpired) as e:return {'error_type':type(e).__name__}
def main():
    global JWK
    need(os.geteuid()==0 and platform.machine()=='x86_64','Run the Y root entry on native x86_64')
    JWK=pwd.getpwnam('jwk');need(JWK.pw_uid==1000,'Y jwk UID changed')
    os.umask(0o077)
    owned_mkdir(P('/data/jwk'));owned_mkdir(BASE)
    need(not (BASE/'build-status.json').exists(),'Prior build state exists; preserve and reconcile instead of implicit retry')
    for rel in ('downloads','source','deps','build','build-logs'):owned_mkdir(BASE/rel)
    STATE['kernel']=platform.release();STATE['jwk_uid']=JWK.pw_uid
    STATE['runtime_prerequisites']={'kvm_device':P('/dev/kvm').exists(),'ublk_control':P('/dev/ublk-control').exists(),
      'svm_cpu_flag':any('svm' in x.split(':',1)[1].split() for x in P('/proc/cpuinfo').read_text().splitlines() if x.startswith('flags')),
      'kvm_amd_modinfo':diagnostic(['modinfo','kvm_amd']), 'ublk_modinfo':diagnostic(['modinfo','ublk_drv'])}
    save()
    try:
        manifest=DELIVERY['source_manifest'];parts=[download(p['name'],p['descriptor']) for p in manifest['parts']]
        archive=BASE/'downloads/AgentENV-5ca17126-source.tar.gz'
        with archive.open('xb') as out:
            for path in parts:out.write(path.read_bytes())
        os.chown(archive,JWK.pw_uid,JWK.pw_gid)
        need(archive.stat().st_size==manifest['archive_bytes'] and sha(archive.read_bytes())==manifest['archive_sha256'],'Reassembled source archive differs')
        with tarfile.open(archive,'r:gz') as tf:
            for member in tf.getmembers():
                path=P(member.name)
                need(not path.is_absolute() and '..' not in path.parts and '.git' not in path.parts,'Unsafe archive member')
                need(member.isfile() or member.isdir() or member.issym(),'Unsupported archive object')
                if member.issym():
                    target=(SOURCE/path.parent/member.linkname).resolve()
                    need(target.is_relative_to(SOURCE),'Source symlink escapes checkout')
        owned_mkdir(SOURCE)
        run('extract-source',['tar','-xzf',str(archive),'-C',str(SOURCE)])
        run('git-init',['git','init','--initial-branch=baseline-5ca17126'],cwd=SOURCE)
        run('git-index-source',['git','-c','core.autocrlf=false','add','--force','--all'],cwd=SOURCE)
        tree=run('git-tree',['git','write-tree'],cwd=SOURCE).strip()
        need(tree==manifest['tree'],'Extracted Git tree differs from pinned baseline')
        obj=download('AgentENV-5ca17126.commit',DELIVERY['commit_object']).read_bytes()
        actual=run('restore-original-commit',['git','hash-object','-t','commit','-w','--stdin'],cwd=SOURCE,input_bytes=obj).strip()
        need(actual==manifest['commit'],'Original Git commit object differs')
        shallow=SOURCE/'.git/shallow';shallow.write_text(manifest['commit']+'\n');os.chown(shallow,JWK.pw_uid,JWK.pw_gid)
        run('git-reference',['git','update-ref','refs/heads/baseline-5ca17126',manifest['commit']],cwd=SOURCE)
        run('git-origin',['git','remote','add','origin',manifest['origin']],cwd=SOURCE)
        need(run('git-verify-clean',['git','status','--porcelain'],cwd=SOURCE).strip()=='','Restored baseline checkout not clean')
        patch_file=download('initial-pool.patch',DELIVERY['startup_patch'])
        run('patch-check',['git','apply','--check',str(patch_file)],cwd=SOURCE)
        run('apply-pool-patch',['git','apply',str(patch_file)],cwd=SOURCE)
        diff=run('record-patch',['git','diff','--binary'],cwd=SOURCE)
        STATE['applied_patch_sha256']=DELIVERY['startup_patch']['sha256'];STATE['source_tree_before_patch']=tree
        STATE['modified_files']=run('record-modified-files',['git','diff','--name-only'],cwd=SOURCE).splitlines()
        need(set(STATE['modified_files'])=={'crates/warm-pool/src/lib.rs','src/cfg.rs','src/sandbox/firecracker/pool.rs','config/default.toml'},'Unexpected patched file set')
        need(shutil.which('dnf') is not None,'Expected openEuler dnf is unavailable')
        run('install-build-dependencies',['dnf','-y','--setopt=sslverify=false','--setopt=*.sslverify=false','install',
           'gcc','gcc-c++','make','cmake','clang','clang-devel','openssl-devel','protobuf-devel','protobuf-compiler',
           'liburing-devel','libaio-devel','zlib-devel','perl','xz','tar'],seconds=1800,user=False)
        rust=DELIVERY['rust'];rust_archive=BASE/'downloads'/rust['name']
        run('download-native-rust',['curl','-k','-fL','--retry','2','--connect-timeout','10','--max-time','900',rust['url'],'-o',str(rust_archive)],seconds=1000)
        need(sha(rust_archive.read_bytes())==rust['sha256'],'Pinned Rust distribution digest differs')
        run('extract-native-rust',['tar','-xJf',str(rust_archive),'-C',str(BASE/'downloads')],seconds=300)
        rust_source=BASE/'downloads'/rust['name'].removesuffix('.tar.xz')
        run('install-user-local-rust',['bash',str(rust_source/'install.sh'),'--prefix='+str(BASE/'deps/rust-1.91.1'),
          '--disable-ldconfig','--components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu'],seconds=300)
        STATE['rustc_version']=run('rustc-version',['rustc','-vV']);STATE['cargo_version']=run('cargo-version',['cargo','-vV'])
        STATE['lockfile_sha256']=sha((SOURCE/'Cargo.lock').read_bytes());save()
        run('build-server-cli-ublk',['cargo','build','--locked','--release','-j','4','-p','agentenv','-p','aenv','-p','uvm-ublk-daemon',
             '--bin','server','--bin','aenv','--bin','uvm-ublk-daemon'],seconds=9000,cwd=SOURCE)
        need(sha((SOURCE/'Cargo.lock').read_bytes())==STATE['lockfile_sha256'],'Cargo.lock changed')
        STATE['binaries']={}
        for name in ('server','aenv','uvm-ublk-daemon'):
            path=BASE/'build/target/release'/name;need(path.is_file() and path.stat().st_uid==JWK.pw_uid,'Built binary missing or owned by wrong user')
            STATE['binaries'][name]={'path':str(path),'sha256':sha(path.read_bytes()),'file':diagnostic(['file','-b',str(path)]),
              'dynamic_dependencies':diagnostic(['ldd',str(path)])}
        run('cli-help',[str(BASE/'build/target/release/aenv'),'--help'])
        run('server-help',[str(BASE/'build/target/release/server'),'--help'])
        STATE['compiled']=True;STATE['state']='COMPILED_WAITING_RUNTIME_DEPLOYMENT';save()
        print(json.dumps(STATE,ensure_ascii=False),flush=True)
    except Exception as error:
        STATE['state']='BUILD_STOPPED_PRESERVE_LOGS';STATE['error_type']=type(error).__name__
        STATE['reason']=str(error)[:400];save();print(json.dumps(STATE,ensure_ascii=False),flush=True);raise
if __name__=='__main__':main()
