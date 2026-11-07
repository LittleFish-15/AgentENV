"""Root provisions build dependencies; all source/toolchain/build work runs as jwk."""
import hashlib,json,os,pathlib,platform,pwd,shutil,signal,stat,subprocess,tarfile,time
P=pathlib.Path
BASE=P('/data/jwk/aenv-y-ae9c626-20261107')
SOURCE=BASE/'source/original-ae9c626'
DELIVERY={'source_manifest': {'commit': 'ae9c62693839ce7effa2b45df31c0039ae4f9fbc', 'archive_sha256': 'ca0c5e713b423c60b25e24187663fcba945721cc603d497b962168c124a35748', 'archive_bytes': 2302583, 'files': 802, 'symlinks': 1, 'parts': [{'name': 'X-original-ae9c626.part001.bin', 'bytes': 716800, 'sha256': '6257a9937eb5efd6960f5ff34168584c893aeeb7992c35eabf26a6b789d818a9', 'descriptor': {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-jwk-aenv-20261107/X-original-ae9c626.part001.bin', 'commit': '2ba12a89ef4915ce783dc717258a176a76b42fd4', 'sha256': '6257a9937eb5efd6960f5ff34168584c893aeeb7992c35eabf26a6b789d818a9', 'bytes': 716800, 'blob': '062c5091ead5e8986c9265d4e6034b6a36ad395f'}}, {'name': 'X-original-ae9c626.part002.bin', 'bytes': 716800, 'sha256': '129923865f3eca50c7319db1b36e272d3fda8fb556b229a1d22fd2b56c253110', 'descriptor': {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-jwk-aenv-20261107/X-original-ae9c626.part002.bin', 'commit': '2ba12a89ef4915ce783dc717258a176a76b42fd4', 'sha256': '129923865f3eca50c7319db1b36e272d3fda8fb556b229a1d22fd2b56c253110', 'bytes': 716800, 'blob': '5eeb464e49593fb11a30caf8f0ea6d499ddc2aa2'}}, {'name': 'X-original-ae9c626.part003.bin', 'bytes': 716800, 'sha256': '971ca87645eb29fa37d06e89ff634685b92ddbbc16d5342a1f2b1d6ccee50d57', 'descriptor': {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-jwk-aenv-20261107/X-original-ae9c626.part003.bin', 'commit': '2ba12a89ef4915ce783dc717258a176a76b42fd4', 'sha256': '971ca87645eb29fa37d06e89ff634685b92ddbbc16d5342a1f2b1d6ccee50d57', 'bytes': 716800, 'blob': '6c01de17af7f0b55c56a14c0bdd94026b4678373'}}, {'name': 'X-original-ae9c626.part004.bin', 'bytes': 152183, 'sha256': '78108326cb4126f30e9a102b96a7e796d0ad6d777d1440c58aaa18e493f8a34d', 'descriptor': {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-jwk-aenv-20261107/X-original-ae9c626.part004.bin', 'commit': '2ba12a89ef4915ce783dc717258a176a76b42fd4', 'sha256': '78108326cb4126f30e9a102b96a7e796d0ad6d777d1440c58aaa18e493f8a34d', 'bytes': 152183, 'blob': '6a776229280189861fe9e853b8932df8540c4b7a'}}], 'origin': 'https://github.com/pclin1212/AgentENV', 'startup_patch_applied': False, 'X_staged_source': '/data/jwk/aenv-baseline-20261103/source/original-ae9c626', 'Y_source': '/data/jwk/aenv-y-ae9c626-20261107/source/original-ae9c626'}, 'rust': {'name': 'rust-1.91.1-x86_64-unknown-linux-gnu.tar.xz', 'sha256': 'db178028da493a663b2e344a142076fb0f72adea4120043983f488de9cf95214', 'url': 'https://static.rust-lang.org/dist/rust-1.91.1-x86_64-unknown-linux-gnu.tar.xz'}}
START=time.monotonic()
STATE={'schema':1,'action':'Y_DOWNLOAD_AND_BUILD','source_commit':'ae9c62693839ce7effa2b45df31c0039ae4f9fbc',
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
        archive=BASE/'downloads/AgentENV-ae9c626.tar.gz'
        with archive.open('xb') as out:
            for path in parts:out.write(path.read_bytes())
        os.chown(archive,JWK.pw_uid,JWK.pw_gid)
        need(archive.stat().st_size==manifest['archive_bytes'] and sha(archive.read_bytes())==manifest['archive_sha256'],'Original X source archive digest differs')
        with tarfile.open(archive,'r:gz') as tf:
            need(tf.pax_headers.get('comment')==manifest['commit'],'Original archive Git commit metadata differs')
            prefixes=set();expected_files={}
            for member in tf.getmembers():
                path=P(member.name);prefixes.add(path.parts[0])
                need(not path.is_absolute() and '..' not in path.parts,'Unsafe original source archive member')
                safe_link=member.issym() and path.parts[1:]==('AGENTS.md',) and member.linkname=='CLAUDE.md'
                need(member.isfile() or member.isdir() or safe_link,'Unsupported original archive object')
                rel=P(*path.parts[1:])
                if member.isfile():expected_files[str(rel)]={'type':'file','sha256':sha(tf.extractfile(member).read())}
                elif safe_link:expected_files[str(rel)]={'type':'symlink','target':member.linkname}
            need(len(prefixes)==1 and len(expected_files)==803,'Original source layout differs')
        owned_mkdir(SOURCE)
        run('extract-original-X-source',['tar','-xzf',str(archive),'--strip-components=1','--no-same-owner','-C',str(SOURCE)])
        def verify_original_files():
            for rel,expected in expected_files.items():
                path=SOURCE/rel
                if expected['type']=='symlink':need(path.is_symlink() and os.readlink(path)==expected['target'],'Original source symlink changed')
                else:need(not path.is_symlink() and path.is_file() and sha(path.read_bytes())==expected['sha256'],'Original source file changed: '+rel)
        verify_original_files()
        STATE['source_archive_sha256']=manifest['archive_sha256'];STATE['source_repository']=manifest['origin']
        STATE['startup_patch_applied']=False;STATE['source_modifications']=[];STATE['verified_original_files']=802
        STATE['provenance']='Exact same original source archive staged on X; archive-based source, no synthetic Git checkout'
        save()
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
        verify_original_files()
        STATE['original_source_unchanged_after_build']=True
        STATE['compiled']=True;STATE['state']='COMPILED_WAITING_RUNTIME_DEPLOYMENT';save()
        print(json.dumps(STATE,ensure_ascii=False),flush=True)
    except Exception as error:
        STATE['state']='BUILD_STOPPED_PRESERVE_LOGS';STATE['error_type']=type(error).__name__
        STATE['reason']=str(error)[:400];save();print(json.dumps(STATE,ensure_ascii=False),flush=True);raise
if __name__=='__main__':main()
