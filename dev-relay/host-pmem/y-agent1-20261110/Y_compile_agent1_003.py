"""Copy local components into a jwk-owned prefix; build exact original sources there."""
import hashlib,json,os,pathlib,pwd,re,shutil,signal,subprocess,time,urllib.parse
P=pathlib.Path
COMMIT=None
BASE=P('/home/jwk/aenv-agent1-20261110-r2');SOURCE=BASE/'source/AgentENV';START=time.monotonic();PARENT=os.getppid()
RUST_SHA='db178028da493a663b2e344a142076fb0f72adea4120043983f488de9cf95214'
STATE={'action':'LOCAL_REUSE_BUILD_INSTALL','source_commit':COMMIT,'source_patches':[],
  'compiled':False,'installed':False,'system_packages_changed':False,'other_user_files_changed':False,
  'stages':[],'copied_components':[]}
JWK=None
def need(ok,msg):
    if not ok:raise RuntimeError(msg)
def sha_file(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024**2),b''):h.update(b)
    return h.hexdigest()
def mkdir(path):
    need(path.parent.resolve()==path.parent and not path.is_symlink(),'Redirected destination')
    if not path.exists():path.mkdir(mode=0o700);os.chown(path,JWK.pw_uid,JWK.pw_gid)
    need(path.stat().st_uid==JWK.pw_uid and path.is_dir(),'Destination not owned by jwk')
def chown_copy(path):
    need(path.resolve().is_relative_to(BASE),'Ownership operation outside private copy')
    for root,dirs,files in os.walk(path,followlinks=False):
        os.chown(root,JWK.pw_uid,JWK.pw_gid)
        for name in dirs+files:os.lchown(P(root)/name,JWK.pw_uid,JWK.pw_gid)
def save():
    tmp=BASE/'status.json.next';target=BASE/'status.json'
    need(not tmp.is_symlink() and not target.is_symlink(),'Redirected status')
    tmp.write_text(json.dumps(STATE,ensure_ascii=False,indent=2)+'\n');os.chown(tmp,JWK.pw_uid,JWK.pw_gid);os.chmod(tmp,0o600);os.replace(tmp,target)
def env():
    v={'HOME':JWK.pw_dir,'USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
      'PATH':str(BASE/'deps/native/bin')+':/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
      'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'http.sslVerify','GIT_CONFIG_VALUE_0':'false',
      'CARGO_HOME':str(BASE/'deps/cargo'),'CARGO_TARGET_DIR':str(BASE/'target'),'CARGO_BUILD_JOBS':'4',
      'CARGO_INCREMENTAL':'0','CARGO_HTTP_SSL_VERIFY':'false','CARGO_HTTP_MULTIPLEXING':'false',
      'CARGO_HTTP_TIMEOUT':'120','CARGO_NET_RETRY':'2','CARGO_NET_GIT_FETCH_WITH_CLI':'true'}
    for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy'):
        if k in os.environ:v[k]=os.environ[k]
    return v
def root_git(repo,*args):
    # Read only original repositories, with optional index refresh disabled.
    return subprocess.run(['git','--no-optional-locks','-c','safe.directory='+str(repo),'-c','core.autocrlf=false','-C',str(repo),*args],
      capture_output=True,text=True,timeout=30,env=dict(os.environ,GIT_CONFIG_SYSTEM='/dev/null',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0'))
def probe(args,environment=None,seconds=15,cwd=BASE):
    try:
        r=subprocess.run(['runuser','-u','jwk','--',*args],cwd=cwd,env=environment or env(),capture_output=True,text=True,timeout=seconds)
        return {'code':r.returncode,'stdout':r.stdout[-12000:],'stderr':r.stderr[-3000:]}
    except (OSError,subprocess.TimeoutExpired) as error:return {'code':None,'error':type(error).__name__}
def run(name,args,environment=None,seconds=900,cwd=BASE,as_jwk=True):
    need(os.getppid()==PARENT,'Entry supervisor exited')
    stage={'name':name,'started_unix':time.time(),'user':'jwk' if as_jwk else 'root_local_clone_only'}
    STATE['stages'].append(stage);STATE['state']=name;save();print(json.dumps({'stage':name,'state':'started'}),flush=True)
    log=BASE/'logs'/(name+'.log');need(not log.exists(),'Previous stage log preserved')
    argv=['runuser','-u','jwk','--','nice','-n','15',*args] if as_jwk else args
    started=time.monotonic();reason=None;last=started
    with log.open('xb') as out:
        os.chown(log,JWK.pw_uid,JWK.pw_gid)
        p=subprocess.Popen(argv,cwd=cwd,env=environment or env(),stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
        stage['pid']=p.pid;save()
        while p.poll() is None:
            now=time.monotonic()
            available=next(int(x.split()[1])*1024 for x in P('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
            if os.getppid()!=PARENT:reason='entry_supervisor_exited'
            elif now-started>seconds or now-START>10200:reason='deadline'
            elif available<128*2**30:reason='available_memory_below_128GiB'
            if reason:
                os.killpg(p.pid,signal.SIGTERM)
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=10)
                break
            if now-last>=30:
                stage['elapsed_seconds']=round(now-started);save();print(json.dumps({'stage':name,'elapsed_seconds':stage['elapsed_seconds'],'log_bytes':log.stat().st_size}),flush=True);last=now
            time.sleep(1)
    stage.update(exit_code=p.returncode,stop_reason=reason,elapsed_seconds=round(time.monotonic()-started,3));save()
    if p.returncode!=0 or reason:
        with log.open('rb') as f:f.seek(max(0,log.stat().st_size-8000));tail=f.read().decode(errors='replace')
        print(json.dumps({'stage':name,'tail':tail}),flush=True);raise RuntimeError('Stage failed: '+name)
    return log.read_text(errors='replace').strip() if log.stat().st_size<32000 else ''
def copy_component(source,dest,label,max_bytes=4*2**30,max_files=150000):
    source=source.resolve();need(source.exists() and not dest.exists(),'Component source missing or private destination already exists')
    need(dest.parent.resolve().is_relative_to(BASE),'Component copy outside jwk prefix')
    count=0;size=0
    if source.is_dir():
        for root,dirs,files in os.walk(source,followlinks=False):
            count+=len(files)
            for name in files:
                p=P(root)/name
                if not p.is_symlink():size+=p.stat().st_size
            need(count<=max_files and size<=max_bytes,'Component copy bound exceeded: '+label)
        shutil.copytree(source,dest,symlinks=True);chown_copy(dest)
    else:
        size=source.stat().st_size;need(size<=max_bytes,'Component too large')
        shutil.copy2(source,dest);os.chown(dest,JWK.pw_uid,JWK.pw_gid)
        need(sha_file(source)==sha_file(dest),'Copied component digest differs')
    STATE['copied_components'].append({'kind':label,'source':str(source),'destination':str(dest),'bytes':size,'files':count});save()
def find_repositories():
    repos=[]
    for first in sorted(P('/home/jwk').iterdir()):
        if first.is_symlink() or not first.is_dir() or first.name.startswith('.') or first.name in ('y-aenv-control',BASE.name):continue
        paths=[first]+[x for x in first.iterdir() if x.is_dir() and not x.is_symlink() and not x.name.startswith('.')][:40]
        for path in paths:
            if not (path/'.git').exists():continue
            head=root_git(path,'rev-parse','HEAD');origin=root_git(path,'remote','get-url','origin')
            if head.returncode!=0:continue
            url=origin.stdout.strip();parsed=urllib.parse.urlsplit(url)
            safe_url=urllib.parse.urlunsplit((parsed.scheme,parsed.hostname or '',parsed.path,'','')) if parsed.scheme else url.split('@')[-1]
            if 'agentenv' not in (path.name+' '+safe_url).lower():continue
            obj=root_git(path,'cat-file','-e',COMMIT+'^{commit}')
            dirty=root_git(path,'status','--porcelain','--untracked-files=no')
            repos.append({'path':str(path),'uid':path.stat().st_uid,'head':head.stdout.strip(),'origin':safe_url,
              'has_target_commit':obj.returncode==0,'tracked_changes_present':bool(dirty.stdout.strip())})
    return repos
def prepare_toolchain():
    # Probe system tools as jwk; do not invoke rustup shims or execute others' binaries as root.
    candidates=[]
    for binary in (P('/usr/bin/rustc'),P('/usr/local/bin/rustc')):
        if binary.is_file() and binary.resolve().name!='rustup' and (binary.parent/'cargo').is_file():
            r=probe([str(binary),'-V']);m=re.match(r'rustc (\d+)\.(\d+)\.(\d+)',r.get('stdout',''))
            if r['code']==0 and m and tuple(map(int,m.groups()))>=(1,91,1):candidates.append((tuple(map(int,m.groups())),binary.parent.parent,'system_readonly'))
    roots=[P('/root/.rustup/toolchains'),P('/home/jwk/.rustup/toolchains'),P('/data/aenv/deps'),
      P('/data/jwk/aenv-y-20261107/deps'),P('/data/jwk/aenv-y-ae9c626-20261107/deps'),P('/opt')]
    roots.extend(x/'.rustup/toolchains' for x in P('/home').iterdir() if x.is_dir() and x.name!='jwk')
    possible=[]
    for root in roots:
        if not root.is_dir():continue
        for child in sorted(root.iterdir()):
            if child.is_dir() and (child/'bin/rustc').is_file() and (child/'bin/cargo').is_file() and (child/'bin/rustc').resolve().name!='rustup':possible.append(child)
    possible=sorted(set(possible),key=lambda p:('1.91.1' not in p.name,str(p)))[:6]
    for i,path in enumerate(possible):
        copied=BASE/'deps'/('rust-copy-'+str(i));copy_component(path,copied,'native_rust_toolchain')
        r=probe([str(copied/'bin/rustc'),'-V']);m=re.match(r'rustc (\d+)\.(\d+)\.(\d+)',r.get('stdout',''))
        STATE.setdefault('toolchain_probes',[]).append({'source':str(path),'copied':str(copied),'result':r});save()
        if r['code']==0 and m and tuple(map(int,m.groups()))>=(1,91,1):
            candidates.append((tuple(map(int,m.groups())),copied,'private_copy'))
            if tuple(map(int,m.groups()))==(1,91,1):break
    if not candidates:
        # Reuse a fully downloaded official distribution only after its pinned digest matches.
        name='rust-1.91.1-x86_64-unknown-linux-gnu.tar.xz'
        for root in (P('/data/jwk/aenv-y-ae9c626-20261107/downloads'),P('/data/jwk/aenv-y-20261107/downloads'),P('/home/jwk'),P('/root'),P('/root/Downloads'),P('/data/aenv/deps')):
            archive=root/name
            if archive.is_file() and not archive.is_symlink() and archive.stat().st_size==192066332 and sha_file(archive)==RUST_SHA:
                copied=BASE/'downloads'/name;copy_component(archive,copied,'verified_complete_rust_archive')
                run('extract-local-rust',['tar','-xJf',str(copied),'-C',str(BASE/'downloads')],seconds=300)
                tree=BASE/'downloads'/name.removesuffix('.tar.xz');prefix=BASE/'deps/rust-1.91.1'
                run('install-local-rust',['bash',str(tree/'install.sh'),'--prefix='+str(prefix),'--disable-ldconfig',
                  '--components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu'],seconds=300)
                candidates.append(((1,91,1),prefix,'verified_local_archive'));break
    STATE['toolchain_candidates']=[{'version':'.'.join(map(str,v)),'prefix':str(p),'kind':k} for v,p,k in candidates];save()
    if not candidates:return None
    v,p,kind=sorted(candidates,key=lambda x:(x[0]!=(1,91,1),x[0]))[0]
    # System compiler stays read-only; all user-local toolchains were copied already.
    return {'version':'.'.join(map(str,v)),'prefix':str(p),'kind':kind,'differs_from_X_1_91_1':v!=(1,91,1)}
def reuse_cargo_cache():
    dest=BASE/'deps/cargo';mkdir(dest);mkdir(dest/'registry')
    roots=[P('/root/.cargo'),P('/home/jwk/.cargo'),P('/data/jwk/aenv-y-20261107/deps/cargo'),P('/data/jwk/aenv-y-ae9c626-20261107/deps/cargo')]
    roots.extend(x/'.cargo' for x in P('/home').iterdir() if x.is_dir() and x.name!='jwk')
    for kind in ('cache','src','index'):
        mkdir(dest/'registry'/kind)
        for root in roots:
            directory=root/'registry'/kind
            if not directory.is_dir():continue
            for candidate in sorted(directory.glob('index.crates.io-*')):
                target=dest/'registry'/kind/candidate.name
                if kind=='index' and (candidate/'config.json').is_file():
                    cfg=json.loads((candidate/'config.json').read_text())
                    dl=urllib.parse.urlsplit(cfg.get('dl',''))
                    if dl.hostname!='static.crates.io' or dl.username or dl.password or cfg.get('auth-required'):continue
                if candidate.is_dir() and not target.exists():copy_component(candidate,target,'public_cargo_registry_'+kind)
    # Never copy credentials.toml, a user cargo config, git config, or SSH data.
    mkdir(dest/'git');mkdir(dest/'git/db')
    for root in roots:
        directory=root/'git/db'
        if not directory.is_dir():continue
        for repo in sorted(directory.glob('libublk-rs-*')):
            target=dest/'git/db'/repo.name
            if not repo.is_dir() or target.exists():continue
            mkdir(target)
            for name in ('objects','refs','HEAD','packed-refs','shallow'):
                p=repo/name
                if p.exists() and not p.is_symlink():copy_component(p,target/name,'public_libublk_git_objects')
            config=target/'config';config.write_text('[core]\n\tbare = true\n[remote "origin"]\n\turl = https://github.com/ublk-org/libublk-rs.git\n');os.chown(config,JWK.pw_uid,JWK.pw_gid)
def main():
    global JWK,COMMIT
    need(os.geteuid()==0,'Use root unified entry');JWK=pwd.getpwnam('jwk');os.umask(0o077)
    mkdir(BASE);need(not (BASE/'status.json').exists(),'Previous build state preserved; explicit resume needed')
    for name in ('source','deps','downloads','logs','bin'):mkdir(BASE/name)
    mkdir(BASE/'deps/native');mkdir(BASE/'deps/native/bin');save()
    try:
        original=P('/home/jwk/AgentENV')
        need(original.is_dir() and (original/'.git').exists(),'Requested /home/jwk/AgentENV repository is missing')
        head=root_git(original,'rev-parse','HEAD');need(head.returncode==0 and re.fullmatch('[0-9a-f]{40}',head.stdout.strip()),'Cannot read requested source HEAD')
        COMMIT=head.stdout.strip();STATE['source_commit']=COMMIT
        need(COMMIT=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc','Source HEAD changed since confirmed agent1 readiness; preserve and review')
        STATE['matches_previously_requested_X_baseline']=COMMIT=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc'
        changes=root_git(original,'status','--porcelain','--untracked-files=all')
        STATE['original_source_status']=changes.stdout[:8000];save()
        need(changes.returncode==0 and not changes.stdout.strip(),'Requested source has local changes; preserved without checkout or patching')
        selected={'path':str(original),'uid':original.stat().st_uid,'head':COMMIT,'clean':True}
        STATE['repositories']=[selected]
        STATE['original_clone']=selected;save()
        STATE['runtime_prerequisites']={}
        for module in ('kvm_amd','ublk_drv'):
            try:
                r=subprocess.run(['modinfo',module],capture_output=True,text=True,timeout=15)
                STATE['runtime_prerequisites'][module]={'code':r.returncode,'stdout':r.stdout[:8000],'stderr':r.stderr[:2000]}
            except (OSError,subprocess.TimeoutExpired) as e:STATE['runtime_prerequisites'][module]={'error':type(e).__name__}
        STATE['runtime_prerequisites']['devices']={p:{'exists':P(p).exists(),'mode':oct(P(p).stat().st_mode&0o777) if P(p).exists() else None} for p in ('/dev/kvm','/dev/ublk-control','/dev/net/tun')}
        cfg=P('/boot/config-'+os.uname().release)
        if cfg.is_file():STATE['runtime_prerequisites']['kernel_config']=[x for x in cfg.read_text().splitlines() if re.search(r'CONFIG_(BLK_DEV_UBLK|KVM|HZ)',x)]
        STATE['runtime_prerequisites']['kernel_build_headers']=str(P('/lib/modules')/os.uname().release/'build')
        STATE['runtime_prerequisites']['kernel_build_headers_exist']=(P('/lib/modules')/os.uname().release/'build').exists()
        save()

        # Clone committed objects locally without hardlinks, without touching the original checkout or hooks.
        args=['git','-c','safe.directory='+selected['path'],'-c','core.autocrlf=false','clone','--local','--no-hardlinks','--no-checkout',selected['path'],str(SOURCE)]
        clone_env=env();clone_env.update(GIT_CONFIG_SYSTEM='/dev/null',GIT_CONFIG_GLOBAL='/dev/null')
        need(P(selected['path']).stat().st_uid==JWK.pw_uid,'Source owner differs from jwk; original ownership preserved')
        run('copy-local-git-clone',args,environment=clone_env,seconds=300,as_jwk=True);chown_copy(SOURCE)
        obj=probe(['git','-C',str(SOURCE),'cat-file','-e',COMMIT+'^{commit}'])
        need(obj['code']==0,'Local clone lacks requested HEAD; no alternate source will be fetched')
        run('checkout-original-commit',['git','-C',str(SOURCE),'checkout','--detach',COMMIT])
        actual=probe(['git','-C',str(SOURCE),'rev-parse','HEAD']);need(actual['stdout'].strip()==COMMIT,'Checked-out commit differs')
        clean=probe(['git','-C',str(SOURCE),'status','--porcelain']);need(clean['code']==0 and not clean['stdout'].strip(),'Private source tree not clean')
        STATE['source_path']=str(SOURCE);STATE['checkout_verified']=True;STATE['lockfile_sha256']=sha_file(SOURCE/'Cargo.lock');save()
        toolchain=prepare_toolchain();STATE['toolchain']=toolchain;save()
        if toolchain is None:
            STATE['state']='BLOCKED_NO_USABLE_LOCAL_RUST_TOOLCHAIN';save();print(json.dumps(STATE,ensure_ascii=False));return
        reuse_cargo_cache()
        environment=env();environment['PATH']=str(P(toolchain['prefix'])/'bin')+':'+environment['PATH'];environment['RUSTC']=str(P(toolchain['prefix'])/'bin/rustc')
        STATE['rustc']=probe([environment['RUSTC'],'-vV'],environment);STATE['cargo']=probe([str(P(toolchain['prefix'])/'bin/cargo'),'-vV'],environment)
        STATE['native_components']={name:probe(['sh','-c','command -v '+name],environment) for name in ('cc','c++','clang','protoc','pkg-config','cmake')};save()
        run('cargo-release-build',[str(P(toolchain['prefix'])/'bin/cargo'),'build','--locked','--release','-j','4',
          '-p','agentenv','-p','aenv','-p','uvm-ublk-daemon','--bin','server','--bin','aenv','--bin','uvm-ublk-daemon'],environment,seconds=9000,cwd=SOURCE)
        need(sha_file(SOURCE/'Cargo.lock')==STATE['lockfile_sha256'],'Cargo.lock changed')
        need(not probe(['git','-C',str(SOURCE),'status','--porcelain'])['stdout'].strip(),'Source modified by build')
        STATE['compiled']=True;STATE['binaries']={}
        for name in ('server','aenv','uvm-ublk-daemon'):
            built=BASE/'target/release'/name;need(built.is_file() and built.stat().st_uid==JWK.pw_uid,'Missing or wrong-owner artifact')
            typ=probe(['file','-b',str(built)]);need('x86-64' in typ.get('stdout',''),'Artifact is not native x86_64')
            copy_component(built,BASE/'bin'/name,'compiled_binary')
            STATE['binaries'][name]={'path':str(BASE/'bin'/name),'sha256':sha_file(BASE/'bin'/name),'file':typ,'ldd':probe(['ldd',str(built)])}
        run('installed-cli-help',[str(BASE/'bin/aenv'),'--help']);run('installed-server-help',[str(BASE/'bin/server'),'--help'])
        script=BASE/'env.sh';script.write_text('export PATH="'+str(BASE/'bin')+':$PATH"\n');os.chown(script,JWK.pw_uid,JWK.pw_gid);os.chmod(script,0o600)
        STATE['installed']=True;STATE['service_started']=False;STATE['deployment_pending']=True
        STATE['runtime_source_files']={}
        for relative in ('config/default.toml','config/deps_manifest.toml','src/privileges.rs','src/sandbox/firecracker/pool.rs','scripts/run-with-capabilities.sh'):
            p=SOURCE/relative
            if p.is_file():
                text=p.read_text(errors='replace')
                STATE['runtime_source_files'][relative]={'sha256':sha_file(p),'selected_lines':[{'line':i,'text':line[:250]} for i,line in enumerate(text.splitlines(),1) if re.search(r'CAP_|startup_size|low_watermark|high_watermark|daemon|metrics_listen|9103|binary_path|image_path|version =|AENV_HOME_PATH|AENV_RUNTIME_PATH',line)][:100]}
        STATE['state']='COMPILED_READY_FOR_ISOLATED_SERVICE_DEPLOYMENT';save();print(json.dumps(STATE,ensure_ascii=False))
    except Exception as error:
        STATE['state']='STOPPED_PRESERVE_PRIVATE_BUILD_LOGS';STATE['error_type']=type(error).__name__;STATE['reason']=str(error)[:500];save();print(json.dumps(STATE,ensure_ascii=False));raise
if __name__=='__main__':main()
