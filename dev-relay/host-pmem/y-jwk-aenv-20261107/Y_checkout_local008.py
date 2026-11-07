"""Use the user's home Git clone and installed toolchain. Never download Rust."""
import hashlib,json,os,pathlib,pwd,shutil,signal,subprocess,time
P=pathlib.Path;COMMIT='ae9c62693839ce7effa2b45df31c0039ae4f9fbc'
BASE=P('/data/jwk/aenv-y-git-20261107');START=time.monotonic();SUPERVISOR=os.getppid()
def sha(b):return hashlib.sha256(b).hexdigest()
def need(ok,why):
    if not ok:raise RuntimeError(why)
def main():
    need(os.geteuid()==0,'Use root entry');jwk=pwd.getpwnam('jwk');os.umask(0o077)
    if not BASE.exists():BASE.mkdir(mode=0o700);os.chown(BASE,jwk.pw_uid,jwk.pw_gid)
    need(BASE.resolve()==BASE and BASE.stat().st_uid==jwk.pw_uid,'Unexpected build directory')
    state={'source_commit':COMMIT,'source_patches':[],'compiled':False,'rust_downloaded':False,'stages':[]}
    def save():
        p=BASE/'status008.json';p.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n');os.chown(p,jwk.pw_uid,jwk.pw_gid)
    env={'HOME':jwk.pw_dir,'USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','PATH':'/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
      'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'http.sslVerify','GIT_CONFIG_VALUE_0':'false',
      'CARGO_HTTP_SSL_VERIFY':'false','CARGO_HTTP_MULTIPLEXING':'false','CARGO_NET_RETRY':'2',
      'CARGO_HOME':str(BASE/'cargo-cache'),'CARGO_TARGET_DIR':str(BASE/'target'),'CARGO_BUILD_JOBS':'4'}
    for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy'):
        if k in os.environ:env[k]=os.environ[k]
    def command(args,cwd,seconds=30):
        return subprocess.run(['runuser','-u','jwk','--',*args],cwd=cwd,env=env,capture_output=True,text=True,timeout=seconds)
    def git(repo,*args):return command(['git','-C',str(repo),*args],repo)
    repos=[]
    for root in sorted(P('/home/jwk').iterdir()):
        if root.is_symlink() or not root.is_dir() or root.name.startswith('.') or root.name=='y-aenv-control':continue
        paths=[root]+[p for p in root.iterdir() if p.is_dir() and not p.is_symlink() and not p.name.startswith('.')][:40]
        for repo in paths:
            if not (repo/'.git').exists():continue
            row={'path':str(repo),'uid':repo.stat().st_uid}
            if row['uid']==jwk.pw_uid:
                remote=git(repo,'remote','get-url','origin');row['origin']=remote.stdout.strip().split('@')[-1]
                status=git(repo,'status','--porcelain');row['clean']=status.returncode==0 and not status.stdout.strip()
                head=git(repo,'rev-parse','HEAD');row['head']=head.stdout.strip()
            repos.append(row)
    state['repositories']=repos;save()
    candidates=[r for r in repos if r['uid']==jwk.pw_uid and ('agentenv' in r.get('origin','').lower() or P(r['path']).name.lower()=='agentenv')]
    if len(candidates)!=1:
        state['state']='REPOSITORY_SELECTION_OR_OWNERSHIP_REQUIRES_REVIEW';save();print(json.dumps(state,ensure_ascii=False));return
    selected=candidates[0];need(selected['clean'],'User Git checkout has changes; preserve without forced checkout')
    repo=P(selected['path']);state['source_path']=str(repo)
    exists=git(repo,'cat-file','-e',COMMIT+'^{commit}')
    if exists.returncode!=0:
        fetched=command(['git','-c','http.sslVerify=false','-C',str(repo),'fetch','--no-tags','https://github.com/pclin1212/AgentENV.git',COMMIT],repo,180)
        need(fetched.returncode==0,'Exact pclin1212 commit fetch failed; existing clone preserved')
    checked=git(repo,'checkout','--detach',COMMIT);need(checked.returncode==0,'Checkout failed without force')
    need(git(repo,'rev-parse','HEAD').stdout.strip()==COMMIT and not git(repo,'status','--porcelain').stdout.strip(),'Checked-out source differs')
    state['checkout_complete']=True;state['lockfile_sha256']=sha((repo/'Cargo.lock').read_bytes());save()
    # Inspect actual native toolchains, bypassing rustup shims that could auto-download.
    toolchains=[]
    roots=[P(jwk.pw_dir)/'.rustup/toolchains',P('/data/jwk/aenv-y-ae9c626-20261107/deps'),P('/data/jwk/aenv-y-20261107/deps')]
    rustcs=[P('/usr/bin/rustc'),P('/usr/local/bin/rustc')]
    for root in roots:
        if root.is_dir():rustcs.extend(root.glob('*/bin/rustc'))
    for rustc in rustcs:
        if not rustc.is_file() or rustc.resolve().name=='rustup':continue
        cargo=rustc.parent/'cargo'
        if not cargo.is_file():continue
        try:r=command([str(rustc),'-V'],repo,10)
        except (OSError,subprocess.TimeoutExpired):continue
        toolchains.append({'rustc':str(rustc),'cargo':str(cargo),'version':r.stdout.strip(),'code':r.returncode})
    state['local_toolchains']=toolchains
    matching=[x for x in toolchains if x['code']==0 and x['version'].startswith('rustc 1.91.1 ')]
    if not matching:
        state['state']='CHECKOUT_COMPLETE_NO_LOCAL_RUST_1_91_1';save();print(json.dumps(state,ensure_ascii=False));return
    tc=matching[0];env['PATH']=str(P(tc['rustc']).parent)+':'+env['PATH'];env['RUSTC']=tc['rustc']
    state['toolchain_used']=tc;state['state']='COMPILING_USER_GIT_CHECKOUT';save()
    log=BASE/'cargo-build008.log';need(not log.exists(),'Prior build log preserved; no implicit retry')
    with log.open('xb') as out:
        os.chown(log,jwk.pw_uid,jwk.pw_gid)
        proc=subprocess.Popen(['runuser','-u','jwk','--','nice','-n','15',tc['cargo'],'build','--locked','--release','-j','4',
          '-p','agentenv','-p','aenv','-p','uvm-ublk-daemon','--bin','server','--bin','aenv','--bin','uvm-ublk-daemon'],
          cwd=repo,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
        while proc.poll() is None:
            if os.getppid()!=SUPERVISOR or time.monotonic()-START>10000:
                os.killpg(proc.pid,signal.SIGTERM)
                try:proc.wait(timeout=10)
                except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
                break
            time.sleep(2)
    state['cargo_exit_code']=proc.returncode
    need(proc.returncode==0,'Cargo build failed; preserve local log')
    need(sha((repo/'Cargo.lock').read_bytes())==state['lockfile_sha256'] and not git(repo,'status','--porcelain').stdout.strip(),'Original source changed during build')
    state['binaries']={n:{'path':str(BASE/'target/release'/n),'sha256':sha((BASE/'target/release'/n).read_bytes())} for n in ('server','aenv','uvm-ublk-daemon')}
    state['compiled']=True;state['state']='COMPILED_ORIGINAL_LOCAL_GIT_CHECKOUT';save();print(json.dumps(state,ensure_ascii=False))
if __name__=='__main__':main()
