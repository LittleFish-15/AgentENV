"""Prepare private runtime assets and a read-only device-owner query helper."""
import hashlib,json,os,pathlib,pwd,subprocess,tomllib
P=pathlib.Path
BASE=P('/home/jwk/aenv-y-clean-20261111');SRC=BASE/'source/AgentENV'
QUERY=r'''
use storage_util::io_ring::spawn_io_ring_worker;
use uvm_ublk::UVMUblkCtrlBuilder;
#[tokio::main(flavor="current_thread")]
async fn main() -> Result<(),Box<dyn std::error::Error>> {
    let args:Vec<String>=std::env::args().collect();
    if args.len()!=2 || args[1]=="--help" {println!("usage: jwk-ublk-query DEVICE_ID (read only)");return Ok(());}
    let id:u32=args[1].parse()?;
    let (ring,_) = spawn_io_ring_worker::<io_uring::squeue::Entry128>(0);
    let mut ctrl=UVMUblkCtrlBuilder::new().dev_id(id).name("jwk-owner-query").build(ring)?;
    ctrl.get_dev_info().await?;
    println!("{{\"id\":{},\"pid\":{},\"flags\":{}}}",id,ctrl.dev_info.ublksrv_pid,ctrl.dev_info.flags);
    Ok(())
}
'''
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    assert os.geteuid()==0
    user=pwd.getpwnam('jwk');os.umask(0o077)
    path=BASE/'runtime-prep003';assert BASE.resolve()==BASE and BASE.stat().st_uid==user.pw_uid and not path.exists()
    path.mkdir(mode=0o700);os.chown(path,user.pw_uid,user.pw_gid)
    state=json.loads((BASE/'status.json').read_text());assert state['compiled'] and state['installed'] and state['source_commit']=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc'
    result={'phase':'PRIVATE_RUNTIME_PREPARATION','uid':user.pw_uid,'serviceStarted':False,'moduleLoadedByTask':False,'assets':[]}
    def command(args,seconds=30,user_mode=False):
        if user_mode:args=['runuser','-u','jwk','--',*args]
        r=subprocess.run(args,capture_output=True,text=True,timeout=seconds)
        return {'code':r.returncode,'stdout':r.stdout[-16000:],'stderr':r.stderr[-2500:]}
    for module in ('ublk_drv','kvm_amd'):result[module]=command(['modinfo',module])
    result['devices']={p:{'exists':P(p).exists(),'uid':P(p).stat().st_uid if P(p).exists() else None,'gid':P(p).stat().st_gid if P(p).exists() else None,
      'mode':oct(P(p).stat().st_mode&0o777) if P(p).exists() else None} for p in ('/dev/kvm','/dev/net/tun','/dev/ublk-control')}
    result['listeners']=command(['ss','-ltnp']);result['overlaybd_etc_exists']=P('/etc/overlaybd').is_dir()
    # Only immutable dependency trees; no aenv application binaries, DBs or secrets.
    import shutil
    target=BASE/'runtime-assets';assert not target.exists();target.mkdir(mode=0o700);os.chown(target,user.pw_uid,user.pw_gid)
    for name in ('firecracker','kernel','overlaybd','regctl','tools'):
        origin=P('/data/aenv/deps')/name
        if not origin.is_dir():result['assets'].append({'name':name,'available':False});continue
        size=0;files=0
        for root,dirs,names in os.walk(origin,followlinks=False):
            dirs[:]=[d for d in dirs if not (P(root)/d).is_symlink()]
            for f in names:
                p=P(root)/f
                if p.is_symlink():continue
                assert not any(x in f.lower() for x in ('credential','secret','private_key')),'Unexpected sensitive file in dependency cache'
                size+=p.stat().st_size;files+=1
            assert size<=2*1024**3 and files<=5000,'Static dependency copy exceeds bound'
        shutil.copytree(origin,target/name,symlinks=True)
        for root,dirs,names in os.walk(target/name,followlinks=False):
            os.chown(root,user.pw_uid,user.pw_gid)
            for f in dirs+names:os.lchown(P(root)/f,user.pw_uid,user.pw_gid)
        result['assets'].append({'name':name,'available':True,'bytes':size,'files':files})
    # Keep all helper code/lockfile separate from the unchanged AgentENV repository.
    project=path/'query-helper';project.mkdir(mode=0o700);(project/'src').mkdir(mode=0o700)
    lock=tomllib.loads((SRC/'Cargo.lock').read_text());packages=lock['package']
    def ver(name,prefix=''):
        choices=[p['version'] for p in packages if p['name']==name and p['version'].startswith(prefix)]
        assert len(choices)==1,(name,choices)
        return choices[0]
    toml='[package]\nname="jwk-ublk-query"\nversion="0.0.0"\nedition="2021"\n[workspace]\n[dependencies]\n'
    toml+='storage-util={path='+json.dumps(str(SRC/'storage/util'))+'}\nuvm-ublk={path='+json.dumps(str(SRC/'storage/ublk'))+'}\n'
    toml+='tokio={version="='+ver('tokio')+'",features=["rt","macros"]}\nio-uring="='+ver('io-uring','0.7.')+'"\n'
    (project/'Cargo.toml').write_text(toml);(project/'src/main.rs').write_text(QUERY);shutil.copyfile(SRC/'Cargo.lock',project/'Cargo.lock')
    for root,dirs,names in os.walk(project):
        os.chown(root,user.pw_uid,user.pw_gid)
        for f in dirs+names:os.chown(P(root)/f,user.pw_uid,user.pw_gid)
    tool=P(state['toolchain']['prefix']);ca=state['private_ca005']['path']
    env=dict(os.environ,HOME=user.pw_dir,USER='jwk',LOGNAME='jwk',PATH=str(tool/'bin')+':/usr/bin:/bin',
      CARGO_HOME=str(BASE/'deps/cargo'),CARGO_TARGET_DIR=str(BASE/'target'),RUSTC=str(tool/'bin/rustc'),
      CARGO_HTTP_CAINFO=ca,CARGO_HTTP_PROXY_CAINFO=ca)
    log=path/'query-build.log'
    with log.open('xb') as out:
        os.chown(log,user.pw_uid,user.pw_gid)
        r=subprocess.run(['runuser','-u','jwk','--','nice','-n','15',str(tool/'bin/cargo'),'build','--offline','--release','-j','4',
          '--manifest-path',str(project/'Cargo.toml')],env=env,stdout=out,stderr=subprocess.STDOUT,timeout=1200)
    result['helper_compile_exit']=r.returncode
    if r.returncode!=0:
        with log.open('rb') as f:f.seek(max(0,log.stat().st_size-12000));result['helper_compile_tail']=f.read().decode(errors='replace')
    else:
        helper=BASE/'target/release/jwk-ublk-query';result['query_helper']={'path':str(helper),'sha256':sha(helper),
          'help':command([str(helper),'--help'],user_mode=True)}
    result['runtime_assets_files']=[{'path':str(p),'bytes':p.stat().st_size} for p in target.rglob('*') if p.is_file() and not p.is_symlink()][:100]
    result['installed_binaries']=state['binaries'];result['stock_ublk_loaded']=P('/sys/module/ublk_drv').is_dir()
    (path/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');os.chown(path/'result.json',user.pw_uid,user.pw_gid)
    print(json.dumps(result,ensure_ascii=False),flush=True)
    assert r.returncode==0,'Device-owner query helper did not compile; no service or device permissions changed'
if __name__=='__main__':main()
