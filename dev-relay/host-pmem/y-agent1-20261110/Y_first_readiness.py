"""Read-only current-machine and local-clone readiness. Never starts a service."""
import hashlib,json,os,pathlib,pwd,re,subprocess
P=pathlib.Path
def call(args):
    try:
        r=subprocess.run(args,capture_output=True,text=True,timeout=20)
        return {'code':r.returncode,'stdout':r.stdout[:12000],'stderr':r.stderr[:1500]}
    except (OSError,subprocess.TimeoutExpired) as e:return {'error':type(e).__name__}
def meta(path):
    p=P(path);out={'path':str(p),'exists':p.exists(),'symlink':p.is_symlink()}
    if p.exists():
        st=p.stat();out.update(uid=st.st_uid,gid=st.st_gid,mode=oct(st.st_mode&0o777),bytes=st.st_size,resolved=str(p.resolve()))
    return out
def main():
    assert os.geteuid()==0
    user=pwd.getpwnam('jwk');repo=P('/home/jwk/AgentENV')
    out={'action':'FIRST_READONLY_READINESS','hostname':os.uname().nodename,'kernel':os.uname().release,
      'jwk':{'uid':user.pw_uid,'gid':user.pw_gid,'home':user.pw_dir},'repository':meta(repo),
      'service_actions':[],'source_changes':False,'component_copies':False,'toolchain_candidates':[]}
    if repo.is_dir() and (repo/'.git').exists():
        git=['git','--no-optional-locks','-c','safe.directory='+str(repo),'-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',str(repo)]
        for name,args in [('HEAD',['rev-parse','HEAD']),('status',['status','--porcelain']),('branches',['branch','--show-current'])]:
            out['repository'][name]=call(git+args)
    roots=[P('/root/.rustup/toolchains'),P(user.pw_dir)/'.rustup/toolchains',P('/opt'),P('/data/aenv/deps')]
    roots.extend(x/'.rustup/toolchains' for x in P('/home').iterdir() if x.is_dir() and x.name!='jwk')
    for root in roots:
        if not root.is_dir():continue
        for path in sorted(root.iterdir())[:40]:
            if (path/'bin/rustc').is_file() and (path/'bin/cargo').is_file():out['toolchain_candidates'].append({'prefix':meta(path),'rustc':meta(path/'bin/rustc'),'cargo':meta(path/'bin/cargo')})
    out['system_tools']={name:shutil_path for name in ('git','rustc','cargo','clang','protoc','cc','cmake','pkg-config') for shutil_path in [__import__('shutil').which(name)]}
    out['devices']={p:meta(p) for p in ('/dev/kvm','/dev/ublk-control','/dev/net/tun')}
    out['svm']=any('svm' in l.split(':',1)[1].split() for l in P('/proc/cpuinfo').read_text().splitlines() if l.startswith('flags'))
    out['listeners']=call(['ss','-ltnp']);out['memory']=call(['free','-b']);out['disk']=call(['df','-B1','/home/jwk','/data'])
    out['os_release']=P('/etc/os-release').read_text()
    out['existing_assets']=[meta(p) for p in ('/usr/bin/aenv','/usr/local/bin/aenv','/data/aenv/deps','/data/jwk','/home/jwk/y-aenv-control')]
    print(json.dumps(out,ensure_ascii=False,sort_keys=True))
if __name__=='__main__':main()
