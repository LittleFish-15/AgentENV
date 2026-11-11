"""Install a private Python/SDK and verify native runtime inputs; leave host unchanged."""
import hashlib,json,os,pathlib,pwd,re,secrets,shutil,stat,subprocess,tomllib
P=pathlib.Path;BASE=P('/home/jwk/aenv-y-clean-20261111')
INPUTS={'python': {'name': 'cpython-3.11.18+20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz', 'browser_download_url': 'https://github.com/astral-sh/python-build-standalone/releases/download/20261110/cpython-3.11.18%2B20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz', 'size': 30783322, 'digest': 'sha256:3288c54cea3db350052019b3f8b558dd8a3da8afa6fda573f5fd2bcb37635b4a', 'tag': '20261110'}}
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    assert os.geteuid()==0;os.umask(0o077)
    user=pwd.getpwnam('jwk');assert BASE.resolve()==BASE and BASE.stat().st_uid==user.pw_uid
    output=BASE/'runtime-prep005';assert not output.exists();output.mkdir(mode=0o700);os.chown(output,user.pw_uid,user.pw_gid)
    previous=json.loads((BASE/'runtime-prep004/result.json').read_text());assert previous['helper_compile_exit']==0
    state=json.loads((BASE/'status.json').read_text());ca=state['private_ca005']['path']
    runuser=shutil.which('runuser') or '/usr/sbin/runuser'
    env=dict(os.environ,HOME=user.pw_dir,USER='jwk',LOGNAME='jwk',PATH='/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin',
      SSL_CERT_FILE=ca,PIP_CERT=ca,PIP_DISABLE_PIP_VERSION_CHECK='1',PYTHONNOUSERSITE='1',PYTHONUNBUFFERED='1')
    result={'action':'PRIVATE_SDK_AND_NATIVE_RUNTIME_PREFLIGHT','serviceStarted':False,'kernelChanged':False,
      'systemPythonChanged':False,'otherServicesChanged':False,'state':'STARTED'}
    def directory(path):
        assert path.parent.resolve()==path.parent
        if not path.exists():path.mkdir(mode=0o700);os.chown(path,user.pw_uid,user.pw_gid)
        assert not path.is_symlink() and path.stat().st_uid==user.pw_uid
    def write(path,raw,mode=0o600):
        assert not path.exists() and not path.is_symlink()
        path.write_bytes(raw if isinstance(raw,bytes) else raw.encode());os.chown(path,user.pw_uid,user.pw_gid);os.chmod(path,mode)
    def call(args,seconds=30,as_user=True):
        r=subprocess.run(([runuser,'-u','jwk','--'] if as_user else [])+list(map(str,args)),env=env,capture_output=True,text=True,timeout=seconds)
        return {'code':r.returncode,'stdout':r.stdout[-12000:],'stderr':r.stderr[-4000:]}
    def logged(args,name,seconds):
        log=output/name
        with log.open('xb') as out:
            os.chown(log,user.pw_uid,user.pw_gid)
            p=subprocess.run([runuser,'-u','jwk','--',*map(str,args)],env=env,stdout=out,stderr=subprocess.STDOUT,timeout=seconds)
        if p.returncode:
            with log.open('rb') as f:f.seek(max(0,log.stat().st_size-8000));tail=f.read().decode(errors='replace')
            raise RuntimeError(name+' failed: '+tail)
    try:
        sdk=BASE/'sdk';directory(sdk);distribution=sdk/'python311-dist005';assert not distribution.exists();directory(distribution)
        asset=INPUTS['python'];archive=sdk/asset['name'];assert not archive.exists()
        print(json.dumps({'stage':'private-python-download','bytes':asset['size'],'version':asset['name']}),flush=True)
        logged(['curl','-k','-fL','--connect-timeout','15','--max-time','600','--retry','2','--retry-max-time','900',
          '--max-filesize',str(40*1024**2),asset['browser_download_url'],'-o',archive],'python-download.log',1000)
        assert archive.stat().st_size==asset['size'] and sha(archive)==asset['digest'].split(':',1)[1],'Python archive digest differs'
        code="""import pathlib,sys,tarfile
archive=pathlib.Path(sys.argv[1]);target=pathlib.Path(sys.argv[2]);assert target.is_dir()
with tarfile.open(archive,'r:gz') as tar:
    members=tar.getmembers();assert len(members)<30000 and sum(x.size for x in members)<512*1024**2
    assert all(pathlib.PurePosixPath(x.name).parts[0]=='python' for x in members)
    tar.extractall(target,members=members,filter='data')
"""
        extracted=call(['/usr/bin/python3','-I','-B','-c',code,archive,distribution],180);assert extracted['code']==0,extracted
        python=distribution/'python/bin/python3.11';version=call([python,'--version']);assert version['code']==0 and 'Python 3.11.' in version['stdout']
        result['python']={'path':str(python),'version':version,'asset':asset,'sha256':sha(python)}
        venv=sdk/'g4-e2b246';assert not venv.exists()
        created=call([python,'-m','venv',venv],120);assert created['code']==0,created
        print(json.dumps({'stage':'sdk-install','e2b':'2.46.0','pyqwest':'0.10.0'}),flush=True)
        logged([venv/'bin/python','-m','pip','install','--index-url','https://pypi.org/simple','--timeout','30','--retries','2',
          'e2b==2.46.0','pyqwest==0.10.0'],'sdk-install.log',900)
        proof=call([venv/'bin/python','-c',"import e2b,pyqwest,sys,json,importlib.metadata as m;print(json.dumps({'python':sys.version,'e2b':m.version('e2b'),'pyqwest':m.version('pyqwest'),'sdk_file':e2b.__file__}))"])
        assert proof['code']==0,proof
        data=json.loads(proof['stdout']);assert data['e2b']=='2.46.0' and data['pyqwest']=='0.10.0'
        freeze=call([venv/'bin/python','-m','pip','freeze']);assert freeze['code']==0
        write(sdk/'g4-e2b246.freeze.txt',freeze['stdout']);result['sdk']={'installed':True,'path':str(venv/'bin/python'),'proof':data,'freeze':freeze['stdout']}
        print(json.dumps({'stage':'native-runtime-preflight'}),flush=True)
        paths={'firecracker':BASE/'runtime-assets/firecracker/1.15.1-patch-v3/firecracker',
          'kernel':BASE/'runtime-assets/kernel/vmlinux-6.1.175/vmlinux.bin','daemon':BASE/'bin/uvm-ublk-daemon','server':BASE/'bin/server'}
        result['native_inputs']={}
        for name,path in paths.items():
            with path.open('rb') as f:header=f.read(64)
            assert header[:4]==b'\x7fELF' and header[4:6]==b'\x02\x01' and int.from_bytes(header[18:20],'little')==62,(name,'not x86_64 ELF')
            result['native_inputs'][name]={'path':str(path),'sha256':sha(path),'architecture':'x86_64','file':call(['file',path])}
            if name!='kernel':result['native_inputs'][name]['ldd']=call(['ldd',path])
        result['firecracker_version']=call([paths['firecracker'],'--version'])
        assert result['firecracker_version']['code']==0
        original=BASE/'config/g4-runtime.toml';assert sha(original)==previous['configuration']['sha256']
        text=original.read_text()
        text=text.replace('[firecracker]\n','[firecracker]\nbinary_path = '+json.dumps(str(paths['firecracker']))+'\n',1)
        text=text.replace('[kernel]\n','[kernel]\nimage_path = '+json.dumps(str(paths['kernel']))+'\n',1)
        config=tomllib.loads(text);assert config['pool']['low_watermark']==300 and config['pool']['high_watermark']==1000
        assert config['machine']['mem_size_mib']==4096 and config['machine']['vcpu_count']==2
        write(BASE/'config/runtime005.toml',text)
        result['service_configuration']={'path':str(BASE/'config/runtime005.toml'),'sha256':sha(BASE/'config/runtime005.toml')}
        for name in ('r','state','fc','logs','tmp','cache'):directory(BASE/name)
        directory(BASE/'config/docker');write(BASE/'config/docker/config.json','{"auths":{}}\n')
        write(BASE/'config/api-key','e2b_'+secrets.token_hex(24)+'\n')
        # The key remains local; never return its bytes or digest in the receipt.
        result['api_key_created']=True
        result['commands']={name:shutil.which(name,path=env['PATH']) for name in ('ip','iptables-restore','iptables-save','debugfs','mkfs.ext4','resize2fs','jq','umoci','zstd','setfacl','getfacl','systemd-run','nsenter','unshare','modprobe')}
        result['ublk_module_loaded']=P('/sys/module/ublk_drv').is_dir()
        result['module_vermagic']=call(['modinfo','-F','vermagic','ublk_drv'],as_user=False)
        result['module_path']=call(['modinfo','-F','filename','ublk_drv'],as_user=False)
        result['module_parameters']=call(['modinfo','-p','ublk_drv'],as_user=False)
        result['devices']={}
        for device in ('/dev/kvm','/dev/ublk-control','/dev/net/tun'):
            path=P(device)
            if path.exists():
                st=path.stat();result['devices'][device]={'exists':True,'uid':st.st_uid,'gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode))}
            else:result['devices'][device]={'exists':False}
        result['listeners']=call(['ss','-ltnp'],as_user=False)
        result['systemd_version']=call(['systemd','--version'],as_user=False)
        result['resources']={'meminfo':P('/proc/meminfo').read_text(),'cpus':os.cpu_count(),'jwk_uid':user.pw_uid,'jwk_gid':user.pw_gid}
        result['block_devices_before']=[p.name for p in P('/dev').glob('ublk*')]
        result['state']='PRIVATE_SDK_READY_AND_NATIVE_INPUTS_VERIFIED_SERVICE_NOT_STARTED'
    except BaseException as error:
        result.update(state='FAILED_PRESERVE_STATE',error=str(error)[-10000:]);raise
    finally:
        path=output/'result.json';write(path,json.dumps(result,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(result,ensure_ascii=False),flush=True)
if __name__=='__main__':main()
