"""Extract signed matching RPMs privately and build ublk as jwk. Never load it."""
import hashlib,json,os,pathlib,pwd,re,shutil,signal,stat,subprocess,time
P=pathlib.Path;PP=pathlib.PurePosixPath
BASE=P('/home/jwk/aenv-agent1-20261110-r2/kernel-build010')
KERNEL='6.6.0-159.4.3.154.oe2403sp4.x86_64'
INPUTS=[{'name': 'kernel-devel', 'path': '/home/jwk/aenv-agent1-20261110-r2/kernel-prep009/downloads/kernel-devel-6.6.0-159.4.3.154.oe2403sp4.x86_64.rpm', 'checksum': '0dea8adb454e569acdf1846540f59f6d8fbb4da8bd26a5a456c81ad53ae2656d', 'checksum_type': 'sha256'}, {'name': 'kernel-source', 'path': '/home/jwk/aenv-agent1-20261110-r2/kernel-prep009/downloads/kernel-source-6.6.0-159.4.3.154.oe2403sp4.x86_64.rpm', 'checksum': 'fbf26904f1136347ab93e5597fb65990719da84deec0f0eebc4444166ef49258', 'checksum_type': 'sha256'}]
START=time.monotonic();PARENT=os.getppid()
def need(ok,msg):
    if not ok:raise RuntimeError(msg)
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024**2),b''):h.update(b)
    return h.hexdigest()
def safe_relative(name,prefix):
    path=PP(name);need(not path.is_absolute() and '..' not in path.parts,'Unsafe RPM archive path')
    parts=path.parts;pre=PP(prefix).parts
    return P(*parts[len(pre):]) if parts[:len(pre)]==pre and len(parts)>len(pre) else None
def exact(stream,n):
    data=b''
    while len(data)<n:
        part=stream.read(n-len(data))
        if not part:raise RuntimeError('Truncated RPM cpio stream')
        data+=part
    return data
def extract(rpm,dest,prefix,headers):
    # rpm2cpio only decodes a verified payload. No RPM transaction or scriptlet.
    need(shutil.which('rpm2cpio') is not None,'rpm2cpio is missing; no package installed automatically')
    process=subprocess.Popen(['rpm2cpio',str(rpm)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    links=[];hard={};pending=[];count=0;total=0;selected=[]
    try:
        while True:
            head=exact(process.stdout,110);need(head[:6] in (b'070701',b'070702'),'Unsupported cpio payload format')
            fields=[int(head[6+i*8:14+i*8],16) for i in range(13)]
            ino,mode,_,_,nlink,_,size,major,minor,_,_,namesize,_=fields
            need(0<namesize<=4096 and size<=256*1024**2,'Archive member bound exceeded')
            name=exact(process.stdout,namesize).rstrip(b'\0').decode();exact(process.stdout,(-(110+namesize))%4)
            if name=='TRAILER!!!':break
            count+=1;total+=size;need(count<=200000 and total<=4*1024**3,'Archive exceeds extraction bound')
            rel=safe_relative(name,prefix)
            choose=rel is not None and (headers or rel.suffix in ('.c','.h'))
            data=b''
            remaining=size
            while remaining:
                part=exact(process.stdout,min(remaining,1024**2));remaining-=len(part)
                if choose:data+=part
            exact(process.stdout,(-size)%4)
            if not choose:continue
            target=dest/rel;need(target.parent.resolve().is_relative_to(dest),'Archive path resolves outside private destination')
            if stat.S_ISDIR(mode):target.mkdir(parents=True,exist_ok=True,mode=0o700)
            elif stat.S_ISREG(mode):
                target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                need(not target.exists() and not target.is_symlink(),'Duplicate extracted file')
                target.write_bytes(data);target.chmod(0o755 if mode&0o111 else 0o644)
                if nlink>1:
                    key=(major,minor,ino)
                    if size:hard[key]=target
                    else:pending.append((target,key))
                selected.append(str(rel))
            elif stat.S_ISLNK(mode):links.append((target,data.decode()))
            else:raise RuntimeError('Special device in extracted source tree')
        for target,key in pending:
            if key in hard:shutil.copyfile(hard[key],target)
        for target,value in links:
            raw=P(value)
            if raw.is_absolute():
                relative=safe_relative(str(raw).lstrip('/'),prefix)
                need(relative is not None,'Absolute symlink outside extracted headers')
                resolved=dest/relative;value=os.path.relpath(resolved,target.parent)
            else:resolved=(target.parent/value).resolve()
            need(resolved.resolve().is_relative_to(dest),'Symlink escapes private extracted tree')
            target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            need(not target.exists() and not target.is_symlink(),'Duplicate extracted symlink');target.symlink_to(value)
        process.stdout.close();error=process.stderr.read(2000).decode(errors='replace');code=process.wait(timeout=30)
        need(code==0,'rpm2cpio failed: '+error)
    finally:
        if process.poll() is None:process.terminate();process.wait(timeout=10)
    return {'entries_scanned':count,'bytes_scanned':total,'selected_files':len(selected),'symlinks':len(links)}
def main():
    need(os.geteuid()==0 and os.uname().release==KERNEL,'Kernel changed; do not build against stale inputs')
    user=pwd.getpwnam('jwk');os.umask(0o077)
    need(BASE.parent.resolve()==BASE.parent and not BASE.exists(),'Private build path already exists; preserve')
    BASE.mkdir(mode=0o700);os.chown(BASE,user.pw_uid,user.pw_gid)
    # Reconfirm trusted RPM signatures before dropping root. No key imports.
    for item in INPUTS:
        p=P(item['path']);need(p.is_file() and digest(p)==item['checksum'],'Kernel RPM digest changed')
        r=subprocess.run(['rpm','--checksig','--verbose',str(p)],capture_output=True,text=True,timeout=30)
        need(r.returncode==0 and re.search(r'Signature.*:\s*OK',r.stdout,re.I),'Trusted RPM signature unavailable')
    os.chdir(BASE);os.setgroups([user.pw_gid]);os.setgid(user.pw_gid);os.setuid(user.pw_uid)
    need(os.geteuid()==user.pw_uid,'Module build must run as jwk')
    state={'action':'PRIVATE_EXTERNAL_UBLK_BUILD','kernel':KERNEL,'uid':os.geteuid(),
      'module_loaded':False,'system_package_install':False,'kernel_changed':False,'rebooted':False,'stages':[]}
    def save(): (BASE/'status.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n')
    def run(name,args,timeout=1200):
        stage={'name':name,'started_unix':time.time()};state['stages'].append(stage);save()
        log=BASE/(name+'.log');need(not log.exists(),'Existing stage output preserved')
        with log.open('xb') as out:
            p=subprocess.Popen(['nice','-n','15',*args],cwd=BASE,env={'HOME':user.pw_dir,'USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','PATH':'/usr/bin:/bin:/usr/sbin:/sbin'},
              stdout=out,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True)
            begun=time.monotonic()
            while p.poll() is None:
                if os.getppid()!=PARENT or time.monotonic()-begun>timeout:
                    os.killpg(p.pid,signal.SIGTERM)
                    try:p.wait(timeout=10)
                    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
                    break
                time.sleep(1)
        stage['exit_code']=p.returncode;stage['elapsed_seconds']=round(time.monotonic()-begun,3);save()
        if p.returncode!=0:
            with log.open('rb') as f:f.seek(max(0,log.stat().st_size-12000));tail=f.read().decode(errors='replace')
            print(json.dumps({'stage':name,'tail':tail}),flush=True);raise RuntimeError('Stage failed: '+name)
        return log.read_text(errors='replace')[-24000:]
    try:
        devel=BASE/'headers';module=BASE/'module';devel.mkdir(mode=0o700);module.mkdir(mode=0o700)
        for item in INPUTS:
            if item['name']=='kernel-devel':state['headers_extraction']=extract(P(item['path']),devel,'usr/src/kernels/'+KERNEL,True)
            elif item['name']=='kernel-source':state['driver_extraction']=extract(P(item['path']),module,'usr/src/linux-'+KERNEL+'/drivers/block',False)
        need((devel/'Makefile').is_file() and (devel/'Module.symvers').is_file(),'Matching external-module headers/symbol CRCs missing')
        release=(devel/'include/config/kernel.release').read_text().strip();need(release==KERNEL,'Header release differs from running kernel')
        boot=P('/boot/config-'+KERNEL);cfg=devel/'.config'
        need(cfg.is_file() and digest(cfg)==digest(boot),'Extracted build configuration differs from boot config')
        driver=module/'ublk_drv.c';need(driver.is_file(),'Exact vendor ublk driver source missing')
        state['driver_source_sha256']=digest(driver);state['module_symvers_sha256']=digest(devel/'Module.symvers');state['config_sha256']=digest(cfg)
        state['driver_includes']=[x for x in driver.read_text().splitlines() if x.startswith('#include')]
        (module/'Makefile').write_text('obj-m := ublk_drv.o\n')
        save();run('build-ublk-module',['make','-C',str(devel),'M='+str(module),'-j','2','modules'])
        binary=module/'ublk_drv.ko';need(binary.is_file(),'No kernel module produced')
        info=run('module-info',['modinfo',str(binary)],timeout=30)
        m=re.search(r'^vermagic:\s*(.*)$',info,re.M);need(m and m.group(1).split()[0]==KERNEL,'Built module vermagic differs')
        state['module']={'path':str(binary),'sha256':digest(binary),'bytes':binary.stat().st_size,'modinfo':info,'vermagic':m.group(1)}
        state['undefined_symbols']=run('module-symbols',['nm','-u',str(binary)],timeout=30)
        state['state']='MODULE_BUILT_NOT_LOADED';save();print(json.dumps(state,ensure_ascii=False))
    except Exception as error:
        state['state']='PRIVATE_MODULE_BUILD_STOPPED';state['error_type']=type(error).__name__;state['reason']=str(error)[:600]
        save();print(json.dumps(state,ensure_ascii=False));raise
if __name__=='__main__':main()
