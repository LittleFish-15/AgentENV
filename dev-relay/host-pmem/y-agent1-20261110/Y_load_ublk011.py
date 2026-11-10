"""Only run after explicit approval to load this one matched external module."""
import hashlib,json,os,pathlib,stat,subprocess,time
P=pathlib.Path
KERNEL='6.6.0-159.4.3.154.oe2403sp4.x86_64'
SOURCE=P('/home/jwk/aenv-agent1-20261110-r2/kernel-build010/module/ublk_drv.ko')
SHA='85439f165a415d7d43b2b1b439db5d179a2d0ed2c6e5c1692696ff9406a5028a'
ADMIN=P('/home/jwk/y-aenv-control/relay-agent1-20261110/admin-modules011')
def need(ok,msg):
    if not ok:raise RuntimeError(msg)
def run(args):
    r=subprocess.run(args,capture_output=True,text=True,timeout=30)
    return {'code':r.returncode,'stdout':r.stdout[-12000:],'stderr':r.stderr[-3000:]}
def filetext(path):
    try:return P(path).read_text().strip()
    except OSError:return None
def main():
    need(os.geteuid()==0 and os.uname().release==KERNEL,'Running kernel changed')
    need(not P('/sys/module/ublk_drv').exists() and not P('/dev/ublk-control').exists(),'ublk is already present; preserve existing module')
    need(not list(P('/sys/class/block').glob('ublkb*')),'Existing ublk devices found; no module action')
    need(filetext('/proc/sys/kernel/modules_disabled')=='0','Module loading is disabled')
    lockdown=filetext('/sys/kernel/security/lockdown');need(lockdown is None or '[none]' in lockdown,'Kernel lockdown active')
    cap=next(x.split()[1] for x in P('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:'))
    need(int(cap,16)&(1<<16),'Entry lacks CAP_SYS_MODULE')
    need(ADMIN.parent.resolve()==ADMIN.parent and ADMIN.parent.stat().st_uid==0,'Untrusted admin module directory parent')
    if not ADMIN.exists():ADMIN.mkdir(mode=0o700)
    need(ADMIN.resolve()==ADMIN and ADMIN.stat().st_uid==0 and not ADMIN.stat().st_mode&0o077,'Untrusted admin module directory')
    raw=SOURCE.read_bytes();need(hashlib.sha256(raw).hexdigest()==SHA,'User-owned module bytes changed; not loaded')
    target=ADMIN/('ublk_drv-'+SHA[:16]+'.ko')
    if target.exists():need(not target.is_symlink() and target.stat().st_uid==0 and hashlib.sha256(target.read_bytes()).hexdigest()==SHA,'Existing staged module differs')
    else:
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    info=run(['modinfo','-F','vermagic',str(target)])
    need(info['code']==0 and info['stdout'].split()[0]==KERNEL,'Module vermagic differs')
    state={'action':'EXPLICITLY_APPROVED_SINGLE_UBLK_LOAD','module_sha256':SHA,'staged_path':str(target),
      'kernel':KERNEL,'taint_before':filetext('/proc/sys/kernel/tainted'),'kernel_replaced':False,'rebooted':False,
      'existing_services_touched':False,'force_flags':False}
    result=run(['insmod',str(target),'ublks_max=10240']);state['insmod']=result
    state['module_present']=P('/sys/module/ublk_drv').is_dir();state['taint_after']=filetext('/proc/sys/kernel/tainted')
    state['kernel_messages']=run(['journalctl','-k','-b','-n','40','--no-pager'])
    if result['code']==0:
        until=time.monotonic()+10
        while time.monotonic()<until and not P('/dev/ublk-control').exists():time.sleep(.2)
    device=P('/dev/ublk-control');state['control_device_exists']=device.exists()
    if device.exists():s=device.stat();state['control_device']={'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'is_character':stat.S_ISCHR(s.st_mode)}
    state['actual_ublks_max']=filetext('/sys/module/ublk_drv/parameters/ublks_max')
    # No automatic unload. Insertion may mark the kernel tainted even if later unloaded.
    print(json.dumps(state,ensure_ascii=False),flush=True)
    need(result['code']==0 and state['module_present'] and state['control_device_exists'],'Module load not confirmed; inspect preserved result, do not force or retry blindly')
if __name__=='__main__':main()
