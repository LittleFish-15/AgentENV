"""Inspect A maintenance prerequisites and preserve exact module bytes only."""
import hashlib,json,lzma,os,platform,stat,subprocess,time
from pathlib import Path
KERNEL='6.6.0-145.3.34.165.oe2403sp3.aarch64'
CANDIDATE_SHA='59767d198966db908e662cfbe0f144b93d8fd20f01a39c917977aa9e8efd8a6a'
ORIGINAL_XZ_SHA='f1fea1b150d15afadd4960c6f3c651f36344fb554c417608378baa7b56b6812e'
ORIGINAL_SHA='abd09dec30cb30214868a16b04b7547b6d979f96eeb4638e6bcecde30d7639df'
def need(ok,why):
    if not ok:raise RuntimeError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def command(argv):
    p=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=25)
    return {'exitCode':p.returncode,'stdout':p.stdout[-12288:].decode(errors='replace'),'stderr':p.stderr[-2048:].decode(errors='replace')}
def text(path):
    try:return Path(path).read_text().strip()
    except OSError as error:return {'unavailable':type(error).__name__}
def ticks(pid):return Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]
def copy_pinned(path,expected,target):
    path=path.resolve(strict=True);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_uid in (0,1204) and 0<a.st_size<=16*1024**2,'Module source metadata differs')
        raw=f.read(16*1024**2+1);b=os.fstat(f.fileno());need((a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)
            and sha(raw)==expected,'Module bytes differ from approved build')
    if target.exists():need(target.read_bytes()==raw and target.stat().st_uid==0,'Different staged module preserved')
    else:
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    return {'source':str(path),'staged':str(target),'bytes':len(raw),'sha256':expected},raw
def main():
    need(os.getuid()==os.geteuid()==0 and platform.node()=='server1' and platform.release()==KERNEL,'Only matching-kernel A root')
    os.umask(0o077);boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    root=Path('/home/jwk/root/recovery')
    for p in [root,root/'obmm-a',root/'obmm-a'/boot,root/'obmm-a'/boot/'prepared-001']:
        if not p.exists():p.mkdir(mode=0o700)
        need(p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode&0o022,'Unsafe maintenance staging')
        if p.name=='prepared-001':need(not p.stat().st_mode&0o077,'Maintenance backup must be private')
    root=root/'obmm-a'/boot/'prepared-001'
    report={'status':'A_PREMAINTENANCE_INSPECTED_NO_KERNEL_CHANGE','bootId':boot,'kernel':KERNEL,
        'obmmBefore':{k:text('/sys/module/obmm/'+k) for k in ('srcversion','refcnt','initstate')},
        'parameters':{p.name:text(p) for p in Path('/sys/module/obmm/parameters').glob('*')},
        'moduleHolders':[p.name for p in Path('/sys/module/obmm/holders').glob('*')],
        'regionDevices':[p.name for p in Path('/dev').glob('obmm_shmdev*')],
        'sysfsRegions':[p.name for p in Path('/sys/devices/obmm').glob('obmm_shmdev*')],
        'kernelTaint':text('/proc/sys/kernel/tainted'),'lockdown':text('/sys/kernel/security/lockdown'),
        'sigEnforce':text('/proc/sys/kernel/module_sig_enforce'),'moduleSigParameter':text('/sys/module/module/parameters/sig_enforce'),
        'servicesStopped':False,'moduleChanged':False,'SDKCalled':False,'UBAllocated':False,'GuestCreated':False,
        'candidateVerified':False,'originalBackupVerified':False,'readinessGaps':[]}
    raw=text('/proc/obmm/preimport_info')
    report['preimport']={'readable':isinstance(raw,str),'dataRows':max(0,len(raw.splitlines())-1) if isinstance(raw,str) else None,
        'rawSha256':sha(raw.encode()) if isinstance(raw,str) else None,'physicalAddressesPublished':False}
    service=command(['systemctl','show','ubse.service','--no-pager','--property=MainPID,ActiveState,SubState,Job,RequiredBy,BoundBy,ConsistsOf,PropagatesStopTo'])
    report['ubse']=service;values=dict(x.split('=',1) for x in service['stdout'].splitlines() if '=' in x);pid=int(values.get('MainPID','0'))
    if pid>1:
        try:
            proc=Path('/proc',str(pid));before=ticks(pid);fds=[]
            for f in (proc/'fd').iterdir():
                try:
                    target=os.readlink(f)
                    if target.startswith('/dev/obmm'):fds.append({'fd':f.name,'target':target})
                except OSError:continue
            report['ubseIdentity']={'pid':pid,'startTicks':before,'cgroup':(proc/'cgroup').read_text().strip(),'obmmFds':fds,
                'identityStable':ticks(pid)==before}
        except OSError as error:report['ubseIdentity']={'unavailable':type(error).__name__}
    for name,path,expected in [('candidate',Path('/home/jwk/agent/ub-host-pmem-build-2c1768644257/kernel-obmm/obmm.ko'),CANDIDATE_SHA),
        ('originalXz',Path('/lib/modules')/KERNEL/'kernel/drivers/ub/obmm/obmm.ko.xz',ORIGINAL_XZ_SHA)]:
        try:
            info,data=copy_pinned(path,expected,root/('candidate.ko' if name=='candidate' else 'original.ko.xz'));report[name]=info
            if name=='candidate':report['candidateVerified']=True
            else:
                original=lzma.decompress(data);need(sha(original)==ORIGINAL_SHA,'Original decompressed backup differs')
                p=root/'original.ko'
                if p.exists():need(p.read_bytes()==original,'Different decompressed backup preserved')
                else:
                    with p.open('xb') as f:f.write(original);f.flush();os.fsync(f.fileno())
                report['originalBackupVerified']=True;report['originalSha256']=ORIGINAL_SHA
        except (OSError,RuntimeError,lzma.LZMAError) as error:report['readinessGaps'].append({'artifact':name,'errorType':type(error).__name__,'reason':str(error)[:250]})
    modinfo=next((str(Path(d)/'modinfo') for d in ('/usr/sbin','/sbin','/usr/bin','/bin') if (Path(d)/'modinfo').is_file()),None)
    if modinfo:
        report['moduleInfo']={}
        for name in ('candidate.ko','original.ko'):
            if (root/name).exists():report['moduleInfo'][name]={key:command([modinfo,'-F',key,str(root/name)]) for key in ('srcversion','vermagic','depends','signer')}
    else:report['readinessGaps'].append({'artifact':'modinfo','reason':'Metadata tool missing; no installation attempted'})
    report['obmmAfter']={k:text('/sys/module/obmm/'+k) for k in ('srcversion','refcnt','initstate')}
    report['kernelStateStableDuringInspection']=report['obmmAfter']==report['obmmBefore']
    with (root/'premaintenance.json').open('x') as f:json.dump(report,f,sort_keys=True);f.flush();os.fsync(f.fileno())
    print('BEGIN_A_PREMAINTENANCE_JSON',flush=True);print(json.dumps(report,sort_keys=True),flush=True);print('END_A_PREMAINTENANCE_JSON',flush=True)
    print('A_PREMAINTENANCE_REPORT_COLLECTED_NO_SERVICES_STOPPED',flush=True)

if __name__=='__main__':main()
