"""Inspect a pinned kernel RPM and simulate its transaction; never install or reboot."""
import hashlib,json,os,re,shutil,socket,stat,subprocess,tempfile
from pathlib import Path
RPM=Path('/home/jwk/kernel-6.6.0_sp3_tlbi3_1027+-28.aarch64.rpm')
SHA='0c9d2e215a676e1538814a733196504de9293a352b1457fe705e625a23532db3'
NEW='6.6.0-sp3-tlbi3-1027+'
def need(ok,why):
    if not ok:raise RuntimeError(why)
def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024**2),b''):h.update(b)
    return h.hexdigest()
def run(args,seconds=30,limit=100000):
    try:
        r=subprocess.run(args,capture_output=True,timeout=seconds)
        return {'argv':args,'exitCode':r.returncode,'stdout':r.stdout[:limit].decode(errors='replace'),
            'stderr':r.stderr[:8000].decode(errors='replace'),'truncated':len(r.stdout)>limit}
    except (OSError,subprocess.TimeoutExpired) as e:return {'argv':args,'state':'UNAVAILABLE','error':str(e)}
def module_name(path):return re.sub(r'\.ko(?:\.(?:xz|gz|zst))?$','',Path(path).name).replace('-','_')
def main():
    need(os.geteuid()==0 and socket.gethostname()=='agent1','Registered B root entry required')
    need(RPM.is_file() and not RPM.is_symlink() and digest(RPM)==SHA,'RPM identity changed')
    out={'status':'PREFLIGHT_ONLY','newKernel':NEW,'runningKernel':os.uname().release,'rpmSha256':SHA}
    listing=run(['rpm','-qp','--dump',str(RPM)],60,16*1024**2)
    need(listing.get('exitCode')==0 and not listing['truncated'],'Package file metadata unavailable')
    entries={}
    for line in listing['stdout'].splitlines():
        fields=line.split()
        need(len(fields)>=11,'Unexpected RPM file metadata')
        path=fields[0]
        need(path.startswith('/') and '..' not in Path(path).parts,'Unsafe package path')
        entries[path]={'bytes':int(fields[1]),'mode':int(fields[4],8)}
    loaded={line.split()[0]:int(line.split()[2]) for line in Path('/proc/modules').read_text().splitlines()}
    available={module_name(path):path for path in entries if re.search(r'\.ko(?:\.(xz|gz|zst))?$',path)}
    out['loadedModulesAbsentFromPackage']=[{'name':n,'references':refs} for n,refs in loaded.items() if n not in available]
    out['loadedCoreModuleIdentity']={}
    for name in ('ubus','ubfi','ummu_core','ummu','obmm','ublk_drv'):
        root=Path('/sys/module')/name
        out['loadedCoreModuleIdentity'][name]={'srcversion':(root/'srcversion').read_text().strip() if (root/'srcversion').is_file() else None,
            'taint':(root/'taint').read_text().strip() if (root/'taint').is_file() else None,
            'parameterNames':sorted(p.name for p in (root/'parameters').iterdir()) if (root/'parameters').is_dir() else []}
    boot=[p for p in entries if p.startswith('/boot/')]
    out['packageBootBytes']=sum(entries[p]['bytes'] for p in boot)
    out['bootFreeBytes']=shutil.disk_usage('/boot').free
    out['existingInitramfsBytes']={p.name:p.stat().st_size for p in Path('/boot').glob('initramfs-*.img') if p.is_file()}
    selected=[p for n,p in available.items() if n in ('ubus','ubfi','ummu_core','ummu','obmm','ublk_drv')]
    selected+=['/boot/config-'+NEW,'/boot/System.map-'+NEW]
    need(all(p in entries and stat.S_ISREG(entries[p]['mode']) for p in selected),'Selected payload not regular files')
    need(sum(entries[p]['bytes'] for p in selected)<128*1024**2,'Selected payload exceeds bound')
    out['candidateModules']={}
    # Extract only exact regular-file paths into a new private temporary directory.
    with tempfile.TemporaryDirectory(prefix='tlbi-install-preflight-') as tmp:
        patterns=[v for p in selected for v in (p.lstrip('/'),'.'+p)]
        a=b=None
        try:
            a=subprocess.Popen(['rpm2cpio',str(RPM)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            b=subprocess.Popen(['cpio','-idm','--quiet','--no-absolute-filenames',*patterns],stdin=a.stdout,cwd=tmp,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            a.stdout.close();stdout,stderr=b.communicate(timeout=240);a.wait(timeout=10)
            need(a.returncode==b.returncode==0,'Selected RPM extraction failed: '+stderr[:1000].decode(errors='replace'))
        finally:
            for p in (a,b):
                if p is not None and p.poll() is None:p.kill();p.wait()
        for name in ('ubus','ubfi','ummu_core','ummu','obmm','ublk_drv'):
            if name not in available:continue
            p=Path(tmp)/available[name].lstrip('/')
            need(p.is_file() and not p.is_symlink() and p.stat().st_size==entries[available[name]]['bytes'],'Extracted module differs')
            r=run(['modinfo',str(p)])
            out['candidateModules'][name]={'exitCode':r.get('exitCode'),'sha256':digest(p),
                'fields':[x for x in r.get('stdout','').splitlines() if x.startswith(('name:','vermagic:','depends:','srcversion:','signer:','parm:'))],
                'stderr':r.get('stderr')}
        mapfile=Path(tmp)/('boot/System.map-'+NEW)
        out['tlbiSymbols']=[line for line in mapfile.read_text().splitlines() if re.search(r'tlbi_ipi|direct_tlbi|stage2_unmap|kvm_pgtable_stage2_unmap',line)][:120]
    out['kernelInstallHelpers']={}
    for name in ('/sbin/installkernel','/sbin/new-kernel-pkg','/usr/bin/kernel-install'):
        p=Path(name)
        if not p.is_file():continue
        raw=p.read_bytes()
        out['kernelInstallHelpers'][name]={'resolvedPath':str(p.resolve()),'sha256':hashlib.sha256(raw).hexdigest(),
            'script':raw.decode(errors='replace') if raw.startswith(b'#!') and len(raw)<=128*1024 else None}
    out['transactionTest']=run(['rpm','-ivh','--test',str(RPM)],120)
    out['secureBoot']=run(['mokutil','--sb-state'])
    out['bootEntries']=run(['grubby','--info=ALL'])
    out['nearbySourcePackages']=run(['find','/home/jwk','-maxdepth','2','-type','f','-iname','*tlbi*src*rpm','-print'])
    need(digest(RPM)==SHA,'RPM changed during inspection')
    out['patch1Confirmed']=False
    out['mutations']={'packageInstalled':False,'bootChanged':False,'rebooted':False,'modulesLoaded':False,'SDKCalled':False}
    print(json.dumps(out,ensure_ascii=False,separators=(',',':')))
if __name__=='__main__':main()
