"""Read-only module feasibility for the already compiled jwk service."""
import hashlib,json,os,pathlib,re,subprocess
P=pathlib.Path
def call(args,limit=14000):
    try:
        r=subprocess.run(args,capture_output=True,text=True,timeout=25)
        return {'code':r.returncode,'stdout':r.stdout[:limit],'stderr':r.stderr[:2000],'truncated':len(r.stdout)>limit}
    except (OSError,subprocess.TimeoutExpired) as e:return {'error_type':type(e).__name__}
def meta(path):
    p=P(path);out={'path':str(p),'exists':p.exists(),'symlink':p.is_symlink()}
    if p.exists():s=p.stat();out.update(uid=s.st_uid,gid=s.st_gid,mode=oct(s.st_mode&0o777),bytes=s.st_size,resolved=str(p.resolve()))
    return out
def main():
    assert os.geteuid()==0
    kernel=os.uname().release
    out={'action':'READONLY_UBLK_NO_REBOOT_FEASIBILITY','kernel':kernel,'moduleLoaded':False,'packagesInstalled':False,
      'serviceStarted':False,'current_headers':meta(P('/lib/modules')/kernel/'build'),'candidates':[],'devices':{}}
    for name,args in {'kernel_packages':['rpm','-qa','--qf','%{NAME} %{VERSION}-%{RELEASE}.%{ARCH} %{SOURCERPM}\n'],
      'boot_kernel_package':['rpm','-qf','/boot/vmlinuz-'+kernel],
      'ublk_info':['modinfo','ublk_drv'],'ublk_dry_run':['modprobe','--dry-run','--verbose','ublk_drv'],
      'secure_boot':['mokutil','--sb-state'],'kernel_version':['uname','-a'],
      'listeners':['ss','-ltnp'],'jwk':['id','jwk']}.items():
        r=call(args,limit=256*1024 if name=='kernel_packages' else 14000)
        if name=='kernel_packages' and 'stdout' in r:r['stdout']='\n'.join(x for x in r['stdout'].splitlines() if re.match(r'kernel(?:-|\s)',x))
        out[name]=r
    cfg=P('/boot/config-'+kernel)
    if cfg.is_file():
        out['kernel_config']=[x for x in cfg.read_text().splitlines() if re.search(r'CONFIG_(?:BLK_DEV_UBLK|IO_URING|MODULES|MODVERSIONS|MODULE_SIG|SYSTEM_TRUSTED|SYSTEM_REVOCATION|KALLSYMS|PREEMPT|HZ)',x)]
    for name,path in {'modules_disabled':'/proc/sys/kernel/modules_disabled','lockdown':'/sys/kernel/security/lockdown','tainted':'/proc/sys/kernel/tainted'}.items():
        try:out[name]=P(path).read_text().strip()
        except OSError:out[name]='unavailable'
    roots=[P('/usr/src'),P('/opt'),P('/root'),P('/home'),P('/data/jwk')];visited=0
    blocked={'.git','node_modules','target','registry','source-cache.git','image-cache','snapshot-store','firecracker-work',
      '.ssh','.gnupg','secrets','y-aenv-control','hadoop','hadoop-3.4.1'}
    for base in roots:
        if not base.is_dir():continue
        for root,dirs,files in os.walk(base,followlinks=False):
            depth=len(P(root).relative_to(base).parts)
            dirs[:]=[d for d in dirs if d not in blocked and not d.startswith('.')] if depth<4 else []
            if P(root).name=='build' and (P(root)/'Module.symvers').is_file():out['candidates'].append(meta(P(root)/'Module.symvers'))
            for name in files:
                visited+=1
                match=(name.startswith('ublk') and re.search(r'\.ko(?:\.(?:xz|zst|gz))?$',name)) or name=='ublk_drv.c'
                match=match or (name.endswith('.rpm') and name.startswith(('kernel-devel-','kernel-source-','kernel-headers-','kernel-modules-','kernel-6.6')))
                if match:
                    p=P(root)/name;row=meta(p)
                    if '.ko' in name:row['module_info']=call(['modinfo',str(p)],limit=6000)
                    elif name.endswith('.rpm'):row['package_info']=call(['rpm','-qp','--qf','%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n',str(p)])
                    out['candidates'].append(row)
                if visited>=40000:dirs[:]=[];break
            if visited>=40000:break
        if visited>=40000:break
    out['scan_files']=visited;out['scan_bound_reached']=visited>=40000
    out['system_sources']=meta('/usr/src');out['existing_module_dirs']=[p.name for p in P('/lib/modules').iterdir() if p.is_dir()]
    out['devices']={x:meta(x) for x in ('/dev/kvm','/dev/ublk-control','/dev/net/tun')}
    cache=P('/var/cache/dnf');out['cached_repositories']=[p.name for p in cache.iterdir() if p.is_dir()] if cache.is_dir() else []
    repo_dir=P('/etc/yum.repos.d');out['repo_files']=[]
    if repo_dir.is_dir():
        for p in sorted(repo_dir.glob('*.repo')):
            lines=[]
            for line in p.read_text(errors='replace').splitlines():
                if re.match(r'\s*(?:\[|name\s*=|enabled\s*=|baseurl\s*=|metalink\s*=|mirrorlist\s*=|gpgcheck\s*=)',line):
                    lines.append(re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@',r'\1[REDACTED]@',line)[:500])
            out['repo_files'].append({'path':str(p),'selected_lines':lines[:100]})
    symbols=[]
    with P('/proc/kallsyms').open() as f:
        for line in f:
            fields=line.split()
            if len(fields)>2 and re.search(r'io_uring_cmd|ublk|__crc_io_uring',fields[2]):symbols.append(fields[2])
            if len(symbols)>=100:break
    out['relevant_kernel_symbol_names']=symbols
    print(json.dumps(out,ensure_ascii=False,sort_keys=True))
if __name__=='__main__':main()
