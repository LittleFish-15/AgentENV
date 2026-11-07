"""Read-only native x86 prerequisites. Never emit credentials or full environments."""
import glob, hashlib, json, os, pathlib, platform, pwd, shutil, stat, subprocess, tomllib
P = pathlib.Path

def call(argv, timeout=20, limit=16000):
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout)
        return {'code': r.returncode, 'stdout': r.stdout[:limit].decode(errors='replace'),
                'stderr': r.stderr[:2000].decode(errors='replace'), 'truncated': len(r.stdout)>limit}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {'unavailable': type(e).__name__}

def file_info(path, digest=False):
    p = P(path)
    if not p.exists(): return {'path':str(p),'exists':False}
    s = p.stat()
    out = {'path':str(p),'resolved':str(p.resolve()),'uid':s.st_uid,'gid':s.st_gid,
           'mode':oct(stat.S_IMODE(s.st_mode)), 'bytes':s.st_size}
    if digest and p.is_file() and s.st_size < 256*1024**2:
        h=hashlib.sha256()
        with p.open('rb') as f:
            for b in iter(lambda:f.read(1024**2),b''):h.update(b)
        out['sha256']=h.hexdigest();out['file']=call(['file','-b',str(p)])
    return out

SAFE_KEYS = {'host','port','enabled','low_watermark','high_watermark','startup_size',
 'startup_prewarm','fill_concurrency','cpu_count','memory_mb','memory_mib','vcpu_count',
 'poll_interval_ms','timeout_ms','health_check_interval_ms','health_check_timeout_ms',
 'home_path','runtime_path','kernel_path','firecracker_path','path','root','data_dir',
 'log_format','span_events','max_size','maintenance','bind','listen','name','size'}
def safe_config(path):
    out = file_info(path)
    try:
        raw=P(path).read_bytes()
        if len(raw)>256*1024: return {**out,'error':'too_large'}
        data=tomllib.loads(raw.decode());values={}
        def walk(obj,prefix=''):
            for key,value in obj.items():
                name=prefix+key
                if isinstance(value,dict):walk(value,name+'.')
                elif key in SAFE_KEYS and not any(x in name.lower() for x in ('secret','token','password','credential','api_key','auth')):
                    if isinstance(value,(bool,int,float,str)) and len(str(value))<300:values[name]=value
        walk(data);out['selected_values']=values
    except Exception as e:out['error']=type(e).__name__
    return out

def main():
    assert os.geteuid()==0 and platform.machine()=='x86_64'
    jwk=pwd.getpwnam('jwk')
    out={'schema':1,'action':'Y_READONLY_INVENTORY','jwk':{'uid':jwk.pw_uid,'gid':jwk.pw_gid,'home':jwk.pw_dir},
      'system':{},'processes':[],'configs':[],'binaries':[],'devices':{},'asset_directories':[]}
    commands={'cpu':['lscpu'],'memory':['free','-b'],'swap':['swapon','--show','--bytes'],
      'disks':['df','-B1','/','/home','/data'],'mounts':['findmnt','-rn','-o','TARGET,FSTYPE','/','/home','/data'],
      'listeners':['ss','-ltn'],'services':['systemctl','list-units','--type=service','--all','--no-legend','--no-pager'],
      'modules':['lsmod'],'numa_balancing':['sysctl','-n','kernel.numa_balancing'],
      'neighbors':['sysctl','net.ipv4.neigh.default.gc_thresh1','net.ipv4.neigh.default.gc_thresh2','net.ipv4.neigh.default.gc_thresh3']}
    for name,argv in commands.items():
        value=call(argv,limit=24000)
        if name in ('services','modules') and 'stdout' in value:
            value['stdout']='\n'.join(l for l in value['stdout'].splitlines() if any(k in l.lower() for k in ('aenv','agentenv','ublk','kvm','firecracker')))
        out['system'][name]=value
    for name,path in {'os':'/etc/os-release','thp':'/sys/kernel/mm/transparent_hugepage/enabled',
       'ublks_max':'/sys/module/ublk_drv/parameters/ublks_max','arp_table':'/proc/net/stat/arp_cache'}.items():
        try:out['system'][name]=P(path).read_text()[:8000]
        except OSError:out['system'][name]='unavailable'
    cfg=P('/boot/config-'+platform.release())
    if cfg.exists():out['system']['kernel_config']=[x for x in cfg.read_text().splitlines() if x.startswith(('CONFIG_HZ=','CONFIG_HZ_','CONFIG_KVM=','CONFIG_BLK_DEV_UBLK='))]
    keys=('AENV_HOME_PATH','AENV_RUNTIME_PATH','AENV_LOG_FORMAT','AENV_LOG_SPAN_EVENTS','RUST_LOG','AENV_CONFIG','AENV_CONFIG_PATH')
    configs=set(); bins=set(); counters={}
    for proc in P('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            comm=(proc/'comm').read_text().strip();uid=proc.stat().st_uid
            if 'firecracker' in comm:
                counters[str(uid)]=counters.get(str(uid),0)+1
                continue
            exe=str((proc/'exe').resolve())
            if comm not in ('server','aenv') and not any(x in exe.lower() for x in ('agentenv','ublk')):continue
            cmd=(proc/'cmdline').read_bytes().decode(errors='replace').split('\0')
            env=dict(x.split('=',1) for x in (proc/'environ').read_bytes().decode(errors='replace').split('\0') if '=' in x)
            selected={k:env[k] for k in keys if k in env}
            row={'pid':int(proc.name),'uid':uid,'comm':comm,'exe':exe,'cwd':str((proc/'cwd').resolve()),'env':selected,
                 'cgroup':(proc/'cgroup').read_text()[:1000]}
            for i,arg in enumerate(cmd):
                if arg in ('--config','-c') and i+1<len(cmd):configs.add(cmd[i+1]);row['config_arg']=cmd[i+1]
                if arg.startswith('--config='):configs.add(arg.split('=',1)[1]);row['config_arg']=arg.split('=',1)[1]
            for k in ('AENV_CONFIG','AENV_CONFIG_PATH'):
                if env.get(k):configs.add(env[k])
            if P(exe).is_file():bins.add(exe)
            out['processes'].append(row)
        except (OSError,ValueError):pass
    out['fc_process_counts_by_uid']=counters
    for path in ('/dev/kvm','/dev/net/tun','/dev/ublk-control'):
        out['devices'][path]=file_info(path)
    out['devices']['ublk_block_devices']=[p.name for p in P('/sys/class/block').glob('ublkb*')][:300]
    for path in ('/usr/local/bin/aenv','/usr/local/bin/firecracker','/home/t00981886/AgentENV/target/release/server',
        '/home/t00981886/AgentENV/target/release/aenv','/home/jwk/.cargo/bin/cargo','/home/jwk/.cargo/bin/rustc'):
        if P(path).exists():bins.add(path)
    out['binaries']=[file_info(p,True) for p in sorted(bins)]
    for base in ('/data/aenv','/tmp/aenv-test-0/run','/home/t00981886/AgentENV','/home/jwk','/data/jwk'):
        p=P(base);row=file_info(p)
        if p.is_dir():row['entries']=[x.name for x in sorted(p.iterdir())][:90]
        out['asset_directories'].append(row)
    for base in ('/home/t00981886/AgentENV/config','/data/aenv','/home/jwk'):
        p=P(base)
        if p.is_dir():
            for pat in ('*.toml','config/*.toml'):
                configs.update(str(x) for x in p.glob(pat) if x.is_file())
    out['configs']=[safe_config(x) for x in sorted(configs)][:30]
    # Authenticate locally if credentials exist; only public template metadata is emitted.
    out['templates']=[]
    import urllib.request
    for path in ('/root/.config/aenv/credentials',str(P(jwk.pw_dir)/'.config/aenv/credentials')):
        p=P(path)
        if not p.exists():continue
        try:
            cred=tomllib.loads(p.read_text());url=cred.get('url','')
            if not (url.startswith('http://127.0.0.1:') or url.startswith('http://localhost:')):
                out['templates'].append({'credential_file':path,'status':'non_loopback_endpoint_skipped'});continue
            req=urllib.request.Request(url.rstrip('/')+'/templates',headers={'X-API-Key':cred['api_key']})
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req,timeout=15) as r:raw=r.read(512*1024+1)
            assert len(raw)<=512*1024
            data=json.loads(raw);rows=data if isinstance(data,list) else data.get('templates',[])
            selected=[]
            for row in rows:
                if 'wikidata' in json.dumps(row).lower():
                    selected.append({k:v for k,v in row.items() if k.lower() in ('id','templateid','template_id','name','alias','aliases','status','cpucount','cpu_count','memorymb','memory_mb','memorymib','buildid','build_id')})
            out['templates'].append({'credential_file':path,'url':url,'count':len(rows),'wikidata':selected})
        except Exception as e:out['templates'].append({'credential_file':path,'error_type':type(e).__name__})
    out['tools']={name:shutil.which(name) for name in ('git','curl','cargo','rustc','cc','clang','pkg-config','cmake','ninja','python3','ip','iptables','nsenter','setpriv','systemd-run','file','jq','docker','skopeo')}
    print(json.dumps(out,ensure_ascii=False,sort_keys=True))

if __name__=='__main__': main()
