"""Read-only evidence for an independent jwk runtime; never copy or provision."""
import hashlib,json,os,pathlib,re,shlex,shutil,stat,subprocess,urllib.request
P=pathlib.Path
def redact(text):
    text=re.sub(r'\b(?:github[_]pat[_]|gh[pousr]_)[A-Za-z0-9_]+','[REDACTED]',text)
    text=re.sub(r'\be2b_[A-Za-z0-9_-]+','[REDACTED]',text)
    text=re.sub(r'''(?i)((?:api[\s_-]?key|token|password|secret|authorization|seed)["']?\s*[=:]\s*["']?)([^"'\s;,}]+)''',r'\1[REDACTED]',text)
    return re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@',r'\1[REDACTED]@',text)
def call(args,user=False,limit=18000,seconds=20):
    if user:args=['runuser','-u','jwk','--',*args]
    try:
        r=subprocess.run(args,capture_output=True,text=True,timeout=seconds)
        return {'code':r.returncode,'stdout':redact(r.stdout[:limit]),'stderr':redact(r.stderr[:1500]),'truncated':len(r.stdout)>limit}
    except (OSError,subprocess.TimeoutExpired) as e:return {'error_type':type(e).__name__}
def meta(path,digest=False):
    p=P(path);out={'path':str(p),'exists':p.exists(),'symlink':p.is_symlink()}
    if not p.exists():return out
    s=p.stat();out.update(uid=s.st_uid,gid=s.st_gid,mode=oct(stat.S_IMODE(s.st_mode)),bytes=s.st_size,resolved=str(p.resolve()))
    if p.is_file():
        out['file']=call(['file','-b',str(p)])
        if digest and s.st_size<=300*1024**2:
            h=hashlib.sha256()
            with p.open('rb') as f:
                for b in iter(lambda:f.read(1024**2),b''):h.update(b)
            out['sha256']=h.hexdigest()
    return out
def script_audit(path):
    out=meta(path,True)
    if not out.get('exists') or out['bytes']>128*1024:return out
    text=P(path).read_text(errors='replace')
    patterns={'swapoff':r'\bswapoff\b','host_cache_drop':r'drop_caches','module_unload':r'\b(?:modprobe\s+-r|rmmod)\b',
      'module_load':r'\b(?:modprobe|insmod)\b','process_kill':r'\b(?:pkill|killall|kill)\b',
      'service_stop':r'\bsystemctl\s+(?:stop|restart)\b','recursive_delete':r'\brm\s+[^\n]*-[^\s]*r',
      'host_sysctl_write':r'\bsysctl\s+-w\b|>\s*/proc/sys','network_mutation':r'\b(?:iptables|nft|ip\s+(?:link|route|netns))\b'}
    out['host_affecting_operations']=[{'line':i,'operations':[name for name,pat in patterns.items() if re.search(pat,line)]}
       for i,line in enumerate(text.splitlines(),1) if line.strip() and not line.lstrip().startswith('#') and any(re.search(pat,line) for pat in patterns.values())]
    safe=[]
    for i,line in enumerate(text.splitlines(),1):
        m=re.match(r'\s*(?:export\s+)?(AENV_HOME_PATH|AENV_RUNTIME_PATH|AENV_DEPS_PATH|AENV_CONFIG_PATH|API_ADDR|RUST_LOG)=(.*)',line)
        if m:safe.append({'line':i,'name':m.group(1),'value':redact(m.group(2))[:400]})
    out['safe_environment_assignments']=safe
    out['server_command_lines']=[i for i,line in enumerate(text.splitlines(),1) if 'server' in line and not line.lstrip().startswith('#')]
    return out
def tree_listing(root,max_depth=3,limit=250):
    root=P(root);out={'root':meta(root),'entries':[]}
    if not root.is_dir():return out
    count=0
    for current,dirs,files in os.walk(root,followlinks=False):
        depth=len(P(current).relative_to(root).parts)
        dirs[:]=sorted(d for d in dirs if d not in ('secrets','.git','logs','persisted-sandboxes')) if depth<max_depth else []
        for name in sorted(dirs)+sorted(files):
            p=P(current)/name
            if 'secret' in name.lower() or 'credential' in name.lower():continue
            out['entries'].append(meta(p));count+=1
            if count>=limit:out['truncated']=True;return out
    return out
def main():
    assert os.geteuid()==0
    out={'action':'READONLY_JWK_RUNTIME_COPY_FEASIBILITY','copies_made':False,'service_actions':[],
      'identity':{'hostname':os.uname().nodename,'kernel':os.uname().release},'processes':[],'scripts':[],'binaries':[],'source':{},'device_access':{}}
    binaries={P('/usr/local/bin/aenv'),P('/usr/bin/aenv')};repos=set();safe_roots=set();root_env=None
    for proc in P('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            comm=(proc/'comm').read_text().strip()
            if comm not in ('server','aenv','uvm-ublk-daemon','firecracker'):continue
            if comm=='firecracker':
                key=str(proc.stat().st_uid);out.setdefault('firecracker_process_counts_by_uid',{})[key]=out.get('firecracker_process_counts_by_uid',{}).get(key,0)+1
                continue
            exe=str((proc/'exe').resolve());args=(proc/'cmdline').read_bytes().decode(errors='replace').split('\0')
            environment=dict(x.split('=',1) for x in (proc/'environ').read_bytes().decode(errors='replace').split('\0') if '=' in x)
            allowed=('AENV_HOME_PATH','AENV_RUNTIME_PATH','AENV_DEPS_PATH','AENV_CONFIG_PATH','API_ADDR','RUST_LOG','LD_LIBRARY_PATH')
            selected={k:redact(v) for k,v in environment.items() if k in allowed or k.startswith(('AENV_POOL_','AENV_ENVD_','AENV_LOG_'))}
            status=(proc/'status').read_text().splitlines()
            caps=[x for x in status if x.startswith(('CapEff:','CapPrm:','CapBnd:','NoNewPrivs:'))]
            namespaces={k:os.readlink(proc/'ns'/k) for k in ('net','mnt','user')}
            out['processes'].append({'pid':int(proc.name),'uid':proc.stat().st_uid,'comm':comm,'exe':exe,
              'running_binary':meta(proc/'exe',True),'arguments':[redact(x) for x in args[:24]],
              'cwd':str((proc/'cwd').resolve()),'selected_environment':selected,'capabilities':caps,'namespaces':namespaces})
            if P(exe).is_file():binaries.add(P(exe))
            if comm=='server':
                repos.add((proc/'cwd').resolve())
                if proc.stat().st_uid==0:root_env=environment
            for key in ('AENV_HOME_PATH','AENV_RUNTIME_PATH','AENV_DEPS_PATH'):
                if environment.get(key) and environment[key].startswith('/'):safe_roots.add(P(environment[key]))
        except (OSError,ValueError):pass
    out['caller_namespaces']={k:os.readlink(P('/proc/self/ns')/k) for k in ('net','mnt','user')}
    out['jwk_identity']=call(['id','jwk'])
    out['device_access']=call(['python3','-c',"import os,json;print(json.dumps({p:{'read':os.access(p,os.R_OK),'write':os.access(p,os.W_OK)} for p in ('/dev/kvm','/dev/ublk-control','/dev/net/tun')}))"],user=True)
    out['devices']={x:meta(x) for x in ('/dev/kvm','/dev/ublk-control','/dev/net/tun')}
    out['ublks_max']=P('/sys/module/ublk_drv/parameters/ublks_max').read_text().strip() if P('/sys/module/ublk_drv/parameters/ublks_max').exists() else None
    out['actual_ublk_block_devices']=len(list(P('/sys/class/block').glob('ublkb*')))
    out['ublk_character_devices']=len(list(P('/dev').glob('ublkc*')))
    out['listeners']=call(['ss','-ltnp'],limit=20000)
    out['disk_space']=call(['df','-B1','/home/jwk','/data'])
    out['memory']=call(['free','-b'])
    for binary in sorted(binaries):
        if not binary.is_file():continue
        row=meta(binary,True);row['capabilities']=call(['getcap',str(binary)])
        row['elf_dynamic']=call(['readelf','-d',str(binary)],limit=12000)
        row['ldd_as_jwk']=call(['ldd',str(binary)],user=True,limit=10000)
        out['binaries'].append(row)
    for repo in sorted(repos):
        row={'path':str(repo)}
        if (repo/'.git').exists():
            prefix=['git','--no-optional-locks','-c','safe.directory='+str(repo),'-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',str(repo)]
            row['HEAD']=call(prefix+['rev-parse','HEAD']);row['modified_files']=call(prefix+['diff','--name-only'])
        scripts=set(repo.glob('*.sh'))
        if (repo/'scripts').is_dir():scripts.update((repo/'scripts').glob('*.sh'))
        scripts={p for p in scripts if re.search(r'run|start|server|setup|aenv',p.name,re.I)}
        out['scripts'].extend(script_audit(p) for p in sorted(scripts)[:35] if p.is_file())
        for name in ('src/privileges.rs','src/setup.rs','src/sandbox/network.rs','config/deps_manifest.toml'):
            p=repo/name
            if not p.is_file():continue
            text=p.read_text(errors='replace')
            row[name]={'metadata':meta(p,True),'relevant_lines':[{'line':i,'text':redact(line)[:300]}
              for i,line in enumerate(text.splitlines(),1) if re.search(r'CAP_|cap_net|cap_sys|ublk|9103|unprivileged|/proc/sys|ip_forward|nft|iptables|version\s*=|url\s*=',line,re.I)][:85]}
        out['source'][str(repo)]=row
    # Static downloaded assets only. Do not read live database contents or secrets.
    for home in sorted(safe_roots):
        if 'run' not in home.name and (home/'deps').is_dir():out.setdefault('runtime_assets',[]).append(tree_listing(home/'deps',4,260))
        out.setdefault('runtime_layout',[]).append(tree_listing(home,1,70))
    out['jwk_existing_directories']=[meta(p) for p in (P('/home/jwk'),P('/data/jwk'),P('/home/jwk/.config/aenv'))]
    # Local GETs only; keep the root credential in memory and out of all output.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    headers={}
    if root_env and root_env.get('AENV_API_KEY'):headers['X-API-Key']=root_env['AENV_API_KEY']
    out['api_readonly']={}
    for path in ('/health','/nodes'):
        try:
            with opener.open(urllib.request.Request('http://127.0.0.1:8000'+path,headers=headers),timeout=8) as response:
                raw=response.read(128*1024);value={'http_status':response.status}
                if path=='/nodes':
                    data=json.loads(raw);rows=data if isinstance(data,list) else data.get('nodes',[data])
                    keys={'id','nodeID','node_id','name','hostname','version','commit','gitCommit','architecture','status'}
                    value['nodes']=[{k:v for k,v in row.items() if k in keys} for row in rows if isinstance(row,dict)]
                out['api_readonly'][path]=value
        except Exception as error:out['api_readonly'][path]={'error_type':type(error).__name__,'http_status':getattr(error,'code',None)}
    print(json.dumps(out,ensure_ascii=False,sort_keys=True))
if __name__=='__main__':main()
