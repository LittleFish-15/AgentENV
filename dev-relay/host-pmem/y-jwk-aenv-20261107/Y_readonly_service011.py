"""Read /usr/bin/aenv and service startup evidence. No execution of unknown binaries."""
import hashlib,json,os,pathlib,pwd,re,shlex,shutil,stat,subprocess,tomllib
P=pathlib.Path
def redact(text):
    text=re.sub(r'\b(?:github[_]pat[_]|gh[pousr]_)[A-Za-z0-9_]+','[REDACTED]',text)
    text=re.sub(r'\be2b_[A-Za-z0-9_-]+','[REDACTED]',text)
    text=re.sub(r'''(?i)((?:api[\s_-]?key|access[_-]?token|password|secret|authorization|seed)["']?\s*[=:]\s*["']?)([^"'\s;,}]+)''',r'\1[REDACTED]',text)
    text=re.sub(r'(?i)(--(?:api-key|token|password)\s+)(\S+)',r'\1[REDACTED]',text)
    return re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@',r'\1[REDACTED]@',text)
def call(args,seconds=20,limit=24000):
    try:
        r=subprocess.run(args,capture_output=True,text=True,timeout=seconds)
        return {'code':r.returncode,'stdout':redact(r.stdout[:limit]),'stderr':redact(r.stderr[:2000]),'truncated':len(r.stdout)>limit}
    except (OSError,subprocess.TimeoutExpired) as e:return {'error_type':type(e).__name__}
def metadata(path,digest=False):
    path=P(path);out={'path':str(path),'exists':path.exists(),'symlink':path.is_symlink()}
    if not path.exists():return out
    s=path.stat();out.update(resolved=str(path.resolve()),uid=s.st_uid,gid=s.st_gid,mode=oct(stat.S_IMODE(s.st_mode)),bytes=s.st_size)
    if path.is_file():
        out['file']=call(['file','-b',str(path)])
        if digest and s.st_size<=256*1024**2:
            h=hashlib.sha256()
            with path.open('rb') as f:
                for b in iter(lambda:f.read(1024**2),b''):h.update(b)
            out['sha256']=h.hexdigest()
    return out
PATH_ENV=('AENV_CONFIG_PATH','AENV_CONFIG','AENV_HOME_PATH','AENV_RUNTIME_PATH','AENV_DEPS_PATH','API_ADDR')
SAFE_KEYS={'home_path','runtime_path','deps_path','virtualization_mode','host','port','addr','listen','bind',
 'low_watermark','high_watermark','startup_prewarm','startup_size','fill_concurrency','enabled',
 'binary_path','image_path','drive_path','version','socket_timeout_secs','socket_poll_ms','poll_ms','init_timeout_secs'}
def config(path):
    out=metadata(path)
    if not out['exists'] or not P(path).is_file():return out
    try:
        raw=P(path).read_bytes()
        if len(raw)>256*1024:return {**out,'error':'size_bound'}
        data=tomllib.loads(raw.decode());selected={}
        def walk(obj,prefix=''):
            for key,value in obj.items():
                full=prefix+key
                if isinstance(value,dict):walk(value,full+'.')
                elif key in SAFE_KEYS and not any(x in full.lower() for x in ('secret','auth','token','password','api_key')) and isinstance(value,(str,int,float,bool)):
                    selected[full]=redact(str(value)) if isinstance(value,str) else value
        walk(data);out['selected_values']=selected
    except Exception as e:out['error_type']=type(e).__name__
    return out
def main():
    assert os.geteuid()==0
    report={'action':'Y_READONLY_AENV_SERVICE','target':metadata('/usr/bin/aenv',True),'service_actions':[],
      'configuration_writes':False,'units':[],'processes':[],'configs':[]}
    target=P('/usr/bin/aenv');candidates=set()
    if target.exists():
        resolved=target.resolve();candidates.add(str(resolved.parent/'server'))
        report['target']['rpm_owner']=call(['rpm','-qf',str(target)])
        report['target']['capabilities']=call(['getcap',str(resolved)])
        with resolved.open('rb') as f:head=f.read(64*1024)
        if head.startswith(b'#!'):report['target']['script_head']=redact(head.decode(errors='replace'))[:12000]
        elif head.startswith(b'\x7fELF'):
            # Static indicators only; --help is not run on an unclassified launcher.
            markers=(b'agentenv server',b'Run setup/provisioning only',b'not authenticated',b'--setup-host',b'AENV_CONFIG_PATH')
            found=set();previous=b''
            with resolved.open('rb') as f:
                for b in iter(lambda:f.read(1024**2),b''):
                    data=previous+b
                    found.update(x.decode() for x in markers if x in data);previous=data[-100:]
            report['target']['static_indicators']=sorted(found)
    names=set()
    for label,args in [('unit_files',['systemctl','list-unit-files','--type=service','--no-legend','--no-pager']),
      ('loaded_units',['systemctl','list-units','--type=service','--all','--no-legend','--no-pager'])]:
        r=call(args,limit=256*1024);lines=[x for x in r.get('stdout','').splitlines() if any(k in x.lower() for k in ('aenv','agentenv','ublk','firecracker'))]
        report[label]={'code':r.get('code'),'matching_lines':lines[:80]}
        for line in lines:
            fields=line.strip().lstrip('●').split()
            if fields and re.fullmatch('[A-Za-z0-9_.@:-]+\.service',fields[0]):names.add(fields[0])
    config_paths=set()
    properties=('LoadState','ActiveState','SubState','UnitFileState','Result','MainPID','ExecMainCode','ExecMainStatus',
      'FragmentPath','DropInPaths','User','Group','WorkingDirectory','ExecStart','ExecStartPre','EnvironmentFiles','NeedDaemonReload')
    for name in sorted(names)[:25]:
        row={'name':name,'properties':call(['systemctl','show',name,*['--property='+p for p in properties]],limit=18000),
          'status':call(['systemctl','status',name,'--no-pager','-l','-n','20'],limit=16000),
          'journal':call(['journalctl','-u',name,'-b','-n','60','--no-pager','-o','short-iso'],limit=24000)}
        env=subprocess.run(['systemctl','show',name,'--property=Environment','--value'],capture_output=True,text=True,timeout=15)
        try:
            selected={k:v for item in shlex.split(env.stdout) if '=' in item for k,v in [item.split('=',1)] if k in PATH_ENV}
        except ValueError:selected={}
        row['selected_environment']=selected
        for key in ('AENV_CONFIG_PATH','AENV_CONFIG'):
            if selected.get(key):config_paths.add(selected[key])
        text=row['properties'].get('stdout','')
        for m in re.finditer(r'--config(?:=|\s+)([^\s;"}]+)',text):
            path=P(m.group(1))
            if path.is_absolute():config_paths.add(str(path))
        for m in re.finditer(r'(?:path|argv\[\])=([^\s;]+)',text):
            if m.group(1).startswith('/'):candidates.add(m.group(1))
        report['units'].append(row)
    for proc in P('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            comm=(proc/'comm').read_text().strip();exe=str((proc/'exe').resolve())
            if comm not in ('server','aenv','uvm-ublk-daemon') and not ('agentenv' in exe.lower()):continue
            args=(proc/'cmdline').read_bytes().decode(errors='replace').split('\0')
            environment=dict(x.split('=',1) for x in (proc/'environ').read_bytes().decode(errors='replace').split('\0') if '=' in x)
            selected={k:environment[k] for k in PATH_ENV if k in environment}
            report['processes'].append({'pid':int(proc.name),'uid':proc.stat().st_uid,'comm':comm,'exe':exe,
              'cwd':str((proc/'cwd').resolve()),'selected_environment':selected,'cgroup':(proc/'cgroup').read_text()[:1500]})
            for i,arg in enumerate(args):
                if arg=='--config' and i+1<len(args):config_paths.add(args[i+1])
            if selected.get('AENV_CONFIG_PATH'):config_paths.add(selected['AENV_CONFIG_PATH'])
        except (OSError,ValueError):pass
    report['listeners']=call(['ss','-ltnp'],limit=24000)
    report['devices']={x:metadata(x) for x in ('/dev/kvm','/dev/ublk-control','/dev/net/tun')}
    report['prerequisites']={'kvm_amd_modinfo':call(['modinfo','kvm_amd'],limit=6000),
      'ublk_modinfo':call(['modinfo','ublk_drv'],limit=6000),
      'svm_cpu_flag':any('svm' in l.split(':',1)[1].split() for l in P('/proc/cpuinfo').read_text().splitlines() if l.startswith('flags'))}
    for root in (P('/etc/aenv'),P('/etc/agentenv'),P('/data/aenv/config')):
        if root.is_dir():config_paths.update(str(p) for p in root.glob('*.toml') if p.is_file())
    report['configs']=[config(p) for p in sorted(config_paths)[:30]]
    candidates.update(('/usr/bin/server','/usr/local/bin/server','/usr/local/bin/aenv'))
    report['related_binaries']=[metadata(p,True) for p in sorted(candidates) if P(p).is_file() and p!='/usr/bin/aenv'][:20]
    print(json.dumps(report,ensure_ascii=False,sort_keys=True))
if __name__=='__main__':main()
