"""Read-only Y post-reboot audit; never starts services or experiments."""
import collections,gzip,hashlib,http.client,json,os,pathlib,platform,re,stat,subprocess,time
from urllib.parse import urlsplit

P=pathlib.Path
B=P('/home/jwk/aenv-y-clean-20261111')
ROOT=P('/run/jwk-aenv-y-clean-20261111')
W=B/'boot-audit-20261116-039'
U='jwk-aenv-y-clean-20261111.service'
UNITS=(U,'jwk-aenv-y-devices-20261111.service','jwk-aenv-y-relays-20261111.service','jwk-aenv-y-proxy-20261111.service','jwk-aenv-y-proxy-20261111.socket')
EXPECTED={'architecture':'x86_64','bootId':'d005bda4-518d-4766-b704-259df7bae4f9','hostname':'debian','kernel':'6.6.122ublk+','machineId':'9c4987ac1e5849409b53b20724f12d34'}
SERVER_SHA='77360e94b86cebf5da014003216440efe68b444e05c45a4194e331c36280a488'
CONFIG_SHA='d6e0911ff0258d02cee95ad8aa620ba863925aadef1d774c7c3cd0950bf252f1'
ENV={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','SYSTEMD_PAGER':'','SYSTEMD_COLORS':'0'}

def digest(raw):return hashlib.sha256(raw).hexdigest()

def bounded(path,limit=8192):
    with P(path).open('rb') as f:
        raw=f.read(limit+1)
    if len(raw)>limit:raise ValueError('Input exceeds read bound')
    return raw

def file_sha(path):
    with P(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def text(path,limit=8192):return bounded(path,limit).decode(errors='replace')

def missing(error):return {'available':False,'errorType':type(error).__name__}

def metadata(path,hash_file=False):
    path=P(path)
    try:
        s=path.lstat();row={'available':True,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'bytes':s.st_size,'inode':s.st_ino,'type':'other'}
        if stat.S_ISLNK(s.st_mode):row['type']='symlink'
        elif stat.S_ISDIR(s.st_mode):row['type']='directory'
        elif stat.S_ISREG(s.st_mode):
            row['type']='file'
            if hash_file and s.st_size<=128*1024**2 and path.parent.resolve()==path.parent:row['sha256']=file_sha(path)
        elif stat.S_ISCHR(s.st_mode) or stat.S_ISBLK(s.st_mode):row.update(type='character' if stat.S_ISCHR(s.st_mode) else 'block',major=os.major(s.st_rdev),minor=os.minor(s.st_rdev))
        elif stat.S_ISSOCK(s.st_mode):row['type']='socket'
        return row
    except OSError as error:return missing(error)

def command(args):
    try:
        p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,timeout=12)
        row={'exitCode':p.returncode,'stdoutBytes':len(p.stdout),'stdoutSha256':digest(p.stdout),'stderrBytes':len(p.stderr),'stderrSha256':digest(p.stderr)}
        if len(p.stdout)>256*1024:row['parseOmitted']='command output exceeds bound';return row,None
        return row,p.stdout.decode(errors='replace')
    except (OSError,subprocess.SubprocessError) as error:return missing(error),None

def exec_summary(raw):
    if raw is None:return {'available':False}
    result={'sha256':digest(raw.encode()),'bytes':len(raw.encode()),'argumentsOmitted':True}
    result['executablePaths']=sorted(set(re.findall(r'(?:^|[ {;])path=(/[A-Za-z0-9_./+-]+)',raw)))[:4]
    scripts=re.findall(r'/(?:home/jwk/aenv-y-clean-20261111|run/jwk-aenv-y-clean-20261111)/[A-Za-z0-9_./+-]+\.(?:py|sh)',raw)
    result['ownedScriptPaths']=sorted(set(scripts))[:8]
    return result

def unit_info(name):
    props=('LoadState','ActiveState','SubState','MainPID','User','Group','Transient','FragmentPath','DropInPaths','ControlGroup','PrivateNetwork','PrivateMounts','PrivateTmp','NoNewPrivileges','ProtectSystem','ProtectHome','LimitNOFILE','LimitNOFILESoft','TasksMax','MemoryMax','MemorySwapMax','CapabilityBoundingSet','AmbientCapabilities','BindPaths','BindReadOnlyPaths','ReadWritePaths')
    status,raw=command(['systemctl','show',name,*[x for p in props for x in ('-p',p)]])
    result={'show':status,'properties':{}}
    if raw is not None:
        for line in raw.splitlines():
            k,sep,v=line.partition('=')
            if sep and k in props:result['properties'][k]=v[:1600]
    status,raw=command(['systemctl','show',name,'-p','ExecStart','--value'])
    result['execStartRead']=status;result['execStart']=exec_summary(raw)
    status,raw=command(['systemctl','cat','--no-pager',name]);result['cat']=status
    if raw is not None:
        allowed={'User','Group','Type','Requires','After','Sockets','CapabilityBoundingSet','AmbientCapabilities','NoNewPrivileges','BindPaths','BindReadOnlyPaths','ReadWritePaths','WorkingDirectory','UMask','SupplementaryGroups'}
        selected=[];omitted=0
        for line in raw.splitlines():
            line=line.strip();k,sep,v=line.partition('=')
            if line.startswith('[') and line.endswith(']'):selected.append(line)
            elif sep and (k in allowed or k.startswith(('Private','Protect','Limit','TasksMax','Memory'))):selected.append(k+'='+v[:1600])
            elif line and not line.startswith('#'):omitted+=1
        result['cat']['whiteListedLines']=selected[:80];result['cat']['omittedDirectiveLines']=omitted;result['cat']['environmentAndUnknownArgumentsOmitted']=True
    return result

def kernel_info():
    result={'release':platform.release(),'pageSize':os.sysconf('SC_PAGE_SIZE'),'clockTicks':os.sysconf('SC_CLK_TCK'),'logicalCPUs':os.cpu_count(),'configFound':False,'configErrors':[],'runtime':{}}
    release=result['release']
    names={'X86_64','ARM64','HZ','HZ_100','HZ_250','HZ_300','HZ_1000','PREEMPT_NONE','PREEMPT_VOLUNTARY','PREEMPT','PREEMPT_DYNAMIC','PREEMPT_RT','TRANSPARENT_HUGEPAGE','TRANSPARENT_HUGEPAGE_ALWAYS','TRANSPARENT_HUGEPAGE_MADVISE','NUMA','NUMA_BALANCING','DEBUG_VM','DEBUG_PAGEALLOC','DEBUG_SPINLOCK','LOCK_STAT','KVM','KVM_INTEL','KVM_AMD','SCHEDSTATS','PAGE_TABLE_CHECK','X86_5LEVEL','MEMCG','PGTABLE_LEVELS'}
    for path in (P('/proc/config.gz'),P('/boot')/('config-'+release),P('/lib/modules')/release/'build/.config'):
        try:
            data=bounded(path,2*1024**2)
            if path.suffix=='.gz':
                import io
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:data=stream.read(2*1024**2+1)
            if len(data)>2*1024**2:raise ValueError('Kernel config exceeds bound')
            selected=[]
            for line in data.decode(errors='replace').splitlines():
                m=re.match(r'(?:# )?CONFIG_([A-Z0-9_]+)(?:=| is not set)',line)
                if m and m.group(1) in names:selected.append(line[:240])
            result.update(configFound=True,configSource=str(path),configBytes=len(data),configSha256=digest(data),selectedConfig=selected,configRuntimeBinding='proc-runtime' if str(path)=='/proc/config.gz' else 'release-named-boot-file' if path.parent==P('/boot') else 'build-tree-fallback-not-proven-running');break
        except (OSError,ValueError,EOFError) as error:result['configErrors'].append({'path':str(path),'errorType':type(error).__name__})
    paths=('/proc/sys/kernel/numa_balancing','/proc/sys/kernel/sched_schedstats','/sys/kernel/mm/transparent_hugepage/enabled','/sys/kernel/mm/transparent_hugepage/defrag','/sys/module/ublk_drv/parameters/ublks_max','/proc/sys/net/ipv4/neigh/default/gc_thresh1','/proc/sys/net/ipv4/neigh/default/gc_thresh2','/proc/sys/net/ipv4/neigh/default/gc_thresh3','/proc/pressure/cpu','/proc/pressure/io','/proc/pressure/memory','/proc/loadavg','/proc/uptime','/proc/meminfo')
    for path in paths:
        try:result['runtime'][path]=text(path,12000 if path=='/proc/meminfo' else 2048).strip()
        except (OSError,ValueError) as error:result['runtime'][path]=missing(error)
    return result

def process_info(pid):
    try:
        proc=P('/proc',str(pid));s=proc.stat();raw=text(proc/'stat');fields=raw.rsplit(')',1)[1].split();row={'available':True,'pid':pid,'uid':s.st_uid,'comm':text(proc/'comm',256).strip(),'starttime':fields[19],'cgroup':text(proc/'cgroup',4096).strip(),'executableSha256':file_sha(proc/'exe')}
        row['namespaceInodes']={n:os.stat(proc/'ns'/n).st_ino for n in ('net','mnt')}
        row['nofile']=next((line for line in text(proc/'limits',10000).splitlines() if line.startswith('Max open files')),None)
        env=bounded(proc/'environ',1024*1024).split(b'\0');allowed={b'AENV_LOG_FORMAT',b'AENV_LOG_SPAN_EVENTS',b'RUST_LOG'}
        row['loggingEnvironment']={k.decode():v.decode(errors='replace')[:600] for item in env for k,sep,v in [item.partition(b'=')] if sep and k in allowed}
        return row
    except (OSError,ValueError,IndexError) as error:return missing(error)

def process_inventory():
    own=0;outside=0;unreadable=0;sample=[];groups=collections.Counter();limits=collections.Counter();other=[];matched=0
    benchmarks={'benchmark_sandbox_lifecycle.py','g4-benchmark_sandbox_lifecycle.py','lifecycle-go','diagnostic-client'}
    for proc in P('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            if proc.stat().st_uid!=1002:continue
            comm=text(proc/'comm',256).strip();cwd=os.readlink(proc/'cwd');inbase=P(cwd).is_relative_to(B)
            if comm=='firecracker':
                if not P(cwd).is_relative_to(B/'fc'):outside+=1;continue
                own+=1;fields=text(proc/'stat').rsplit(')',1)[1].split();nofile=next((x for x in text(proc/'limits',10000).splitlines() if x.startswith('Max open files')),None);cg=text(proc/'cgroup',4096).strip();groups[cg]+=1;limits[nofile]+=1
                if len(sample)<8:sample.append({'pid':int(proc.name),'uid':1002,'cwd':cwd,'starttime':fields[19],'nofile':nofile,'cgroup':cg})
            elif inbase:
                args=bounded(proc/'cmdline',16384).split(b'\0');known=sorted({P(a.decode(errors='replace')).name for a in args if a and P(a.decode(errors='replace')).name in benchmarks})
                if known:
                    matched+=1
                    if len(other)<20:other.append({'pid':int(proc.name),'comm':comm,'knownBenchmarkNames':known})
        except (OSError,ValueError,IndexError):unreadable+=1
    return {'ownFirecrackerCount':own,'otherJwkFirecrackerCount':outside,'unreadableJwkProcesses':unreadable,'ownFirecrackerSample':sample,'cgroupCounts':[{'value':k[:1500],'count':v} for k,v in groups.most_common(8)],'nofileCounts':[{'value':k,'count':v} for k,v in limits.most_common(8)],'otherBenchmarkCount':matched,'otherBenchmarkSample':other,'measurement':'single non-atomic read-only process scan; no stability assertion or signals'}

def api_info():
    result={'readOnly':True,'credentialsExported':False,'calls':{}};key=None
    try:
        path=B/'config/api-key'
        if path.is_symlink() or path.resolve()!=path:raise ValueError('Redirected key path')
        key=text(path).strip()
        if not key:raise ValueError('Empty API key')
        for target in ('/health','/v2/sandboxes?limit=100&state=running','/v2/sandboxes?limit=100&state=paused'):
            conn=http.client.HTTPConnection('127.0.0.1',18080,timeout=4)
            try:
                conn.request('GET',target,headers={'X-API-Key':key});response=conn.getresponse();raw=response.read(512*1024+1);row={'status':response.status,'responseBytes':len(raw)}
                if len(raw)>512*1024:row['bodyNotParsed']='response exceeds bound'
                elif target!='/health' and response.status==200:
                    body=json.loads(raw);row['sandboxCount']=len(body) if isinstance(body,list) else None;row['bodyType']='list' if isinstance(body,list) else type(body).__name__;row['possiblyMoreThanLimit']=isinstance(body,list) and len(body)>=100
                result['calls'][target]=row
            except (OSError,http.client.HTTPException,ValueError) as error:result['calls'][target]=missing(error)
            finally:conn.close()
    except (OSError,ValueError) as error:result.update(missing(error))
    finally:key=None
    return result

def proxy_environment_presence():
    rows={}
    for name in ('HTTPS_PROXY','HTTP_PROXY','https_proxy','http_proxy'):
        value=os.environ.get(name);row={'present':bool(value),'valueExported':False}
        if value:
            try:
                parsed=urlsplit(value);row.update(urlParsed=True,urlHasUsername=parsed.username is not None,urlHasPassword=parsed.password is not None)
            except ValueError as error:row.update(urlParsed=False,errorType=type(error).__name__)
        rows[name]=row
    return rows

def private_ca_status():
    try:
        source=B/'status.json'
        if source.is_symlink() or source.resolve()!=source:raise ValueError('Redirected status input')
        data=json.loads(text(source,2*1024**2));value=data.get('private_ca005',{}).get('path')
        if not isinstance(value,str) or not P(value).is_absolute():raise ValueError('Private CA path unavailable')
        return {'available':True,'path':value,'metadata':metadata(P(value),True),'statusContentsExported':False}
    except (OSError,ValueError,TypeError,AttributeError) as error:return missing(error)

def main():
    os.umask(0o077)
    result={'action':'Y_POST_REBOOT_READ_ONLY_AUDIT','success':False,'experimentStarted':False,'serviceMutated':False,'kernelParametersChanged':False,'XContacted':False,'errors':[],'unixNs':time.time_ns()};safe_output=False
    try:
        if os.getuid()!=0 or os.geteuid()!=0:raise RuntimeError('Root required')
        identity={'hostname':platform.node(),'machineId':text('/etc/machine-id').strip(),'bootId':text('/proc/sys/kernel/random/boot_id').strip(),'kernel':platform.release(),'architecture':platform.machine()};result['identity']=identity
        if identity!=EXPECTED:raise RuntimeError('Fresh node/boot identity mismatch')
        if B.resolve()!=B or B.stat().st_uid!=1002:raise RuntimeError('Unexpected deployment owner/path')
        safe_output=True
        result['rootProxyEnvironment']=proxy_environment_presence();result['privateCAFromPersistentStatus']=private_ca_status()
        result['hostNamespaceInodes']={n:os.stat(P('/proc/self/ns')/n).st_ino for n in ('net','mnt')}
        result['existingDeployment']={str(p):metadata(p,True) for p in (B/'bin/server',B/'config/runtime005.toml')}
        result['binaryAndConfigMatch']=(result['existingDeployment'][str(B/'bin/server')].get('sha256')==SERVER_SHA and result['existingDeployment'][str(B/'config/runtime005.toml')].get('sha256')==CONFIG_SHA)
        result['units']={name:unit_info(name) for name in UNITS}
        pid=result['units'][U]['properties'].get('MainPID','0')
        result['mainProcess']=process_info(int(pid)) if pid.isdigit() and int(pid)>1 else {'available':False,'reason':'no_main_pid'}
        paths=(ROOT,ROOT/'dev',ROOT/'dev/ublk-control',ROOT/'jwk-ublk-query',ROOT/'device_broker011.py',ROOT/'broker-config011.json',ROOT/'broker-ready011.json',ROOT/'proxy-code010/auth_proxy010.py',ROOT/'proxy-credentials009.json',ROOT/'proxy-ca009.pem',P('/dev/ublk-control'),P('/dev/kvm'),P('/dev/jwk-aenv-y-clean-20261111-011'),P('/dev/jwk-aenv-y-clean-20261111-011/ublk-control'),P('/var/lib/jwk-aenv-y-control017/jwk-ublk-query017'),B/'r/api.sock',B/'r/egress.sock',B/'r/ublk.sock',B/'scripts/.run.lock',B/'runtime-code014/runtime_supervisor014.py',B/'g6-no-anchor-six-20261113-037/runtime_formal.py',B/'g7-20261112-031/lifecycle-go',B/'diagnosis-no-anchor-20261116-038')
        hash_names={'jwk-ublk-query','jwk-ublk-query017','device_broker011.py','broker-config011.json','auth_proxy010.py','runtime_supervisor014.py','runtime_formal.py','lifecycle-go'}
        result['paths']={str(p):metadata(p,p.name in hash_names) for p in paths}
        try:
            path=B/'config/host-context008.json'
            if path.is_symlink() or path.resolve()!=path:raise ValueError('Redirected host context')
            context=json.loads(text(path));result['hostContext']={k:context.get(k) for k in ('boot_id','netns','mntns','uid')};result['hostContextMatchesCurrentBoot']=context.get('boot_id')==identity['bootId']
        except (OSError,ValueError) as error:result['hostContext']=missing(error)
        result['kernel']=kernel_info();result['processes']=process_inventory();result['api']=api_info()
        candidates=[]
        for folder in (B,B/'scripts'):
            try:
                for p in sorted(folder.iterdir()):
                    if len(candidates)>=32:break
                    if p.is_file() and not p.is_symlink() and (p.suffix=='.sh' or ('start' in p.name.lower() and p.suffix=='.py')):candidates.append({'path':str(p),**metadata(p,True)})
            except OSError as error:result['errors'].append({'operation':'list_manual_scripts','errorType':type(error).__name__})
        result['manualScriptCandidates']=candidates;result['success']=True
    except BaseException as error:result.update(errorType=type(error).__name__,error=str(error)[:500])
    # Only this new evidence directory is writable. No prior files are replaced.
    try:
        if not safe_output:raise RuntimeError('Identity or deployment owner not verified; no output directory created')
        if W.exists() or W.is_symlink():raise RuntimeError('Existing audit evidence preserved')
        if W.parent.resolve()!=W.parent:raise RuntimeError('Redirected evidence parent')
        W.mkdir(mode=0o700);result['outputDirectory']=str(W)
    except BaseException as error:result.update(success=False,outputErrorType=type(error).__name__,outputError=str(error)[:500])
    raw=json.dumps(result,separators=(',',':')).encode()
    if len(raw)>120*1024:
        for unit in result.get('units',{}).values():unit.get('cat',{}).pop('whiteListedLines',None)
        result['collectionTruncated']=True;raw=json.dumps(result,separators=(',',':')).encode()
    if len(raw)>120*1024:
        result={'action':result['action'],'success':False,'experimentStarted':False,'error':'Audit output exceeds bound','identity':result.get('identity'),'outputDirectory':str(W)};raw=json.dumps(result,separators=(',',':')).encode()
    if W.is_dir() and 'outputErrorType' not in result:
        with (W/'result.json').open('xb') as f:f.write(raw+b'\n')
    print(raw.decode(),flush=True)

if __name__=='__main__':main()
