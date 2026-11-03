"""Start isolated genuine-original Titanic Runtime using retained binaries only.
No UB/provider/kernel action or Guest creation. Explicit owned-service stop only.
"""
import base64,grp,hashlib,http.client,json,os,platform,re,secrets,socket,stat,subprocess,sys,time,types,zlib
from pathlib import Path
BASE=Path('/home/jwk/root/hpo-services-v1');PORT=18251
ORIGINAL=Path('/home/jwk/agent/deployments/agentenv-ae9c626-baseline')
NODES={'node-a': {'identity': {'hostname': 'server1', 'machineId': '5292d505787a4272ac8f4fcafbea5e07', 'bootId': '7bd42416-46a3-49c4-af22-7318836954b2', 'kernel': '6.6.0-145.3.34.165.oe2403sp3.aarch64', 'architecture': 'aarch64', 'uid': 1204, 'gid': 1205}, 'binaries': {'bin/server': {'path': '/home/jwk/agent/deployments/agentenv-ae9c626-baseline/bin/server', 'present': True, 'bytes': 88810328, 'uid': 1204, 'symlink': False, 'sha256': '0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff'}, 'bin/aenv': {'path': '/home/jwk/agent/deployments/agentenv-ae9c626-baseline/bin/aenv', 'present': True, 'bytes': 14686000, 'uid': 1204, 'symlink': False, 'sha256': 'ac2cf76020ce2ed0cf06f1105e06c34534a35ed8247fca0cb57e2d53269771e1'}, 'bin/uvm-ublk-daemon': {'path': '/home/jwk/agent/deployments/agentenv-ae9c626-baseline/bin/uvm-ublk-daemon', 'present': True, 'bytes': 24374680, 'uid': 1204, 'symlink': False, 'sha256': '13bd2ac381cf877348a39c0b198e2061479ae237c0f54cbcbeae0ab14e700172'}, 'deps/firecracker/1.15.1-patch-v3/firecracker': {'path': '/home/jwk/agent/deployments/agentenv-ae9c626-baseline/deps/firecracker/1.15.1-patch-v3/firecracker', 'present': True, 'bytes': 3190408, 'uid': 1204, 'symlink': False, 'sha256': 'a64b8f068d47bd6ec85aa755b8f8863e16d0ae14be551376218fed401ee0bdf8'}}}, 'node-b': {'identity': {'hostname': 'agent1', 'machineId': 'ae1ee682fbf544ffb4828c403bf658f5', 'bootId': 'bb7a0176-895d-4262-b1cb-200cef6f13c1', 'kernel': '6.6.0-145.3.34.165.oe2403sp3.aarch64', 'architecture': 'aarch64', 'uid': 1204, 'gid': 1205}, 'binaries': {'bin/server': {'path': '/home/jwk/agent/deployments/agentenv-ae9c626-baseline/bin/server', 'present': True, 'bytes': 88810328, 'uid': 1204, 'symlink': False, 'sha256': '0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff'}, 'bin/aenv': {'path': '/home/jwk/agent/deployments/agentenv-ae9c626-baseline/bin/aenv', 'present': True, 'bytes': 14686000, 'uid': 1204, 'symlink': False, 'sha256': 'ac2cf76020ce2ed0cf06f1105e06c34534a35ed8247fca0cb57e2d53269771e1'}, 'bin/uvm-ublk-daemon': {'path': '/home/jwk/agent/deployments/agentenv-ae9c626-baseline/bin/uvm-ublk-daemon', 'present': True, 'bytes': 24374680, 'uid': 1204, 'symlink': False, 'sha256': '13bd2ac381cf877348a39c0b198e2061479ae237c0f54cbcbeae0ab14e700172'}, 'deps/firecracker/1.15.1-patch-v3/firecracker': {'path': '/home/jwk/agent/deployments/agentenv-ae9c626-baseline/deps/firecracker/1.15.1-patch-v3/firecracker', 'present': True, 'bytes': 3190408, 'uid': 1204, 'symlink': False, 'sha256': 'a64b8f068d47bd6ec85aa755b8f8863e16d0ae14be551376218fed401ee0bdf8'}}}}
PROXY='IiIiWmVyby1jYXBhYmlsaXR5IGxvY2FsIFRDUC9VTklYIGJyaWRnZTsgbm8gU1NIIGFuZCBubyBjcmVkZW50aWFsIGhhbmRsaW5nLiIiIgppbXBvcnQgYXN5bmNpbwppbXBvcnQganNvbgppbXBvcnQgb3MKZnJvbSBwYXRobGliIGltcG9ydCBQYXRoCmltcG9ydCByZQppbXBvcnQgc3RhdAppbXBvcnQgc3lzCgoKYXN5bmMgZGVmIG1haW4oKToKICAgIGFzc2VydCBvcy5nZXR1aWQoKT09b3MuZ2V0ZXVpZCgpPT0xMjA0CiAgICBhc3NlcnQgYWxsKGludChsLnNwbGl0KClbMV0sMTYpPT0wIGZvciBsIGluIFBhdGgoJy9wcm9jL3NlbGYvc3RhdHVzJykucmVhZF90ZXh0KCkuc3BsaXRsaW5lcygpCiAgICAgICAgICAgICAgIGlmIGwuc3RhcnRzd2l0aCgoJ0NhcEluaDonLCdDYXBQcm06JywnQ2FwRWZmOicsJ0NhcEFtYjonKSkpCiAgICBwPVBhdGgoc3lzLmFyZ3ZbMl0pO3N0PXAuc3RhdCgpCiAgICBhc3NlcnQgcC5yZXNvbHZlKCk9PXAgYW5kIHN0LnN0X3VpZD09MCBhbmQgbm90IHN0YXQuU19JTU9ERShzdC5zdF9tb2RlKSYwbzAyMgogICAgY2ZnPWpzb24ubG9hZHMocC5yZWFkX2J5dGVzKCkpO2luc2lkZT1zeXMuYXJndlsxXT09J2luc2lkZScKICAgIGFzc2VydCBzeXMuYXJndlsxXSBpbiAoJ2luc2lkZScsJ2hvc3QnKSBhbmQgY2ZnWydwb3J0J109PTE4MjUxCiAgICBhc3NlcnQgcmUuZnVsbG1hdGNoKCcvaG9tZS9qd2svYWdlbnQvci9ocG8tW2FiXS12MS9hY3RpdmUvYXBpLnNvY2snLGNmZ1snc29ja2V0J10pCiAgICBhc3luYyBkZWYgY29ubmVjdChyZWFkZXIsd3JpdGVyKToKICAgICAgICBwZWVyPU5vbmUKICAgICAgICB0cnk6CiAgICAgICAgICAgIGlmIGluc2lkZTpyLHc9YXdhaXQgYXN5bmNpby5vcGVuX2Nvbm5lY3Rpb24oJzEyNy4wLjAuMScsY2ZnWydwb3J0J10pCiAgICAgICAgICAgIGVsc2U6cix3PWF3YWl0IGFzeW5jaW8ub3Blbl91bml4X2Nvbm5lY3Rpb24oY2ZnWydzb2NrZXQnXSkKICAgICAgICAgICAgcGVlcj13CiAgICAgICAgICAgIGFzeW5jIGRlZiBwdW1wKGEsYixvYnNlcnZlPUZhbHNlKToKICAgICAgICAgICAgICAgIGZpcnN0PVRydWUKICAgICAgICAgICAgICAgIHdoaWxlIFRydWU6CiAgICAgICAgICAgICAgICAgICAgZGF0YT1hd2FpdCBhLnJlYWQoNjU1MzYpCiAgICAgICAgICAgICAgICAgICAgaWYgbm90IGRhdGE6CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIGIuY2FuX3dyaXRlX2VvZigpOmIud3JpdGVfZW9mKCk7YXdhaXQgYi5kcmFpbigpCiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICAgICAgaWYgb2JzZXJ2ZSBhbmQgZmlyc3Q6CiAgICAgICAgICAgICAgICAgICAgICAgIGZpcnN0PUZhbHNlCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIGRhdGEuc3BsaXQoYicgJywxKVswXSBub3QgaW4gKGInR0VUJyxiJ0hFQUQnLGInT1BUSU9OUycpOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgbWFya2VyPVBhdGgoY2ZnWydzb2NrZXQnXSkucGFyZW50LydleHRlcm5hbC1tdXRhdGlvbi1vYnNlcnZlZCcKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmZD1vcy5vcGVuKG1hcmtlcixvcy5PX1dST05MWXxvcy5PX0NSRUFUfG9zLk9fRVhDTHxvcy5PX05PRk9MTE9XLDBvNjAwKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9zLndyaXRlKGZkLGInZXh0ZXJuYWwgQVBJIG11dGF0aW9uIG9ic2VydmVkOyBiYWNraW5nIHJldGlyZW1lbnQgcmVxdWlyZXMgcmVjb25jaWxpYXRpb25cbicpO29zLmNsb3NlKGZkKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IEZpbGVFeGlzdHNFcnJvcjpwYXNzCiAgICAgICAgICAgICAgICAgICAgYi53cml0ZShkYXRhKTthd2FpdCBiLmRyYWluKCkKICAgICAgICAgICAgYXdhaXQgYXN5bmNpby53YWl0X2Zvcihhc3luY2lvLmdhdGhlcihwdW1wKHJlYWRlcix3LG5vdCBpbnNpZGUpLHB1bXAocix3cml0ZXIpKSw2MDApCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLGFzeW5jaW8uVGltZW91dEVycm9yLENvbm5lY3Rpb25FcnJvcik6cGFzcwogICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgIHdyaXRlci5jbG9zZSgpCiAgICAgICAgICAgIGlmIHBlZXIgaXMgbm90IE5vbmU6cGVlci5jbG9zZSgpCiAgICBpZiBpbnNpZGU6CiAgICAgICAgYXNzZXJ0IG5vdCBQYXRoKGNmZ1snc29ja2V0J10pLmV4aXN0cygpCiAgICAgICAgc2VydmVyPWF3YWl0IGFzeW5jaW8uc3RhcnRfdW5peF9zZXJ2ZXIoY29ubmVjdCxjZmdbJ3NvY2tldCddKQogICAgICAgIG9zLmNobW9kKGNmZ1snc29ja2V0J10sMG82MDApCiAgICBlbHNlOnNlcnZlcj1hd2FpdCBhc3luY2lvLnN0YXJ0X3NlcnZlcihjb25uZWN0LCcxMjcuMC4wLjEnLGNmZ1sncG9ydCddKQogICAgYXN5bmMgd2l0aCBzZXJ2ZXI6YXdhaXQgc2VydmVyLnNlcnZlX2ZvcmV2ZXIoKQoKCmlmIF9fbmFtZV9fPT0nX19tYWluX18nOmFzeW5jaW8ucnVuKG1haW4oKSkK'

def need(ok,reason):
    if not ok:raise RuntimeError(reason)


def wire(value):
    # The existing provider's manifest/config digest preserves JSON key order.
    return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()


def identity():
    return {'hostname':platform.node(),'machineId':Path('/etc/machine-id').read_text().strip(),
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'kernel':platform.release(),'architecture':platform.machine(),'uid':1204,'gid':1205}


def read(path,limit=512*1024,owners=(0,1204)):
    path=Path(path);need(path.resolve(strict=True)==path,'Input path redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_uid in owners and a.st_size<=limit,'Input owner/type/size differs')
        data=f.read(limit+1);b=os.fstat(f.fileno())
    sig=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    need(len(data)<=limit and sig(a)==sig(b)==sig(path.stat()),'Input changed')
    return data


def digest(path):
    path=Path(path);need(path.resolve(strict=True)==path,'Hash source redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    h=hashlib.sha256()
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_size<=4*1024**3,'Hash source invalid')
        for block in iter(lambda:f.read(1024**2),b''):h.update(block)
        b=os.fstat(f.fileno())
    sig=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    need(sig(a)==sig(b)==sig(path.stat()),'Source changed during hashing')
    return h.hexdigest()


def folder(p,uid=0,gid=0,mode=0o755):
    need(p.resolve()==p,'Directory redirected')
    if not p.exists():p.mkdir(mode=mode);os.chown(p,uid,gid);os.chmod(p,mode)
    s=p.stat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==uid and not stat.S_IMODE(s.st_mode)&0o022,'Directory identity differs')


def put(p,raw,uid=0,gid=0,mode=0o644):
    need(p.parent.resolve()==p.parent and not p.is_symlink(),'Output redirected')
    if p.exists():
        s=p.stat();need(s.st_uid==uid and stat.S_IMODE(s.st_mode)==mode and read(p,len(raw)+1)==raw,'Prior output differs; preserved');return
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:
        os.fchown(f.fileno(),uid,gid);os.fchmod(f.fileno(),mode);f.write(raw);f.flush();os.fsync(f.fileno())


def tool(name):
    for prefix in ('/usr/sbin','/usr/bin','/sbin','/bin'):
        p=Path(prefix)/name
        if p.is_file():
            s=p.resolve().stat();need(s.st_uid==0 and not s.st_mode&0o022,'System tool is writable')
            return str(p)
    raise RuntimeError('Missing system tool: '+name)


def cmd(argv,seconds=60,owner=False,check=True,env=None):
    opts={'user':1204,'group':1205,'extra_groups':[grp.getgrnam('ubsmd').gr_gid],'umask':0o077} if owner else {}
    r=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,capture_output=True,timeout=seconds,
        env=env or {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/home/jwk','LANG':'C','LC_ALL':'C'},**opts)
    need(not check or r.returncode==0,'Command failed: '+Path(str(argv[0])).name+' exit='+str(r.returncode))
    return r


def props(name):
    r=cmd([tool('systemctl'),'show',name,'--no-pager',
        '--property=MainPID,ActiveState,LoadState,Result,ExecMainStatus,Description,User,Group,ControlGroup'])
    return dict(line.split('=',1) for line in r.stdout.decode().splitlines() if '=' in line)


def ticks(pid):return Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]


def zero_caps(pid):
    return all(int(line.split()[1],16)==0 for line in Path('/proc',str(pid),'status').read_text().splitlines()
               if line.startswith(('CapInh:','CapPrm:','CapEff:','CapAmb:')))


def toml(value):
    import tomllib
    lines=[]
    def emit(row,prefix):
        if prefix:lines.append('['+'.'.join(prefix)+']')
        for key,v in row.items():
            need(re.fullmatch('[A-Za-z0-9_-]+',key) is not None,'Invalid TOML key')
            if not isinstance(v,dict):lines.append(key+' = '+json.dumps(v))
        lines.append('')
        for key,v in row.items():
            if isinstance(v,dict):emit(v,prefix+[key])
    emit(value,[]);raw=('\n'.join(lines)+'\n').encode()
    need(tomllib.loads(raw.decode())==value,'TOML serialization differs');return raw

class Start:
    def mark(self,phase):
        self.state['phase']=phase
        temporary=self.path.with_name('journal-'+secrets.token_hex(8)+'.next')
        put(temporary,wire(self.state)+b'\n',mode=0o600);os.replace(temporary,self.path)
        fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
        print('PHASE='+self.node+':'+phase,flush=True)

    def once(self,label,fn):
        old=self.state['steps'].get(label)
        if old:
            need(old['state']=='done','Prior '+label+' outcome requires explicit reconciliation')
            return old['result']
        self.state['steps'][label]={'state':'intent'};self.mark(label+'_intent')
        value=fn();self.state['steps'][label]={'state':'done','result':value};self.mark(label+'_confirmed')
        return value

    def bound(self,label):
        row=self.state['units'][label];p=props(row['name'])
        need(row.get('pid') and p['ActiveState']=='active' and int(p['MainPID'])==row['pid'] and
            p['Description']==row['description'] and ticks(row['pid'])==row['ticks'],'Owned '+label+' process changed')
        return row

    def _launch(self,label,argv,extra):
        name='aenv-hpo-'+self.n+'-'+label+'-'+self.auth['runId'][-8:]+'.service'
        need(props(name)['LoadState']=='not-found','New unit name already exists')
        row={'name':name,'description':'AgentENV Host DAX '+self.auth['runId']+' '+self.node+' '+label,
             'argvSha256':self.api.digest(self.api.encoded(argv)),'launchIntent':True}
        self.state['units'][label]=row;self.mark(label+'_unit_launch_intent')
        common=['Type=exec','Restart=no','UMask=0077','KillMode=control-group','TimeoutStopSec=90',
            'LimitNOFILE=65536','LimitCORE=0','StandardOutput=journal','StandardError=journal',
            'WorkingDirectory='+str(self.work),'Description='+row['description']]
        cmd([tool('systemd-run'),'--quiet','--unit='+name,*['--property='+x for x in common+extra],'--',*argv])
        p=props(name);need(p['ActiveState']=='active' and int(p['MainPID'])>0,'Unit start not confirmed')
        row.update(pid=int(p['MainPID']),ticks=ticks(int(p['MainPID'])));self.mark(label+'_unit_started')
        return row

    def runtime(self):
        self.candidate_live()
        source_base=Path(self.plan['sourceDeployment']);deps=self.active/'deps'
        # Reuse dependency payloads; only small configs are independently copied.
        # No rootfs/memory lower payload is copied or linked here.
        count=total=0
        for p in sorted((source_base/'deps').rglob('*')):
            need(p.resolve(strict=True)==p,'Dependency symlink refused')
            relative=p.relative_to(source_base/'deps');dest=deps/relative
            if p.is_dir():folder(dest,1204,1205,0o700);continue
            s=p.stat();need(stat.S_ISREG(s.st_mode) and s.st_uid==1204,'Unexpected dependency owner/type')
            count+=1;total+=s.st_size;need(count<=2048 and total<=3*1024**3,'Dependency budget exceeded')
            if str(relative)=='overlaybd/etc/overlaybd/overlaybd.json':continue
            need(not dest.exists(),'Dependency export already exists; preserve partial runtime')
            if p.suffix=='.json':put(dest,read(p,2*1024**2),1204,1205,0o600)
            else:os.link(p,dest)
        overlay=deps/'overlaybd/etc/overlaybd'
        for p in (deps/'overlaybd',deps/'overlaybd/etc',overlay):folder(p,1204,1205,0o700)
        clean={'logConfig':{'logLevel':1,'logPath':str(self.active/'logs/overlaybd.log')},
            'cacheConfig':{'cacheType':'file','cacheDir':str(self.active/'state/overlaybd-cache'),
                           'cacheSizeGB':1,'refillSize':262144,'blockSize':65536},
            'credentialFilePath':'','credentialConfig':{},'ioEngine':0,
            'p2pConfig':{'enable':False},'enableAudit':False,'registryFsVersion':'v2'}
        put(overlay/'overlaybd.json',json.dumps(clean).encode(),1204,1205,0o600)
        cfg={'home_path':str(self.active/'state'),'runtime_path':str(self.active/'run'),
            'deps_path':str(deps),'virtualization_mode':'kvm',
            'firecracker':{'binary_path':str(deps/'firecracker/1.15.1-patch-v3/firecracker'),
                'work_dir':str(self.active/'fc'),'serial_dir':str(self.active/'logs'),'log_level':'Info'},
            'kernel':{'image_path':str(deps/'kernel/vmlinux-6.1.175/vmlinux.bin')},
            'tools':{'version':'0.1.1','drive_path':str(deps/'tools/0.1.1/tools.ext4')},
            'snapshot':{'repository_backend':'posix_fs','p2p_enabled':False,
},
            'backend':{'posix_fs':{'snapshot_store':str(self.work/'seed')}},
            'ublk':{'daemon_binary_path':self.plan['binaries']['bin/uvm-ublk-daemon']['path'],
                'daemon_socket_path':str(self.active/'run/ublk.sock'),'daemon_log_path':str(self.active/'logs/ublk.log'),
                'daemon_metrics_listen_addr':''},'image':{'cache':{'gc':{'enabled':False}}},'p2p':{'enabled':False},
            'pool':{'network':{'maintenance_enabled':False},'block':{'enabled':False,'startup_prewarm':False},
                    'firecracker':{'enabled':False,'startup_prewarm':False}},'observability':{'enabled':False}}
        # Check actual Linux sun_path budget, not only the path prefix.
        need(len(os.fsencode(self.active/'fc/agentenv-fc-XXXXXX/firecracker.socket'))<=107,'FC socket budget exceeded')
        put(BASE/'public/runtime.toml',toml(cfg))
        key='e2b_'+secrets.token_hex(24)
        put(self.active/'cli/aenv/credentials',('url = "http://127.0.0.1:18251"\napi_key = '+json.dumps(key)+'\n').encode(),1204,1205,0o600)
        put(BASE/'private/runtime.env',('AENV_API_KEY='+key+'\nAPI_ADDR=127.0.0.1:18251\n'
            'AENV_CONFIG_PATH='+str(BASE/'public/runtime.toml')+'\n'
            'HOME=/home/jwk\nAENV_HOME_PATH='+str(self.active/'state')+'\n'
            'AENV_DEPS_PATH='+str(deps)+'\nAENV_RUNTIME_PATH='+str(self.active/'run')+'\n'
            'PATH='+str(source_base/'native/bin')+':/usr/sbin:/usr/bin:/sbin:/bin\n'
            'LD_LIBRARY_PATH='+str(source_base/'native/lib')+':'+str(source_base/'native/fallback/lib')+'\n'
            'XTABLES_LIBDIR='+str(source_base/'native/xtables')+'\n'
            'TMPDIR='+str(self.active/'tmp')+'\nXDG_CACHE_HOME='+str(self.active/'cache')+'\n').encode(),mode=0o600)
        before=os.stat('/proc/self/ns/net').st_ino
        prestart=('import os\nfrom pathlib import Path\nassert os.geteuid()==0\n'
            'assert os.stat("/proc/self/ns/net").st_ino != '+str(before)+'\n'
            'Path("/proc/sys/net/ipv4/ip_forward").write_text("1\\n")\n').encode()
        put(BASE/'public/runtime-prestart.py',prestart)
        server=self.plan['binaries']['bin/server']['path']
        row=self.launch('runtime',[server],['User=1204','Group=1205','SupplementaryGroups=ubsmd kvm',
            'AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN','CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN',
            'PrivateNetwork=yes','PrivateMounts=yes','EnvironmentFile='+str(BASE/'private/runtime.env'),
            'ExecStartPre=+/usr/bin/python3 -I -B '+str(BASE/'public/runtime-prestart.py'),
            'BindReadOnlyPaths='+self.plan['sourceManagedLayers']+':'+self.plan['privateReadonlyBindTarget']+' '+
                str(self.work/'seed/repository/catalog')+' '+str(self.work/'seed/repository/snapshots')])
        end=time.monotonic()+90
        while time.monotonic()<end:
            self.bound('runtime')
            check=cmd([tool('nsenter'),'-t',str(row['pid']),'-n','--',tool('curl'),'-sS','--max-time','3',
                '-o','/dev/null','-w','%{http_code}','http://127.0.0.1:18251/health'],10,check=False)
            if check.returncode==0 and check.stdout==b'204':break
            time.sleep(1)
        else:raise RuntimeError('Runtime health not confirmed; backing retained')
        return {'unit':row,'health':204,'configSha256':digest(BASE/'public/runtime.toml'),
                'binarySha256':self.plan['binaries']['bin/server']['sha256'],
                'privateNetwork':True,'HostForwardingChanged':False}

    def proxies(self):
        rt=self.bound('runtime')
        config={'port':PORT,'socket':str(self.active/'api.sock')}
        put(BASE/'public/proxy.json',self.api.encoded(config));put(BASE/'public/proxy.py',source('proxy'))
        common=['User=1204','Group=1205','NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=']
        self.launch('inside-proxy',['/usr/bin/python3','-I','-B',str(BASE/'public/proxy.py'),'inside',str(BASE/'public/proxy.json')],
            common+['PrivateNetwork=yes','JoinsNamespaceOf='+rt['name']])
        end=time.monotonic()+15
        while not (self.active/'api.sock').exists() and time.monotonic()<end:
            self.bound('inside-proxy');time.sleep(.2)
        need((self.active/'api.sock').exists(),'Inside API proxy socket not ready')
        self.launch('host-proxy',['/usr/bin/python3','-I','-B',str(BASE/'public/proxy.py'),'host',str(BASE/'public/proxy.json')],common)
        end=time.monotonic()+20
        while time.monotonic()<end:
            self.bound('host-proxy');self.bound('inside-proxy')
            try:
                c=http.client.HTTPConnection('127.0.0.1',PORT,timeout=3);c.request('GET','/health')
                r=c.getresponse();body=r.read(4096);c.close()
                if r.status==204 and body==b'':break
            except OSError:pass
            time.sleep(.5)
        else:raise RuntimeError('Host API proxy health not confirmed')
        need(zero_caps(self.bound('host-proxy')['pid']) and zero_caps(self.bound('inside-proxy')['pid']),
             'API proxy capabilities differ')
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/home/jwk','LANG':'C','LC_ALL':'C',
             'LD_LIBRARY_PATH':str(Path(self.plan['sourceDeployment'])/'native/lib')+':'+
                               str(Path(self.plan['sourceDeployment'])/'native/fallback/lib'),
             'XDG_CONFIG_HOME':str(self.active/'cli')}
        check=cmd([self.plan['binaries']['bin/aenv']['path'],'list','--output','json'],30,owner=True,env=env)
        need(json.loads(check.stdout)==[],'New Runtime is not empty; preserve consumers')
        wrapper=('#!/bin/sh\nexport HOME=/home/jwk\nexport XDG_CONFIG_HOME='+str(self.active/'cli')+'\n'
            'export LD_LIBRARY_PATH='+str(Path(self.plan['sourceDeployment'])/'native/lib')+':'+
            str(Path(self.plan['sourceDeployment'])/'native/fallback/lib')+'\n'
            'exec '+self.plan['binaries']['bin/aenv']['path']+' "$@"\n').encode()
        put(self.active/'aenv-original',wrapper,1204,1205,0o700)
        return {'api':'http://127.0.0.1:18251','health':204,'CLI':str(self.active/'aenv-original'),
                'initialSandboxCount':0,'Guest_created':False,'guestCreationEnabled':False}

    def stop_unit(self,label):
        row=self.state['units'].get(label)
        if not row or row.get('stopped'):return
        self.bound(label);self.mark(label+'_stop_intent');cmd([tool('systemctl'),'stop',row['name']],120)
        p=props(row['name']);need(p['MainPID']=='0' and p['ActiveState']=='inactive','Unit exit not confirmed')
        row['stopped']=True;self.mark(label+'_stopped')

    def launch(self,label,argv,extra):
        if label=='runtime':
            env={}
            for line in read(BASE/'private/runtime.env').decode().splitlines():
                if line:
                    key,value=line.split('=',1);need(re.fullmatch('[A-Z_][A-Z0-9_]*',key) and '\0' not in value,'Invalid private Runtime environment');env[key]=value
            put(self.active/'runtime-env.json',self.api.encoded(env),1204,1205,0o600)
            bootstrap='import json,os,sys;e=json.load(open(sys.argv[1]));x=sys.argv[2];os.execve(x,[x,"--config",sys.argv[3]],e)'
            argv=['/usr/bin/python3','-I','-B','-c',bootstrap,str(self.active/'runtime-env.json'),argv[0],str(BASE/'public/runtime.toml')]
            before=os.stat('/proc/self/ns/net').st_ino
            pre='import os;from pathlib import Path;assert os.geteuid()==0;assert os.stat("/proc/self/ns/net").st_ino!='+str(before)+';Path("/proc/sys/net/ipv4/ip_forward").write_text("1\\n")'
            inline='import base64;exec(base64.b64decode("'+base64.b64encode(pre.encode()).decode()+'"))'
            extra=[x for x in extra if not x.startswith(('EnvironmentFile=','ExecStartPre='))]+['ExecStartPre=+/usr/bin/python3 -I -B -c '+json.dumps(inline)]
        return self._launch(label,argv,extra)

    def __init__(self,node,action):
        need(os.getuid()==os.geteuid()==0 and identity()==NODES[node]['identity'],'Exact A/B root boot identity required')
        self.node=node;self.n=node[-1];self.auth={'runId':'titanic-original-20261103-v1'};self.work=Path('/home/jwk/agent/r')/('hpo-'+self.n+'-v1');self.active=self.work/'active';self.path=BASE/'private/journal.json'
        self.api=types.SimpleNamespace(digest=lambda x:hashlib.sha256(x).hexdigest(),encoded=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode())
        self.plan={'sourceDeployment':str(ORIGINAL),'binaries':NODES[node]['binaries'],'sourceManagedLayers':str(self.work/'seed/repository/managed-layers'),'privateReadonlyBindTarget':str(self.work/'seed/repository/managed-layers')}
        if self.path.exists():
            self.state=json.loads(read(self.path));need(self.state['entrySha256']==digest(__file__) and self.state['identity']==identity() and action=='stop','Previous start exists; inspect rather than retry');return
        need(action=='start' and not BASE.exists() and not self.active.exists(),'Prior original service state preserved')
        with socket.socket() as probe:probe.bind(('127.0.0.1',PORT))
        for row in self.plan['binaries'].values():need(digest(row['path'])==row['sha256'],'Original binary differs')
        for rel in ('deps/kernel/vmlinux-6.1.175/vmlinux.bin','deps/tools/0.1.1/tools.ext4','deps/overlaybd/bin/overlaybd-create','deps/overlaybd/bin/overlaybd-apply','deps/overlaybd/bin/overlaybd-commit'):
            path=ORIGINAL/rel;need(path.resolve()==path and path.is_file() and path.stat().st_size>0,'Retained original offline dependency missing: '+rel)
        repo=self.work/'seed/repository'
        for rel in ('catalog','catalog/aliases','catalog/records','volumes','volumes/aliases','volumes/records','snapshots','managed-layers'):
            path=repo/rel;need(path.resolve()==path and path.is_dir() and path.stat().st_uid==1204,'Complete ordinary original seed layout missing')
        record=json.loads(read(repo/'catalog/records/01a19b76-130a-75c2-bf0a-76b49acc1943.json'))
        for item in record['committed']['rootfs_layers']+record['committed']['memory_layers']:
            layer=item.get('Managed',item);path=repo/'managed-layers'/('sha256_'+layer['digest'][7:]+'.overlaybd.commit');need(path.resolve()==path and path.stat().st_uid==1204 and path.stat().st_size==layer['size'],'Previously verified original lower differs')
        need(int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))*1024>=8*1024**3,'Insufficient available RAM')
        folder(BASE,mode=0o711);folder(BASE/'private',mode=0o700);folder(BASE/'public');folder(self.active,1204,1205,0o700)
        for name in ('state','logs','config','cache','tmp','deps','fc','run','cli','cli/aenv'):folder(self.active/name,1204,1205,0o700)
        self.state={'version':1,'node':node,'identity':identity(),'entrySha256':digest(__file__),'steps':{},'units':{},'phase':'prepared','Guest_created':False,'SDK_called':False,'UBAllocated':False};self.mark('prepared')

    def candidate_live(self):
        need(identity()==self.state['identity'],'Original service node changed')
        for row in self.plan['binaries'].values():need(Path(row['path']).is_file(),'Original executable disappeared')

    def start(self):
        self.once('runtime',self.runtime);self.once('proxies',self.proxies)
        cfg=__import__('tomllib').loads(read(BASE/'public/runtime.toml').decode());need('ub_rootfs_index' not in cfg['snapshot'] and 'ub_rootfs_index_sha256' not in cfg['snapshot'],'Original accidentally configured UB')
        self.state['report']={'status':'TITANIC_GENUINE_ORIGINAL_SERVICES_READY_NOT_GUEST_ACCEPTANCE','identity':identity(),'runtime':self.state['steps']['runtime']['result'],'access':self.state['steps']['proxies']['result'],'binaries':self.plan['binaries'],'config':cfg,'SDKCalled':False,'UBAllocated':False,'GuestCreated':False,'existingServicesChanged':False};self.mark('original_services_ready_held');print(json.dumps(self.state['report'],indent=2))

    def stop(self):
        need(not (self.active/'external-mutation-observed').exists(),'Original Guest mutation needs reconciliation before stop')
        need(self.state['phase']=='original_services_ready_held','Partial original start requires inspection; no automatic cleanup')
        env={'HOME':'/home/jwk','PATH':'/usr/sbin:/usr/bin:/sbin:/bin','XDG_CONFIG_HOME':str(self.active/'cli'),'LD_LIBRARY_PATH':str(ORIGINAL/'native/lib')+':'+str(ORIGINAL/'native/fallback/lib')}
        r=cmd([self.plan['binaries']['bin/aenv']['path'],'list','--output','json'],30,owner=True,env=env);need(json.loads(r.stdout)==[],'Original inventory not empty')
        for name in ('host-proxy','inside-proxy','runtime'):self.stop_unit(name)
        self.mark('original_services_stopped');print(json.dumps({'status':'TITANIC_ORIGINAL_OWN_SERVICES_STOPPED','SDKCalled':False,'candidateServicesChanged':False}))

def source(name):
    need(name=='proxy','Only existing proxy source allowed');return base64.b64decode(PROXY)
def main():
    need(len(sys.argv)==2 and sys.argv[1] in ('start','stop'),'Explicit start/stop required');node={'server1':'node-a','agent1':'node-b'}.get(platform.node());need(node,'Only A/B');app=None
    try:
        app=Start(node,sys.argv[1]);app.start() if sys.argv[1]=='start' else app.stop()
    except Exception as error:
        if app is not None:
            app.state['failure']={'type':type(error).__name__,'reason':str(error)[:400]};app.mark('stopped_preserve_state')
            print(json.dumps({'status':'ORIGINAL_START_STOPPED_PRESERVE_STATE','errorType':type(error).__name__,'reason':str(error)[:400],'units':{k:props(v['name']) for k,v in app.state['units'].items()},'SDKCalled':False}))
        raise
if __name__=='__main__':main()
