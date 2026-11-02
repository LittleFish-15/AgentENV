"""Titanic-specific reuse of verified SDK/DAX service methods; no compile/module change.
Source snapshots are already verified; only a new isolated UB object/view/Runtime
is created after both node prerequisites pass. Explicit B->A retirement only.
"""
import argparse,base64,ctypes,fcntl,grp,hashlib,http.client,json,os,platform,re,secrets,socket,stat,subprocess,sys,time,types,zlib
from pathlib import Path
BASE=Path('/home/jwk/root/hpt-services-v1')
SESSION='relay-20261029-0d032371'
CONTROL='LittleFish-15/AgentENV-relay-control';RESULTS='LittleFish-15/AgentENV-relay-results'
CREDS=Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json')
ADAPTER_SHA='34ed1c5666b5628cc37b4c75f95a44766b0cd119eb02f0df8c9ce15a54bcdfa0'
SDK_SHA='88686bc4e869c6442eb7d88128a2d3efd82468696c489734fc80b4692ac60223'
KERNEL='6.6.0-145.3.34.165.oe2403sp3.aarch64';BYTES=1900019712;PORT=18241
IMAGE_SHA='1885507d61327de6dd1bb9c3ec9e36db9af9d4218a54e14f741973f536fd6cfb'
READERS=['titanic-reader-b-20261102-v1'];RUN='titanic-dax-20261102-v1'
SID='01a19b76-130a-75c2-bf0a-76b49acc1943'
NODES={'node-a': {'identity': {'hostname': 'server1', 'machineId': '5292d505787a4272ac8f4fcafbea5e07', 'bootId': '7bd42416-46a3-49c4-af22-7318836954b2', 'kernel': '6.6.0-145.3.34.165.oe2403sp3.aarch64', 'architecture': 'aarch64', 'uid': 1204, 'gid': 1205}, 'planPath': '/home/jwk/agent/r/hpab-a-v1/service-input-plan.json', 'planSha256': '677bfd7a9324831c5819c6f780be06ae702cd222e60aa1c4e2b00db9d889ab23', 'readerEpoch': 'publisher'}, 'node-b': {'identity': {'hostname': 'agent1', 'machineId': 'ae1ee682fbf544ffb4828c403bf658f5', 'bootId': 'bb7a0176-895d-4262-b1cb-200cef6f13c1', 'kernel': '6.6.0-145.3.34.165.oe2403sp3.aarch64', 'architecture': 'aarch64', 'uid': 1204, 'gid': 1205}, 'planPath': '/home/jwk/agent/r/hpab-b-v1/service-input-plan.json', 'planSha256': 'e3cf3d217f9ce5666ae18d198fd212648632cdc2ea8fed8d111995c64c3d6c16', 'readerEpoch': '8f6aef52fd781abaddda5ff6ef508b7f'}}
IMAGE={'status': 'TITANIC_HOST_IMAGE_PREPARED_NO_UB_ALLOCATION', 'templateId': '01a19b76-130a-75c2-bf0a-76b49acc1943', 'catalogSha256': 'bf645afa402a35cd92eca1310672ce2a2c4dfac79e7ffb234afaf5228457a92e', 'uniqueLowerBytes': 1831881728, 'imageBytes': 1900019712, 'imageSha256': '1885507d61327de6dd1bb9c3ec9e36db9af9d4218a54e14f741973f536fd6cfb', 'path': '/home/jwk/agent/r/hpt-a-v1/rootfs-lowers.ext4', 'files': [{'name': 'd32b65a48bc49a4219e1ed5f0b6ce58d5e44925953b7f7ff23736d2d20e368c1.commit', 'digest': 'sha256:d32b65a48bc49a4219e1ed5f0b6ce58d5e44925953b7f7ff23736d2d20e368c1', 'bytes': 181881856}, {'name': 'b00d5f996bb062f65e74ade8679fe29ba647d4839f24859321265882ba448b11.commit', 'digest': 'sha256:b00d5f996bb062f65e74ade8679fe29ba647d4839f24859321265882ba448b11', 'bytes': 74634240}, {'name': '13c5c59ee93c48b9f207dcaab3c76c04a4dbb602ae00c3038b32ffb0990a2e47.commit', 'digest': 'sha256:13c5c59ee93c48b9f207dcaab3c76c04a4dbb602ae00c3038b32ffb0990a2e47', 'bytes': 119854080}, {'name': '1c671d7f88ffa8f88bb299b896dafadbc45547b297cc3538f32415a5273507c2.commit', 'digest': 'sha256:1c671d7f88ffa8f88bb299b896dafadbc45547b297cc3538f32415a5273507c2', 'bytes': 67687424}, {'name': 'de53270e689dceffa03f7862b27bcc699836610ed1627a1d97915cfdd625b91c.commit', 'digest': 'sha256:de53270e689dceffa03f7862b27bcc699836610ed1627a1d97915cfdd625b91c', 'bytes': 71619584}, {'name': 'd21b0a6fcafeb4318eac115c31b832cae1eb92a951c93ccbe6ebd12e1c0d27c1.commit', 'digest': 'sha256:d21b0a6fcafeb4318eac115c31b832cae1eb92a951c93ccbe6ebd12e1c0d27c1', 'bytes': 1113510912}, {'name': '9e249d26c98eaf37f564f73c1893b65e2d38f3050da0b55a17b0ea77276e0d8a.commit', 'digest': 'sha256:9e249d26c98eaf37f564f73c1893b65e2d38f3050da0b55a17b0ea77276e0d8a', 'bytes': 67556352}, {'name': '9813e159c96968c3fa00b7995c2176603dd4c074064412dde5bbdcf29571d250.commit', 'digest': 'sha256:9813e159c96968c3fa00b7995c2176603dd4c074064412dde5bbdcf29571d250', 'bytes': 67425280}, {'name': 'a228bcf176c8abc5736fffb67b3b7583211b22c08f5e4b4380d03f85cd6d405d.commit', 'digest': 'sha256:a228bcf176c8abc5736fffb67b3b7583211b22c08f5e4b4380d03f85cd6d405d', 'bytes': 67687424}, {'name': '316c899ed59bd1fed1b1c0e9d73c53a140f0f7eb9f65ffcf8fe4bd33753742b6.commit', 'digest': 'sha256:316c899ed59bd1fed1b1c0e9d73c53a140f0f7eb9f65ffcf8fe4bd33753742b6', 'bytes': 24576}], 'UBAllocated': False, 'GuestCreated': False, 'mounted': False, 'fsDaxTested': False, 'sourceCacheEvicted': False}
FILES={'managed-layers/sha256_3b92c077e27c3bdb0361f9629e05827626ee11a884c29dcbbffeb08a0ee49fbb.overlaybd.commit': {'bytes': 444424192, 'sha256': '3b92c077e27c3bdb0361f9629e05827626ee11a884c29dcbbffeb08a0ee49fbb'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/firecracker-manifest.json': {'bytes': 243, 'sha256': 'f41e714129f9351d9987ba0395f6c8d4a52b6805f6c3d341226f6ca74262c411'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/vm_state.bin': {'bytes': 12137, 'sha256': '3363f3f8cb0f8883a180ad359626f3f22e8431d65c6ac7b225c6d0424c45333a'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/commit': {'bytes': 9, 'sha256': 'cc962289af2873dd6dad32931554372a7d2d2de5bd5859c8265eb58b5197a88e'}, 'catalog/records/01a19b76-130a-75c2-bf0a-76b49acc1943.json': {'bytes': 15596, 'sha256': 'bf645afa402a35cd92eca1310672ce2a2c4dfac79e7ffb234afaf5228457a92e'}}
EMBEDDED={'api': {'sha256': 'b958c459c09db2fe72d508762e8bdab06bd642bfc2f33c6723462ac45353fdcd', 'bytes': 31491, 'z64': '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'}, 'proxy': {'sha256': 'b03b60801d310f2a672ac490d5bcad6a1441f61953137bed43ec843b3f808323', 'bytes': 2505, 'z64': 'eNqFVl1v2zYUffevIPwwkoAif6zNBht6CFJ3DZDFQeOh3bJAoCTKZiORGknHCbAfv0tSSmzH9uQHX1LkuV+Hh+r3+39xrc5y1rBMVMK+oErlrEKLy9vBHzdX31GmRbHkUyQVurv7gpgsnJlrXnBpBaxcwVQl5DLu9/s9UTdKW8TMi8yF6oY/jJKdrUyv1KpGDbOrSmSonb6FYbdE884yltlX+8X0ej2PjApeopoJSeikh+BhxnCPHS+5XYuC0CQJA96ORuPhh+2lrKqIkJZUsWkgbULvRw/R6BxWDlGpNKqQkD4oggeNVvnA8KocuHjWBtNYc1aklj/DxgAAFeCGUO9i6xElAg+WaWs2AsAIvmTNlVxNcOSsW1231qwsW+uiziaY0gDVJD4GyD1mevl0P36gU2OTxmHa1l2bUQNBGVU9cZdu4xtlLKxLoQIuq9C5UNP4Lr36ff5pRsKKWhWc/jRUw/HYI+blMnE9iyvFCkOakG72Yl2KdCqkEQVPXoMaPSQJDpN4O6KtBa6apFsT4ZUyFlMfEvi6x67BGFBGv44/jLYhNI/LdVXVzOauEytV88GPzeOALYF9Az1YNfbsnmUPZ0+jAcuteOID1ojYqPwRRx7amRzAu1p19MmVlDy3xKXGdbTRwnLd0slXnnOd3CjJX2esfpn09pobMprA/oRtmHhlfqwaLtPWh1CS4NH4l3gIv1EbV0h5lzC8Mkex1lI8bwMeSG4n9M3O1FvezbpuCIuySGVQ4SeefGbglU72mYtKoYFpC73m715tVqLiyL16v809BbOsy8Fzh5x//PjzOT24GKroaOn2HEZrF2VxzmTq+5RyVcLRz+Kt0TT4y+JCe2E4CpVBQI/HImmL4pnpC3A8pFAfX71TYbu8Wo3JMMLRiN4PH3zG7khk+LfZAkcZ/jK7+OT+57eLq/nNHabHHbunZvoRmuzFYZcJccO0OxsYxIlryaqzeg0nHihz1iZX4JPQ72h+MPnC6asjJgmhRDCcp9++zm+u//zX25dfZxeLYM6+X14H62b+eX59Pf8WDdX5cEj/1w9s8j0mZQHF6VJCF7dXqEur61kxRRnLH+EmAtWwQvMaygDmP2uwDRhweHK44vymvyWmUwDPK2Uc+OlI+HPOG4s+A+tnz8JYM9Na6UkDInVwX0tM4np/mpi7B90NUrh9SDexhP5yTfyZ7YQqCtxxukOj8KZTLxrtFLUNm8zvfLxRh7oQNVdrGyYvXyXFj+luVqWAcld7hAje2trRfUl06oOE8RR3+jlxEzuL33Sz96ZPXu7dnkOc5r7qW758x/WeTvp7NghleE9avYyOiKUjwAouv11329z0inzC2Z6fkyofNNh9BrThTwJiGMT+z3WfO0QK3zpQpzSVrOZpChdsmrovnjTFky4EvXanz3GK9v4D1oTlLw=='}}


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


def source(name):
    item=EMBEDDED[name];d=zlib.decompressobj();raw=d.decompress(base64.b64decode(item['z64'],validate=True),256*1024+1)
    need(d.eof and not d.unused_data and not d.unconsumed_tail and len(raw)==item['bytes'] and hashlib.sha256(raw).hexdigest()==item['sha256'],'Embedded code differs')
    return raw

def module(name):
    m=types.ModuleType(name);m.__file__=str(BASE/(name+'.py'));exec(compile(source(name),m.__file__,'exec'),m.__dict__);return m

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


    def event(self,kind,value):
        payload=wire(value)
        r={'version':1,'node':self.node,'runId':self.auth['runId'],'identity':identity(),
           'entrySha256':self.entrySha,'kind':kind,'dataJson':payload.decode(),'dataSha256':self.api.digest(payload)}
        key='hpab-events/'+SESSION+'/'+self.auth['runId']+'/nobuild-v2/'+self.node+'/'+kind+'.json'
        self.result.immutable_result(RESULTS,1438089386,'main',key,self.api.encoded(r));return r


    def peer_event(self,kind,wait=0):
        key='hpab-events/'+SESSION+'/'+self.auth['runId']+'/nobuild-v2/'+self.peer+'/'+kind+'.json'
        end=time.monotonic()+wait
        while True:
            code,raw,_=self.result.contents(RESULTS,key,'main')
            if code==200:
                r=json.loads(raw)
                need(r['node']==self.peer and r['identity']==self.auth['nodes'][self.peer]['identity'] and
                    r['runId']==self.auth['runId'] and r['entrySha256']==self.entrySha and r['kind']==kind,
                    'Peer receipt binding differs')
                need(isinstance(r['dataJson'],str) and self.api.digest(r['dataJson'].encode())==r['dataSha256'],
                     'Peer payload bytes differ')
                r['data']=json.loads(r['dataJson']);return r
            need(code==404,'Peer result unavailable')
            if time.monotonic()>=end:return None
            print('WAIT_PEER='+self.peer+':'+kind,flush=True);time.sleep(10)


    def python(self,name,*args):
        bootstrap="import sys,runpy;sys.path.insert(0,sys.argv.pop(1));m=sys.argv.pop(1);sys.argv[0]=m;runpy.run_module(m,run_name='__main__')"
        return ['/usr/bin/python3','-I','-B','-c',bootstrap,str(BASE/'code'),name,*map(str,args)]


    def bound(self,label):
        row=self.state['units'][label];p=props(row['name'])
        need(row.get('pid') and p['ActiveState']=='active' and int(p['MainPID'])==row['pid'] and
            p['Description']==row['description'] and ticks(row['pid'])==row['ticks'],'Owned '+label+' process changed')
        return row


    def _launch(self,label,argv,extra):
        name='aenv-hpt-'+self.n+'-'+label+'-'+self.auth['runId'][-8:]+'.service'
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


    def ready(self,label,path,key,value,seconds=1200):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            self.bound(label)
            if path.exists():
                r=json.loads(read(path))
                if r.get(key)==value:return r
                need(r.get(key) not in ('unresolved_preserved','stopped_preserve_resources',
                      'rootfs_stopped_preserve_resources','unresolved_create'),'Helper reported preserved failure')
            time.sleep(1)
        raise RuntimeError('Helper readiness not confirmed; preserve, never relaunch SDK')


    def sdk(self,publication=None):
        self.candidate_live();owner=self.active/'provider'
        need(not owner.exists(),'Prior SDK intent exists; never allocate/import twice')
        cfg={'version':1,'mode':'pmem','role':'publish' if self.node=='node-a' else 'import',
            'workDir':str(owner),'adapter':str(BASE/'public/libaenv-ub.so'),'adapterSha256':'sha256:'+ADAPTER_SHA,
            'region':'default','logicalBudgetBytes':BYTES,'maxCoverageBytes':4294967296,
            'hostPmemReleaseReceipt':str(BASE/'public/local-release.json')}
        if self.node=='node-a':
            image=self.plan['image'];need(image['sha256']==IMAGE_SHA and image['bytes']==BYTES,'Container identity differs')
            source_spec={'objectId':'image-'+IMAGE_SHA,'generation':IMAGE_SHA[:32],
                'sha256':'sha256:'+IMAGE_SHA,'bytes':BYTES,'socket':str(owner/'data.sock')}
            put(BASE/'public/catalog.json',self.api.encoded({'version':1,'objects':[{'path':image['path'],'backing':source_spec}]}))
            cfg.update(readers=READERS,catalog=str(BASE/'public/catalog.json'),
                       hostPmemReaderEpochs={READERS[0]:self.auth['nodes']['node-b']['readerEpoch']})
        else:
            need(publication['mode']=='pmem' and publication['readers']==READERS and len(publication['replicas'])==1,
                 'Peer publication shape differs')
            put(BASE/'public/publisher.json',wire(publication))
            cfg.update(readerId=READERS[0],manifest=str(BASE/'public/publisher.json'))
        put(BASE/'public/sdk-config.json',self.api.encoded(cfg))
        self.state['SDK_called']=None;self.mark('sdk_start_intent')
        self.launch('sdk',self.python('aenv_ub_provider','serve',BASE/'public/sdk-config.json','--run'),
            ['User=1204','Group=1205','SupplementaryGroups=ubsmd','NoNewPrivileges=yes',
             'CapabilityBoundingSet=','AmbientCapabilities=','LimitMEMLOCK=4294967296','MemoryMax=6G'])
        record=self.ready('sdk',owner/'owner.json','state','serving')
        observed=json.loads(read(owner/'replicas.json'))
        need(observed['mode']=='pmem' and observed['readers']==READERS and len(observed['replicas'])==1 and
            observed['replicas'][0]['identity']['sha256']=='sha256:'+IMAGE_SHA and
            observed['replicas'][0]['identity']['bytes']==BYTES,'SDK published identity differs')
        need(publication is None or observed==publication,'Importer publication differs')
        need(zero_caps(self.bound('sdk')['pid']),'SDK owner capabilities differ')
        self.state['SDK_called']=True
        return {'publication':observed,'ownerJournal':record,'process':self.bound('sdk')}


    def view(self):
        from aenv_ub_provider import host_pmem_rootfs,stored,contract
        sdk=self.state['steps']['sdk']['result'];publication=sdk['publication'];owner=self.bound('sdk')
        source_spec={**publication['replicas'][0]['identity'],'socket':str(self.active/'provider/data.sock')}
        files=[]
        for f in self.plan['layers']:
            if f['kind']!='rootfs':continue
            files.append({'name':f['digest'][7:]+'.commit','replica':{
                'brokerSocket':str(self.active/'lower.sock'),'objectName':'aenv_'+secrets.token_hex(16),
                'generation':secrets.token_hex(16),'layerDigest':f['digest'],'fileBytes':f['bytes'],
                'mappingBytes':((f['bytes']+stored.HEADER_BYTES+stored.ALIGN-1)//stored.ALIGN)*stored.ALIGN,
                'allowRepositoryFallback':False}})
        cfg={'version':1,'workDir':str(BASE/'view'),'source':source_spec,'ownerUid':1204,
            'ownerPid':owner['pid'],'ownerStartTicks':owner['ticks'],'publication':publication,
            'releaseReceipt':str(BASE/'public/local-release.json'),'kernelRelease':KERNEL,
            'moduleSrcversion':'C2BBB64D75C618180ABA3A6','files':files,'brokerSocket':str(self.active/'lower.sock'),
            'brokerGid':1205,'runtimeIndex':str(BASE/'public/rootfs-index.json'),'payloadResponses':2}
        plan=host_pmem_rootfs.plan(cfg);put(BASE/'private/rootfs-config.json',contract.canonical(cfg),mode=0o600)
        self.state['viewConfigSha256']=plan['configSha256'];self.mark('rootfs_view_intent')
        self.launch('view',self.python('aenv_ub_provider.host_pmem_rootfs','serve','--config',BASE/'private/rootfs-config.json',
            '--expected-config-sha256',plan['configSha256'],'--approval','CREATE_READONLY_ROOTFS_HOST_PMEM'),
            ['PrivateMounts=yes','CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH','MemoryMax=6G'])
        record=self.ready('view',BASE/'view/host-pmem-session.json','phase','rootfs_broker_ready')
        evidence=record.get('rootfsBroker',{}).get('fileEvidence',[])
        need(len(evidence)==10 and all(x['activeDax'] and x['readonlyMount'] for x in evidence),
             'Actual DAX file binding not confirmed')
        index=json.loads(read(BASE/'public/rootfs-index.json'))
        need(len(index['replicas'])==10 and all(x['allowRepositoryFallback'] is False for x in index['replicas']),
             'Required DAX runtime index differs')
        return {'configSha256':plan['configSha256'],'journal':record,'indexSha256':digest(BASE/'public/rootfs-index.json')}


    def runtime(self):
        self.candidate_live();self.bound('sdk');self.bound('view')
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
                'ub_rootfs_index':str(BASE/'public/rootfs-index.json'),
                'ub_rootfs_index_sha256':self.state['steps']['view']['result']['indexSha256']},
            'backend':{'posix_fs':{'snapshot_store':str(self.work/'seed')}},
            'ublk':{'daemon_binary_path':self.plan['binaries']['bin/uvm-ublk-daemon']['path'],
                'daemon_socket_path':str(self.active/'run/ublk.sock'),'daemon_log_path':str(self.active/'logs/ublk.log'),
                'daemon_metrics_listen_addr':''},'image':{'cache':{'gc':{'enabled':False}}},'p2p':{'enabled':False},
            'pool':{'network':{'maintenance_enabled':False},'block':{'enabled':False,'startup_prewarm':False},
                    'firecracker':{'enabled':False,'startup_prewarm':False}},'observability':{'enabled':False},
            'node_identity':{'node_id':'host-dax-'+self.n,'cluster_id':self.auth['runId'],
                             'service_instance_id':'hpab-'+self.n+'-runtime'}}
        # Check actual Linux sun_path budget, not only the path prefix.
        need(len(os.fsencode(self.active/'fc/agentenv-fc-XXXXXX/firecracker.socket'))<=107,'FC socket budget exceeded')
        put(BASE/'public/runtime.toml',toml(cfg))
        key='e2b_'+secrets.token_hex(24)
        put(self.active/'cli/aenv/credentials',('url = "http://127.0.0.1:18241"\napi_key = '+json.dumps(key)+'\n').encode(),1204,1205,0o600)
        put(BASE/'private/runtime.env',('AENV_API_KEY='+key+'\nAPI_ADDR=127.0.0.1:18241\n'
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
                '-o','/dev/null','-w','%{http_code}','http://127.0.0.1:18241/health'],10,check=False)
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
        put(self.active/'aenv-host-dax',wrapper,1204,1205,0o700)
        return {'api':'http://127.0.0.1:18241','health':204,'CLI':str(self.active/'aenv-host-dax'),
                'initialSandboxCount':0,'Guest_created':False,'guestCreationEnabled':False}


    def stop_unit(self,label):
        row=self.state['units'].get(label)
        if not row or row.get('stopped'):return
        self.bound(label);self.mark(label+'_stop_intent');cmd([tool('systemctl'),'stop',row['name']],120)
        p=props(row['name']);need(p['MainPID']=='0' and p['ActiveState']=='inactive','Unit exit not confirmed')
        row['stopped']=True;self.mark(label+'_stopped')


    def stop(self):
        sys.path.insert(0,str(BASE/'code'))
        # After external API use, a separate consumer reconciliation is required.
        need(not (self.active/'external-mutation-observed').exists(),
             'External sandbox mutation observed; reconcile consumers before retiring backing')
        if 'runtime' in self.state['units'] and not self.state['units']['runtime'].get('stopped'):
            need('proxies' in self.state['steps'] and self.state['steps']['proxies']['state']=='done',
                 'Runtime acceptance incomplete; consumer outcome requires explicit inspection')
            base=Path(self.plan['sourceDeployment'])
            env={'HOME':'/home/jwk','PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C',
                'XDG_CONFIG_HOME':str(self.active/'cli'),
                'LD_LIBRARY_PATH':str(base/'native/lib')+':'+str(base/'native/fallback/lib')}
            r=cmd([self.plan['binaries']['bin/aenv']['path'],'list','--output','json'],30,owner=True,env=env)
            need(json.loads(r.stdout)==[],'Runtime inventory is not confirmed empty')
        self.state['terminal']=True;self.mark('explicit_stop_generation_terminal')
        for label in ('host-proxy','inside-proxy','runtime'):self.stop_unit(label)
        if self.node=='node-a' and 'sdk' not in self.state['steps'] and 'sdk' not in self.state['units']:
            code,_,_=self.result.contents(RESULTS,'hpab-events/'+SESSION+'/'+self.auth['runId']+'/nobuild-v2/'+self.node+'/publication.json','main')
            need(code==404 and not (self.active/'provider').exists(),'Unconfirmed publication prevents cancellation')
            self.state['publicationNotAttempted']=True;self.mark('publisher_cancelled_without_sdk_attempt')
            self.event('publication-cancelled',{'publicationAttempted':False,'terminal':True})
            return
        if self.node=='node-b' and 'sdk' not in self.state['steps'] and 'sdk' not in self.state['units']:
            cancelled=self.peer_event('publication-cancelled')
            if cancelled is not None:
                need(cancelled['data']=={'publicationAttempted':False,'terminal':True},'Publisher cancellation differs')
                self.state['publicationNotAttempted']=True;self.mark('importer_cancelled_no_publication');return
            peer=self.peer_event('publication')
            need(peer is not None and not (self.active/'provider').exists(),'Publisher outcome unknown; preserve reader state')
            from aenv_ub_provider import contract
            manifest=peer['data']
            cancelled={'version':1,'scope':'host-pmem-reader-cancel','state':'not_imported',
                'ownerId':manifest['ownerId'],'manifestSha256':'sha256:'+hashlib.sha256(contract.canonical(manifest)).hexdigest(),
                'readerId':READERS[0],'epoch':self.auth['nodes']['node-b']['readerEpoch'],
                'sdkImportAttempted':False,'terminal':True}
            self.event('reader-released',cancelled);self.mark('reader_terminal_not_imported');return
        if 'view' in self.state['units'] and not self.state.get('viewReleased'):
            from aenv_ub_provider import host_pmem_cli
            cfg=json.loads(read(BASE/'private/rootfs-config.json'))
            need(not self.state.get('viewRetirePending'),'Prior DAX retirement reply unknown; preserve')
            self.state['viewRetirePending']=True;self.mark('view_retire_intent')
            result=host_pmem_cli.request_action(cfg,self.state['viewConfigSha256'],'retire')
            need(result['state']=='local_resources_released','DAX retirement not acknowledged')
            self.state.update(viewReleased=True,viewRetirePending=False);self.mark('view_released')
        elif 'view' not in self.state['steps'] and 'sdk' in self.state['units'] and not self.state.get('viewReleased'):
            from aenv_ub_provider import host_pmem_guard
            sdk=self.state['steps']['sdk']['result'];publication=sdk['publication'];owner=self.bound('sdk')
            source_spec={**publication['replicas'][0]['identity'],'socket':str(self.active/'provider/data.sock')}
            receipt={'version':1,'scope':'local-host-pmem','state':'released',
                'publication':host_pmem_guard.publication_binding(publication,source_spec),'source':source_spec,
                'bootId':identity()['bootId'],'ownerUid':1204,'ownerPid':owner['pid'],'ownerStartTicks':owner['ticks'],
                'volumeCreated':False,'creationOutcome':'not_attempted','volumeUuid':None,'volumeId':None,
                'mountAbsent':True,'localVolumeAbsent':True,'sharedBackingReleaseAuthorized':False}
            put(BASE/'public/local-release.json',wire(receipt)+b'\n')
            self.state['viewReleased']=True;self.mark('view_never_attempted_local_receipt_written')
        # An attempted but unconfirmed view is never replaced by a fabricated release.
        if 'sdk' in self.state['units'] and not self.state.get('sdkReleased'):
            need(self.state.get('viewReleased') is True,'No complete local DAX retirement; preserve SDK')
            argv=self.python('aenv_ub_provider','retire',self.active/'provider')
            if self.node=='node-a':
                peer=self.peer_event('reader-released',wait=0)
                need(peer is not None,'B importer release required before global deletion')
                put(BASE/'public/peer-release.json',wire(peer['data']))
                argv+=['--peer-receipt',str(BASE/'public/peer-release.json')]
            need(not self.state.get('sdkRetirePending'),'Prior SDK retirement reply unknown; preserve')
            self.state['sdkRetirePending']=True;self.mark('sdk_retire_intent')
            result=cmd(argv,600,owner=True,check=False)
            need(result.returncode==0 and json.loads(result.stdout)['state']=='released','SDK release not confirmed')
            journal=json.loads(read(self.active/'provider/owner.json'))
            need(journal['state']=='released' and journal.get('finalize_acknowledged') is True,'SDK journal incomplete')
            self.state.update(sdkReleased=True,sdkRetirePending=False);self.mark('sdk_released')
            for label in ('view','sdk'):
                if label not in self.state['units']:continue
                end=time.monotonic()+30
                while time.monotonic()<end:
                    p=props(self.state['units'][label]['name'])
                    if p['MainPID']=='0' and p['ActiveState']=='inactive':
                        self.state['units'][label]['stopped']=True;self.mark(label+'_exit_confirmed');break
                    time.sleep(.5)
                else:raise RuntimeError('Released helper exit unconfirmed; preserve module')
            if self.node=='node-b':self.event('reader-released',json.loads(read(self.active/'provider/release.json')))
            else:
                need(all(x.get('delete_acknowledged') and x.get('creation_confirmed') for x in journal['objects']) and
                     journal.get('base_post_sha256_verified') is True,'Global deletion/base integrity not confirmed')
                self.event('global-released',{'globalObjectDeleteAcknowledged':True,
                    'ownerId':self.state['steps']['sdk']['result']['publication']['ownerId']})
        self.mark('local_backing_released')


    def __init__(self,node,api,result,action):
        self.node=node;self.n=node[-1];self.peer='node-b' if node=='node-a' else 'node-a'
        need(os.getuid()==os.geteuid()==0 and identity()==NODES[node]['identity'],'Node boot/kernel differs')
        self.api=api;self.result=result;self.auth={'runId':RUN,'nodes':NODES}
        self.entrySha=digest(Path(__file__));self.work=Path('/home/jwk/agent/r')/('hpt-'+self.n+'-v1');self.active=self.work/'active'
        self.path=BASE/'private/journal.json';self.plan=json.loads(read(Path(NODES[node]['planPath'])))
        need(digest(NODES[node]['planPath'])==NODES[node]['planSha256'],'Retained plan differs')
        self.plan=dict(self.plan,workDirectory=str(self.work),image={'path':IMAGE['path'],'sha256':IMAGE_SHA,'bytes':BYTES},
            layers=[dict(f,kind='rootfs') for f in IMAGE['files']],sourceManagedLayers=str(self.work/'seed/repository/managed-layers'),
            privateReadonlyBindTarget=str(self.work/'seed/repository/managed-layers'))
        if self.path.exists():
            self.state=json.loads(read(self.path,2*1024**2));need(self.state['entrySha256']==self.entrySha and self.state['identity']==identity(),'Prior transaction differs')
            need(action in ('release','status'),'Prior start preserved; use inspection, never implicit allocation retry')
            return
        need(action=='start' and not BASE.exists() and not self.active.exists(),'Prior experiment paths preserved')
        need(Path('/sys/module/obmm/srcversion').read_text().strip()=='C2BBB64D75C618180ABA3A6' and Path('/sys/module/obmm/parameters/pmem_ro_enable').read_text().strip()=='Y','Existing candidate unavailable; do not switch modules')
        need(digest('/usr/lib64/libubsm_sdk.so')==SDK_SHA,'Installed SDK differs')
        available=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))*1024
        need(available>=8*1024**3,'Less than 8GiB Host MemAvailable; this is not UB pool capacity evidence')
        for rel,spec in FILES.items():
            original=(Path('/home/jwk/agent/dsbench-20261102/candidate-a/seed/repository') if self.node=='node-a' else self.work/'seed/repository')/rel
            need(original.resolve()==original and original.stat().st_uid==1204 and original.stat().st_size==spec['bytes'],'Snapshot file identity differs')
            if spec['bytes']<1024**2:need(digest(original)==spec['sha256'],'Small snapshot metadata differs')
        with socket.socket() as probe:probe.bind(('127.0.0.1',PORT))
        folder(BASE,mode=0o711);folder(BASE/'private',mode=0o700);folder(BASE/'public')
        ubse=props('ubse.service');need(ubse['ActiveState']=='active' and int(ubse['MainPID'])>0,'UBSE not active')
        self.state={'version':1,'node':node,'runId':RUN,'entrySha256':self.entrySha,'identity':identity(),'steps':{},'units':{},'phase':'prepared','SDK_called':False,'Guest_created':False,
            'logicalUbBytes':BYTES,'maxPostMapCoverageBytes':4294967296,'physicalHardQuota':False,'physicalIncrementBytes':None,'netSavingsBytes':None,
            'ubse':{'pid':int(ubse['MainPID']),'ticks':ticks(int(ubse['MainPID']))}}
        self.mark('prepared')

    def candidate_live(self):
        need(Path('/sys/module/obmm/srcversion').read_text().strip()=='C2BBB64D75C618180ABA3A6' and Path('/sys/module/obmm/parameters/pmem_ro_enable').read_text().strip()=='Y','Existing candidate changed')
        row=self.state['ubse'];need(props('ubse.service')['MainPID']==str(row['pid']) and ticks(row['pid'])==row['ticks'],'UBSE changed')

    def export_code(self):
        old=Path(NODES[self.node]['planPath']).parent;manifest_raw=read(old/'provider-source-manifest.json')
        need(hashlib.sha256(manifest_raw).hexdigest()==self.plan['providerManifestSha256'],'Provider manifest differs')
        manifest=json.loads(manifest_raw);folder(BASE/'code');folder(BASE/'code/aenv_ub_provider')
        for rel,pin in manifest.items():
            need(re.fullmatch(r'(aenv_ub_provider|tests)/[A-Za-z0-9_]+\.py',rel),'Invalid provider source path')
            if not rel.startswith('aenv_ub_provider/'):continue
            raw=read(old/'provider-code'/rel,256*1024);need(hashlib.sha256(raw).hexdigest()==pin,'Existing provider source differs');put(BASE/'code'/rel,raw)
        adapter=Path('/home/jwk/agent/r')/('lazy4-'+self.n+'-v1/libaenv-ub.so');need(digest(adapter)==ADAPTER_SHA,'Adapter differs')
        put(BASE/'public/libaenv-ub.so',read(adapter,1024**2),gid=1205,mode=0o640)
        for row in list(self.plan['binaries'].values())+list(self.plan['dependencies'].values()):need(digest(row['path'])==row['sha256'],'Reused binary differs')
        folder(self.active,1204,1205,0o700)
        for name in ('state','logs','config','cache','tmp','deps','fc','run','cli','cli/aenv'):folder(self.active/name,1204,1205,0o700)
        # A links only the same five snapshot artifacts; rootfs files are absent on both new seeds.
        if self.node=='node-a':
            repo=self.work/'seed/repository'
            for name in ('seed','seed/repository','seed/repository/managed-layers','seed/repository/snapshots','seed/repository/snapshots/'+SID,'seed/repository/catalog','seed/repository/catalog/records'):folder(self.work/name,1204,1205,0o700)
            original=Path('/home/jwk/agent/dsbench-20261102/candidate-a/seed/repository')
            for rel,spec in sorted(FILES.items(),key=lambda x:x[0].startswith('catalog/')):
                dest=repo/rel;need(not dest.exists(),'New seed destination exists');os.link(original/rel,dest)
        return {'providerManifestSha256':self.plan['providerManifestSha256'],'compilerCalled':False,'rootfsCopied':False}

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

    def start(self):
        need(not self.state.get('terminal'),'Terminal generation never restarted')
        self.once('export_code',self.export_code);sys.path.insert(0,str(BASE/'code'));self.candidate_live()
        self.event('prerequisites-ready',{'imageSha256':IMAGE_SHA,'imageBytes':BYTES,'providerManifestSha256':self.plan['providerManifestSha256'],'templateId':SID,'noModuleChange':True})
        peer=self.peer_event('prerequisites-ready',600)
        need(peer and peer['data']['imageSha256']==IMAGE_SHA and peer['data']['imageBytes']==BYTES and peer['data']['templateId']==SID and peer['data']['providerManifestSha256']==self.plan['providerManifestSha256'],'Peer prerequisites differ; no SDK call')
        if self.node=='node-a':
            self.once('sdk',lambda:self.sdk());self.event('publication',self.state['steps']['sdk']['result']['publication'])
        else:
            peer=self.peer_event('publication',1800);need(peer is not None,'Publisher not confirmed; no import retry');self.once('sdk',lambda:self.sdk(peer['data']))
        self.once('view',self.view);self.bound('sdk');self.bound('view')
        self.once('runtime',self.runtime);self.once('proxies',self.proxies)
        report={'status':'TITANIC_DAX_SERVICES_READY_NO_GUEST_ACCEPTANCE','node':self.node,'templateId':SID,'identity':identity(),
            'publication':self.state['steps']['sdk']['result']['publication'],'view':self.state['steps']['view']['result'],'runtime':self.state['steps']['runtime']['result'],'access':self.state['steps']['proxies']['result'],
            'logicalUbBytes':BYTES,'maxPostMapCoverageBytes':4294967296,'physicalHardQuota':False,'physicalIncrementBytes':None,'netSavingsBytes':None,'Guest_created':False,'moduleChanged':False,'oldT1ServicesChanged':False}
        self.state['report']=report;self.mark('services_ready_held');self.event('services-ready',report);print(json.dumps(report,indent=2))

    def release(self):
        # Unknown SDK/view/unit creation must be reconciled; never fabricate absence.
        need(not self.state.get('sdkRetirePending') and not self.state.get('viewRetirePending'),'Unconfirmed prior retirement; inspect before retry')
        for name in ('sdk','view'):
            step=self.state['steps'].get(name)
            if step:need(step['state']=='done','Unconfirmed '+name+' mutation; preserve')
        self.stop()
        print(json.dumps({'status':'TITANIC_LOCAL_RELEASE_RECORDED_NO_MODULE_CHANGE','node':self.node,'sdkReleased':self.state.get('sdkReleased',False),'publicationNotAttempted':self.state.get('publicationNotAttempted',False),'moduleChanged':False}))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['start','release','status']);args=parser.parse_args()
    node={'server1':'node-a','agent1':'node-b'}.get(platform.node());need(node,'Only A/B')
    api=module('api');tokens=json.loads(read(CREDS,8192,owners=(1204,)));result=api.GitHub(tokens['resultToken']);result.private_repo(RESULTS,1438089386)
    app=Start(node,api,result,args.action)
    try:
        if args.action=='start':app.start()
        elif args.action=='release':app.release()
        else:print(json.dumps(app.state,indent=2))
    except Exception as error:
        app.state['failure']={'errorType':type(error).__name__,'reason':str(error)[:500]};app.mark('stopped_preserve_resources')
        print(json.dumps({'status':'TITANIC_DAX_STOPPED_PRESERVE_RESOURCES','phase':app.state.get('phase'),'errorType':type(error).__name__,'reason':str(error)[:500],'automaticRetry':False,'automaticModuleChange':False}))
        raise
if __name__=='__main__':main()
