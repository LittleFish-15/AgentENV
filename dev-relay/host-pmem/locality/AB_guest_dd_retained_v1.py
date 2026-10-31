"""T1 application then fresh microbenchmark Guests, two per node at a time.

Prepared locally while the host read experiment runs. No jobs are queued by
this source. Execution requires verified previous-read closure and fixed spec.
"""
import argparse,base64,concurrent.futures,fcntl,hashlib,http.client,io,json,os,re,shlex,socket,stat,struct,subprocess,sys,tarfile,threading,time,tomllib,traceback,types,zlib
from pathlib import Path
BASE=Path('/home/jwk/root/hpra-v1')
HOME=Path('/home/jwk/root/t1-locality-v1')
SESSION='relay-20261029-0d032371';RUN='guest-dd-20261031-r1'
CONTROL='LittleFish-15/AgentENV-relay-control';RESULTS='LittleFish-15/AgentENV-relay-results'
ROOT_ENTRY_SHA='f41f111a5d92d9ba373f34b65d7686b02a0c63ce6d11e114ab2be0b5ea98357d'
OWNER_SHA='1ca1717821569dfc4e36f12e01e7359da0de76919742e6cf3978ef7ab0df9e7c'
OWNER_SOURCE_SHA='267fb85d059df72c1707e30d3740ae97ef8e62697d93c2b7a36760d1696fb721'
COMMAND_FAILURES=[]


def source(name):
    row=BUNDLED[name];d=zlib.decompressobj();raw=d.decompress(base64.b64decode(row['z64']),row['bytes']+1)
    need(d.eof and not d.unused_data and not d.unconsumed_tail and len(raw)==row['bytes'] and digest(raw)==row['sha256'],'Fixed source payload changed')
    return raw


def current_identity():
    return {'hostname':socket.gethostname(),'machineId':Path('/etc/machine-id').read_text().strip(),
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel':os.uname().release,'architecture':os.uname().machine}


def validate_preflight_resume(prior,proof,reader):
    need(digest(reader(prior/'failure-local.json'))==proof['failureSha256'] and
         digest(reader(prior/'report.tar.gz',24*1024**2))==proof['archiveSha256'],'Previous preflight evidence changed')
    failure=json.loads(reader(prior/'failure-local.json'))
    need(failure['errorType']=='Network' and failure['reason']=='GitHub request unavailable (HTTP 403)'
         and any(f['function']=='ensure_owner_helper' for f in failure['frames']),
         'Different failure; do not restart any Guest work')
    allowed={'experiment.lock','prior-worker-release-verified.json','probe-host-selftest.json',
             'failure-local.json','failed.json','failure-with-cleanup.json','report.tar.gz','final-archive.json'}
    need(all(p.is_file() and not p.is_symlink() and p.name in allowed for p in prior.iterdir()),
         'Previous directory contains additional or attempted Guest work')
    need(digest(reader(prior/'probe-host-selftest.json'))==proof['selftestSha256'],'Previous probe selftest differs')


def need(ok,why):
    if not ok:raise RuntimeError(why)

def digest(raw):return hashlib.sha256(raw).hexdigest()

def wire(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def atomic(path,value):
    path=Path(path);tmp=path.with_name(path.name+'.next')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:out.write(wire(value));out.flush();os.fsync(out.fileno())
    os.replace(tmp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def read(path,limit=8*1024**2):
    path=Path(path);need(path.resolve(strict=True)==path,'Redirected input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as src:
        st=os.fstat(src.fileno());need(stat.S_ISREG(st.st_mode) and st.st_uid in (0,1204) and st.st_size<=limit,'Input type/owner/size differs')
        raw=src.read(limit+1);need(len(raw)<=limit,'Input grew beyond bound');return raw

def load_module(name,raw):
    m=types.ModuleType(name);m.__file__=str(BASE/'entry.py') if name=='services' else '<embedded-'+name+'>'
    sys.modules[name]=m;exec(compile(raw,m.__file__,'exec'),m.__dict__);return m

def run(argv,timeout=15):
    p=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if p.returncode!=0:
        COMMAND_FAILURES.append({'command':Path(str(argv[0])).name,'exitCode':p.returncode,
            'stdout':p.stdout[:8192].decode(errors='replace'),'stderr':p.stderr[:8192].decode(errors='replace')})
    need(p.returncode==0,'Bounded command failed: '+Path(str(argv[0])).name+' exit '+str(p.returncode))
    return p.stdout.decode()

class UnixHTTP(http.client.HTTPConnection):
    def __init__(self,path,timeout):super().__init__('localhost',timeout=timeout);self.path=path
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect(str(self.path))

class Api:
    def __init__(self,ctx):self.ctx=ctx
    def call(self,method,path,body=None,timeout=30):
        need((method=='GET' and (path=='/v2/sandboxes?limit=1' or re.fullmatch('/sandboxes/[A-Za-z0-9_-]+',path))) or
             (method=='POST' and path=='/v2/sandboxes') or
             (method=='DELETE' and re.fullmatch('/sandboxes/[A-Za-z0-9_-]+',path)),'Route outside experiment')
        self.ctx.guard();c=UnixHTTP(self.ctx.active/'api.sock',timeout)
        try:
            c.request(method,path,None if body is None else wire(body),{'X-API-Key':self.ctx.key,'Content-Type':'application/json'})
            r=c.getresponse();raw=r.read(2*1024**2+1);need(len(raw)<=2*1024**2,'API result exceeds bound')
            if method in ('POST','DELETE'):
                # Record the actual HTTP outcome before JSON decoding or engine
                # validation can fail. Never persist returned access tokens.
                preview=None
                if not 200<=r.status<300:
                    preview=self.ctx.transport.redact(raw[:32768],[self.ctx.key]).decode(errors='replace')
                    preview=re.sub(r'(?i)(["\']?[\w-]*(?:token|secret|password)["\']?\s*[:=]\s*)["\'][^"\']*["\']',r'\1"[REDACTED]"',preview)
                evidence={'method':method,'route':path,'httpStatus':r.status,'responseBytes':len(raw),'responseSha256':digest(raw),
                    'errorPreview':preview,'previewTruncated':len(raw)>32768,'receivedUnixNs':time.time_ns()}
                fd=os.open(self.ctx.work/'http-outcomes.jsonl',os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'ab') as out:out.write(wire(evidence)+b'\n');out.flush();os.fsync(out.fileno())
            value=json.loads(raw) if raw else None
            return r.status,value
        finally:c.close()

class Context:
    def guard(self):
            need(self.service.identity()==self.expected['identity'],'Identity changed')
            for label in ('runtime','sdk','view'):self.app.bound(label)
            self.app.candidate_live()
            need(self.app.bound('runtime')==self.runtime and digest(read(BASE/'public/rootfs-index.json'))==self.expected['indexSha256'],'Runtime/index changed')
            if self.permission_error:raise RuntimeError(self.permission_error)

    def owner_permissions(self,*args,**kwargs):
        raise RuntimeError("No lifecycle or ACL mutation allowed in retained Guest dd task")

    def no_foreign_jwk_daemon(self):
            # Do not grant new device access while another jwk daemon can be the
            # creator. Existing nodes are always excluded regardless of ownership.
            cg=Path('/proc',str(self.pid),'cgroup').read_text()
            for p in Path('/proc').iterdir():
                if not p.name.isdigit():continue
                try:
                    if 'uvm-ublk' not in (p/'comm').read_text():continue
                    ident=MEM.identity(int(p.name))
                    if ident['uids']==[1204]*4:need((p/'cgroup').read_text()==cg,'Other jwk ublk daemon active; no device permission changes')
                except (FileNotFoundError,ProcessLookupError):continue

    def process_row(self,pid,role):
            ident=MEM.identity(pid);p=Path('/proc')/str(pid);st=(p/'exe').stat()
            need(len(set(ident['uids']))==1 and ident['uids'][0] in (0,1204),'Unexpected process owner')
            return {'pid':pid,'startTicks':ident['startTicks'],'uid':ident['uids'][0],'role':role,
                    'executable':os.readlink(p/'exe'),'exeDev':st.st_dev,'exeInode':st.st_ino}

    def observe(self):
            self.guard();expected={j['sandboxId']:j for j in self.jobs};found={};runtime_cg=Path('/proc',str(self.pid),'cgroup').read_text()
            fcmeta=Path(self.app.plan['binaries']['deps/firecracker/1.15.1-patch-v3/firecracker']['path']).stat()
            for proc in Path('/proc').iterdir():
                if not proc.name.isdigit():continue
                try:
                    if (proc/'cgroup').read_text()!=runtime_cg:continue
                    st=(proc/'exe').stat()
                    if (st.st_dev,st.st_ino)!=(fcmeta.st_dev,fcmeta.st_ino):continue
                    err=Path(os.readlink(proc/'fd/2'));sid=err.parent.name
                    need(sid in expected and sid not in found and err.name=='firecracker-stderr.log','Unexpected FC in owned Runtime')
                    cwd=(proc/'cwd').resolve();need(cwd.parent==self.active/'fc' and cwd.name.startswith('agentenv-fc-'),'FC directory differs')
                    raw=read(cwd/'overlaybd/image.json');config=json.loads(raw)
                    BIND.check_binding(config,self.template['rootfsLayers'],'full',self.index)
                    row={'sandboxId':sid,'process':self.process_row(int(proc.name),'fc'),'cwd':str(cwd),'configSha256':digest(raw),'upper':[],'devices':[]}
                    for key in ('data','index'):
                        p=Path(config['upper'][key]);p=p if p.is_absolute() else cwd/'overlaybd'/p
                        need(p.resolve()==p and p.is_relative_to(cwd),'Upper escaped Guest directory');m=p.stat()
                        need(m.st_uid==1204 and m.st_nlink==1 and stat.S_ISREG(m.st_mode),'Upper ownership/type differs')
                        row['upper'].append({'path':str(p),'category':'private-upper','identity':MEM.immutable_identity(m),'immutable':False})
                    for fd in (proc/'fd').iterdir():
                        try:
                            m=fd.stat()
                            if not stat.S_ISBLK(m.st_mode):continue
                            target=Path(os.readlink(fd))
                            if not re.fullmatch('/dev/ublkb[0-9]+',str(target)):continue
                            h=os.open(target,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
                            try:size=struct.unpack('=Q',fcntl.ioctl(h,0x80081272,b'\0'*8))[0]
                            finally:os.close(h)
                            row['devices'].append({'path':str(target),'inode':m.st_ino,'major':os.major(m.st_rdev),'minor':os.minor(m.st_rdev),'bytes':size,
                                'maxSectorsKiB':int(Path('/sys/class/block',target.name,'queue/max_sectors_kb').read_text())})
                        except FileNotFoundError:continue
                    rootdev=(cwd/'user-rootfs').resolve()
                    need(any(d['path']==str(rootdev) for d in row['devices']),'FC lacks declared rootfs device')
                    need(all(d['maxSectorsKiB']==256 for d in row['devices']),'Actual rootfs/memory I/O limits differ from 256KiB')
                    row['rootfsDevice']=str(rootdev);found[sid]=row
                except (FileNotFoundError,ProcessLookupError):continue
            need(set(found)==set(expected),'Not every confirmed Guest has an actual FC/DAX binding')
            upper=[(x['identity']['dev'],x['identity']['inode']) for r in found.values() for x in r['upper']]
            need(len(set(upper))==4,'Private upper aliases across Guests')
            return found

    def file_sample(self,row):
            try:
                fd=os.open(row['path'],os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
                try:FSDAX.validate_fd(fd,os.fstat(fd).st_size,fs_dax=False)
                finally:os.close(fd)
                return MEM.file_sample(row,Path('/home/jwk/agent'),os.sysconf('SC_PAGESIZE'))
            except (OSError,ValueError,TimeoutError) as error:return {'path':row['path'],'category':row['category'],'residentBytes':None,'errorType':type(error).__name__}

    def dax_evidence(self):
            view=self.app.state['steps']['view']['result']['journal'];broker=view['rootfsBroker'];pid=broker['pid']
            # The root view process remains bound; also freeze its broker child identity.
            need(MEM.identity(pid)==self.broker_identity,'DAX broker changed')
            values=[]
            for item in broker['inheritedFiles']:
                fd=os.open(f'/proc/{pid}/fd/{item["fd"]}',os.O_RDONLY|os.O_CLOEXEC)
                try:values.append({'layerDigest':item['replica']['layerDigest'],**FSDAX.validate_fd(fd,item['replica']['fileBytes'])})
                finally:os.close(fd)
            return {'files':values,'ordinaryFileDataPageCacheApplicable':False,'mincoreUsed':False,'publication':view['publication']}

    def collect(self,include_files=False):
            self.guard();begin=time.monotonic_ns()
            values={'node':self.node,'unixNs':time.time_ns(),'beginNs':begin,'hostMemoryBytes':MEM.kib_fields(Path('/proc/meminfo').read_text()),
                    'processes':[MEM.process_sample(p) for p in self.processes],'ordinaryFiles':None,'blockDevices':None,
                    'uniqueLogicalUbBytes':1811939328,'incrementalPhysicalUbBytes':None,'netSavingsBytes':None,
                    'GuestRamOnlyBytes':None,'samplingAtomicAcrossNodes':False,'cacheDropPerformed':False}
            if include_files:
                values['ordinaryFiles']=[self.file_sample(row) for row in self.files]
                values['blockDevices']=[]
                for row in self.devices:
                    try:values['blockDevices'].append(MEM.device_sample(row,os.sysconf('SC_PAGESIZE')))
                    except (OSError,ValueError,TimeoutError) as e:values['blockDevices'].append({'path':row['path'],'residentBytes':None,'errorType':type(e).__name__})
                values['dax']=self.dax_evidence()
            values['endNs']=time.monotonic_ns();return values

    def launcher(self,argv,**kwargs):
            self.guard();return subprocess.Popen(['nsenter','-t',str(self.pid),'-n','--',*argv],**kwargs)

    def setup_inputs(self):
            self.no_foreign_jwk_daemon()
            source=Path('/home/jwk/agent/deployments/agentenv-lazy-four-32ce41c')
            templates,steps=INPUT.load_inputs(source,self.n,1,read,REPLAY.steps_from);self.template=templates[0];self.steps=steps[0]
            INPUT.check_catalogs(source,templates,read)
            need(self.template['templateId']=='01a15c9e-54d0-7b92-a50b-0b6ec2e9136b' and len(self.steps)==32,'Fixed T1/32-step scope differs')
            self.files=[]
            for layer in self.app.plan['layers']:
                path=Path(layer['source']);self.files.append({'path':str(path),'category':layer['kind']+'-lower-source',
                    'identity':MEM.immutable_identity(path.stat()),'immutable':True})
            if self.n=='a':
                p=Path(self.app.plan['image']['path']);self.files.append({'path':str(p),'category':'full-source-image','identity':MEM.immutable_identity(p.stat()),'immutable':True})
            self.broker_identity=MEM.identity(self.app.state['steps']['view']['result']['journal']['rootfsBroker']['pid'])
            self.processes=[self.process_row(self.pid,'runtime'),self.process_row(os.getpid(),'collector'),self.process_row(self.broker_identity['pid'],'dax-broker')]
            for label in ('sdk','view'):
                row=self.app.bound(label);self.processes.append(self.process_row(row['pid'],label))
            self.dax_evidence()
            # Binary hashing only, no payload reads or rebuilding.
            for entry in self.app.plan['binaries'].values():need(digest(read(Path(entry['path']),128*1024**2))==entry['sha256'],'Reused binary digest differs')
            self.env={'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','PATH':'/usr/sbin:/usr/bin:/sbin:/bin',
                'XDG_CONFIG_HOME':str(self.active/'cli'),'LD_LIBRARY_PATH':str(Path(self.app.plan['sourceDeployment'])/'native/lib')+':'+str(Path(self.app.plan['sourceDeployment'])/'native/fallback/lib')}

    def release(self,*args,**kwargs):
        raise RuntimeError("No lifecycle or ACL mutation allowed in retained Guest dd task")

    def upload(self):
            # Only experiment-owned files, bounded archive, no tokens/environment.
            import io,tarfile
            frozen=self.work/'report.tar.gz'
            if frozen.exists():raw=read(frozen,24*1024**2)
            else:
                out=io.BytesIO()
                with tarfile.open(fileobj=out,mode='w:gz') as tar:
                    for path in sorted(self.work.rglob('*')):
                        if not path.is_file() or path.is_symlink() or path.name in ('experiment.lock','archive.json','report.tar.gz'):continue
                        need(path.stat().st_size<=256*1024**2,'Report file too large');tar.add(path,arcname=str(path.relative_to(self.work)),recursive=False)
                raw=out.getvalue();need(len(raw)<=24*1024**2,'Report exceeds private transport bound')
                with frozen.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
            chunks=[]
            for n,start in enumerate(range(0,len(raw),16*1024)):
                piece=raw[start:start+16*1024];key=f'guest-locality/{SESSION}/{RUN}/{self.node}/artifacts/{digest(raw)}/{n}.json'
                self.result_put(RESULTS,1438089386,'main',key,wire({'sha256':digest(piece),'dataBase64':base64.b64encode(piece).decode()}));chunks.append({'path':key,'sha256':digest(piece),'bytes':len(piece)})
                time.sleep(2)
            self.event('archive',{'sha256':digest(raw),'bytes':len(raw),'chunks':chunks})

def file_digest(path,expected_bytes):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size!=expected_bytes:
            raise ValueError('Dedicated experiment file length/type differs')
        sha=hashlib.sha256()
        for data in iter(lambda:stream.read(MIB),b''):sha.update(data)
        after=os.fstat(stream.fileno())
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(
                after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
            raise RuntimeError('Experiment file changed while reading')
        return sha.hexdigest()

def process_identity(pid):
    return (Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19]

def decode_reference_metadata(data):
    """Decode only the fixed prefix from public ubs-engine 1.0.1 source.

    Caller must report runtime-package/source matching separately. No raw
    physical addresses, credentials or username are emitted by this decoder.
    """
    if len(data)<2+META_PREFIX.size:raise ValueError('OBMM private metadata prefix is unavailable')
    value=META_PREFIX.unpack_from(data,2)
    version,kind=value[:2]
    if version!=1 or kind!=2:raise ValueError('Not the reference version1 shared-memory metadata')
    def text(raw):
        prefix=raw.split(b'\0',1)[0]
        if not prefix:raise ValueError('Empty shared-object provenance field')
        return prefix.decode('ascii')
    return {'schema':'ubs-engine-1.0.1-custom-v1-prefix','schemaRuntimeAttested':False,
            'version':version,'kind':kind,'exportNodeId':text(value[10]),
            'exportMemId':value[12],'globalName':text(value[14]),
            'rawMetadataSha256':hashlib.sha256(data).hexdigest()}

def region_evidence(pid,ticks,ranges,runtime_attested=False,evidence_dir=None):
    if process_identity(pid)!=ticks:raise ValueError('Root helper identity differs')
    found={}
    for fd in (Path('/proc')/str(pid)/'fd').iterdir():
        try:
            target=os.readlink(fd)
            match=re.fullmatch('/dev/obmm_shmdev([0-9]+)',target)
            if not match:continue
            info=fd.stat();number=int(match[1]);root=Path('/sys/devices/obmm')/('obmm_shmdev'+str(number))
            if not stat.S_ISCHR(info.st_mode):raise ValueError('Region is not a character device')
            kind=(root/'type').read_text().strip();size=int((root/'size').read_text().strip(),0)
            row={'localRegionId':number,'kind':kind,'bytes':size,
                 'device':[os.major(info.st_rdev),os.minor(info.st_rdev)],
                 'ranges':[value for value in ranges if value['rdev']==info.st_rdev]}
            if not row['ranges']:continue
            count=int((root/'priv_len').read_text().strip())
            if not 0<count<=512:raise ValueError('Unexpected private metadata length')
            with (root/'priv').open('rb') as stream:data=stream.read(count)
            if evidence_dir is not None:
                directory=Path(evidence_dir)
                directory.mkdir(mode=0o700,exist_ok=True)
                directory_info=directory.lstat()
                if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid!=0
                        or directory_info.st_mode&0o077 or directory.resolve(strict=True)!=directory):
                    raise ValueError('Private evidence directory differs')
                saved=directory/('region-'+str(number)+'-priv.bin')
                if saved.exists() or saved.is_symlink():
                    info_saved=saved.lstat()
                    if (not stat.S_ISREG(info_saved.st_mode) or info_saved.st_uid!=0 or info_saved.st_mode&0o077
                            or info_saved.st_size!=len(data) or saved.read_bytes()!=data):
                        raise ValueError('Private provenance artifact changed')
                else:
                    out=os.open(saved,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(out,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
                row['privateMetadataFile']=str(saved)
            try:
                row['provenance']=decode_reference_metadata(data)
                row['provenance']['schemaRuntimeAttested']=runtime_attested is True
            except (ValueError,UnicodeError) as error:row['provenance']=None;row['reason']=str(error)
            found[number]=row
        except (OSError,ValueError) as error:
            # Missing evidence is explicit, never a positive mapping claim.
            found['fd-'+fd.name]={'provenance':None,'reason':str(error)}
    if process_identity(pid)!=ticks:raise ValueError('Root helper changed during evidence capture')
    return list(found.values())

def engine_schema(rpm,pid,ticks):
    observed={}
    try:
        if process_identity(pid)!=ticks:raise ValueError('UBSE process changed')
        exe=Path(os.readlink(Path('/proc')/str(pid)/'exe')).resolve(strict=True)
        info=exe.stat()
        if info.st_uid!=0 or info.st_mode&0o022 or not 0<info.st_size<=128*MIB:
            raise ValueError('UBSE executable ownership/size differs')
        query='%{NAME}\n%{VERSION}\n%{RELEASE}\n%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{FILEDIGESTS}\n]'
        result=subprocess.run([rpm,'-qf','--qf',query,str(exe)],capture_output=True,text=True,
                              timeout=30,env={'PATH':'/usr/sbin:/sbin:/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
        lines=result.stdout.splitlines()
        observed['observedPackage']=lines[:4]
        observed['executable']=str(exe)
        if result.returncode or lines[:4]!=['ubs-engine','1.0.1','1.oe2403sp3','8']:
            raise ValueError('Installed engine package does not match reviewed schema source')
        rows=dict(line.split('\t',1) for line in lines[4:] if '\t' in line)
        expected=rows.get(str(exe))
        if expected is None or not re.fullmatch('[0-9a-f]{64}',expected):raise ValueError('RPM executable digest missing')
        actual=file_digest(exe,info.st_size)
        observed['executableSha256']=actual
        if (actual!=expected or actual!='22ce7d2f4309765d18e4df41a8a2941aacd023cac46d8f135aee0cd4a2e19d45'
                or info.st_size!=9704056 or process_identity(pid)!=ticks):
            raise ValueError('Runtime executable differs from the pinned official RPM binary')
        return {'attested':True,'package':'ubs-engine-1.0.1-1.oe2403sp3','executableSha256':actual,
                'executable':str(exe),'fileIdentity':[info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns],
                'binaryRpmSha256':'e777429d01d7f99aedceafb0cf723bb39fa626c49a8d0078ea657f718b1a0e84',
                'sourceRpmSha256':'8cd3800d1056c0fa76bc36a7ebf13f513c9d094eb754cd9ce2dd459efa6efc8b'}
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        return {'attested':False,'reason':str(error),**observed}

def shared_graph(first,second,image_bytes):
    """Match logical ranges to the same export node/region under pinned schema."""
    def ranges(sample):
        if not sample.get('engineSchema',{}).get('attested'):
            raise ValueError('Runtime engine schema not attested')
        result=[];capacity={}
        for row in sample.get('mappingEvidence',[]):
            meta=row.get('provenance')
            if (not meta or meta.get('schemaRuntimeAttested') is not True
                    or meta.get('version')!=1 or meta.get('kind')!=2 or row.get('kind') not in ('export','import')):
                raise ValueError('Incomplete region provenance')
            origin=(meta['exportNodeId'],row['localRegionId'] if row['kind']=='export' else meta['exportMemId'])
            if not origin[0] or origin[1]<=0:raise ValueError('Unknown export origin')
            previous=capacity.setdefault(origin,row['bytes'])
            if previous!=row['bytes']:raise ValueError('Conflicting origin region sizes')
            for region in row.get('ranges',[]):
                offset,count,logical=region['offset'],region['bytes'],region['logicalOffset']
                if min(offset,logical)<0 or count<=0 or offset+count>row['bytes']:
                    raise ValueError('Region range exceeds backing')
                result.append((logical,count,origin,offset))
        result.sort();cursor=0
        for logical,count,_,_ in result:
            if logical!=cursor:raise ValueError('Logical source ranges have holes or duplicates')
            cursor+=count
        if cursor!=image_bytes:raise ValueError('Mapping evidence does not cover the complete image')
        return result,capacity
    try:
        a,ac=ranges(first);b,bc=ranges(second)
        if a!=b:return {'matched':False,'reason':'Logical ranges refer to different export origins'}
        if ac!=bc:return {'matched':False,'reason':'Export origin capacities differ'}
        return {'matched':True,'originCount':len(ac),'referencedRegionCapacityBytes':sum(ac.values()),
                'physicalIncrementBytes':None,
                'meaning':'same exported region identities/ranges; capacity is not new physical allocation'}
    except (KeyError,TypeError,ValueError) as error:
        return {'matched':None,'reason':str(error),'physicalIncrementBytes':None}


MIB=1048576
META_PREFIX=struct.Struct("<BBIII52s16sQQQ16s16sQI52s")
import ctypes
def validate_fd(fd, length, fs_dax=True):
    import fcntl
    info = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    if (not stat.S_ISREG(info.st_mode) or info.st_size != length
            or flags & os.O_ACCMODE != os.O_RDONLY or flags & os.O_SYNC):
        raise ValueError('FS-DAX requires an exact-length readonly regular FD')
    libc = ctypes.CDLL(None, use_errno=True)
    statx = libc.statx
    statx.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                     ctypes.c_uint, ctypes.c_void_p]
    statx.restype = ctypes.c_int
    data = ctypes.create_string_buffer(256)
    if statx(fd, b'', 0x1000, 0x7ff, data) != 0:  # AT_EMPTY_PATH, BASIC_STATS
        raise OSError(ctypes.get_errno(), 'statx on FS-DAX FD failed')
    attributes = struct.unpack_from('=Q', data.raw, 8)[0]
    size = struct.unpack_from('=Q', data.raw, 40)[0]
    supported = struct.unpack_from('=Q', data.raw, 56)[0]
    if not supported & 0x200000 or bool(attributes & 0x200000) != fs_dax or size != length:
        raise ValueError('File does not have the required S_DAX state')
    readonly_mount = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
    if fs_dax and not readonly_mount:
        raise ValueError('FS-DAX publication must be on a readonly mount')
    return {'device': info.st_dev, 'inode': info.st_ino, 'bytes': size,
            'activeDax': fs_dax, 'readonlyMount': readonly_mount,
            'crossNodePhysicalIdentityAccepted': False}
FSDAX=types.SimpleNamespace(validate_fd=validate_fd)

BUNDLED={'REPLAY': {'sha256': '2e0f31142d8fca47724f319c96aae8758f4b0a07d051614a1d92537a9f23a259', 'bytes': 1839, 'z64': 'eNp1VduO2zYQfd+vmAoJJMGS17tB8iBFCPLgBgs0QbEJigK2YdDSeM21RKokfUvTf++QlGwh6/hBpuZy5nJmKN60Uhl41lIkChO9qfF4U+EaBGIVyW0CDWrNnjDOboB+nDTSgNxmoBjXCI87YXiDU6WkinrbGw8hVcNq/h2XrDRcisj/dUhBEDyIClukhzDAm7bGhk7M2oBcg9kgKNxzPGBFBzJTWKVYcSMVlFLsyZhMxwTkAI06ZQepKl24Ksa6rbnpYzoLPJbYGviL1TufcKbQ7JQAb9QX6EBm2f3it2IWaqOWCtualbj0scNkKAwXV0BsKq3U3Ap0MXOAY04VHKN1zZ7i0R2sqQh7Bi4gCtNU1tWSYAk8TQUe3Dle5Hubaw8x4wvnx63TGX8xrC26FJfY9h7dMb6So2XIKN5ELkRHStcBJxprw5TRB242UThXcxHGmVMU7jm7zxZnH6yve/3sczfwOXsQtb+OkqX3V8MMnF663F1cusKdxgm7jtZcm6hhbWR7kHhhHA9n3Mtmk2sEOxaSveXhO2+jMxc9UNbzVexvBln4wXyWXETOoFsUbbDVy7WSTaTYoaOiYoYVdi/HtWSVdppcyQMNwyI3qBouWF18kQIvGRlsbErWdRYaxZ6xpIE90YwOu26L45oLYkqUGFmvpOKliYEwrijHT2ii0FcfxglN5sWS1LNetSDuFXUjzmg7DRddw+3PWxTXzYe5eR2VfEAVxX459G7VcEObseaC6w0dKqqaSD93wXvlK4Vse0arsGan4lKAe1/ayypMJpeg7qIzpxYjZ+BjcmGSNfWdesJEBZP3hVO+f/NuMknCB0E08wouHfbBwguqJWrMWnu7Rf/2FWe/uhETn1yYuZhdIv95NJefhUvCadOaE206ljvDVjUOEghpNvyMOdO+M918bbCul6VsGiqmi5k0TG1R9de6EKiKQKOBkYSWt7hmvM4plvs8/Pnx0/SxKJk5Sz5//PJS+Onh2/Kl9I/p169F+vvj3zmUFaQp3MKPH6TkBu7u3+YQjAaL1RURukwwh1v6nAiDYn+74uJ2tdOnlTyCJVHuDKQavk0fP0O6hbfwZjIBb8X0BtIa0hLCkV+5f3bS0DDbKuNRQInICotXH3JoFVG9hnA+F8HIt2QUwGtN7yHMg1fWcB7kPt1J8D+2JGG+'}, 'GROUP': {'bytes': 14022, 'sha256': 'bfdf9854ca4d30e0d68e044eff5be17cea969755b6793dcfc634eb6f2c72e106', 'z64': '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'}, 'ENGINE': {'sha256': '5d0cd8d4cf45b8301532517af832710c3928458f20c1cc64b0991500ddb1b89d', 'bytes': 19924, 'z64': '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'}, 'MEM': {'sha256': '8efd02869237d0d9e960706912b2f994f58d3012414b2478c8ef187421781ce2', 'bytes': 12512, 'z64': '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'}, 'INPUT': {'sha256': '4def90ce7b150ef2d9fc71beb6c3e99b9d416be7130ad2ce37dc0509df066260', 'bytes': 5905, 'z64': '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'}, 'BIND': {'sha256': '8e19fa3e9e95963152fb689ee526b5d4a564eeb1d2c2233f792f1609ac7d6c4f', 'bytes': 1155, 'z64': 'eNplU0uP2yAQvu+vmBu2hLJtpfYQiUpd9aFeWinSnqJoRcw4oSHgAt7d7Gr/eweM7aTBFzMM8z1m0MfO+Qh7GfZGb/mf4OzNjcIWLKKq3IE/7U/18gZoaQq6CO6w9FIHhFVvoz7iN++dr1LacLFxNqKND0HvrIy9x8rIE/pQqnikmB0BF2EvP3z8VCXcheqPXajWlV8zpXcYIttw+g/6BdmmhtZ58KAtDPU2PGAnvYzOB1ExTt+S1fUCbeMUVvS3x+ehTjVS22NzeNhqq7TdVUS01TuOzx02ERV/lF5LGzkd43Nhm10oBwm6Ys7rnbbSEFzbG8NqkFaBQVvqrZlxT0SPGAuRwmP9+vM7zlbOxTZAaFyHoHTbpsy6GNMG8fqWbC6AQsxogIYsfyU7svqvxZ+ln23JvNfMY2d0I4nA29i2uV6mvMyqSvojMdDOso0Q77OUEg9RRkxRKijViU0yE88i7Qqx5sB+2kdptLpVfY5GhAQ6lC1SE2XZxF4a/kS8MIHCi+6uLJyaU9oxtWS4Pc+JEEOhOZL5jmnDCM1Jw56zL/kcMtw4uLfOK9pdNufKyKkxyzM+ix3GivVbGgod4JezyNnvkgg/euIFvR0lmRP0AQPc351hpC7PUstYoKeZRpGMzwj/S60vLmQ+061EJL3aRCZbMp2smTQkfIWdC5oe0ek77beyOZB3dIl2Ac9MnLUJMdXgF8h5sRX+7bWnnt7fQXlqo5lAfe/QH3UM0I5o9T8oToGe'}, 'CONTRACT': {'sha256': '04683a6197e42fdb998088a30ba87b93444cffe95e1b7361d436c0e91f14a02e', 'bytes': 5135, 'z64': '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'}, 'TRANSFER': {'sha256': '3c6988b27cbba61e74eb7f6c0be34ce72c5572f443bed740d8adefec820884f7', 'bytes': 5367, 'z64': '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'}}
PROBE=zlib.decompress(base64.b64decode('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'))

need(digest(PROBE)=='18855dff8f72ad945d4f9e6225344adeae24b111e0028194e323f0539bdb026f',"Fixed native Guest probe differs")

for name in BUNDLED:
    globals()[name]=load_module(name,source(name))


def validate_prior_guests(prior,proof):
    for relative,expected in proof.items():
        need(relative in ('app-r0/cohort.json','app-r0/release.json','micro-r0/cohort.json','micro-r0/release.json'),
             'Prior proof path outside fixed groups')
        raw=read(prior/relative);need(digest(raw)==expected,'Prior release evidence changed')
        row=json.loads(raw)
        if relative.endswith('cohort.json'):
            need(row['sandboxIds']==[] and row['openRequests']==[] and row['outcomeUncertain'] is False,
                 'Prior Guest operation unresolved')
            ops=row['operations']
            need(len(ops)==4 and [x['kind'] for x in ops]==['create','create','delete','delete']
                 and [x['httpStatus'] for x in ops]==[201,201,204,204],'Prior lifecycle ACK incomplete')
        else:
            need(row['ownedGuestsReleased'] is True and row['deviceGrantsGone'] is True and row['backingHeld'] is True,
                 'Prior Guests/devices not released')
    need(len(proof)==4,'Both prior groups must have release and operation proofs')

def validate_ram_record(row,mode):
    need(row['mode']==mode and row['workingSetBytes']==256*1024**2 and row['state']=='completed','RAM result shape differs')
    need(row['scope']=='prefaulted private anonymous Guest RAM, not UB','RAM scope differs')
    elapsed=row['endNs']-row['startNs']
    need(30*10**9<=elapsed<300*10**9 and row['operations']>0 and row['mmapAndPrefaultNs']>=0,'RAM timing/count invalid')
    need(row['actualBytes']==row['operations']*8,'RAM byte/operation count differs')
    need(row['recordLimitReached'] is False and len(row['records'])>0,'Incomplete RAM records')
    records=row['records']
    need(all(isinstance(x,list) and len(x)==5 for x in records),'RAM raw record schema differs')
    need(sum(x[1] for x in records)==row['actualBytes'] and sum(x[0] for x in records)==row['operations'],
         'RAM raw record totals differ')
    previous=row['startNs']
    for x in records:
        need(x[4]==0 and previous<=x[2]<x[3]<=row['endNs'],'RAM raw timing/error differs')
        previous=x[3]


DD_RAW=zlib.decompress(base64.b64decode('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'))
need(digest(DD_RAW)=='c68e3b234b15d73ddb6f116df0393cff94ed68fbded2850b9c4945b53b172a0a',"dd contract differs")
DD=load_module("dd_contract",DD_RAW)

class HeldApp:
    def __init__(self,spec,journal,plan):
        self.spec=spec;self.active=Path(spec['active']);self.plan=plan
        self.state={'steps':{'view':{'result':{'journal':journal}}}}
    def candidate_live(self):
        need(Path('/sys/module/obmm/srcversion').read_text().strip()=='C2BBB64D75C618180ABA3A6'
             and Path('/sys/module/obmm/parameters/pmem_ro_enable').read_text().strip()=='Y','Candidate module changed')
    def bound(self,label):
        row=self.spec['processes'][label];need(MEM.identity(row['pid'])['startTicks']==row['startTicks'],'Retained '+label+' changed')
        need(MEM.identity(row['pid'])['uids']==[row['uid']]*4,'Retained '+label+' UID changed')
        return {'pid':row['pid'],'ticks':row['startTicks']}


class GuestExperiment(Context):
    def __init__(self,spec):
        global BASE
        self.spec=spec;self.node=spec['node'];self.n=self.node[-1];self.peer='node-b' if self.node=='node-a' else 'node-a'
        self.pin=digest(read(Path(__file__),512*1024));self.expected={'identity':spec['identity'],'indexSha256':spec['indexSha256']}
        need(os.getuid()==os.geteuid()==0 and current_identity()==spec['identity'],'Root/node/boot differs')
        self.group='admission';self.root=HOME/self.node/'dd-only-r1';self.work=self.root
        self.case=None;self.jobs=[];self.bindings={};self.processes=[];self.devices=[];self.permissions=[]
        self.permission_error=None;self.stop=threading.Event();self.lock=threading.RLock()
        self.createdWork=False
        # No overlap with the current Host/SDK experiment, even if someone
        # accidentally invokes this prepared entry before controller approval.
        old=Path('/home/jwk/root/ub-read-perf-v1')/self.node
        complete=read(old/'completed.json');need(digest(complete)==spec['previousReadCompletedEnvelopeSha256'],'Previous completed event changed')
        worker=TRANSFER.closed_worker_identity(old,read)
        try:still=MEM.identity(worker['pid'])['startTicks']==worker['startTicks']
        except (FileNotFoundError,ProcessLookupError):still=False
        need(not still,'Host/SDK measurement worker still running')
        self.previous_archive_sha=digest(read(old/'report.tar.gz',24*1024**2))
        if spec.get('previousReadArchiveSha256') is not None:
            need(self.previous_archive_sha==spec['previousReadArchiveSha256'],'Previous frozen read archive changed')
        prior=HOME/self.node/'resume-r1'
        validate_prior_guests(prior,spec['priorGuestReleaseProof'])
        self.previous_preflight=HOME/self.node
        ram=HOME/self.node/'ram-only-r1'
        self.priorRamLock=os.open(ram/'experiment.lock',os.O_RDWR|os.O_NOFOLLOW)
        info=os.fstat(self.priorRamLock)
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077,'RAM lock ownership differs')
        fcntl.flock(self.priorRamLock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        expected=spec['completedRamProof']
        allowed={'final-completed.json','ram/cohort.json','ram/retained-guests.json','ram/bindings.json'}
        need(set(expected)==allowed,'RAM proof manifest incomplete')
        values={}
        for relative,pin in expected.items():
            data=read(ram/relative);need(digest(data)==pin,'Frozen RAM completion evidence changed')
            values[relative]=json.loads(data)
        self.ram_completed=values['final-completed.json'];self.ram_state=values['ram/cohort.json']
        self.ram_retained=values['ram/retained-guests.json'];self.ram_bindings=values['ram/bindings.json']
        need(self.ram_completed['identity']==spec['identity'] and self.ram_completed['node']==self.node
             and self.ram_completed['runId']=='guest-ram-20261031-r1'
             and self.ram_completed['entrySha256']=='48b8010ba53f6e01d8dc85ab07d29106371d0452d0a5c64b200a31912e382531',
             'RAM completion node/boot/entry differs')
        DD.validate_retained(self.ram_state,self.ram_retained,self.ram_completed,time.time_ns())
        need(not self.root.exists(),'Prior Guest run exists; no create retry')
        HOME.mkdir(mode=0o711,exist_ok=True);self.root.mkdir(mode=0o700)
        self.createdWork=True
        atomic(self.root/'prior-worker-release-verified.json',worker)
        need(HOME.resolve()==HOME and HOME.stat().st_uid==0 and not HOME.stat().st_mode&0o022,'Unsafe experiment root')
        fd=os.open(self.root/'experiment.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.locks=[fd,self.priorRamLock]
        entry=read(Path('/home/jwk/root/relay/entry.py'),256*1024);need(digest(entry)==ROOT_ENTRY_SHA,'Unified transport changed')
        self.transport=load_module('t1_transport',entry).API
        credential=Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json');need(not credential.stat().st_mode&0o077,'Credential permissions differ')
        token=json.loads(read(credential,8192));self.results=self.transport.GitHub(token['resultToken']);self.results.private_repo(RESULTS,1438089386)
        need(TRANSFER.ensure_previous_archive(self)==self.previous_archive_sha,'Previous archive transfer incomplete')
        self.approval={'nodes':{self.node:{'identity':spec['identity']},self.peer:{'identity':spec['peerIdentity']}}}
        self.service=types.SimpleNamespace(identity=current_identity)
        plan=json.loads(read(Path(spec['planPath'])));need(digest(read(Path(spec['planPath'])))==spec['planSha256'],'Original preparation changed')
        journal=json.loads(read(Path(spec['viewJournalPath'])));need(journal['phase']=='rootfs_broker_ready','DAX view unavailable')
        self.app=HeldApp(spec,journal,plan);self.active=self.app.active;self.runtime=self.app.bound('runtime');self.pid=self.runtime['pid']
        BASE=Path(spec['serviceRoot']);self.indexraw=read(BASE/'public/rootfs-index.json');need(digest(self.indexraw)==spec['indexSha256'],'Rootfs index changed')
        self.index=json.loads(self.indexraw);self.key=tomllib.loads(read(self.active/'cli/aenv/credentials').decode())['api_key']
        self.api=Api(self);self.helper=HOME/'public/ublk_owner';self.guard()
        self.before_devices={};self.selfcheck_probe();self.ensure_owner_helper();self.setup_inputs()
        need(self.template['resources']=={'cpu_count':2,'memory_mib':4096,'disk_size_mib':65536},'T1 full snapshot resources differ')
        self.base_files=list(self.files);self.base_processes=list(self.processes)
        self.verify_broker_read_accounting_source()
        ubse=int(subprocess.run(['systemctl','show','ubse.service','--property=MainPID','--value'],check=True,capture_output=True,text=True,timeout=15).stdout)
        schema=engine_schema('/usr/bin/rpm',ubse,process_identity(ubse));need(schema.get('attested'),'UB engine source schema unknown')
        self.provenance={'engineSchema':schema,'mappingEvidence':region_evidence(spec['processes']['sdk']['pid'],
            spec['processes']['sdk']['startTicks'],journal['volume']['segments'],True,None)}

    def selfcheck_probe(self):
        ordinary=Path('/home/jwk/agent/r')/('t1-probe-'+self.n+'-v1')
        if hasattr(self,'previous_preflight'):
            before=json.loads(read(self.previous_preflight/'probe-host-selftest.json'))
            need(before['exitCode']==0 and before['probeSha256']==digest(PROBE)
                 and digest(read(ordinary/'probe',1024**2))==digest(PROBE),'Existing checked probe is no longer the same binary')
            atomic(self.root/'probe-host-selftest.json',{**before,'reusedEarlierSuccessfulSelftest':True})
            return
        need(not ordinary.exists() and ordinary.parent.resolve()==ordinary.parent,'Probe staging already exists')
        ordinary.mkdir(mode=0o700);os.chown(ordinary,1204,1205)
        binary=ordinary/'probe'
        fd=os.open(binary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
        with os.fdopen(fd,'wb') as f:f.write(PROBE);f.flush();os.fchown(f.fileno(),1204,1205);os.fsync(f.fileno())
        need(digest(read(binary,1024**2))==digest(PROBE),'Staged cross-build differs')
        command=['/usr/bin/setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all','--ambient-caps=-all',
                 '--bounding-set=-all','--no-new-privs',str(binary),'selftest',str(ordinary/'owned-selftest'),'0']
        p=subprocess.run(command,capture_output=True,timeout=15,cwd=str(ordinary),env={'PATH':'/usr/bin:/bin','HOME':'/home/jwk'})
        atomic(self.root/'probe-host-selftest.json',{'exitCode':p.returncode,'stdout':p.stdout.decode(errors='replace'),
            'stderr':p.stderr.decode(errors='replace'),'probeSha256':digest(PROBE),'scope':'Host AArch64 ABI smoke only; Guest acceptance pending'})
        need(p.returncode==0,'Native probe Host selftest failed; no Guest created')

    def verify_broker_read_accounting_source(self):
        # This is only a process-level activity indicator. recv/send operations
        # are not inferred from rchar; positive payload attribution also needs
        # the known DAX-only broker implementation and absence of other Guests.
        atomic(self.root/'accounting-boundary.json',{'brokerIo':'/proc/PID/io rchar and syscr deltas',
            'scope':'node aggregate, not exact per-Guest request counts or hardware bytes',
            'brokerDaxOnlyBound':True,'GuestDirectDoesNotBypassHostDeviceCache':True,
            'physicalUbIncrementBytes':None,'netSavingsBytes':None})

    def ensure_owner_helper(self):
        public=HOME/'public';public.mkdir(mode=0o755,exist_ok=True)
        need(public.resolve()==public and public.stat().st_uid==0 and not public.stat().st_mode&0o022,'Untrusted helper directory')
        candidate=Path(self.spec['ownerHelperSourcePath'])
        need(candidate.is_file(),'Previously verified local owner helper is missing; no Guest creation')
        need(candidate.stat().st_uid==0 and not candidate.stat().st_mode&0o022,'Unsafe existing kernel owner query')
        raw=read(candidate,1024**2);need(digest(raw)==OWNER_SHA,'Existing kernel owner query differs')
        # Both nodes already have this verified binary. Its local use has no
        # dependency on publishing an unused cross-node copy.
        if self.helper.exists():need(read(self.helper,1024**2)==raw and self.helper.stat().st_uid==0,'Different staged helper preserved')
        else:
            fd=os.open(self.helper,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
            with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        atomic(self.root/'owner-query-reused.json',{'sha256':OWNER_SHA,'path':str(self.helper),'nativeCompilation':False,
            'sourceSha256':OWNER_SOURCE_SHA,'scope':'GET_DEV_INFO only; grant only new kernel-owned jwk devices'})

    def event(self,kind,data):
        actual='failed' if kind=='failed' else self.group+'-'+kind
        value={'runId':RUN,'node':self.node,'identity':self.expected['identity'],'entrySha256':self.pin,'kind':actual,'data':data}
        atomic(self.root/(actual+'.json'),value)
        self.result_put(RESULTS,1438089386,'main','guest-locality/'+SESSION+'/'+RUN+'/'+self.node+'/'+actual+'.json',wire(value))
        print('PHASE='+self.node+':'+actual,flush=True);return data

    def result_put(self,*args):
        for attempt in range(4):
            try:return self.results.immutable_result(*args)
            except self.transport.Network as error:
                if error.status not in (0,409,422,429,500,502,503,504) or attempt==3:
                    raise RuntimeError('Private result PUT unavailable: HTTP '+str(error.status)) from None
                time.sleep(2+attempt)

    def peer_event(self,kind,seconds=900):
        actual=self.group+'-'+kind;end=time.monotonic()+seconds
        while time.monotonic()<end:
            self.guard()
            for name in ('failed',actual):
                code,raw,_=self.results.contents(RESULTS,'guest-locality/'+SESSION+'/'+RUN+'/'+self.peer+'/'+name+'.json','main')
                if code==200:
                    row=json.loads(raw);need(row['identity']==self.spec['peerIdentity'] and row['entrySha256']==self.pin and row['kind']==name,'Peer binding differs')
                    need(name!='failed','Peer stopped; no new workload');return row['data']
                need(code==404,'Peer event unavailable')
            print('WAIT_PEER='+self.peer+':'+actual,flush=True);time.sleep(5)
        raise RuntimeError('Peer barrier timed out')

    def collect(self,include_files=False):
        row=super().collect(include_files);row['phase']=self.group
        try:
            text=Path('/proc',str(self.broker_identity['pid']),'io').read_text()
            row['brokerProcessIo']={k.strip():int(v) for k,v in (line.split(':',1) for line in text.splitlines())}
        except (OSError,ValueError):row['brokerProcessIo']=None
        return row

    def begin_guests(self,*args,**kwargs):
        raise RuntimeError("No lifecycle or ACL mutation allowed in retained Guest dd task")

    def run_steps(self,label,steps,shell=None):
        target=self.work/label;target.mkdir(mode=0o700)
        jobs=[dict(j,steps=steps) for j in self.jobs]
        before=self.collect(False)
        report=GROUP.NativeGroupReplay(target,self.active/'aenv-host-dax',self.env,jobs,
            shell or REPLAY.shell_command,self.case.owned,self.collect,lambda x:atomic(target/'replay.json',x),launcher=self.launcher).run()
        need(report['status']=='LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED' and report['pendingCommands']==0,'Command transport incomplete')
        atomic(target/'operation-window.json',{'before':before,'after':self.collect(False),
            'scope':'local two-Guest aggregate broker activity window; not exact per-Guest hardware IO',
            'samplingAtomicAcrossNodes':False})
        return report

    def app_timing_rows(self,label,report):
        rows=[]
        for slot,job in enumerate(report['jobs']):
            for index,value in enumerate(job['results']):
                stdout=read(self.work/label/'commands'/f'{slot}-{index}.stdout',16*1024**2).decode(errors='replace')
                rows.append({'slot':slot,'commandIndex':index,'guestExitCode':value['guestExitCode'],
                    'cliElapsedSeconds':value['elapsedSeconds'],'guestTiming':CONTRACT.infer_app_times(stdout)})
        atomic(self.work/(label+'-guest-timing.json'),rows)

    def adopt_guests(self):
        ids=DD.validate_retained(self.ram_state,self.ram_retained,self.ram_completed,time.time_ns())
        self.group='dd';self.work=self.root/'dd';self.work.mkdir(mode=0o700)
        atomic(self.work/'cohort.json',self.ram_state)
        self.case=ENGINE.Cohort(self.api,self.ram_state,lambda x:atomic(self.work/'cohort.json',x),
            None,None,None,None,run_id=self.ram_state['runId'],mutation_guard=lambda:need(False,'Lifecycle mutations forbidden in dd task'))
        self.jobs=[]
        for slot,sid in enumerate(ids):
            need(self.case.owned(sid) is not None,'Retained Guest expired; do not create replacement')
            self.jobs.append({'sandboxId':sid,'slot':slot,'templateId':self.template['templateId'],
                'replaySha256':self.template['replaySha256'],'catalogSha256':self.template['catalogSha256'],
                'lowerContentSha256':BIND.content_signature(self.template['rootfsLayers']),
                'resources':{k:self.template['resources'][k] for k in ('cpu_count','memory_mib')},'steps':[]})
        self.bindings=self.observe()
        for sid,row in self.bindings.items():
            previous=self.ram_bindings[sid]
            need(row['process']==previous['process'] and row['configSha256']==previous['configSha256']
                 and row['devices']==previous['devices'],'Retained FC/device binding changed')
        self.files=list(self.base_files);self.processes=list(self.base_processes);unique={}
        for row in self.bindings.values():
            self.files.extend(row['upper']);self.processes.append(row['process'])
            for d in row['devices']:unique[(d['major'],d['minor'])]=d
        cg=Path('/proc',str(self.pid),'cgroup').read_text()
        daemon=Path(self.app.plan['binaries']['bin/uvm-ublk-daemon']['path']).stat()
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():continue
            try:
                exe=(proc/'exe').stat()
                if (exe.st_dev,exe.st_ino)==(daemon.st_dev,daemon.st_ino) and (proc/'cgroup').read_text()==cg:
                    self.processes.append(self.process_row(int(proc.name),'daemon'))
            except (FileNotFoundError,ProcessLookupError):continue
        need(any(p['role']=='daemon' for p in self.processes),'Retained Runtime daemon unavailable')
        self.devices=list(unique.values());atomic(self.work/'bindings.json',self.bindings)
        self.event('adopted',{'sandboxIds':ids,'newGuestsCreated':False});self.peer_event('adopted')

    def run_dd_steps(self,label,actions):
        need(len(actions)==2,'Two retained Guest slots required')
        DD.validate_retained(self.ram_state,self.ram_retained,self.ram_completed,time.time_ns())
        target=self.work/label;target.mkdir(mode=0o700)
        jobs=[dict(j,steps=[{'action':action,'delay':0}]) for j,action in zip(self.jobs,actions) if action is not None]
        before=self.collect(False)
        result=GROUP.NativeGroupReplay(target,self.active/'aenv-host-dax',self.env,jobs,REPLAY.shell_command,
            self.case.owned,self.collect,lambda x:atomic(target/'replay.json',x),launcher=self.launcher).run()
        need(result['status']=='LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED' and result['pendingCommands']==0,'Unconfirmed Guest command; no retry')
        after=self.collect(False)
        atomic(target/'operation-window.json',{'before':before,'after':after,
            'backend':DD.classify_backend(before,after),'atomicAcrossNodes':False,'activeSlots':[i for i,a in enumerate(actions) if a is not None]})
        return result

    def execute(self):
        self.event('ready',{'priorRamRun':'guest-ram-20261031-r1','template':self.template['templateId'],'probeSha256':digest(PROBE)})
        peer=self.peer_event('ready');need(peer['template']==self.template['templateId'] and peer['probeSha256']==digest(PROBE),'Peer inputs differ')
        self.adopt_guests()
        need(self.run_dd_steps('idle-control',['/agentenv/bin/busybox sleep 10']*2)['nonzeroCommands']==0,'Idle control failed')
        result=self.run_dd_steps('discovery',[DD.discovery_action()]*2)
        need(result['nonzeroCommands']==0,'Guest dd metadata discovery failed')
        discoveries=[DD.parse_discovery(read(self.work/'discovery'/'commands'/f'{i}-0.stdout',4*1024**2).decode()) for i in (0,1)]
        self.event('discovered',{'guests':discoveries});peer=self.peer_event('discovered')
        selection=DD.select_common(discoveries+peer['guests']);atomic(self.work/'selection.json',selection)
        probe=CONTRACT.directory('guest-ram-20261031-r1')+'/probe'
        # Verify existing binary only; never replace a binary inside retained Guests.
        check='test "$(/agentenv/bin/busybox sha256sum '+shlex.quote(probe)+' | /agentenv/bin/busybox cut -d " " -f 1)" = '+digest(PROBE)
        need(self.run_dd_steps('existing-timer-check',[check]*2)['nonzeroCommands']==0,'Retained timing binary changed')
        direct_enabled=selection['directAdvertisedAll']
        for case in DD.matrix(direct_enabled):
            name=case['name']
            if case['mode']=='direct' and not direct_enabled:
                atomic(self.work/(name+'-not-run.json'),{'reason':'Prior direct error; no implicit buffered fallback'});continue
            self.event(name+'-ready',case);self.peer_event(name+'-ready')
            actions=[None if case['idleSlot']==i else DD.read_action(case,selection,discoveries[i],probe) for i in (0,1)]
            result=self.run_dd_steps(name,actions);parsed=[]
            for i,action in enumerate(actions):
                if action is None:continue
                text=read(self.work/name/'commands'/f'{i}-0.stdout',4*1024**2).decode()
                parsed.append({'slot':i,**DD.parse_read(text,case,selection,result['jobs'][i]['results'][0]['guestExitCode'])})
            accepted=all(x['accepted'] for x in parsed)
            atomic(self.work/(name+'-result.json'),{'case':case,'records':parsed,'accepted':accepted})
            if case['mode']!='direct':need(accepted,'Buffered dd failed; preserve exact output')
            self.event(name+'-done',{'accepted':accepted});other=self.peer_event(name+'-done')
            if case['mode']=='direct' and not (accepted and other['accepted']):direct_enabled=False
        upper_executed=False
        if self.spec.get('includeUpper',False):
            need(self.run_dd_steps('upper-setup',[DD.upper_setup(RUN)]*2)['nonzeroCommands']==0,'Private upper directory setup failed')
            sync_supported=all('fdatasync' in x['ddHelp'] for x in discoveries+peer['guests'])
            atomic(self.work/'upper-scope.json',{'syncSupportedAll':sync_supported,'UBWrite':False,
                'maxFilesBytesPerGuest':128*1024**2,'zeroFilledSynthetic':True,'rawBlockDeviceWrites':False})
            for roundno in range(3):
                for sync in ([False,True] if sync_supported else [False]):
                    item=DD.upper_action(RUN,probe,roundno,sync);name=item['case']['name']
                    self.event(name+'-ready',{'syncIncluded':sync});self.peer_event(name+'-ready')
                    result=self.run_dd_steps(name,[item['action']]*2);records=[]
                    for i in (0,1):
                        output=read(self.work/name/'commands'/f'{i}-0.stdout',4*1024**2).decode()
                        records.append(DD.parse_read(output,item['case'],item['selection'],result['jobs'][i]['results'][0]['guestExitCode']))
                    need(all(x['accepted'] for x in records),'Private upper dd failed; no retry')
                    atomic(self.work/(name+'-result.json'),{'contract':item,'records':records})
                    self.event(name+'-done',{'accepted':True});self.peer_event(name+'-done')
            upper_executed=True
        self.guard();self.observe()
        for sid in self.case.state['sandboxIds']:need(self.case.owned(sid) is not None,'Guest no longer retained')
        atomic(self.work/'retained-guests.json',{'sandboxIds':self.case.state['sandboxIds'],'requestedLifetimeSeconds':7200,
            'createdOperations':self.ram_state['operations'],'leaseRenewed':False,'newGuestsCreated':False,'deletedGuests':False})
        self.event('retained',{'sandboxIds':self.case.state['sandboxIds']});self.peer_event('retained')
        self.group='final';self.work=self.root
        self.event('completed',{'status':'DD_LOWER_MEASUREMENTS_COMPLETED_GUESTS_RETAINED',
            'sandboxIds':self.case.state['sandboxIds'],'directAcceptedAll':direct_enabled,
            'UBWrites':False,'upperBenchmarkExecuted':upper_executed,'newGuestsCreated':False,'deletedGuests':False})


def main():
    compressed=base64.b64decode(''.join(sys.argv[1:]),validate=True);d=zlib.decompressobj();raw=d.decompress(compressed,65537)
    need(d.eof and not d.unused_data and not d.unconsumed_tail and len(raw)<=65536,'Bounded job differs')
    ctx=None
    try:
        ctx=GuestExperiment.__new__(GuestExperiment);ctx.__init__(json.loads(raw));ctx.execute();return 0
    except BaseException as error:
        failure={'status':'T1_GUEST_TEST_STOPPED','errorType':type(error).__name__,'reason':str(error)[:1000],
            'originalServicesHeld':True,'globalBackingHeld':True,'automaticCreateRetry':False,
            'frames':[{'file':Path(x.filename).name,'line':x.lineno,'function':x.name} for x in traceback.extract_tb(error.__traceback__)[-6:]]}
        if ctx is not None and getattr(ctx,'createdWork',False):
            atomic(ctx.work/'failure-local.json',failure)
            try:
                if hasattr(ctx,'results'):ctx.event('failed',failure)
            except Exception:pass
            # User explicitly requested retaining Guests for subsequent dd tests.
            # No delete or retry is attempted, including on partial failure.
            failure['ownedGuestsReleased']=False
            failure['cleanupStopped']='User requested Guest retention; preserve cohort and all request intents'
            failure['knownSandboxIds']=ctx.case.state['sandboxIds'] if ctx.case is not None else []
            atomic(ctx.work/'failure-with-cleanup.json',failure)
        print(json.dumps(failure),flush=True);return 1
    finally:
        if ctx is not None and getattr(ctx,'createdWork',False) and hasattr(ctx,'results'):
            ctx.work=ctx.root;ctx.group='final'
            try:ctx.upload()
            except Exception as error:print('PRIVATE_T1_REPORT_UPLOAD_PENDING='+type(error).__name__,flush=True)


# BUILD inserts reviewed helper functions, API, Context mixin, and fixed engines.
if __name__=='__main__':raise SystemExit(main())
