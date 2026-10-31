"""Phase 1: readonly object-to-OBMM provenance and live-state evidence."""
import base64,hashlib,json,os,platform,re,stat,struct,subprocess,sys,time,zlib
from pathlib import Path
MIB=1048576
META_PREFIX=struct.Struct('<BBIII52s16sQQQ16s16sQI52s')

def need(ok,why):
    if not ok:raise RuntimeError(why)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def wire(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def current_identity():
    return {'hostname':platform.node(),'machineId':Path('/etc/machine-id').read_text().strip(),
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel':platform.release(),'architecture':platform.machine()}
def safe_read(path,limit=1024**2,owner=None):
    path=Path(path);need(path.resolve()==path and not path.is_symlink(),'Redirected metadata file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());need(stat.S_ISREG(st.st_mode) and st.st_size<=limit and (owner is None or st.st_uid==owner),'Metadata owner/type/size differs')
        raw=f.read(limit+1);need(len(raw)<=limit,'Metadata file grew');return raw
def command(argv,limit=16384):
    p=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=20)
    return {'exitCode':p.returncode,'stdout':p.stdout[-limit:].decode(errors='replace'),'stderr':p.stderr[-2048:].decode(errors='replace'),
        'truncated':len(p.stdout)>limit}
def classification(rows,expected_bytes):
    valid=[r for r in rows if r.get('kind') in ('export','import') and r.get('ranges')]
    spans=sorted((s['logicalOffset'],s['bytes'],r['kind']) for r in valid for s in r['ranges']);cursor=0;local=remote=0
    for offset,count,kind in spans:
        if offset!=cursor or count<=0:return {'state':'unknown','reason':'Region evidence does not uniquely cover source','localBytes':None,'remoteBytes':None}
        cursor+=count
        if kind=='export':local+=count
        else:remote+=count
    if cursor!=expected_bytes:return {'state':'unknown','reason':'Region evidence incomplete','localBytes':None,'remoteBytes':None}
    return {'state':'local' if remote==0 else ('remote' if local==0 else 'mixed'),'localBytes':local,'remoteBytes':remote,
        'scope':'current local OBMM export/import classification; full peer graph must be matched separately'}
def main():
    need(os.getuid()==os.geteuid()==0 and 0<len(sys.argv[1:])<=16,'Unified root task required')
    compressed=base64.b64decode(''.join(sys.argv[1:]),validate=True);need(len(compressed)<=8192,'Task specification too large')
    dec=zlib.decompressobj();raw=dec.decompress(compressed,65537)
    need(dec.eof and len(raw)<=65536 and not dec.unconsumed_tail,'Task specification bound exceeded');spec=json.loads(raw)
    actual=current_identity();need(spec['identity']==actual and spec['node'] in ('node-a','node-b'),'Inspection node/boot differs')
    out=Path('/home/jwk/root/bench-locality')
    for p in [out,out/spec['node'],out/spec['node']/actual['bootId'],out/spec['node']/actual['bootId']/'origin-001']:
        if not p.exists():p.mkdir(mode=0o700)
        st=p.stat();need(p.resolve()==p and st.st_uid==0 and not st.st_mode&0o077,'Unsafe private evidence directory')
    out=out/spec['node']/actual['bootId']/'origin-001'
    report={'phase':1,'status':'UB_ORIGIN_INSPECTED_READ_ONLY','node':spec['node'],'identity':actual,'expectedPublication':spec['publication'],
        'historicalProvider':spec['provider'],'historicalView':spec['view'],'obmm':{},'services':{},'currentProviderCandidates':[],
        'expectedLogicalBytes':spec['bytes'],'sourceRangesAreHistoricalUntilLiveBindingVerified':True,
        'providerBindingVerified':False,'mappingEvidence':[],'engineSchema':{'attested':False,'reason':'No live matching UBSE observed'},
        'classification':{'state':'unknown','reason':'No verified live matching provider'},'SDKCalled':False,'UBAllocated':False,
        'UBWritten':False,'GuestCreated':False,'servicesChanged':False,'moduleChanged':False,'physicalIncrementBytes':None}
    for field in ('srcversion','refcnt','parameters/pmem_ro_enable'):
        try:report['obmm'][field]=Path('/sys/module/obmm',field).read_text().strip()
        except OSError as error:report['obmm'][field]={'unavailable':type(error).__name__}
    for unit in ('ubse.service','ubsmd.service'):
        info=command(['systemctl','show',unit,'--no-pager','--property=MainPID,ActiveState,LoadState,Result'])
        report['services'][unit]=info
    ubse=report['services']['ubse.service'];values=dict(line.split('=',1) for line in ubse['stdout'].splitlines() if '=' in line)
    if values.get('ActiveState')=='active' and int(values.get('MainPID','0'))>1:
        try:
            pid=int(values['MainPID']);report['engineSchema']=engine_schema('/usr/bin/rpm',pid,process_identity(pid))
        except (OSError,ValueError,subprocess.SubprocessError) as error:report['engineSchema']={'attested':False,'reason':type(error).__name__}
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            if proc.stat().st_uid!=1204:continue
            args=(proc/'cmdline').read_bytes().split(b'\0')
            if b'aenv_ub_provider' in args and b'serve' in args:
                report['currentProviderCandidates'].append({'pid':int(proc.name),'startTicks':process_identity(int(proc.name)),
                    'knownProviderPid':int(proc.name)==spec['provider']['pid']})
        except (OSError,ValueError):continue
    # Do not reinterpret a reused PID or an old rdev after reboot as the old
    # object. A newly created/recovered provider needs its own fresh mapping.
    provider=spec['provider'];pid=provider['pid'];binding_reason=None
    if actual['bootId']!=provider['bootId']:binding_reason='Historical provider belongs to a previous boot; source mapping cannot be reused'
    else:
        try:
            if process_identity(pid)!=provider['startTicks']:binding_reason='Historical provider exited or PID was reused'
            elif Path('/proc',str(pid)).stat().st_uid!=1204:binding_reason='Provider UID differs'
        except OSError:binding_reason='Historical provider process is absent'
    if binding_reason is None:
        try:
            owner_raw=safe_read(Path(spec['ownerJournal']),owner=1204);publication_raw=safe_read(Path(spec['replicas']),owner=1204)
            owner=json.loads(owner_raw);publication=json.loads(publication_raw)
            need(publication==spec['publication'],'Live publication differs from expected object/generation')
            need(owner['state']=='serving' and owner['ownerId']==publication['ownerId'] and owner['manifestSha256']==spec['manifestSha256'],
                'Provider is not serving the same immutable publication')
            report['ownerJournal']={k:owner.get(k) for k in ('version','state','role','mode','ownerId','manifestSha256')}
            report['ownerJournalRawSha256']=digest(owner_raw);report['publicationRawSha256']=digest(publication_raw)
            report['mappingEvidence']=region_evidence(pid,provider['startTicks'],spec['segments'],report['engineSchema'].get('attested') is True,out)
            need(process_identity(pid)==provider['startTicks'] and safe_read(Path(spec['ownerJournal']),owner=1204)==owner_raw
                and safe_read(Path(spec['replicas']),owner=1204)==publication_raw,'Provider generation changed while observing')
            report['providerBindingVerified']=True;report['sourceRangesAreHistoricalUntilLiveBindingVerified']=False
            report['classification']=classification(report['mappingEvidence'],spec['bytes'])
        except (OSError,ValueError,RuntimeError) as error:binding_reason=str(error)[:350]
    report['providerBindingReason']=binding_reason
    view=spec['view']
    if actual['bootId']==view['bootId']:
        try:
            if process_identity(view['pid'])==view['startTicks']:
                mounts=Path('/proc',str(view['pid']),'mountinfo').read_text()
                report['currentDaxMounts']=[line for line in mounts.splitlines() if 'ubpmem_ro' in line][:8]
        except OSError:report['currentDaxMounts']=None
    # Store raw private region metadata locally only, never in stdout/GitHub.
    raw=wire(report);need(len(raw)<=256*1024,'Provenance report exceeds bound')
    path=out/'report.json'
    if path.exists():need(path.read_bytes()==raw,'Prior observation differs; preserve it')
    else:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    print('BEGIN_UB_ORIGIN_JSON',flush=True);print(raw.decode(),flush=True);print('END_UB_ORIGIN_JSON',flush=True)
    print('UB_ORIGIN_READ_ONLY_REPORT_COLLECTED; LOCALITY='+report['classification']['state'],flush=True)

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

if __name__=='__main__':main()
