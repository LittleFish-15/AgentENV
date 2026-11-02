"""One bounded read-only admission for retained services and Titanic build state.

No lifecycle action, SDK call, compilation, image data read, or credential output.
The installed root relay records stdout under /home/jwk/root.
"""
import hashlib,http.client,json,os,platform,re,socket,stat,subprocess,time,tomllib
from pathlib import Path

ROOT=Path('/home/jwk/root');WORK=Path('/home/jwk/agent/dsbench-20261031')

def need(ok,why):
    if not ok:raise RuntimeError(why)

def read(path,limit=4*1024**2):
    need(path.resolve()==path and not path.is_symlink(),'Redirected input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());need(stat.S_ISREG(st.st_mode) and st.st_uid in (0,1204) and st.st_size<=limit,'Input bounds/type/owner differ')
        raw=f.read(limit+1);need(len(raw)<=limit,'Input grew beyond bound');return raw

def meta(path,hash_small=False):
    if not path.exists():return {'path':str(path),'present':False}
    st=path.lstat();out={'path':str(path),'present':True,'bytes':st.st_size,'uid':st.st_uid,'mode':oct(stat.S_IMODE(st.st_mode)),'symlink':stat.S_ISLNK(st.st_mode)}
    if hash_small and stat.S_ISREG(st.st_mode) and not path.is_symlink() and st.st_size<=128*1024**2:
        out['sha256']=hashlib.sha256(read(path,128*1024**2)).hexdigest()
    return out

def selected_json(path,keys):
    if not path.exists():return {'present':False,'path':str(path)}
    raw=read(path);row=json.loads(raw)
    return {'present':True,'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),
            'selected':{k:row[k] for k in keys if k in row}}

def identity(pid):
    p=Path('/proc')/str(pid);ticks=(p/'stat').read_text().rsplit(')',1)[1].split()[19]
    uids=re.search(r'(?m)^Uid:\s+(.*)$',(p/'status').read_text())[1].split()
    return {'pid':pid,'startTicks':ticks,'uids':list(map(int,uids))}

def unit(name):
    p=subprocess.run(['/usr/bin/systemctl','show',name,'--no-pager',
        '--property=MainPID,LoadState,ActiveState,SubState,Result,ExecMainStatus,ControlGroup'],
        capture_output=True,text=True,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    data=dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
    out={'unit':name,'exitCode':p.returncode,'properties':data}
    pid=int(data.get('MainPID','0'))
    if pid:
        try:
            before=identity(pid);exe=Path(os.readlink(Path('/proc')/str(pid)/'exe'))
            out['process']=before;out['executable']=meta(exe,True);out['stable']=identity(pid)==before
        except (OSError,RuntimeError,ValueError):out['stable']=False
    return out

class Unix(http.client.HTTPConnection):
    def __init__(self,path):super().__init__('localhost',timeout=5);self.path=path
    def connect(self):self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(5);self.sock.connect(str(self.path))

def request(path,route,key):
    need(route in ('/health','/v2/sandboxes?limit=100','/templates'),'Only fixed read-only endpoints')
    c=Unix(path)
    try:
        c.request('GET',route,headers={'X-API-Key':key});r=c.getresponse();raw=r.read(2*1024**2+1)
        need(len(raw)<=2*1024**2,'Bounded API result exceeded')
        out={'route':route,'httpStatus':r.status,'responseBytes':len(raw)}
        if r.status==200 and route!='/health':
            body=json.loads(raw)
            if isinstance(body,list):
                out['count']=len(body);out['rows']=[{k:x[k] for k in ('sandboxID','templateID','templateId','name','endAt','startedAt') if k in x} for x in body[:100] if isinstance(x,dict)]
            else:out['shape']='unexpected_non_list'
        return out
    except (OSError,ValueError,http.client.HTTPException,RuntimeError) as e:return {'route':route,'errorType':type(e).__name__}
    finally:c.close()

def runtime(active):
    out={'active':str(active),'socket':meta(active/'api.sock')}
    if not (active/'api.sock').exists():return out
    need(stat.S_ISSOCK((active/'api.sock').lstat().st_mode),'API path is not socket')
    credential=active/'cli/aenv/credentials';key=''
    if credential.exists():
        st=credential.stat();need(not st.st_mode&0o077,'Credential permission differs')
        key=tomllib.loads(read(credential,16384).decode()).get('api_key','')
    out['checks']=[request(active/'api.sock',route,key) for route in ('/health','/v2/sandboxes?limit=100','/templates')]
    return out

def build_state(node):
    base=WORK/'apply-sourcefix-v1';result={'node':node,'prepared':selected_json(WORK/'prepared-inputs.json',('state','uid','uniqueCompressedBytes')),
        'candidate':selected_json(base/'candidate.json',('state','candidate','sha256','sourceBefore','sourceAfter','explicitMissingConfigRejected','buildLinkage')),'steps':[]}
    if (base/'steps').is_dir():
        for p in sorted((base/'steps').glob('*.json'))[:40]:
            row=json.loads(read(p,65536));item={'phase':p.stem,'exitCode':row.get('exitCode'),'recordSha256':hashlib.sha256(read(p,65536)).hexdigest()}
            log=base/'logs'/(p.stem+'.log');item['log']=meta(log)
            if row.get('exitCode')!=0 and log.is_file():
                # Only fixed private native build logs; never process environment or service logs.
                with log.open('rb') as stream:stream.seek(max(0,log.stat().st_size-6000));item['failureTail']=stream.read(6000).decode(errors='replace')
            result['steps'].append(item)
    if result['candidate'].get('selected',{}).get('candidate'):
        p=Path(result['candidate']['selected']['candidate']);need(p.is_relative_to(base),'Candidate path outside private prefix');result['candidateBinary']=meta(p,True)
    converted=WORK/'native-conversion-titanic-v1/converted-rootfs.json'
    result['conversion']=selected_json(converted,('state','uid','images','GuestCreated','SDKCalled'))
    # Large image/layer files are stat-only here; no payload warming or pretend digest validation.
    images=result['conversion'].get('selected',{}).get('images',[])
    result['convertedFileStats']=[]
    for image in images[:1]:
        for lower in image.get('rootfsLowers',[])[:64]:
            p=Path(lower['file']);need(p.is_relative_to(WORK),'Lower escaped private workspace')
            result['convertedFileStats'].append(meta(p))
    return result

def main():
    need(os.getuid()==os.geteuid()==0,'Use installed root entry')
    host=platform.node();node={'server1':'node-a','agent1':'node-b'}.get(host);need(node,'Only A/B')
    n=node[-1];now={'hostname':host,'machineId':Path('/etc/machine-id').read_text().strip(),
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel':platform.release(),'architecture':platform.machine()}
    names=['ubse.service','aenv-original-t1-'+n+'-runtime-1030r1.service','aenv-original-t1-'+n+'-inside-1030r1.service',
        'aenv-hpab-'+n+'-runtime-v1.service','aenv-hpab-'+n+'-sdk-v1.service','aenv-hpab-'+n+'-view-v1.service']
    if n=='a':names+=['aenv-hpra-a-sdk-61031-v1.service','aenv-hpra-a-view-61031-v1.service','aenv-hpra-a-runtime-61031-v1.service']
    units=[unit(name) for name in names]
    # Discover exact relevant unit names without reading ExecStart or Environment.
    listing=subprocess.run(['/usr/bin/systemctl','list-units','--all','--type=service','--no-legend','--plain','--no-pager'],capture_output=True,text=True,timeout=15)
    for line in listing.stdout.splitlines():
        name=line.split()[0] if line.split() else ''
        if re.fullmatch(r'(?:aenv-(?:hpab|hpra|original-t1)|jwk-aenv-(?:lazy-four|original|baseline|dsec-hostfile))[a-zA-Z0-9_.-]*\.service',name) and name not in names:
            need(len(units)<40,'Service listing bound exceeded');units.append(unit(name));names.append(name)
    active=[Path('/home/jwk/agent/r')/('hpab-'+n+'-v1')/leaf for leaf in ('active','rejoin-r1')]
    active.append(ROOT/('orig-'+n))
    oldjob=ROOT/'relay/jobs/dsbench-titanic-build-007-node-a'
    servers=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdecimal():continue
        try:
            exe=Path(os.readlink(p/'exe'))
            if exe.name!='server' or not (exe.is_relative_to('/home/jwk/agent') or exe.is_relative_to(ROOT)):continue
            ident=identity(int(p.name))
            if ident['uids']!=[1204]*4:continue
            need(len(servers)<16,'Owned server count bound exceeded')
            servers.append({'process':ident,'executable':meta(exe,True),'cgroup':(p/'cgroup').read_text()[:4096],
                'stable':identity(int(p.name))==ident})
        except (FileNotFoundError,ProcessLookupError):continue
    report={'status':'TITANIC_READINESS_OBSERVED_NO_MUTATION','node':node,'identity':now,'unixNs':time.time_ns(),
        'ownedServerProcesses':servers,
        'services':units,'runtimes':[runtime(p) for p in active],'build':build_state(node),
        'priorBuildJob':{'state':selected_json(oldjob/'state.json',('state','identity','startedUnixNs','exitCode','jobSha256')),
            'report':selected_json(oldjob/'report.json',('state','identity','jobId','jobSha256','exitCode','elapsedSeconds'))} if n=='a' else None,
        'obmm':{key:(Path('/sys/module/obmm')/key).read_text().strip() if (Path('/sys/module/obmm')/key).exists() else None for key in ('srcversion','refcnt','parameters/pmem_ro_enable')},
        'SDKCalled':False,'GuestCreated':False,'servicesChanged':False,'compiled':False,'globalObjectAllocated':False,
        'templateAcceptance':'API listing alone is not boot/dependency/trajectory acceptance'}
    print('BEGIN_TITANIC_READINESS');print(json.dumps(report,ensure_ascii=False,indent=2));print('END_TITANIC_READINESS')

if __name__=='__main__':main()
