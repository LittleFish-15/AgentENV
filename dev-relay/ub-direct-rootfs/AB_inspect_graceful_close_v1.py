"""Read current scope before closing this UB-rootfs experiment. No mutation.

Only a private diagnostic report is written. No SDK initialization, allocation,
retire, POST, DELETE, process signalling, service or module action is performed.
"""
import hashlib,http.client,json,os,re,stat,subprocess,time
from pathlib import Path
ROOT=Path('/home/jwk/agent')
HOST_ENTRY=ROOT/'AB_direct_full_host_v1.py'
HOST_PIN='de7d33573d8ae46d37c08e811973deab20d16cf855adf256f9b7b6f25bbb7cc0'
BASES={'full':'agentenv-direct-ub-deletefix-v1','original':'agentenv-ae9c626-baseline','olderDirect':'agentenv-direct-ub-guest-v1'}
PREFIXES={'full':'jwk-aenv-direct-ub-deletefix-v1-node-','original':'jwk-aenv-ae9c626-node-','olderDirect':'jwk-aenv-direct-ub-guest-v1-node-'}

def document(path):
    assert path.resolve(strict=True)==path and path.is_relative_to(ROOT)
    with path.open('rb') as f:
        m=os.fstat(f.fileno());assert stat.S_ISREG(m.st_mode) and m.st_uid in (0,1204) and m.st_size<=8*1024**2
        raw=f.read(8*1024**2+1)
    return json.loads(raw),hashlib.sha256(raw).hexdigest()
def process(pid):
    p=Path('/proc')/str(pid)
    try:
        ticks=(p/'stat').read_text().rsplit(')',1)[1].split()[19]
        fds=[]
        for fd in (p/'fd').iterdir():
            try:
                target=os.readlink(fd)
                if re.fullmatch(r'/dev/(?:obmm(?:_shmdev[0-9]+)?|ublk[bc][0-9]+)',target):fds.append({'fd':fd.name,'device':target})
            except FileNotFoundError:pass
        return {'pid':pid,'startTicks':ticks,'executable':os.readlink(p/'exe'),'deviceFDs':fds,
                'identityStable':(p/'stat').read_text().rsplit(')',1)[1].split()[19]==ticks}
    except FileNotFoundError:return {'pid':pid,'state':'not-observed'}
def unit(name):
    r=subprocess.run(['systemctl','show',name,'--no-pager','--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,User,Group,Job'],capture_output=True,text=True,timeout=15,check=True)
    value=dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)
    group=value.get('ControlGroup');members=[]
    if group:
        for p in Path('/proc').iterdir():
            if not p.name.isdecimal():continue
            try:
                if any(line.endswith(':'+group) or (':'+group+'/') in line for line in (p/'cgroup').read_text().splitlines()):members.append(process(int(p.name)))
            except FileNotFoundError:pass
    value['processes']=members;return value
def request_summary(state):
    result={k:state[k] for k in ('runId','phase','status','sandboxIds','openRequests','outcomeUncertain') if k in state}
    if 'groups' in state:
        result['groups']={name:{'phase':g.get('phase'),'cases':{i:request_summary(c) for i,c in g.get('cases',{}).items()}}
                          for name,g in state['groups'].items()}
    return result
def inventory(base,properties):
    pid=int(properties.get('MainPID','0'))
    if properties.get('ActiveState')!='active' or pid<2:return {'available':False,'reason':'unit not active'}
    proc=Path('/proc')/str(pid)
    if os.readlink(proc/'exe')!=str(base/'bin/server'):return {'available':False,'reason':'unexpected unit executable'}
    env=dict(x.split(b'=',1) for x in (proc/'environ').read_bytes().split(b'\0') if b'=' in x)
    match=re.fullmatch(rb'127\.0\.0\.1:(180[0-9]{2})',env.get(b'API_ADDR',b''))
    if not match:return {'available':False,'reason':'no declared loopback API'}
    path=base/'config/api-key';assert path.resolve(strict=True)==path
    with path.open('rb') as f:
        meta=os.fstat(f.fileno());assert stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_size<=1024
        key=f.read().decode().strip()
    connection=http.client.HTTPConnection('127.0.0.1',int(match[1]),timeout=5)
    try:
        connection.request('GET','/v2/sandboxes?limit=100',headers={'X-API-Key':key})
        response=connection.getresponse();raw=response.read(2*1024**2+1);assert len(raw)<=2*1024**2
        result={'httpStatus':response.status,'paginated':bool(response.getheader('X-Next-Token'))}
        if response.status==200:
            value=json.loads(raw);assert isinstance(value,list)
            result['sandboxes']=[{**{k:v[k] for k in ('sandboxID','templateID','state') if k in v},
                'experimentMetadata':{k:x for k,x in v.get('metadata',{}).items() if k in ('cow_batch','full_compare_batch','variant','template_index','slot')}} for v in value]
        return result
    finally:connection.close()
def provider_status(node):
    raw=HOST_ENTRY.read_bytes();assert len(raw)==81083 and hashlib.sha256(raw).hexdigest()==HOST_PIN
    # Run the pinned, read-only status call as the same ordinary UID as the
    # broker. Root never executes the provider payload or calls its SDK.
    code="""import hashlib,json,os,stat,types
from pathlib import Path
p=Path('/home/jwk/agent/AB_direct_full_host_v1.py')
assert p.resolve(strict=True)==p
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
with os.fdopen(fd,'rb') as f:
 m=os.fstat(f.fileno());assert stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_size==81083
 raw=f.read(81084)
assert hashlib.sha256(raw).hexdigest()=='de7d33573d8ae46d37c08e811973deab20d16cf855adf256f9b7b6f25bbb7cc0'
s={'__name__':'verified_status_only','__file__':str(p)}
exec(compile(raw,str(p),'exec'),s)
s['ordinary'](NODE)
print(json.dumps(s['control'](s['paths'](NODE),{'operation':'status'})))
""".replace('NODE',repr(node))
    argv=['setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs',
          '/usr/bin/python3','-I','-B','-c',code]
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=25)
    if result.returncode:return {'available':False,'reason':'Pinned read-only status call failed','exitCode':result.returncode}
    return {'available':True,'value':json.loads(result.stdout)}
def main():
    assert os.getuid()==os.geteuid()==0,'Root on the declared experiment node required'
    node={'server1':'a','agent1':'b'}[os.uname().nodename]
    report={'status':'UB_ROOTFS_CLOSE_SCOPE_READ_ONLY','node':node,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'experimentStateChanged':False,'SDKCalled':False,'retireSent':False,'signalsSent':False,'servicesChanged':False,
            'obmmChangeClearance':False,'scope':'inspect only; B importer release receipt is required before A owner retirement',
            'units':{},'journals':{},'provider':{}}
    for role,name in BASES.items():
        value=unit(PREFIXES[role]+node+'.service');report['units'][role]=value
        try:value['inventory']=inventory(ROOT/'deployments'/name,value)
        except Exception as e:value['inventory']={'available':False,'errorType':type(e).__name__}
    for name in ('ubse.service','ubsmd.service'):report['units'][name]=unit(name)
    provider=ROOT/'r'/('uf-'+node+'-v1')
    for name in ('provider-process.json','context.json','p/owner.json','p/release.json','p/stored-owner.json'):
        path=provider/name
        try:
            value,pin=document(path)
            if name=='context.json':value={k:value[k] for k in ('node','ownerId','manifestSha256','readerId') if k in value}
            if name=='p/stored-owner.json':value={'state':value.get('state'),'finalize_acknowledged':value.get('finalize_acknowledged'),
                'objects':[{'creation_confirmed':x.get('creation_confirmed'),'delete_acknowledged':x.get('delete_acknowledged')} for x in value.get('objects',[])]}
            report['provider'][name]={'sha256':pin,'value':value}
            if name=='provider-process.json':report['provider']['currentProcess']=process(value['pid'])
        except FileNotFoundError:report['provider'][name]={'present':False}
    try:report['provider']['status']=provider_status(node)
    except Exception as e:report['provider']['status']={'available':False,'errorType':type(e).__name__}
    for role,relative in (('full','acceptance/exit-pair-v1/state.json'),('full','comparison/deletefix-full-v1/run.json'),
                         ('full','comparison/deletefix-full-v1/failure-original.json'),('olderDirect','acceptance/direct-pair-v1/state.json')):
        path=ROOT/'deployments'/BASES[role]/relative
        try:
            value,pin=document(path);report['journals'][role+'/'+relative]={'sha256':pin,'summary':request_summary(value)}
        except FileNotFoundError:report['journals'][role+'/'+relative]={'present':False}
    report['unexecutedRepairDirectoryPresent']=(ROOT/'deployments'/BASES['full']/'comparison/deletefix-full-v1/original-socket-repair-v1').exists()
    report['obmm']={}
    for name in ('refcnt','version','parameters/pmem_ro_enable'):
        try:report['obmm'][name]=(Path('/sys/module/obmm')/name).read_text().strip()[:256]
        except FileNotFoundError:report['obmm'][name]=None
    out=ROOT/'r'/('ub-rootfs-close-'+node+'-'+str(time.time_ns()));out.mkdir(mode=0o700)
    report['outputDirectory']=str(out)
    data=(json.dumps(report,indent=2)+'\n').encode();fd=os.open(out/'inspection.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data)
    print('BEGIN_UB_ROOTFS_CLOSE_SCOPE');print(data.decode());print('END_UB_ROOTFS_CLOSE_SCOPE')
if __name__=='__main__':
    try:main()
    except Exception as e:print(json.dumps({'status':'STOPPED_CLOSE_INSPECTION_NO_ACTION','errorType':type(e).__name__,'reason':str(e)}));raise SystemExit(1)
