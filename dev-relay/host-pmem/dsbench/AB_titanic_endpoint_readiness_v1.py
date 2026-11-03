"""Read-only exact endpoint extraction, current retained resources, original pins.
No process/service/device action, SDK call, Guest command or image payload read.
"""
import hashlib,http.client,json,os,re,socket,stat,subprocess,time
from pathlib import Path
EXPECTED={'node-a': {'bytes': 28734, 'sha256': '70c4f5b23807ec2e02e376e2f3abae98e2a76a449a2406c7975e4733e142744d', 'sandboxIds': ['01a19c63-5028-7360-8a4e-8a5356fd953f', '01a19c63-550b-7660-a802-68ce63c2d927']}, 'node-b': {'bytes': 23246, 'sha256': '84b040542548ed022c6364ebafc91e15acab73d741bcdc0cefdd3cab17b581db', 'sandboxIds': ['01a19c63-5450-72d3-9a74-5d7acb86deb7', '01a19c63-592a-7432-b30e-a7d33721446f']}}
def need(ok,why):
    if not ok:raise RuntimeError(why)
def read(p,limit=2*1024**2):
    need(p.resolve()==p and p.is_file() and p.stat().st_size<=limit,'Read input identity/bounds differs');return p.read_bytes()
def sha(b):return hashlib.sha256(b).hexdigest()
def meta(p,hash_file=False):
    if not p.exists():return {'path':str(p),'present':False}
    s=p.lstat();r={'path':str(p),'present':True,'bytes':s.st_size,'uid':s.st_uid,'symlink':p.is_symlink()}
    if hash_file and stat.S_ISREG(s.st_mode) and not p.is_symlink() and s.st_size<=128*1024**2:
        h=hashlib.sha256()
        with p.open('rb') as f:
            for b in iter(lambda:f.read(1024**2),b''):h.update(b)
        r['sha256']=h.hexdigest()
    return r
class UnixHTTP(http.client.HTTPConnection):
    def __init__(self,path):super().__init__('localhost',timeout=10);self.path=path
    def connect(self):self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(10);self.sock.connect(str(self.path))
def unit(name):
    p=subprocess.run(['/usr/bin/systemctl','show',name,'--no-pager','--property=MainPID,ActiveState,LoadState,SubState,Result'],capture_output=True,text=True,timeout=10)
    return {'name':name,'exitCode':p.returncode,'properties':dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)}
def main():
    need(os.getuid()==os.geteuid()==0,'Unified root entry required');node={'server1':'node-a','agent1':'node-b'}.get(socket.gethostname());need(node,'Only A/B');n=node[-1]
    path=Path('/home/jwk/root/titanic-measure-r2')/node/'business/final-before-release.json';raw=read(path);need(len(raw)==EXPECTED[node]['bytes'] and sha(raw)==EXPECTED[node]['sha256'],'Frozen endpoint hash differs')
    r=json.loads(raw);categories={}
    for f in r['ordinaryFiles']:
        k=f['category'];v=f.get('residentBytes');categories[k]=None if v is None or categories.get(k,0) is None else categories.get(k,0)+v
    endpoint={'sha256':sha(raw),'bytes':len(raw),'unixNs':r['unixNs'],'hostMemoryBytes':r['hostMemoryBytes'],'fileResidentBytesByCategory':categories,'processes':r['processes'],'blockDevices':r['blockDevices'],'dax':{'files':r['dax']['files'],'ordinaryFileDataPageCacheApplicable':False},'physicalUbIncrementBytes':None}
    base=Path('/home/jwk/root/hpt-services-v1');state=json.loads(read(base/'private/journal.json'));units=[unit(x['name']) for x in state['units'].values()];current_boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();inventory={'state':'NOT_QUERIED_UNBOUND_RUNTIME','sandboxIds':None}
    runtime=state['units']['runtime'];props=next(x['properties'] for x in units if x['name']==runtime['name'])
    if state['identity']['bootId']==current_boot and props.get('ActiveState')=='active' and props.get('MainPID')==str(runtime['pid']):
        ticks=Path('/proc',str(runtime['pid']),'stat').read_text().rsplit(')',1)[1].split()[19];need(ticks==runtime['ticks'],'Runtime PID reused')
        import tomllib
        active=Path('/home/jwk/agent/r')/('hpt-'+n+'-v1/active');key=tomllib.loads(read(active/'cli/aenv/credentials').decode())['api_key'];c=UnixHTTP(active/'api.sock')
        try:
            c.request('GET','/v2/sandboxes?limit=100',headers={'X-API-Key':key});reply=c.getresponse();data=reply.read(2*1024**2+1);need(reply.status==200 and len(data)<=2*1024**2,'Inventory read not confirmed');items=json.loads(data);need(isinstance(items,list),'Inventory shape differs');inventory={'state':'READ_CURRENT_SAME_BOOT_RUNTIME','httpStatus':200,'items':[{k:x.get(k) for k in ('sandboxID','sandboxId','id','status','templateID')} for x in items],'priorSandboxIds':EXPECTED[node]['sandboxIds']}
        finally:c.close()
    original=Path('/home/jwk/agent/deployments/agentenv-ae9c626-baseline');files=[meta(original/x,True) for x in ('bin/server','bin/aenv','bin/uvm-ublk-daemon','deps/firecracker/1.15.1-patch-v3/firecracker')]
    original_units=[unit('aenv-original-t1-'+n+'-'+x+'-1030r1.service') for x in ('runtime','inside','host')]
    seed=Path('/home/jwk/agent/r')/('hpt-'+n+'-v1/seed/repository');missing=[]
    for x in json.loads(read(seed/'catalog/records/01a19b76-130a-75c2-bf0a-76b49acc1943.json'))['committed']['rootfs_layers']:
        layer=x['Managed'];p=seed/'managed-layers'/('sha256_'+layer['digest'][7:]+'.overlaybd.commit')
        if not p.exists():missing.append({'digest':layer['digest'],'bytes':layer['size']})
    print(json.dumps({'status':'TITANIC_ENDPOINT_AND_ORIGINAL_READINESS_OBSERVED_NO_ACTION','node':node,'unixNs':time.time_ns(),'currentBootId':current_boot,'exactBusinessEndpoint':endpoint,'candidateUnits':units,'inventory':inventory,'originalBinaries':files,'originalUnits':original_units,'originalPreparedConfig':meta(Path('/home/jwk/root/original-t1/public')/('runtime-'+n+'.toml')),'missingOrdinaryTitanicRootfsLayers':missing,'SDKCalled':False,'GuestCreated':False,'servicesChanged':False,'resourcesReleased':False,'largePayloadHashed':False},separators=(',',':')))
if __name__=='__main__':main()
