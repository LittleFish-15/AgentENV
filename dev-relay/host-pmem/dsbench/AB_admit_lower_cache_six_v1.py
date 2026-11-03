"""Batch read-only admission for six genuine-original cache-footprint cases.
No workload, service, SDK, mount, eviction, compiler or payload read.
"""
import base64,hashlib,http.client,json,os,platform,re,socket,stat,subprocess,time,tomllib,types,zlib
from pathlib import Path
ROOT=Path('/home/jwk/root');WORK=Path('/home/jwk/agent/dsbench-20261031')
BUNDLED={'INPUT': {'sha256': '4def90ce7b150ef2d9fc71beb6c3e99b9d416be7130ad2ce37dc0509df066260', 'z64': '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'}, 'REPLAY': {'sha256': '2e0f31142d8fca47724f319c96aae8758f4b0a07d051614a1d92537a9f23a259', 'z64': 'eNp1VduO2zYQfd+vmAoJJMGS17tB8iBFCPLgBgs0QbEJigK2YdDSeM21RKokfUvTf++QlGwh6/hBpuZy5nJmKN60Uhl41lIkChO9qfF4U+EaBGIVyW0CDWrNnjDOboB+nDTSgNxmoBjXCI87YXiDU6WkinrbGw8hVcNq/h2XrDRcisj/dUhBEDyIClukhzDAm7bGhk7M2oBcg9kgKNxzPGBFBzJTWKVYcSMVlFLsyZhMxwTkAI06ZQepKl24Ksa6rbnpYzoLPJbYGviL1TufcKbQ7JQAb9QX6EBm2f3it2IWaqOWCtualbj0scNkKAwXV0BsKq3U3Ap0MXOAY04VHKN1zZ7i0R2sqQh7Bi4gCtNU1tWSYAk8TQUe3Dle5Hubaw8x4wvnx63TGX8xrC26FJfY9h7dMb6So2XIKN5ELkRHStcBJxprw5TRB242UThXcxHGmVMU7jm7zxZnH6yve/3sczfwOXsQtb+OkqX3V8MMnF663F1cusKdxgm7jtZcm6hhbWR7kHhhHA9n3Mtmk2sEOxaSveXhO2+jMxc9UNbzVexvBln4wXyWXETOoFsUbbDVy7WSTaTYoaOiYoYVdi/HtWSVdppcyQMNwyI3qBouWF18kQIvGRlsbErWdRYaxZ6xpIE90YwOu26L45oLYkqUGFmvpOKliYEwrijHT2ii0FcfxglN5sWS1LNetSDuFXUjzmg7DRddw+3PWxTXzYe5eR2VfEAVxX459G7VcEObseaC6w0dKqqaSD93wXvlK4Vse0arsGan4lKAe1/ayypMJpeg7qIzpxYjZ+BjcmGSNfWdesJEBZP3hVO+f/NuMknCB0E08wouHfbBwguqJWrMWnu7Rf/2FWe/uhETn1yYuZhdIv95NJefhUvCadOaE206ljvDVjUOEghpNvyMOdO+M918bbCul6VsGiqmi5k0TG1R9de6EKiKQKOBkYSWt7hmvM4plvs8/Pnx0/SxKJk5Sz5//PJS+Onh2/Kl9I/p169F+vvj3zmUFaQp3MKPH6TkBu7u3+YQjAaL1RURukwwh1v6nAiDYn+74uJ2tdOnlTyCJVHuDKQavk0fP0O6hbfwZjIBb8X0BtIa0hLCkV+5f3bS0DDbKuNRQInICotXH3JoFVG9hnA+F8HIt2QUwGtN7yHMg1fWcB7kPt1J8D+2JGG+'}}
OFFICE=[{'id': 'D03', 'instanceId': 'dsbench-analysis-00000011-2014-round-2-purple-city', 'imageRef': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-analysis-00000011-2014-round-2-purple-city@sha256:fc8bfe8dae7e9b28a923e257b2969374e467fd0ea803b2a0c482b3764f5d4d93', 'replaySha256': '16b196f6c08932bea2cde2587e7fa90215c64cde5c319330e32e470a4b029c17', 'executedStepCount': 19, 'configuredDelaySeconds': 82.0}, {'id': 'D06', 'instanceId': 'dsbench-modeling-bike-sharing-demand', 'imageRef': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-modeling-bike-sharing-demand@sha256:7fb6ceb6e2eb2e5a8aa0f21d6c9daff37699f3a6bb812f53fa7c45283977a734', 'replaySha256': '00b57edc9de7b62ccb2634a17f4a581143c76c8851e20840571891b32d1d078a', 'executedStepCount': 9, 'configuredDelaySeconds': 50.0}, {'id': 'D07', 'instanceId': 'dsbench-modeling-nlp-getting-started', 'imageRef': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-modeling-nlp-getting-started@sha256:87cd51c5c6b19732c068a4bef5844ea3bdb939e1be70ed24820e54f125669a15', 'replaySha256': 'a286d3d570d61193da1c80499370473bd0ab31c2a5bb67e3b4d3618832423ab4', 'executedStepCount': 9, 'configuredDelaySeconds': 50.0}]
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

def main():
    need(os.getuid()==os.geteuid()==0,'Unified root entry required');node={'server1':'node-a','agent1':'node-b'}.get(platform.node());need(node,'Only A/B');n=node[-1]
    modules={}
    for name,item in BUNDLED.items():
        raw=zlib.decompress(base64.b64decode(item['z64']));need(hashlib.sha256(raw).hexdigest()==item['sha256'],'Existing input parser differs');m=types.ModuleType(name);m.__file__='<reused-'+name+'>';exec(compile(raw,name,'exec'),m.__dict__);modules[name]=m
    code=[];source=Path('/home/jwk/agent/deployments/agentenv-lazy-four-32ce41c')
    try:
        templates,steps=modules['INPUT'].load_inputs(source,n,4,read,modules['REPLAY'].steps_from);modules['INPUT'].check_catalogs(source,templates,read)
        repo=source/'state/snapshot-store/repository'
        for index in (1,2,3):
            template=templates[index];record=json.loads(read(repo/'catalog/records'/(template['templateId']+'.json')));committed=record['committed'];files=[];unique={}
            for kind,layers in [('rootfs',[x['Managed'] for x in committed['rootfs_layers']]),('memory',committed['memory_layers'])]:
                for layer in layers:
                    path=repo/'managed-layers'/(layer['digest'].replace(':','_')+'.overlaybd.commit');observed=meta(path);files.append({'kind':kind,'digest':layer['digest'],'expectedBytes':layer['size'],'observed':observed})
                    if kind=='rootfs':need(layer['digest'] not in unique or unique[layer['digest']]==layer['size'],'Conflicting rootfs size');unique[layer['digest']]=layer['size']
            code.append({'case':'T'+str(index+1),'instanceId':template['instanceId'],'templateId':template['templateId'],'catalogSha256':template['catalogSha256'],'replaySha256':template['replaySha256'],'resources':template['resources'],'actionCount':len(steps[index]),'configuredWaitSeconds':sum(x['delay'] for x in steps[index]),'rootfsLowerFileBytes':sum(unique.values()),'rootfsUniqueFiles':len(unique),'files':files,'snapshotArtifacts':[meta(repo/'snapshots'/template['templateId']/x,True) for x in ('commit','vm_state.bin','firecracker-manifest.json')],'payloadHashesRecomputed':False,'GuestAcceptance':False})
    except (OSError,ValueError,RuntimeError,KeyError) as e:code.append({'state':'CODE_INPUT_CHECK_INCOMPLETE','errorType':type(e).__name__,'reason':str(e)[:400]})
    office=[];prepared=WORK/'prepared-inputs.json';prep=json.loads(read(prepared,8*1024**2)) if prepared.exists() else {}
    for target in OFFICE:
        row=dict(target);found=[x for x in prep.get('sourceManifests',[]) if x.get('image','').split('/')[-1].split(':')[0]==target['instanceId']]
        row['preparedManifestMatched']=len(found)==1 and found[0].get('arm64ManifestDigest')==target['imageRef'].split('@')[1]
        row['compressedInputs']=[]
        if found:
            for layer in found[0].get('layers',[]):
                if isinstance(layer,dict) and isinstance(layer.get('digest'),str):row['compressedInputs'].append(meta(WORK/'oci-blobs'/layer['digest'][7:]))
        row['runtimeAccepted']=False;office.append(row)
    conversion=[]
    for leaf in ('native-conversion-v1','native-conversion-sourcefix-v1','native-conversion-titanic-v1'):
        file=WORK/leaf/'converted-rootfs.json'
        conversion.append(selected_json(file,('state','uid','images','GuestCreated','SDKCalled')))
    original=Path('/home/jwk/agent/deployments/agentenv-ae9c626-baseline')
    report={'status':'SIX_ORIGINAL_SCENES_BATCH_ADMISSION_READONLY','node':node,'identity':{'hostname':platform.node(),'machineId':Path('/etc/machine-id').read_text().strip(),'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel':platform.release(),'architecture':platform.machine()},'code':code,'office':office,'preparedInputsState':prep.get('state'),'conversion':conversion,'converter':selected_json(WORK/'apply-sourcefix-v1/candidate.json',('state','candidate','sha256','buildLinkage')),'nativeTools':[meta(WORK/'apply-sourcefix-v1/build/overlaybd/src/tools/overlaybd-apply')],'originalBinaries':[meta(original/x,True) for x in ('bin/server','bin/aenv','bin/uvm-ublk-daemon','deps/firecracker/1.15.1-patch-v3/firecracker')],'originalUnits':[unit('aenv-hpo-'+n+'-'+label+'-61103-v1.service') for label in ('runtime','inside-proxy','host-proxy')],'runtime':runtime(Path('/home/jwk/agent/r')/('hpo-'+n+'-v1/active')),'memory':{k:int(v.split()[0])*1024 for k,v in (x.split(':',1) for x in Path('/proc/meminfo').read_text().splitlines()) if k in ('MemTotal','MemAvailable','Cached','Buffers')},'SDKCalled':False,'GuestCreated':False,'servicesChanged':False,'cacheEvicted':False,'imagePayloadHashed':False,'ratioDefinition':'per node: resident rootfs lower valid bytes / total distinct rootfs lower bytes; not virtual disk capacity or cross-node overlap'}
    raw=json.dumps(report,separators=(',',':'));need(len(raw.encode())<192*1024,'Bounded admission report exceeded');print(raw)
if __name__=='__main__':main()
