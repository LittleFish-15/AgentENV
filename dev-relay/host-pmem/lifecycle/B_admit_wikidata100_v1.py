"""Read existing B runtimes, Wikidata templates and lifecycle SDK prerequisites."""
import hashlib,http.client,json,os,re,socket,subprocess,tomllib,urllib.parse
from pathlib import Path
def run(args,timeout=20,limit=50000):
    try:
        p=subprocess.run(args,capture_output=True,timeout=timeout)
        return {'exitCode':p.returncode,'stdout':p.stdout[:limit].decode(errors='replace'),'stderr':p.stderr[:2000].decode(errors='replace'),'truncated':len(p.stdout)>limit}
    except (OSError,subprocess.TimeoutExpired) as e:return {'state':'unavailable','error':str(e)}
def get(url,key,path):
    u=urllib.parse.urlsplit(url)
    if u.scheme!='http' or u.hostname not in ('127.0.0.1','localhost') or u.username or u.password:raise RuntimeError('Only local existing API allowed')
    c=http.client.HTTPConnection(u.hostname,u.port or 80,timeout=15)
    try:
        c.request('GET',path,headers={'X-API-Key':key});r=c.getresponse();raw=r.read(2*1024**2+1)
        if len(raw)>2*1024**2:raise RuntimeError('API output too large')
        return r.status,json.loads(raw) if raw else None
    finally:c.close()
def meta(p):
    if not p.exists():return {'path':str(p),'present':False}
    s=p.stat();return {'path':str(p),'present':True,'uid':s.st_uid,'mode':oct(s.st_mode&0o7777),'bytes':s.st_size,'symlink':p.is_symlink()}
def main():
    if os.geteuid()!=0 or socket.gethostname()!='agent1':raise RuntimeError('Registered B root entry required')
    result={'status':'B_WIKIDATA100_ADMISSION_ONLY','kernel':os.uname().release,'architecture':os.uname().machine,
      'planned':{'total':100,'batchSize':100,'rounds':1,'warmup':1,'cpu':2,'memoryMiB':4096,
        'phases':['create','pause','resume','delete'],'keepMemory':True,'requestTimeout':600,'sandboxTimeout':86400},
      'host':{'meminfo':Path('/proc/meminfo').read_text(),'cpu':run(['lscpu']), 'disk':run(['df','-h','/home','/'])},
      'services':run(['systemctl','list-units','--all','--plain','--no-pager','aenv*']), 'runtimes':[]}
    configs=[('original','/home/jwk/agent/r/hpo-b-v1/active/cli/aenv/credentials'),
      ('default-jwk','/home/jwk/.config/aenv/credentials'),('default-root','/root/.config/aenv/credentials')]
    for role,name in configs:
        p=Path(name);row={'role':role,'credentialsPresent':p.is_file()}
        if p.is_file():
            try:
                creds=tomllib.loads(p.read_text());url=creds['url'];key=creds['api_key']
                row['apiUrl']=url
                status,templates=get(url,key,'/templates');row['templatesHTTP']=status
                if status==200 and isinstance(templates,list):
                    row['templateCount']=len(templates)
                    row['wikidata']=[t for t in templates if 'wikidata' in json.dumps(t).lower()]
                    row['templateNames']=[{k:t[k] for k in ('templateID','templateId','name','names','aliases','cpuCount','memoryMB','status') if k in t} for t in templates][:100]
                status,items=get(url,key,'/v2/sandboxes?limit=100');row['inventoryHTTP']=status
                if status==200 and isinstance(items,list):row['initialInventoryCount']=len(items);row['inventoryIsEmpty']=not items
            except Exception as e:row['inspectionErrorType']=type(e).__name__
        result['runtimes'].append(row)
    runtimecfg=Path('/home/jwk/root/hpo-services-v1/public/runtime.toml')
    if runtimecfg.is_file():
        raw=runtimecfg.read_bytes();cfg=tomllib.loads(raw.decode())
        result['originalRuntimeConfig']={'sha256':hashlib.sha256(raw).hexdigest(),'snapshot':{k:v for k,v in cfg.get('snapshot',{}).items() if 'key' not in k.lower()},
          'hasUBIndex':any('ub_rootfs' in k for k in cfg.get('snapshot',{}))}
    roots=[Path('/home/jwk/agent/deployments/agentenv-lazy-four-32ce41c/state/snapshot-store/repository'),
      Path('/home/jwk/agent/r/hpo-b-v1/seed/repository')]
    result['wikidataCatalogs']=[]
    for root in roots:
        directory=root/'catalog/records'
        if not directory.is_dir():continue
        files=list(directory.glob('*.json'))
        if len(files)>1000:raise RuntimeError('Catalog count exceeded bound')
        for p in files:
            if p.is_symlink() or p.stat().st_size>2*1024**2:continue
            raw=p.read_bytes()
            if b'wikidata' not in raw.lower():continue
            record=json.loads(raw);committed=record.get('committed') or {}
            row={'path':str(p),'sha256':hashlib.sha256(raw).hexdigest(),'id':record.get('id'),'alias':record.get('alias'),
                'resources':record.get('resources'),'committedKeys':list(committed),'rootfsLayers':committed.get('rootfs_layers'),
                'memoryLayers':committed.get('memory_layers'),'memoryStartup':committed.get('memory_startup'),
                'runtimeVersions':committed.get('runtime_versions'),'attachedDrives':bool(committed.get('attached_drives')),
                'volumeSnapshots':bool(committed.get('volume_snapshots'))}
            result['wikidataCatalogs'].append(row)
    probe="import json,sys,importlib.metadata as m; print(json.dumps({'version':sys.version,'e2b':m.version('e2b')}))"
    executables={x for x in ('/usr/bin/python3.11','/usr/local/bin/python3.11','/home/jwk/.venv-lifecycle/bin/python','/home/jwk/.venv-lifecycle/bin/python','/home/jwk/agent/.venv/bin/python') if Path(x).is_file()}
    discovery=run(['find','/home/jwk','-maxdepth','7','-type','d','-name','e2b-*.dist-info','-print'],40,10000)
    result['sdkDiscovery']=discovery
    for name in discovery.get('stdout','').splitlines()[:20]:
        venv=Path(name).parent.parent.parent.parent
        if (venv/'bin/python').is_file():executables.add(str(venv/'bin/python'))
    result['sdkInterpreters']=[{'path':p,'probe':run(['runuser','-u','jwk','--',p,'-I','-B','-c',probe])} for p in sorted(executables)]
    helper=Path('/home/jwk/root/t1-locality-v1/public/ublk_owner');result['ublkOwnerHelper']=meta(helper)
    if helper.is_file():result['ublkOwnerHelper']['sha256']=hashlib.sha256(helper.read_bytes()).hexdigest()
    result['existingUblkDevices']=[meta(p) for p in Path('/dev').glob('ublk[bc]*')][:200]
    result['mutations']={'sandboxesCreated':0,'servicesChanged':False,'kernelChanged':False,'SDKCalled':False}
    print(json.dumps(result,ensure_ascii=False,separators=(',',':')))
if __name__=='__main__':main()
