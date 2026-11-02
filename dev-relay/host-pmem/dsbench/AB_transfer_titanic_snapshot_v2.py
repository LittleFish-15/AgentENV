"""Transfer only captured memory/state/catalog through private release assets.

No rootfs payload copy to B, no VM, SDK, service, mount or module action.
Large files are streamed individually, never archived or buffered in full.
"""
import ssl
import hashlib,http.client,json,os,re,socket,stat,sys,time,types,urllib.error,urllib.parse,urllib.request
from pathlib import Path
SID='01a19b76-130a-75c2-bf0a-76b49acc1943'
SESSION='relay-20261029-0d032371'
REPO='LittleFish-15/AgentENV-relay-results';REPO_ID=1438089386
TAG='private-titanic-snapshot-'+SID
ROOT=Path('/home/jwk/root/titanic-transfer-20261102')
SOURCE=Path('/home/jwk/agent/dsbench-20261102/candidate-a/seed/repository')
DEST=Path('/home/jwk/agent/r/hpt-b-v1/seed/repository')
CATALOG_SHA='bf645afa402a35cd92eca1310672ce2a2c4dfac79e7ffb234afaf5228457a92e'
ENTRY_SHA='f41f111a5d92d9ba373f34b65d7686b02a0c63ce6d11e114ab2be0b5ea98357d'
RUN='titanic-snapshot-transfer-20261102-r1'
MAX_FILE=512*1024**2
EXPECTED_FILES={'managed-layers/sha256_3b92c077e27c3bdb0361f9629e05827626ee11a884c29dcbbffeb08a0ee49fbb.overlaybd.commit': {'bytes': 444424192, 'sha256': '3b92c077e27c3bdb0361f9629e05827626ee11a884c29dcbbffeb08a0ee49fbb'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/vm_state.bin': {'bytes': 12137, 'sha256': '3363f3f8cb0f8883a180ad359626f3f22e8431d65c6ac7b225c6d0424c45333a'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/firecracker-manifest.json': {'bytes': 243, 'sha256': 'f41e714129f9351d9987ba0395f6c8d4a52b6805f6c3d341226f6ca74262c411'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/commit': {'bytes': 9, 'sha256': 'cc962289af2873dd6dad32931554372a7d2d2de5bd5859c8265eb58b5197a88e'}, 'catalog/records/01a19b76-130a-75c2-bf0a-76b49acc1943.json': {'bytes': None, 'sha256': 'bf645afa402a35cd92eca1310672ce2a2c4dfac79e7ffb234afaf5228457a92e'}}

def need(ok,why):
    if not ok:raise RuntimeError(why)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def wire(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def read(path,limit=4*1024**2):
    need(path.resolve()==path and path.is_file() and path.stat().st_size<=limit,'Bounded input differs');return path.read_bytes()
def file_sha(path):
    need(path.resolve()==path and path.is_file(),'File redirected')
    h=hashlib.sha256()
    with path.open('rb') as f:
        before=os.fstat(f.fileno())
        for b in iter(lambda:f.read(1024**2),b''):h.update(b)
        after=os.fstat(f.fileno())
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'File changed during hash')
    return h.hexdigest()
def directory(path,uid):
    need(path.is_relative_to(ROOT) or path.is_relative_to(DEST.parents[1]),'Directory outside transfer')
    if not path.parent.exists():directory(path.parent,uid)
    if not path.exists():path.mkdir(mode=0o700);os.chown(path,uid,1205 if uid==1204 else 0);os.chmod(path,0o700)
    st=path.stat();need(path.resolve()==path and st.st_uid==uid and not st.st_mode&0o077,'Private transfer directory differs')
def atomic(path,value):
    raw=wire(value);temp=path.with_suffix('.next')
    with temp.open('wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.replace(temp,path)
def safe_relative(name):
    return bool(re.fullmatch(r'managed-layers/sha256_[0-9a-f]{64}\.overlaybd\.commit',name)
        or name=='catalog/records/'+SID+'.json'
        or name in {'snapshots/'+SID+'/'+f for f in ('vm_state.bin','firecracker-manifest.json','commit','memory-startup.pack')})
def identity():return {'hostname':socket.gethostname(),'machineId':Path('/etc/machine-id').read_text().strip(),
    'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'architecture':os.uname().machine,'kernel':os.uname().release}

def validate_assets(entries):
    need(isinstance(entries,list) and len(entries)==len(EXPECTED_FILES) and {e['relative'] for e in entries}==set(EXPECTED_FILES),'Snapshot dependency set differs')
    for item in entries:
        expected=EXPECTED_FILES[item['relative']]
        need(item['sha256']==expected['sha256'] and type(item['bytes']) is int and 0<item['bytes']<=MAX_FILE,'Artifact content identity differs')
        if expected['bytes'] is not None:need(item['bytes']==expected['bytes'],'Artifact size differs')
        else:need(item['bytes']<=512*1024,'Catalog size exceeds bound')
    need(sum(e['bytes'] for e in entries)<MAX_FILE,'Transfer scope exceeds total bound')

class DownloadRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,response,code,message,headers,newurl):
        url=urllib.parse.urlparse(newurl)
        need(url.scheme=='https' and url.port in (None,443) and not url.username and not url.password and
             url.hostname in ('api.github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'),
             'Asset redirect outside allowed GitHub hosts')
        redirected=super().redirect_request(request,response,code,message,headers,newurl)
        if url.hostname!='api.github.com':redirected.remove_header('Authorization')
        return redirected


TRANSFER_STAGE='initialization'
def safe_network_detail(error):
    reason=getattr(error,'reason',error)
    detail={'errorType':type(error).__name__,'stage':TRANSFER_STAGE,
            'httpStatus':error.code if isinstance(error,urllib.error.HTTPError) else getattr(error,'status',None),
            'proxyConfigured':bool(urllib.request.getproxies())}
    if isinstance(reason,socket.gaierror):detail.update(kind='DNS',errno=reason.errno)
    elif isinstance(reason,ssl.SSLCertVerificationError):detail.update(kind='TLS_CERTIFICATE',verifyCode=getattr(reason,'verify_code',None))
    elif isinstance(reason,(TimeoutError,socket.timeout)):detail.update(kind='TIMEOUT')
    elif isinstance(reason,OSError):detail.update(kind='OS_NETWORK',errno=reason.errno,reasonType=type(reason).__name__)
    else:detail.update(kind='HTTP' if isinstance(error,urllib.error.HTTPError) else 'OTHER',reasonType=type(reason).__name__)
    if type(error) in (RuntimeError,ValueError):detail['reason']=str(error)[:600]
    return detail

def load_api():
    raw=read(Path('/home/jwk/root/relay/entry.py'),128*1024);need(digest(raw)==ENTRY_SHA,'Unified entry version differs')
    module=types.ModuleType('fixed_transfer_api');module.__file__='/home/jwk/root/relay/entry.py';sys.modules[module.__name__]=module
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    path=Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json');need(not path.stat().st_mode&0o077,'Credential permissions differ')
    token=json.loads(read(path,8192))['resultToken']
    client=module.API.GitHub(token);client.private_repo(REPO,REPO_ID)
    return module.API,client

def api_json(client,method,path,value=None):
    code,row,_=client.request(method,'/repos/'+REPO+path,value)
    need(code in (200,201),'Private artifact API did not confirm operation');return row
def asset_headers(client,accept='application/vnd.github+json'):
    return {'Authorization':'Bearer '+client.token,'Accept':accept,'User-Agent':'AgentENV-Titanic-private-transfer','X-GitHub-Api-Version':'2022-11-28'}
def ensure_release(client,state,path):
    client.private_repo(REPO,REPO_ID)
    releases=api_json(client,'GET','/releases?per_page=100')
    matches=[r for r in releases if r['tag_name']==TAG]
    need(len(matches)<=1,'Ambiguous existing private release')
    if matches:release=matches[0]
    else:
        need(not state.get('releaseIntent'),'Previous release creation not confirmed; do not repeat')
        state['releaseIntent']=True;atomic(path,state)
        release=api_json(client,'POST','/releases',{'tag_name':TAG,'name':TAG,'body':'Private scoped memory/state/catalog transfer for Titanic. No credentials or runtime environment files.',
            'draft':True,'prerelease':True,'make_latest':'false'})
    need(release['draft'] is True and release['tag_name']==TAG,'Release no longer private draft scope')
    state['releaseId']=release['id'];atomic(path,state);return release['id']
def upload(client,api,release_id,item,state,state_path):
    global TRANSFER_STAGE
    TRANSFER_STAGE="upload:"+item["relative"]
    assets=api_json(client,'GET',f'/releases/{release_id}/assets?per_page=100')
    name=item['sha256']+'.bin';matches=[a for a in assets if a['name']==name]
    need(len(matches)<=1,'Duplicate content asset')
    if matches:
        asset=matches[0];need(asset['state']=='uploaded' and asset['size']==item['bytes'],'Prior asset incomplete; preserve')
    else:
        if state.get('uploadIntent') and state['uploadIntent']['name']!=name:
            state.setdefault('previousUnconfirmedUploadIntents',[]).append(state['uploadIntent'])
        state['uploadIntent']={'name':name,'sha256':item['sha256'],'bytes':item['bytes']};atomic(state_path,state)
        p=SOURCE/item['relative'];need(p.stat().st_size==item['bytes'] and file_sha(p)==item['sha256'],'Source artifact changed')
        url='https://uploads.github.com/repos/'+REPO+f'/releases/{release_id}/assets?name='+name
        headers=asset_headers(client);headers.update({'Content-Type':'application/octet-stream','Content-Length':str(item['bytes'])})
        client.private_repo(REPO,REPO_ID)
        with p.open('rb') as stream:
            before=os.fstat(stream.fileno())
            req=urllib.request.Request(url,data=stream,headers=headers,method='POST')
            with urllib.request.build_opener(api.NoRedirect()).open(req,timeout=600) as response:
                raw=response.read(2*1024**2+1);need(response.status==201 and len(raw)<=2*1024**2,'Asset upload acknowledgment differs');asset=json.loads(raw)
            after=os.fstat(stream.fileno())
            need(stream.tell()==item['bytes'] and (before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns),'Upload source stream changed')
    need(asset['name']==name and asset['size']==item['bytes'],'Asset identity differs')
    if asset.get('digest'):need(asset['digest']=='sha256:'+item['sha256'],'Server asset checksum differs')
    state.setdefault('uploaded',{})[name]={'id':asset['id'],'bytes':asset['size'],'serverDigest':asset.get('digest')};state.pop('uploadIntent',None);atomic(state_path,state)
    print('SNAPSHOT_ASSET_AVAILABLE='+item['relative'],flush=True)
    return {**item,'assetId':asset['id'],'assetName':name,'serverDigest':asset.get('digest')}

def download(client,item,state,state_path):
    relative=item['relative'];need(safe_relative(relative) and 0<item['bytes']<=MAX_FILE and re.fullmatch('[0-9a-f]{64}',item['sha256']),'Asset manifest path/size invalid')
    need(type(item['assetId']) is int and item['assetId']>0 and item['assetName']==item['sha256']+'.bin','Asset URL identity differs')
    target=DEST/relative;directory(target.parent,1204)
    if target.exists():need(target.stat().st_size==item['bytes'] and file_sha(target)==item['sha256'],'Existing different destination preserved');return
    part=target.with_name(target.name+'.partial');offset=part.stat().st_size if part.exists() else 0
    need(not part.is_symlink() and 0<=offset<=item['bytes'],'Partial transfer outside bounds')
    if part.exists():need(stat.S_ISREG(part.lstat().st_mode) and part.stat().st_uid==1204,'Partial file owner/type differs')
    h=hashlib.sha256()
    if offset:
        with part.open('rb') as f:
            for b in iter(lambda:f.read(1024**2),b''):h.update(b)
    if offset<item['bytes']:
        client.private_repo(REPO,REPO_ID)
        row=api_json(client,'GET',f'/releases/assets/{item["assetId"]}')
        need(row['name']==item['assetName'] and row['size']==item['bytes'] and row['state']=='uploaded','Source asset changed')
        headers=asset_headers(client,'application/octet-stream')
        if offset:headers['Range']='bytes='+str(offset)+'-'
        request=urllib.request.Request('https://api.github.com/repos/'+REPO+f'/releases/assets/{item["assetId"]}',headers=headers)
        with urllib.request.build_opener(DownloadRedirect()).open(request,timeout=120) as response:
            need(response.status==(206 if offset else 200),'Unexpected asset range response; preserve partial')
            if offset:need((response.headers.get('Content-Range') or '').startswith('bytes '+str(offset)+'-'),'Range start differs')
            with part.open('ab' if offset else 'xb') as f:
                os.fchown(f.fileno(),1204,1205);os.fchmod(f.fileno(),0o600);total=offset;deadline=time.monotonic()+2700
                while True:
                    need(time.monotonic()<deadline,'Asset download time bound exceeded')
                    chunk=response.read(min(1024**2,item['bytes']-total+1))
                    if not chunk:break
                    total+=len(chunk);need(total<=item['bytes'],'Asset larger than fixed descriptor');f.write(chunk);h.update(chunk)
                f.flush();os.fsync(f.fileno());need(total==item['bytes'],'Truncated asset; partial preserved')
    need(h.hexdigest()==item['sha256'],'Asset checksum differs; partial preserved')
    need(not target.exists(),'Destination appeared during download');os.rename(part,target)
    state.setdefault('verifiedFiles',[]).append(relative);atomic(state_path,state)
    print('SNAPSHOT_FILE_VERIFIED='+relative,flush=True)

def main():
    need(os.getuid()==os.geteuid()==0,'Root relay scope required');os.umask(0o077)
    node={'server1':'node-a','agent1':'node-b'}.get(socket.gethostname());need(node,'A/B only')
    directory(ROOT,0);work=ROOT/node;directory(work,0);state_path=work/'state.json'
    state=json.loads(read(state_path)) if state_path.exists() else {'node':node,'identity':identity(),'runId':RUN}
    need(state['node']==node and state['identity']==identity() and state['runId']==RUN,'Previous transfer identity differs')
    atomic(state_path,state);api,client=load_api()
    key='titanic-transfer/'+SESSION+'/'+RUN+'/manifest.json'
    if node=='node-a':
        verified=json.loads(read(Path('/home/jwk/root/titanic-candidate-capture-20261102/snapshot-verified.json')))
        need(verified['templateId']==SID and verified['catalogSha256']==CATALOG_SHA and verified['temporaryFcExited'] is True,'Captured source proof differs')
        entries=[]
        for item in verified['artifacts']:
            if item['kind']=='rootfs':continue
            p=Path(item['file']);need(p.is_relative_to(SOURCE),'Captured source outside repository')
            relative=p.relative_to(SOURCE).as_posix();need(safe_relative(relative),'Unreviewed artifact path')
            entries.append({'relative':relative,'bytes':item.get('bytes',item.get('size')),'sha256':item.get('sha256',item.get('digest','')[7:])})
        catalog=SOURCE/'catalog/records'/(SID+'.json');need(file_sha(catalog)==CATALOG_SHA,'Catalog changed')
        entries.append({'relative':catalog.relative_to(SOURCE).as_posix(),'bytes':catalog.stat().st_size,'sha256':CATALOG_SHA})
        need(len(entries)<=8 and sum(r['bytes'] for r in entries)<MAX_FILE and len({r['relative'] for r in entries})==len(entries),'Transfer scope exceeds bounds')
        validate_assets(entries)
        for row in entries:need(0<row['bytes']<=MAX_FILE and file_sha(SOURCE/row['relative'])==row['sha256'],'Captured artifact checksum differs')
        release_id=ensure_release(client,state,state_path)
        # Validate the real upload route using the required smallest artifact first.
        # Do not spend time starting the 424MiB transfer before this succeeds.
        assets=[upload(client,api,release_id,item,state,state_path) for item in sorted(entries,key=lambda x:x['bytes'])]
        value={'schema':1,'runId':RUN,'templateId':SID,'catalogSha256':CATALOG_SHA,'releaseId':release_id,
            'assets':assets,'rootfsCopied':False,'rootfsRequiresStrictUbIndex':True,'sourceIdentity':identity()}
        client.immutable_result(REPO,REPO_ID,'main',key,wire(value))
        state['phase']='snapshot_assets_published_rootfs_not_copied';atomic(state_path,state)
        print('TITANIC_SNAPSHOT_ASSETS_PUBLISHED_PRIVATE')
    else:
        deadline=time.monotonic()+3600
        while True:
            code,raw,_=client.contents(REPO,key,'main')
            if code==200:break
            need(code==404 and time.monotonic()<deadline,'Snapshot publication unavailable; no resource change')
            print('WAIT_TITANIC_SNAPSHOT_ASSETS',flush=True);time.sleep(15)
        value=json.loads(raw);need(value['schema']==1 and value['runId']==RUN and value['templateId']==SID and value['catalogSha256']==CATALOG_SHA,'Transfer manifest differs')
        need(value['rootfsCopied'] is False and value['rootfsRequiresStrictUbIndex'] is True,'Unexpected ordinary rootfs fallback')
        need(len(value['assets'])<=8 and sum(r['bytes'] for r in value['assets'])<MAX_FILE,'Transfer manifest too large')
        validate_assets(value['assets'])
        for item in sorted(value['assets'],key=lambda r:(r['relative'].startswith('catalog/'),r['relative'].endswith('/commit'),r['relative'])):
            download(client,item,state,state_path)
        need(file_sha(DEST/'catalog/records'/(SID+'.json'))==CATALOG_SHA,'Imported catalog changed')
        state['phase']='snapshot_files_verified_not_runnable_without_UB';atomic(state_path,state)
        print('TITANIC_B_SNAPSHOT_FILES_VERIFIED_NOT_GUEST_ACCEPTANCE')
    print(json.dumps({'status':state['phase'],'node':node,'templateId':SID,'rootfsCopied':False,'SDKCalled':False,'GuestCreated':False,
        'servicesChanged':False,'UBAllocated':False,'bytesInAssets':sum(r['bytes'] for r in value['assets'])},indent=2))

if __name__=='__main__':
    try:main()
    except BaseException as error:
        print(json.dumps({'status':'TITANIC_TRANSFER_STOPPED_PRESERVE_STATE',**safe_network_detail(error)}),flush=True)
        raise SystemExit(1)
