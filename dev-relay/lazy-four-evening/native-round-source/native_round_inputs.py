"""Bound native coordinator inputs before SDK allocation or service activation."""
import hashlib,json,os,re,stat
from pathlib import Path

ROOT=Path('/home/jwk/agent')
CORE='5e6621c9c9d2e347959a61a46c7f6d99688eeb55'
LEGACY='32ce41c0ac6436198860f888e07ef9793e58dc40'
LEGACY_TREE='0e973a6e101c1a1c71b48bf70f2d910f48cd672f'
MIB=1024**2

def need(ok,reason):
    if not ok:raise RuntimeError(reason)

def read(path,limit=2*MIB):
    path=Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Redirected input path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        before=os.fstat(source.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204 and before.st_nlink==1 and 0<before.st_size<=limit,'Unexpected input metadata')
        data=source.read(limit+1);after=os.fstat(source.fileno())
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(data)==before.st_size,'Input changed')
    return data

def digest_file(path,limit):
    path=Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Redirected content path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        before=os.fstat(source.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204 and 0<before.st_size<=limit,'Content type/size/owner differs')
        digest=hashlib.file_digest(source,'sha256').hexdigest();after=os.fstat(source.fileno())
    stamp=lambda m:(m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
    need(stamp(before)==stamp(after),'Content changed during validation')
    return digest,before.st_size

def paths(node,scenario):
    need(node in ('node-a','node-b') and scenario in ('single-a','dual-ab')
         and (scenario=='dual-ab' or node=='node-a'),'Unsupported native node/scenario')
    prefix='native-archive-single' if scenario=='single-a' else 'native-archive'
    work=ROOT/'r'/(prefix+'-rollout-v1')
    return {'work':work,'deployment':ROOT/'deployments'/(prefix+'-v1'),
            'source':ROOT/(prefix+'-provider-source'),'provider':work/('generation-'+node),
            'providerPlan':work/('provider-plan-'+node),'unit':'jwk-aenv-'+prefix+'-v1-'+node+'.service'}

def preflight_a(preparation,legacy_report,runtime_report,tools_report):
    prepared=json.loads(read(preparation))
    need(prepared.get('status')=='FOUR_NATIVE_IMAGES_AND_BINARIES_PREPARED_NOT_DEPLOYED'
         and prepared.get('coreCommit')==LEGACY and prepared.get('coreTree')==LEGACY_TREE
         and len(prepared.get('cases',[]))==4,'Complete retained native raw preparation is required; do not rerun/export automatically')
    legacy=json.loads(read(legacy_report));runtime=json.loads(read(runtime_report));tools=json.loads(read(tools_report))
    need(legacy.get('status')=='COORDINATED_CANDIDATE_BINARIES_BUILT_NOT_DEPLOYED'
         and legacy.get('release',{}).get('coreCommit')==LEGACY and legacy['release'].get('tree')==LEGACY_TREE,
         'Retained coordinated build incomplete')
    need(runtime.get('status')=='CONTENT_OBSERVER_BINARIES_BUILT_TESTED_NOT_DEPLOYED'
         and runtime.get('release',{}).get('coreCommit')==CORE,'Current Runtime build incomplete; use the pinned offline builder first')
    required={'native-archive-file-lifecycle-tests','provider-protocol-and-archive-tests','content-observer-source-tests',
              'native-posix-archive-publication-tests','build-content-observer-binaries'}
    need(set(runtime.get('phases',{}))==required and all(v.get('exitCode')==0 for v in runtime['phases'].values()),'New Runtime tests/build incomplete')
    need(tools.get('status')=='PRIVATE_TOOLS_IMAGE_PREPARED_NOT_GUEST_ACCEPTANCE' and tools.get('mode')=='runtime'
         and tools.get('originalUnchanged') is True and tools.get('lowerFilesystem')=='ext4','Retained native Guest tools unavailable')
    return prepared,legacy,runtime,tools

def image_selection(prepared):
    images=[];contents={};sources=set()
    for index,item in enumerate(prepared['cases']):
        need(item.get('templateIndex')==index and item.get('resources',{}).get('cpu_count')==2
             and item['resources'].get('memory_mib')==4096,'Reference case order/resources differ')
        image=item['nativeImage'];path=Path(image['path'])
        expected=ROOT/'builds/native-four-inputs-v1'/('case-'+str(index))/'raw/rootfs.ext4'
        need(path==expected and type(image.get('bytes')) is int and 0<image['bytes']<=4096*MIB
             and image['bytes']%(2*MIB)==0,'Unexpected retained raw image path/size')
        digest,size=digest_file(path,4096*MIB)
        need(size==image['bytes'] and 'sha256:'+digest==image['sha256'],'Retained raw image content changed')
        config=json.loads(read(item['sourceConfig']))
        need(not any(config.get('upper',{}).get(k) for k in ('data','index','target','gzipIndex')),'Mutable source config refused')
        lowers=[{'digest':x['digest'],'size':x['size']} for x in config['lowers']]
        need(lowers and all(re.fullmatch('sha256:[0-9a-f]{64}',x['digest']) and type(x['size']) is int and x['size']>0 for x in lowers),
             'Committed source identities required')
        identity='sha256:'+hashlib.sha256(json.dumps([0,lowers],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        need(identity==item['sourceImage'] and identity not in sources,'Prepared source image identity differs or is repeated')
        sources.add(identity);contents[digest]=size
        images.append({'sourceConfig':item['sourceConfig'],'paths':[str(path)],'filesystem':'ext4'})
    logical=sum((size+4*MIB-1)//(4*MIB)*(4*MIB) for size in contents.values())
    coverage=sum((size+128*MIB-1)//(128*MIB)*(128*MIB)+128*MIB for size in contents.values())
    need(logical<=16*1024**3 and logical<=coverage<=18*1024**3,'Declared native generation budget exceeds field bounds')
    return {'version':1,'images':images},logical,coverage

def provider_request(node,scenario,selected_paths,adapter_pin,logical,coverage):
    layout=paths(node,scenario);previous=ROOT/('r/lazy4-a-v1' if node=='node-a' else 'r/lazy4-b-v1')
    need(re.fullmatch('[0-9a-f]{64}',adapter_pin),'Invalid retained adapter pin')
    request={'version':1,'scenario':scenario,'installation':str(layout['source']),
             'deviceRuntime':str(layout['work']/'device-runtime.json'),'output':str(layout['provider']),
             'adapter':str(previous/'libaenv-ub.so'),'adapterSha256':'sha256:'+adapter_pin,
             'region':'default','logicalBudgetBytes':logical,'coverageBytes':coverage}
    if node=='node-a':request['imageSet']=str(selected_paths['images'])
    else:
        request.update(bindingCatalog=str(selected_paths['binding']),bindingCatalogSha256='sha256:'+selected_paths['bindingSha256'],
                       publisherManifest=str(selected_paths['manifest']),publisherManifestSha256='sha256:'+selected_paths['manifestSha256'])
    return request

def write_private(path,value):
    # All checks precede this explicit stage; no SDK/service operation here.
    with Path(path).open('x') as output:
        json.dump(value,output,indent=2);output.flush();os.fsync(output.fileno())
