"""Transfer the verified original OCI and immutable rootfs commits; never a DB.

Only the known experiment input is selected. pack reads the existing successful
export selection; receive verifies a new local archive; seed writes only the
not-yet-started coordinated deployment. No SDK or Guest operations occur here.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tarfile

ROOT=Path('/home/jwk/agent')
DEPLOYMENT=ROOT/'deployments/agentenv-native-d3e61ea'
CORE='d3e61ea93495f1eff668934a003d4ca87c7cfa94'
HELPER_SHA='424ddd4cb3edc36f52b79081fedbfda67fed569578df0d7a323824611d94e048'
OCI=ROOT/'relay/reports/node-a-cow-parent-mbw69dma/image'
OCI_DIGEST='sha256:039f1b18eb5c1bf56c074234e718af2f6156cbb729d638f05d1d8cf95dffe409'
SOURCE='sha256:cf786498f77bf4ba6235156ab8540d0b9335e874e70b95efbeb53168e0dce68d'
GIB=1024**3


def need(ok,reason):
    if not ok:raise ValueError(reason)


def stamp(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def safe(path,exists=True):
    path=Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=exists)==path,'Path outside experiment root or redirected')
    return path


def opened(path,limit=2*GIB):
    fd=os.open(safe(path),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        meta=os.fstat(fd)
        # Read-only source commit files may legitimately have repository hardlinks.
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and 0<meta.st_size<=limit,'Unexpected source type/owner/length')
        return os.fdopen(fd,'rb'),meta
    except BaseException:os.close(fd);raise


def read(path,limit=2*1024**2):
    stream,before=opened(path,limit)
    with stream:
        value=stream.read(before.st_size+1)
        need(len(value)==before.st_size and stamp(before)==stamp(os.fstat(stream.fileno())),'Input changed')
    return value


def transfer(source,length,target=None):
    digest=hashlib.sha256();left=length
    while left:
        block=source.read(min(left,1024**2));need(bool(block),'Short input')
        left-=len(block);digest.update(block)
        if target is not None:target.write(block)
    need(not source.read(1),'Input exceeds declared length')
    return digest.hexdigest()


def copy_checked(path,destination,row):
    source,before=opened(path)
    need(before.st_size==row['bytes'],'Source length differs')
    with source,destination.open('xb') as target:
        need(transfer(source,row['bytes'],target)==row['sha256'],'Source digest differs')
        need(stamp(before)==stamp(os.fstat(source.fileno())),'Source changed while copying')
        target.flush();os.fsync(target.fileno())


def identity(layers):
    value=[0,[{'digest':x['digest'],'size':x['size']} for x in layers]]
    return 'sha256:'+hashlib.sha256(json.dumps(value,separators=(',',':')).encode()).hexdigest()


def validate_config(config,layers):
    need(isinstance(config,dict) and len(layers)==12 and identity(layers)==SOURCE,'Unexpected original source identity')
    upper=config.get('upper') or {}
    need(isinstance(upper,dict) and not any(upper.get(k) for k in ('data','index','target','gzipIndex')),'Mutable upper is not an input base')
    values=config.get('lowers',[])
    need(len(values)==len(layers),'Source layer count differs')
    for value,layer in zip(values,layers):
        need({k:value.get(k) for k in ('digest','size')}=={k:layer[k] for k in ('digest','size')},'Source layer order/content differs')
        need(not any(value.get(k) for k in ('ub','gzipIndex','targetFile','targetDigest')),'Unsupported source layer backing')
    need(not config.get('resultFile') and not config.get('recordTracePath') and not config.get('accelerationLayer'),
         'Mutable tracing/result/acceleration config is not transferable')


def validate_manifest(manifest):
    need(set(manifest)=={'version','coreCommit','sourceImage','ociManifest','layers','ociBlobs','files'}
         and type(manifest['version']) is int and manifest['version']==1 and manifest['coreCommit']==CORE
         and manifest['sourceImage']==SOURCE and manifest['ociManifest']==OCI_DIGEST,'Input package identity differs')
    layers=manifest['layers'];need(isinstance(layers,list) and len(layers)==12 and identity(layers)==SOURCE,'Wrong original lower selection')
    expected={'source-config.json','oci/index.json','oci/oci-layout'}
    for row in layers+manifest['ociBlobs']:
        need(set(row)=={'digest','size'} and re.fullmatch(r'sha256:[0-9a-f]{64}',row['digest'])
             and type(row['size']) is int and 0<row['size']<=2*GIB,'Bad content descriptor')
    need(2<=len(manifest['ociBlobs'])<=14,'Unexpected OCI inventory')
    need(OCI_DIGEST in {x['digest'] for x in manifest['ociBlobs']},'OCI manifest missing')
    expected.update('layers/'+x['digest'][7:]+'.commit' for x in layers)
    expected.update('oci/blobs/sha256/'+x['digest'][7:] for x in manifest['ociBlobs'])
    need(set(manifest['files'])==expected,'File selection differs')
    for name,row in manifest['files'].items():
        need(set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=2*GIB
             and re.fullmatch('[0-9a-f]{64}',row['sha256']),'Bad file descriptor')
    for kind,rows in (('layers',layers),('oci',manifest['ociBlobs'])):
        for row in rows:
            name=('layers/'+row['digest'][7:]+'.commit') if kind=='layers' else ('oci/blobs/sha256/'+row['digest'][7:])
            need(manifest['files'][name]=={'bytes':row['size'],'sha256':row['digest'][7:]},'Blob/layer descriptor mismatch')
    need(sum(r['bytes'] for r in manifest['files'].values())<=3*GIB,'Input package exceeds 3 GiB')
    return manifest['files']


def validate_oci_inventory(manifest,raw,config_raw):
    need('sha256:'+hashlib.sha256(raw).hexdigest()==OCI_DIGEST,'OCI manifest content differs')
    oci=json.loads(raw);need(oci.get('schemaVersion')==2 and len(oci.get('layers',[]))==12,'OCI shape differs')
    rows=[{'digest':OCI_DIGEST,'size':len(raw)}]+[{k:r[k] for k in ('digest','size')} for r in [oci['config']]+oci['layers']]
    expected={r['digest']:r['size'] for r in rows}
    need(all(expected[r['digest']]==r['size'] for r in rows)
         and expected=={r['digest']:r['size'] for r in manifest['ociBlobs']},'OCI blob closure is incomplete')
    need(len(config_raw)==oci['config']['size'] and 'sha256:'+hashlib.sha256(config_raw).hexdigest()==oci['config']['digest'],'OCI config content differs')
    config=json.loads(config_raw)
    need(config.get('os')=='linux' and config.get('architecture')=='arm64','OCI architecture differs')


def validate_received_oci(directory,manifest):
    raw=read(directory/'oci/blobs/sha256'/OCI_DIGEST[7:])
    config_digest=json.loads(raw)['config']['digest']
    need(re.fullmatch(r'sha256:[0-9a-f]{64}',config_digest),'Invalid OCI config digest')
    validate_oci_inventory(manifest,raw,read(directory/'oci/blobs/sha256'/config_digest[7:]))


def select_inputs():
    helper=ROOT/'A_export_real_rootfs_v1.py';raw=read(helper)
    need(hashlib.sha256(raw).hexdigest()==HELPER_SHA,'Prior reviewed input selector differs')
    scope={'__name__':'verified_input_selector'};exec(compile(raw,str(helper),'exec'),scope)
    request,evidence,(_,source_raw),_=scope['inputs']()
    need(request['sourceImage']==SOURCE,'Original source identity differs')
    layers=[{k:x[k] for k in ('digest','size')} for x in request['layers']]
    validate_config(json.loads(source_raw),layers)
    inputs={'source-config.json':source_raw}
    files={}
    for row in request['layers']:
        name='layers/'+row['digest'][7:]+'.commit';inputs[name]=Path(row['path'])
        files[name]={'bytes':row['size'],'sha256':row['digest'][7:]}
    manifest_path=OCI/'blobs/sha256'/OCI_DIGEST[7:];manifest_raw=read(manifest_path)
    need('sha256:'+hashlib.sha256(manifest_raw).hexdigest()==OCI_DIGEST,'Original OCI manifest differs')
    oci=json.loads(manifest_raw)
    need(oci.get('schemaVersion')==2 and len(oci.get('layers',[]))==12,'Unexpected OCI layer inventory')
    blobs=[{'digest':OCI_DIGEST,'size':len(manifest_raw)}]+[{k:r[k] for k in ('digest','size')} for r in [oci['config']]+oci['layers']]
    by_digest={r['digest']:r for r in blobs}
    need(all(by_digest[r['digest']]==r for r in blobs),'Conflicting OCI descriptors')
    blobs=list(by_digest.values())
    config=json.loads(read(OCI/'blobs/sha256'/oci['config']['digest'][7:]))
    need(config.get('architecture')=='arm64' and config.get('os')=='linux','Expected Linux ARM64 OCI')
    for row in blobs:
        name='oci/blobs/sha256/'+row['digest'][7:];inputs[name]=OCI/'blobs/sha256'/row['digest'][7:]
        files[name]={'bytes':row['size'],'sha256':row['digest'][7:]}
    inputs['oci/oci-layout']=b'{"imageLayoutVersion":"1.0.0"}\n'
    inputs['oci/index.json']=json.dumps({'schemaVersion':2,'manifests':[{
        'mediaType':oci.get('mediaType','application/vnd.oci.image.manifest.v1+json'),
        'digest':OCI_DIGEST,'size':len(manifest_raw),'platform':{'os':'linux','architecture':'arm64'},
        'annotations':{'org.opencontainers.image.ref.name':'verified-base'}}]},separators=(',',':')).encode()
    for name,item in inputs.items():
        if isinstance(item,bytes):files[name]={'bytes':len(item),'sha256':hashlib.sha256(item).hexdigest()}
    manifest={'version':1,'coreCommit':CORE,'sourceImage':SOURCE,'ociManifest':OCI_DIGEST,
              'layers':layers,'ociBlobs':blobs,'files':files}
    validate_manifest(manifest)
    validate_oci_inventory(manifest,manifest_raw,read(OCI/'blobs/sha256'/oci['config']['digest'][7:]))
    return inputs,manifest


def pack(destination):
    inputs,manifest=select_inputs();destination=safe(destination,False)
    need(not destination.exists() and destination.parent.is_dir(),'Fresh archive required')
    need(shutil.disk_usage(destination.parent).free>=sum(r['bytes'] for r in manifest['files'].values())+2*GIB,'Insufficient pack headroom')
    with destination.open('xb') as output,tarfile.open(fileobj=output,mode='w') as archive:
        data=json.dumps(manifest,sort_keys=True,indent=2).encode()
        info=tarfile.TarInfo('manifest.json');info.size=len(data);info.mode=0o600;archive.addfile(info,io.BytesIO(data))
        for name,item in inputs.items():
            row=manifest['files'][name];info=tarfile.TarInfo(name);info.size=row['bytes'];info.mode=0o600
            if isinstance(item,bytes):archive.addfile(info,io.BytesIO(item));continue
            source,before=opened(item);need(before.st_size==row['bytes'],'Source size changed')
            with source:
                digest=hashlib.sha256()
                class Reader:
                    def read(self,length):
                        data=source.read(length);digest.update(data);return data
                archive.addfile(info,Reader())
                need(not source.read(1) and stamp(before)==stamp(os.fstat(source.fileno())),'Source changed during pack')
                need(digest.hexdigest()==row['sha256'],'Source SHA256 changed')
    stream,meta=opened(destination,3*GIB+1024**2)
    with stream:sha=transfer(stream,meta.st_size)
    return {'status':'ROOTFS_INPUTS_PACKED_NOT_TRANSFERRED','archive':str(destination),'bytes':meta.st_size,
            'sha256':sha,'sourceImage':SOURCE,'databaseCopied':False,'UB_published':False}


def receive(archive_path,pin,destination):
    need(re.fullmatch('[0-9a-f]{64}',pin),'Explicit archive SHA256 required')
    stream,before=opened(archive_path,3*GIB+1024**2)
    with stream:
        need(transfer(stream,before.st_size)==pin,'Archive SHA256 differs');stream.seek(0)
        with tarfile.open(fileobj=stream,mode='r:') as archive:
            members=[]
            for item in archive:
                members.append(item);need(len(members)<=32 and item.isfile() and not item.issparse(),'Invalid archive members')
            need(len({m.name for m in members})==len(members),'Duplicate archive members')
            info=archive.getmember('manifest.json');need(0<info.size<=65536,'Invalid manifest size')
            manifest=json.load(archive.extractfile(info));files=validate_manifest(manifest)
            need({m.name for m in members}==set(files)|{'manifest.json'},'Archive inventory differs')
            need(all(archive.getmember(n).size==r['bytes'] for n,r in files.items()),'Archive member sizes differ')
            destination=safe(destination,False);need(not destination.exists() and not destination.is_symlink(),'Fresh destination required')
            need(shutil.disk_usage(destination.parent).free>=sum(r['bytes'] for r in files.values())+2*GIB,'Insufficient receive headroom')
            destination.mkdir(mode=0o700)
            for name,row in files.items():
                path=destination/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                with archive.extractfile(name) as source,path.open('xb') as target:
                    need(transfer(source,row['bytes'],target)==row['sha256'],'Member digest differs')
                    target.flush();os.fsync(target.fileno())
            need(stamp(before)==stamp(os.fstat(stream.fileno())),'Archive changed')
    validate_received_oci(destination,manifest)
    with (destination/'manifest.json').open('x') as target:json.dump(manifest,target,indent=2)
    return {'status':'ROOTFS_INPUTS_RECEIVED_NOT_SEEDED','inputDirectory':str(destination),'archiveSha256':pin,'sourceImage':SOURCE}


def unit_absent(node):
    result=subprocess.run(['/usr/bin/systemctl','show','jwk-aenv-native-d3e61ea-'+node+'.service',
                           '--property=LoadState','--value'],capture_output=True,text=True,timeout=10)
    need(result.stdout.strip()=='not-found','New Runtime already exists; never seed a running state')


def seed(directory,node):
    import fcntl
    import tomllib
    directory=safe(directory);deployment=safe(DEPLOYMENT)
    installation=json.loads(read(deployment/'installation.json'))
    need(installation.get('node')==node and installation.get('commit')==CORE,'Prepared deployment identity differs')
    definition=json.loads(read(deployment/'definition-native.json'))
    config_text=read(deployment/'config/runtime.toml').decode()
    need(definition.get('node')==node and definition.get('config')==config_text,'Immutable deployment definition differs')
    config=tomllib.loads(config_text)
    need(config['home_path']==str(deployment/'state') and config['image']['cache']['gc']['enabled'] is False
         and 'root_dir' not in config['image']['cache'],'Expected isolated default cache with GC disabled')
    lock=os.open(deployment/'cohort.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);unit_absent(node)
        journal=json.loads(read(deployment/'cohort-state.json'))
        need(journal=={'version':1,'phase':'prepared','openRequests':[],'sandboxIds':[],'outcomeUncertain':False},'Initial untouched deployment required')
        manifest=json.loads(read(directory/'manifest.json'));files=validate_manifest(manifest)
        validate_received_oci(directory,manifest)
        raw=read(directory/'source-config.json')
        need(hashlib.sha256(raw).hexdigest()==files['source-config.json']['sha256'],'Source config differs')
        original=json.loads(raw);validate_config(original,manifest['layers'])
        for name,row in files.items():
            if name.startswith('layers/'):continue # checked while copying below
            stream,before=opened(directory/name)
            with stream:
                need(before.st_size==row['bytes'] and transfer(stream,row['bytes'])==row['sha256'],'Input metadata/OCI changed')
                need(stamp(before)==stamp(os.fstat(stream.fileno())),'Input changed during verification')
        total=sum(x['size'] for x in manifest['layers'])
        need(shutil.disk_usage(deployment).free>=total+2*GIB,'Insufficient seed headroom')
        cache=deployment/'state/image-cache';temporary=deployment/'state/image-cache-seed.partial'
        need(not cache.exists() and not cache.is_symlink() and not temporary.exists() and not temporary.is_symlink(),'Prior cache or partial seed preserved')
        temporary.mkdir(mode=0o700);(temporary/'configs').mkdir(mode=0o700);(temporary/'commits').mkdir(mode=0o700)
        lowers=[]
        for layer,value in zip(manifest['layers'],original['lowers']):
            relative=Path('commits')/layer['digest'].replace(':','-')/'overlaybd.commit'
            target=temporary/relative;target.parent.mkdir(mode=0o700,exist_ok=True)
            name='layers/'+layer['digest'][7:]+'.commit'
            if not target.exists():copy_checked(directory/name,target,files[name])
            lower={'file':str(cache/relative),'digest':layer['digest'],'size':layer['size']}
            if value.get('uuid'):lower['uuid']=value['uuid']
            lowers.append(lower)
        derived={'lowers':lowers,'upper':{},'repoBlobUrl':''}
        validate_config(derived,manifest['layers'])
        name=OCI_DIGEST.replace(':','-')+'-image.json'
        data=(json.dumps(derived,indent=2)+'\n').encode()
        with (temporary/'configs'/name).open('xb') as target:target.write(data);target.flush();os.fsync(target.fileno())
        unit_absent(node)
        os.rename(temporary,cache) # New destination only; live source/state never moved.
        receipt={'status':'ORIGINAL_ROOTFS_INPUTS_SEEDED_NOT_GUEST_ACCEPTANCE','node':node,'coreCommit':CORE,
                 'sourceImage':SOURCE,'layers':manifest['layers'],'sourceConfig':str(cache/'configs'/name),
                 'sourceConfigSha256':hashlib.sha256(data).hexdigest(),'ociReference':'ocidir://'+str(directory/'oci')+'@'+OCI_DIGEST,
                 'databaseCopied':False,'SDK_called':False,'Guest_created':False,'servicesChanged':False,
                 'preparationReadAllInputs':True,'coldCacheClaimed':False}
        with (deployment/'rootfs-inputs.json').open('x') as target:json.dump(receipt,target,indent=2);target.flush();os.fsync(target.fileno())
        return receipt
    finally:os.close(lock)


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='mode',required=True)
    p=sub.add_parser('pack');p.add_argument('--archive',type=Path,required=True)
    p=sub.add_parser('receive');p.add_argument('--archive',type=Path,required=True);p.add_argument('--sha256',required=True);p.add_argument('--destination',type=Path,required=True)
    p=sub.add_parser('seed');p.add_argument('--input-directory',type=Path,required=True);p.add_argument('--node',choices=('node-a','node-b'),required=True)
    for p in sub.choices.values():p.add_argument('--run',action='store_true')
    args=parser.parse_args()
    if not args.run:print(json.dumps({'status':'PLAN_ONLY','mode':args.mode,'SDK_called':False,'servicesChanged':False}));return 0
    need(os.name=='posix' and os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Use ordinary experiment user')
    caps=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(caps[k].strip(),16)==0 for k in ('CapInh','CapPrm','CapEff','CapAmb')),'Zero capabilities required')
    if args.mode=='pack':need(socket.gethostname()=='server1','Input pack uses node A verified source')
    if args.mode=='seed':need(socket.gethostname()==('server1' if args.node=='node-a' else 'agent1'),'Use declared seed node')
    os.umask(0o077)
    if args.mode=='pack':result=pack(args.archive)
    elif args.mode=='receive':result=receive(args.archive,args.sha256,args.destination)
    else:result=seed(args.input_directory,args.node)
    print(json.dumps(result,indent=2));return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED_ROOTFS_INPUTS_PRESERVE_ALL_OUTPUTS','errorType':type(error).__name__,
                          'reason':str(error)[:1000],'SDK_called':False,'servicesChanged':False},indent=2));raise SystemExit(1)
