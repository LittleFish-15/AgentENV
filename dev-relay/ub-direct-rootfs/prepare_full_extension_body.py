"""Prepare four-template extension metadata; cannot start a provider or Guest.

The retained provider holds the node SDK guard. This entry neither acquires nor
changes that lock, and it never authorizes concurrent SDK initialization.
"""
import argparse,base64,hashlib,io,json,os,platform,re,stat,sys,tarfile,time,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
SOURCE=ROOT/'deployments/agentenv-lazy-four-32ce41c'
FULL=ROOT/'deployments/agentenv-direct-ub-guest-v1'
OWNER='563b042793d747b085a286e221a97993'
MANIFEST='sha256:92974af667c6e01c3394c76e9eb3a5e40aa508dd736ad189200a266384bb4ec0'
SEEDS={'a':'6247c51df4993d5a6935b7112567989bb189cff2bcf69e874d0154207b0ced15',
       'b':'91d33a86fb12ffa75e6b6af70f327566fc39ac9d7e79e362fbfa0e96a68f2294'}
APPROVED_TOTAL_COVERAGE=4*1024**3
QUANTUM=128*1024**2
RETAINED_EXPORT_COVERAGE=19*QUANTUM

def need(ok,reason):
    if not ok:raise RuntimeError(reason)

def read(path,limit=2*1024**2):
    need(path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Redirected/outside metadata input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204 and before.st_size<=limit,'Metadata owner/type/size differs')
        raw=stream.read(limit+1);after=os.fstat(stream.fileno())
    stamp=lambda m:(m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
    need(len(raw)==before.st_size and stamp(before)==stamp(after),'Metadata changed during read')
    return raw

def load(path):return json.loads(read(path))

def write(path,value):
    with path.open('x',encoding='utf-8') as stream:
        json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())

def seed_layers(seed,read_record,stat_layer):
    need(len(seed['templates'])==4,'Exactly four retained templates required')
    need(len({row['templateId'] for row in seed['templates']})==4
         and all(re.fullmatch('[A-Za-z0-9_-]{1,128}',row['templateId']) for row in seed['templates']),
         'Distinct bounded template identities required')
    selected={};identities=[]
    for index,template in enumerate(seed['templates']):
        need(template['templateIndex']==index and template['resources']=={'cpu_count':2,'memory_mib':4096},'Template order/resources differ')
        raw=read_record(template['templateId'])
        need(hashlib.sha256(raw).hexdigest()==template['catalogSha256'],'Catalog changed')
        record=json.loads(raw)
        need(record['id']==template['templateId'] and record['resources']==template['resources'],'Catalog identity/resources differ')
        rows=record['committed']['rootfs_layers']
        need(all(set(row)=={'Managed'} for row in rows) and [row['Managed'] for row in rows]==template['rootfsLayers'],
             'Committed rootfs sequence differs')
        for layer in template['rootfsLayers']:
            digest,size=layer['digest'],layer['size']
            need(re.fullmatch('sha256:[0-9a-f]{64}',digest) and type(size) is int and size>0,'Invalid lower identity')
            need(digest not in selected or selected[digest][1]==size,'Conflicting duplicate lower')
            if digest not in selected:
                path,identity=stat_layer(digest,size)
                selected[digest]=(path,size);identities.append({'digest':digest,'size':size,'fileIdentity':identity})
    need(len(selected)<=64,'Unique lower set exceeds provider bound')
    return selected,identities

def lock_snapshot(path,pid):
    """Observe only the exact guard inode. Never flock/unlink/touch the guard."""
    try:
        need(path.resolve(strict=True)==path,'SDK guard redirected')
        meta=path.stat();need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204,'SDK guard metadata differs')
        rows=[]
        for line in Path('/proc/locks').read_text().splitlines():
            parts=line.split()
            if len(parts)!=8 or parts[1]!='FLOCK':continue
            device=parts[5].split(':')
            if len(device)!=3:continue
            if (int(device[0],16),int(device[1],16),int(device[2]))==(os.major(meta.st_dev),os.minor(meta.st_dev),meta.st_ino):
                rows.append({'pid':int(parts[4]),'mode':parts[3],'start':parts[6],'end':parts[7]})
        return {'available':True,'rows':rows,'heldByRetainedProvider':any(row['pid']==pid for row in rows),
                'releaseOrBypassAttempted':False,'emptyRowsProveNoGuard':False}
    except (OSError,ValueError) as error:
        return {'available':False,'errorType':type(error).__name__,'heldByRetainedProvider':None,'releaseOrBypassAttempted':False}

def package(work):
    raw=zlib.decompress(base64.b64decode(PAYLOAD,validate=True))
    need(hashlib.sha256(raw).hexdigest()==ARCHIVE_SHA256,'Embedded core package changed')
    seen=set()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            need(member.isfile() and member.name in SOURCE_HASHES and member.name not in seen,'Unexpected package member')
            need(not Path(member.name).is_absolute() and '..' not in Path(member.name).parts,'Invalid package path')
            data=archive.extractfile(member).read();need(hashlib.sha256(data).hexdigest()==SOURCE_HASHES[member.name],'Package content differs')
            path=work/'source'/member.name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with path.open('xb') as output:output.write(data)
            seen.add(member.name)
    need(seen==set(SOURCE_HASHES),'Incomplete core package')
    need(not any(name.startswith('aenv_ub_provider') for name in sys.modules),'Provider package already imported from another source')
    sys.path.insert(0,str(work/'source'))
    from aenv_ub_provider import full_set,service
    return full_set,service

def prepare(node):
    need(sys.platform=='linux' and platform.machine()=='aarch64'
         and platform.node()=={'a':'server1','b':'agent1'}[node],'Wrong native node')
    need(os.getuid()==os.geteuid()==1204,'Prepare as ordinary jwk')
    caps=[line.split()[1] for line in Path('/proc/self/status').read_text().splitlines()
          if line.startswith(('CapInh:','CapPrm:','CapEff:','CapAmb:'))]
    need(len(caps)==4 and not any(int(value,16) for value in caps),'Zero capabilities required')
    old=ROOT/'r'/('uf-'+node+'-v1');work=ROOT/'r'/('uf4-meta-'+node+'-v1')
    need(work.parent.resolve(strict=True)==work.parent and not work.exists() and not work.is_symlink(),'Existing metadata preparation preserved')
    process=load(old/'provider-process.json');owner=load(old/'p/owner.json')
    need(type(process['pid']) is int and process['pid']>1 and re.fullmatch('[0-9]+',process['startTicks']),
         'Invalid retained process identity')
    need(owner['state']=='serving' and owner['ownerId']==OWNER and owner['manifestSha256']==MANIFEST,'Retained owner generation differs')
    def stable():
        need(process['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Provider boot changed')
        need((Path('/proc')/str(process['pid'])/'stat').read_text().rsplit(')',1)[1].split()[19]==process['startTicks'],'Retained provider exited/changed')
        need(load(old/'p/owner.json')==owner,'Retained provider owner state changed')
    stable()
    raw=read(SOURCE/'rootfs-inputs.json');need(hashlib.sha256(raw).hexdigest()==SEEDS[node],'Fixed seed changed')
    seed=json.loads(raw)
    need(seed['node']=='node-'+node and seed['status']=='ORDINARY_FOUR_SNAPSHOTS_SEEDED_NOT_GUEST_ACCEPTANCE','Seed provenance differs')
    repository=SOURCE/'state/snapshot-store/repository'
    need(seed['repository']==str(repository),'Retained repository path differs')
    def stat_layer(digest,size):
        path=repository/'managed-layers'/(digest.replace(':','_')+'.overlaybd.commit')
        need(path.resolve(strict=True)==path,'Lower path redirected')
        meta=path.stat();need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_size==size,'Lower metadata differs')
        return path,[meta.st_dev,meta.st_ino,meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns]
    sources,identities=seed_layers(seed,lambda sid:read(repository/'catalog/records'/(sid+'.json')),stat_layer)
    manifest=load(old/'p/replicas.json');index_bytes=read(old/'p/runtime-index.json');index=json.loads(index_bytes)
    definition=load(FULL/'guest-definition.json')
    need(definition['ub']['path']==str(old/'p/runtime-index.json') and definition['ub']['sha256']==hashlib.sha256(index_bytes).hexdigest(),
         'Retained Runtime index pin differs')
    mapping=load(old/'p/mapping-evidence.json')
    need(mapping['ownerId']==OWNER and mapping['manifestSha256']==MANIFEST
         and mapping['backingCoverageBytes']==RETAINED_EXPORT_COVERAGE,'Retained mapping coverage differs')
    os.umask(0o077);work.mkdir(mode=0o700)
    report={'status':'PREPARING_METADATA_ONLY','node':node,'coreCommit':CORE_REMOTE,'workDirectory':str(work),
            'SDKCalled':False,'GuestCreated':False,'servicesChanged':False,'providerStarted':False,
            'readyForAllocation':False,'globalSdkGuardBypassed':False,'runtimeIndexInstalled':False}
    try:
        full_set,service=package(work)
        need(service.identity(manifest)==MANIFEST and manifest['ownerId']==OWNER,'Retained manifest identity differs')
        refs=full_set.validate_fragment(manifest,index)
        need(len(refs)==8 and {r.objectName for r in refs}=={r['objectName'] for r in mapping['mappings']},'Retained eight-object scope differs')
        plan=full_set.plan_extension(sources,manifest,index,RETAINED_EXPORT_COVERAGE,QUANTUM,APPROVED_TOTAL_COVERAGE)
        write(work/'plan.json',plan);write(work/'lower-file-identities.json',identities)
        guard=lock_snapshot(ROOT/'relay'/('ub-layer-sdk-node-'+node+'.lock'),process['pid'])
        blocked=['existing_per_node_exclusive_sdk_guard_policy','native_multi_provider_coexistence_not_accepted',
                 'two_node_guest_pair_and_controlled_extension_launch_not_accepted']
        if not plan['withinDeclaredBudget']:blocked.append('projected_total_exceeds_current_4GiB_scope')
        write(work/'provider-proposal.json',{'launchable':False,'serviceConfig':None,'blockedBy':blocked,
             'proposedWorkDirectory':str(ROOT/'r'/('uf4-'+node+'-v1')/'p'),
             'role':'publish' if node=='a' else 'import','mode':'stored-direct',
             'newMappingBytes':plan['newMappingBytes'],'newProjectedCoverageBytes':plan['newProjectedCoverageBytes'],
             'totalProjectedCoverageBytes':plan['projectedTotalCoverageBytes'],
             'oldProviderDirectoryPreserved':str(old),'guardObservation':guard})
        stable()
        report.update(status='FULL_EXTENSION_METADATA_REVIEW_REQUIRED_NO_SDK',
            templates=4,uniqueLayers=len(sources),retainedLayers=len(refs),newLayers=len(plan['newLayers']),
            planSha256=service.identity(plan),retainedProvider=process,guardObservation=guard,blockedBy=blocked,
            projectedTotalCoverageBytes=plan['projectedTotalCoverageBytes'],
            retainedCostSource='reported A export coverage; B mappings are not an additional allocation',
            lowerPayloadRead=False,sourceRootfsFilesCopied=False)
    except Exception as error:
        report.update(status='STOPPED_EXTENSION_METADATA_PRESERVE_OUTPUTS',errorType=type(error).__name__,reason=str(error)[:800])
    write(work/'report.json',report)
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--node',choices=('a','b'),required=True)
    parser.add_argument('--prepare',action='store_true');args=parser.parse_args()
    if not args.prepare:
        print(json.dumps({'status':'PLAN_ONLY','SDKCalled':False,'canLaunchProviders':False,'budgetScopeBytes':APPROVED_TOTAL_COVERAGE}));return 0
    report=prepare(args.node);print(json.dumps(report,indent=2))
    return 0 if report['status']=='FULL_EXTENSION_METADATA_REVIEW_REQUIRED_NO_SDK' else 1

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED_EXTENSION_PREFLIGHT_NO_SDK','errorType':type(error).__name__,'reason':str(error)[:800]}))
        raise SystemExit(1)
