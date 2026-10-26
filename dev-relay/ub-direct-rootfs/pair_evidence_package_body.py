"""Collect retained pair receipts and merge them offline. No SDK/API actions.

Collection reads saved reports plus current provider identity and small device
attributes for an allocation ledger. It never repeats Guest or payload reads.
"""
import argparse,base64,hashlib,json,os,platform,re,stat,sys,time,types,uuid,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
WORK=ROOT/'deployments/agentenv-direct-ub-guest-v1/acceptance/direct-pair-v1'
CONTROLLER='6c01a15e36a056b29a400e52f33f38981ff0abf3ca939185e6a4074dd9fda1fa'
PHASES={'a':('a-written','a-released'),'b':('peer-isolated','b-released')}
COMMANDS={'a':('a-private-write',),'b':('b-after-a-write','b-after-a-exit')}

def need(ok,reason):
    if not ok:raise ValueError(reason)

def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def verifier():
    raw=zlib.decompress(base64.b64decode(VERIFIER['z64'],validate=True))
    need(digest(raw)==VERIFIER['sha256'],'Pinned receipt verifier changed')
    module=types.ModuleType('fixed_pair_verifier')
    exec(compile(raw,'<fixed-pair-verifier>','exec'),module.__dict__)
    return module

def names(node):
    return ['report.json','ready-receipt.json','pair-phases.json','state.json','command-intent.json','command-result.json',
            *[phase+'-receipt.json' for phase in PHASES[node]],
            *[label+suffix for label in COMMANDS[node] for suffix in ('-intent.json','-result.json')]]

def local_completion(node,values):
    need(set(values)==set(names(node)),'Incomplete or unexpected local receipt set')
    ready=values['ready-receipt.json'];report=values['report.json']
    journal=values['pair-phases.json'];life=values['state.json']
    need(ready['node']==report['node']==node and ready['runId']==report['pairRunId'],'Local pair identity differs')
    need(report['status']=='DIRECT_UB_ONE_REAL_GUEST_READY_RETAINED','Ready stage did not complete')
    need(journal['phase']==PHASES[node][-1] and 'pending' not in journal and 'error' not in journal,
         'Local continuation is incomplete/uncertain')
    need(life['runId']==ready['runId'] and not life['sandboxIds'] and not life['openRequests']
         and life['outcomeUncertain'] is False,'Unresolved local API journal')
    for label,file in [('base-read','command-intent.json'),*[(label,label+'-intent.json') for label in COMMANDS[node]]]:
        intent=values[file]
        need(intent['label']==label and intent['sandboxId']==ready['sandboxId']
             and intent['guestTimeoutSeconds']==300 and intent['cliTimeoutSeconds']==330,'Command intent scope/timeout differs')
    for phase in PHASES[node]:
        receipt=values[phase+'-receipt.json']
        need(receipt['kind']==phase and receipt['node']==node and receipt['runId']==ready['runId']
             and receipt['controllerSha256']==CONTROLLER,'Continuation controller or phase differs')

def read_owned(path,root_only=False):
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Redirected/outside evidence file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid in ((0,) if root_only else (0,1204))
             and before.st_size<=2*1024**2,'Evidence owner/type/size differs')
        raw=stream.read(2*1024**2+1);after=os.fstat(stream.fileno())
    stamp=lambda m:(m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
    need(len(raw)==before.st_size and stamp(before)==stamp(after),'Evidence changed while reading')
    return {'sha256':digest(raw),'bytes':len(raw),'stat':list(stamp(before)),
            'value':json.loads(raw),'rawBase64':base64.b64encode(raw).decode()}

def provider_identity(node,expected):
    path=ROOT/'r'/('uf-'+node+'-v1')/'provider-process.json'
    actual=read_owned(path)['value'];need(actual==expected,'Provider identity differs from accepted ready report')
    need(actual['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Provider boot changed')
    proc=Path('/proc')/str(actual['pid'])
    need((proc/'stat').read_text().rsplit(')',1)[1].split()[19]==actual['startTicks'],'Provider PID exited/reused')
    status=(proc/'status').read_text()
    uids=re.search(r'(?m)^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$',status)
    need(uids and [int(v) for v in uids.groups()]==[1204]*4,'Provider UID changed')
    return actual

def region_rows(node,mapping):
    """Small current sysfs metadata, not VMA/PFN or lower-content sampling."""
    devices={}
    for obj in mapping['mappings']:
        offset=0
        for seg in obj['segments']:
            need(seg['logicalOffset']==offset and seg['bytes']>0,'Incomplete mapped segment layout')
            offset+=seg['bytes'];name=seg['device']
            need(re.fullmatch('/dev/obmm_shmdev[0-9]+',name),'Unexpected OBMM device path')
            if name in devices:
                need((devices[name]['major'],devices[name]['minor'])==(seg['major'],seg['minor']),'Conflicting device identity')
                continue
            meta=Path(name).stat()
            need(stat.S_ISCHR(meta.st_mode) and (os.major(meta.st_rdev),os.minor(meta.st_rdev))==(seg['major'],seg['minor']), 'Mapped device changed')
            base=Path('/sys/devices/obmm')/Path(name).name
            def attribute(field):
                value=(base/field).read_text().strip();need(len(value)<=128,'Oversized device metadata');return value
            role=attribute('type');size=int(attribute('size'),0)
            need(role==('export' if node=='a' else 'import') and 0<size<=16*1024**3,'Device role/size differs')
            reservation=int(attribute('export_info/node_mem_size'),0) if node=='a' else None
            need(node!='a' or 0<reservation<=16*1024**3,'Export node reservation unavailable')
            field='export_info/deid' if node=='a' else 'import_info/deid'
            endpoint=attribute(field)
            need(re.fullmatch(r'0x[0-9a-f]+:0x[0-9a-f]+',endpoint),'Invalid export endpoint identity')
            after=Path(name).stat()
            need((meta.st_rdev,meta.st_ino,meta.st_ctime_ns)==(after.st_rdev,after.st_ino,after.st_ctime_ns),'Device changed during observation')
            devices[name]={'device':name,'major':seg['major'],'minor':seg['minor'],'inode':meta.st_ino,
                           'role':role,'bytes':size,'reservationBytes':reservation,'exportEndpoint':endpoint}
        need(offset==obj['mappingBytes'],'Object segments do not cover mapping length')
    return list(devices.values())

def collect(node,output):
    need(sys.platform=='linux' and os.getuid()==os.geteuid()==0
         and platform.node()=={'a':'server1','b':'agent1'}[node],'Collect on declared node as root')
    need(output.parent==WORK and output.name=='evidence-'+node+'.json' and not output.exists() and not output.is_symlink(),
         'Use fresh fixed local evidence output')
    need(WORK.resolve(strict=True)==WORK and WORK.stat().st_uid==0,'Pair evidence directory changed')
    import fcntl
    lock=os.open(WORK/'run.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        meta=os.fstat(lock);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and meta.st_nlink==1,'Pair snapshot lock changed')
        fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
        files={name:read_owned(WORK/name,True) for name in names(node)}
        need(sum(row['bytes'] for row in files.values())<=4*1024**2,'Combined receipt budget exceeded')
        values={name:row['value'] for name,row in files.items()};local_completion(node,values)
        ready=values['report.json'];provider=provider_identity(node,ready['provider']['providerProcess'])
        root=ROOT/'r'/('uf-'+node+'-v1')/'p'
        owner=read_owned(root/'owner.json')['value'];mapping_record=read_owned(root/'mapping-evidence.json')
        mapping=mapping_record['value'];initial=values['ready-receipt.json']
        need(owner['state']=='serving' and owner['ownerId']==mapping['ownerId']==initial['ownerId']
             and owner['manifestSha256']==mapping['manifestSha256']==initial['manifestSha256'],'Retained allocation context differs')
        region_error=None
        try:rows=region_rows(node,mapping)
        except OSError as error:
            rows=None;region_error={'type':type(error).__name__,'reason':'Current device metadata unavailable; allocation ledger remains NA'}
        provider_identity(node,provider)
        for name,row in files.items():need(read_owned(WORK/name,True)['sha256']==row['sha256'],'Evidence replaced during collection')
        result={'version':1,'kind':'retained-pair-evidence','node':node,'collectorSha256':digest(Path(__file__).read_bytes()),
                'collectedUnixNs':time.time_ns(),'files':files,'providerIdentity':provider,'mappingEvidence':mapping_record,
                'currentRegions':rows,'regionObservationError':region_error,
                'SDKCalled':False,'GuestCommandsRun':False,'APIRequestsMade':False,
                'rawGuestOutputIncluded':False,'physicalSharingAccepted':False,'netSavingsBytes':None,
                'scope':'saved receipts plus current provider identity and small device metadata; not a new Guest or payload test'}
        raw=json.dumps(result,indent=2).encode();need(len(raw)<=16*1024**2,'Evidence capsule budget exceeded')
        fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        return {'status':'RETAINED_PAIR_EVIDENCE_COLLECTED_NOT_AGGREGATED','node':node,
                'path':str(output),'sha256':digest(output.read_bytes()),'SDKCalled':False,'newGuestAcceptance':False}
    finally:os.close(lock)

def decode_capsule(capsule,node,pin):
    need(capsule['version']==1 and capsule['kind']=='retained-pair-evidence' and capsule['node']==node
         and capsule['collectorSha256']==pin,'Wrong evidence capsule/controller')
    need(capsule['SDKCalled'] is False and capsule['GuestCommandsRun'] is False and capsule['APIRequestsMade'] is False,'Collector scope differs')
    values={}
    for name,row in capsule['files'].items():
        raw=base64.b64decode(row['rawBase64'],validate=True)
        need(len(raw)==row['bytes'] and digest(raw)==row['sha256'] and json.loads(raw)==row['value'],'Source evidence bytes differ')
        values[name]=row['value']
    local_completion(node,values)
    raw=base64.b64decode(capsule['mappingEvidence']['rawBase64'],validate=True)
    need(len(raw)==capsule['mappingEvidence']['bytes'] and digest(raw)==capsule['mappingEvidence']['sha256']
         and json.loads(raw)==capsule['mappingEvidence']['value'],'Mapping evidence bytes differ')
    return values

def merge(a,b,pin,gate):
    nodes={'a':a,'b':b};values={node:decode_capsule(capsule,node,pin) for node,capsule in nodes.items()}
    bundle={'version':1,'readyReports':{},'readyReceipts':{},'phaseReceipts':{},'phaseJournals':{},'lifecycleJournals':{},'commandResults':{}}
    for node,rows in values.items():
        bundle['readyReports'][node]=rows['report.json'];bundle['readyReceipts'][node]=rows['ready-receipt.json']
        bundle['phaseJournals'][node]=rows['pair-phases.json'];bundle['lifecycleJournals'][node]=rows['state.json']
        bundle['commandResults'][node]={'base-read':rows['command-result.json'],**{label:rows[label+'-result.json'] for label in COMMANDS[node]}}
        for phase in PHASES[node]:bundle['phaseReceipts'][phase]=rows[phase+'-receipt.json']
    acceptance=gate.verify(bundle,CONTROLLER)
    if any(capsule.get('currentRegions') is None for capsule in nodes.values()):
        return bundle,None,{'status':'PAIR_RECEIPTS_VERIFIED_ALLOCATION_LEDGER_UNAVAILABLE','acceptance':acceptance,
            'allocationLedgerAvailable':False,'uniqueExportRegions':None,'reportedReservationBytes':None,
            'collectorSha256':pin,'independentHardwareReobservation':False,'netSavingsBytes':None,
            'scope':'Guest receipt chain only; missing current device metadata is NA and cannot authorize comparison allocation accounting'}
    expected=gate.normalized_replicas(bundle['phaseReceipts']['a-written']['boundReplicas'])
    by_name={row['objectName']:row for row in expected};maps={};regions={}
    for node,capsule in nodes.items():
        provider=bundle['readyReports'][node]['provider'];mapping=capsule['mappingEvidence']['value']
        need(capsule['providerIdentity']==provider['providerProcess'],'Mapping epoch differs from ready provider')
        need(mapping['ownerId']==provider['ownerId'] and mapping['manifestSha256']==provider['manifestSha256']
             and mapping['allocationCalls']==(8 if node=='a' else 0),'Allocation ownership/count differs')
        maps[node]={row['objectName']:row for row in mapping['mappings']}
        need(set(maps[node])==set(by_name) and len(mapping['mappings'])==8,'Mapped objects differ from actual Guest bindings')
        regions[node]={row['device']:row for row in capsule['currentRegions']}
        need(len(regions[node])==len(capsule['currentRegions']),'Duplicate current region metadata')
        need(set(regions[node])=={seg['device'] for obj in maps[node].values() for seg in obj['segments']},
             'Current device metadata is not the exact mapped set')
    ledger={'version':1,'mode':'full-stored','presence':'retained','ownerId':bundle['readyReceipts']['a']['ownerId'],
            'manifestSha256':bundle['readyReceipts']['a']['manifestSha256'],'objects':[],
            'incrementalPhysicalChargeBytes':None,'physicalSharingAccepted':False,
            'scope':'unique A export reservation; imported windows are not another allocation'}
    for name,reference in sorted(by_name.items()):
        left,right=maps['a'][name],maps['b'][name]
        need(left['mappingBytes']==right['mappingBytes']==reference['mappingBytes']
             and left['protection']==right['protection']=='PROT_READ_MAP_SHARED','Read-only mapping shape differs')
        la,lb=left['segments'],right['segments'];need(len(la)==len(lb)>0,'Segment counts differ')
        owned=[];offset=0
        for x,y in zip(la,lb):
            need(x['logicalOffset']==y['logicalOffset']==offset and x['bytes']==y['bytes']>0,'Cross-node logical segment layout differs')
            offset+=x['bytes'];export,imp=regions['a'][x['device']],regions['b'][y['device']]
            need(export['role']=='export' and imp['role']=='import' and export['exportEndpoint']==imp['exportEndpoint'], 'Export/import route differs')
            need(export['major']==x['major'] and export['minor']==x['minor'] and imp['major']==y['major'] and imp['minor']==y['minor']
                 and export['bytes']>=x['bytes'] and imp['bytes']>=y['bytes'],'Current region identity/coverage differs')
            need(type(export['reservationBytes']) is int and export['reservationBytes']>0
                 and imp['reservationBytes'] is None,'Export cost missing or import incorrectly billed')
            owned.append({'role':'export','exportNode':'a','exportBootId':a['providerIdentity']['bootId'],
                          'exportRegionId':str(export['major'])+':'+str(export['minor'])+':'+export['device'],
                          'bytes':export['reservationBytes']})
        need(offset==reference['mappingBytes'],'Incomplete object coverage')
        ledger['objects'].append({'objectName':name,'regions':owned})
    unique={}
    for obj in ledger['objects']:
        for row in obj['regions']:
            key=(row['exportBootId'],row['exportRegionId'])
            need(key not in unique or unique[key]==row['bytes'],'Inconsistent repeated region cost');unique[key]=row['bytes']
    summary={'status':'PAIR_BUNDLE_AND_RETAINED_LEDGER_VERIFIED','acceptance':acceptance,
             'allocationLedgerAvailable':True,
             'uniqueExportRegions':len(unique),'reportedReservationBytes':sum(unique.values()),
             'collectorSha256':pin,'independentHardwareReobservation':False,'netSavingsBytes':None,
             'scope':'validated target-provided receipt chain and device metadata; no fresh Guest execution or global benefit claim'}
    return bundle,ledger,summary

def unpack_transfer(value):
    need(value['format']=='pair-evidence-zlib-v1' and type(value['bytes']) is int
         and 0<value['bytes']<=16*1024**2,'Invalid transfer envelope')
    decoder=zlib.decompressobj()
    raw=decoder.decompress(base64.b64decode(value['z64'],validate=True),16*1024**2+1)
    need(len(raw)==value['bytes'] and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data
         and digest(raw)==value['sha256'],'Truncated, oversized or changed transfer capsule')
    return json.loads(raw)

def load_capsule(path):
    with path.open('rb') as stream:raw=stream.read(16*1024**2+1)
    need(len(raw)<=16*1024**2,'Evidence capsule oversized')
    start=b'BEGIN_PAIR_EVIDENCE_CAPSULE';end=b'END_PAIR_EVIDENCE_CAPSULE'
    if start in raw:
        need(raw.count(start)==raw.count(end)==1,'Ambiguous transfer blocks')
        value=json.loads(raw.split(start,1)[1].split(end,1)[0])
        return unpack_transfer(value)
    value=json.loads(raw)
    return unpack_transfer(value) if value.get('format')=='pair-evidence-zlib-v1' else value

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='mode',required=True)
    collect_args=sub.add_parser('collect');collect_args.add_argument('--node',choices=('a','b'),required=True)
    collect_args.add_argument('--collect',action='store_true')
    collect_args.add_argument('--emit-capsule',action='store_true')
    combine=sub.add_parser('merge');combine.add_argument('--a',type=Path,required=True);combine.add_argument('--b',type=Path,required=True)
    combine.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.mode=='collect':
        if not args.collect:print(json.dumps({'status':'PLAN_ONLY','SDKCalled':False,'GuestCommandsRun':False}));return 0
        output=WORK/('evidence-'+args.node+'.json')
        print(json.dumps(collect(args.node,output),indent=2))
        if args.emit_capsule:
            raw=output.read_bytes()
            envelope={'format':'pair-evidence-zlib-v1','bytes':len(raw),'sha256':digest(raw),
                      'z64':base64.b64encode(zlib.compress(raw,9)).decode()}
            print('BEGIN_PAIR_EVIDENCE_CAPSULE');print(json.dumps(envelope));print('END_PAIR_EVIDENCE_CAPSULE')
        return 0
    need(not args.output.exists() and not args.output.is_symlink(),'Fresh merge output required')
    bundle,ledger,summary=merge(load_capsule(args.a),load_capsule(args.b),digest(Path(__file__).read_bytes()),verifier())
    args.output.mkdir(mode=0o700)
    for name,value in (('pair-bundle.json',bundle),('allocation-ledger.json',ledger),('verification.json',summary)):
        if value is None:continue
        with (args.output/name).open('x',encoding='utf-8') as stream:
            json.dump(value,stream,indent=2);stream.flush();os.fsync(stream.fileno())
    print(json.dumps(summary,indent=2));return 0

if __name__=='__main__':raise SystemExit(main())
