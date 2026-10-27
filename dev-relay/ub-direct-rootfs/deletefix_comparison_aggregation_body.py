"""Offline verification of actual completed first-template comparison receipts.

No target access, experiments, workload replay, cache operations or networking.
The pinned first-template scope cannot be promoted to a sixteen-Guest result.
"""
import argparse,base64,hashlib,json,math,os,re,types,zlib
from pathlib import Path

CONTROLLER='26e9d27b79a86a43a41e9bbc8c76e754854e44095402a71e1ee7e0652da56bd0'
EXIT_CONTROLLER_PIN='375abb9d585f9348f2d45678c82fd9f93ba20234e9806b5025f01175f7b65bf1'
CATEGORIES=('rootfs-lower-original','rootfs-lower-ub-source','memory-lower','private-upper','experiment-log')

def need(ok,why):
    if not ok:raise ValueError(why)

def fingerprint(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def dependency(name):
    row=MODULES[name];raw=zlib.decompress(base64.b64decode(row['z64'],validate=True))
    need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'Embedded module changed')
    module=types.ModuleType('verified_'+name)
    exec(compile(raw,name+'.py','exec'),module.__dict__)
    return module

def integer(value,label):
    need(type(value) is int and value>=0,'Invalid '+label)
    return value

def elapsed(value):
    need(type(value) in (int,float) and math.isfinite(value) and value>=0,'Invalid duration')
    return value

def totals(sample,node,variant,boot,ledger,guests,*,idle=False):
    need(sample['node']==node and sample['group']==variant and sample['bootId']==boot,'Sample identity differs')
    need(sample['cacheEvictionPerformed'] is False and sample['atomicGlobalSnapshot'] is False,'Sampling policy differs')
    need(integer(sample['endNs'],'sample end')>=integer(sample['beginNs'],'sample start'),'Sample time reversed')
    need(sample['uniqueUBReservation']==ledger,'Sample used another UB cost ledger')
    processes=sample['processes'];seen=set();roles={}
    for row in processes:
        identity=(row['pid'],row['startTicks'])
        need(not any(pid==row['pid'] for pid,_ in seen),'Process counted twice');seen.add(identity)
        need(row['role'] in ('fc','runtime','daemon','provider','collector'),'Unknown process accounting role')
        roles.setdefault(row['role'],[]).append(row)
    need(len(roles.get('fc',[]))==len(guests),'FC sample count differs')
    if idle:
        need(len(roles.get('runtime',[]))==2 and len(roles.get('daemon',[]))<=2
             and all(len(roles.get(role,[]))==1 for role in ('provider','collector')),'Idle process scope differs')
    else:need(all(len(roles.get(role,[]))==1 for role in ('runtime','daemon','provider','collector')),'Auxiliary process scope differs')
    fc_seen={(row['pid'],row['startTicks']) for row in roles.get('fc',[])}
    for guest in guests.values():
        need((guest['fcIdentity']['pid'],guest['fcIdentity']['startTicks']) in fc_seen,'Expected FC absent from sample')
        need((guest['daemonIdentity']['pid'],guest['daemonIdentity']['startTicks'])==
             (roles['daemon'][0]['pid'],roles['daemon'][0]['startTicks']),'Daemon sample identity differs')
    pss={role:sum(integer(row['metricsBytes']['Pss'],'PSS') for row in rows) for role,rows in roles.items()}
    categories={key:None for key in CATEGORIES}
    files=sample.get('ordinaryFiles')
    if isinstance(files,dict) and files.get('available') is True:
        rows=files['uniqueFiles'];keys=set();categorized={key:[] for key in CATEGORIES}
        for row in rows:
            key=(row['identity']['dev'],row['identity']['inode'])
            need(key not in keys,'Ordinary inode counted twice');keys.add(key)
            need(row['category'] in categorized,'Unexpected file category')
            value=row.get('residentBytes')
            if value is not None:integer(value,'file residency')
            if row.get('stableDuringSample') is not True:value=None
            categorized[row['category']].append(value)
        for category,values in categorized.items():
            if values and all(value is not None for value in values):categories[category]=sum(values)
    # Device cache, Guest RAM and PSS can overlap. Keep their raw observations
    # separate instead of adding them into a fabricated physical total.
    return {'hostMemoryBytes':sample['hostMemoryBytes'],'fileResidentBytes':categories,
            'processPssBytesByRole':pss,'blockDevices':sample.get('blockDevices'),
            'authoritativeGuestRam':sample.get('authoritativeGuestRam'),
            'beginNs':sample['beginNs'],'endNs':sample['endNs'],
            'actualUpperModes':sample.get('actualUpperModes'),'processCountsByRole':{role:len(rows) for role,rows in roles.items()},
            'beforeCreationIncludesBothRuntimeVariants':idle,
            'disjointTotalBytes':None,'accessAndResidentIntersectionBytes':None}

def difference(before,after):
    return after-before if type(before) is int and type(after) is int else None

def phase(value,node,variant,pair_result,pair,ledger,modules):
    receipt=value['receipt'];replay=value['replay'];context=receipt['context']
    expected=modules['admission'].VERSIONS[variant]
    need(receipt['status']=='LOCAL_COMPARISON_PHASE_RELEASED' and receipt['node']==node
         and receipt['variant']==variant and receipt['controllerSha256']==CONTROLLER,'Wrong phase/controller')
    need(receipt['pairBundleSha256']==pair_result['bundleSha256'],'Comparison did not use accepted pair')
    need(receipt['sharedObjectsRetired'] is False and receipt['crossNodeSynchronizationVerified'] is False,'Unsupported retirement/synchronization claim')
    need(context['node']==node and context['variant']==variant and context['verifiedCommit']==expected['commit'],'Wrong build declaration')
    need(all(context['binaries'][key]==expected[key] for key in ('server','uvm-ublk-daemon','aenv')),'Modified runtime is not the original')
    need(re.fullmatch('[0-9a-f]{32}',receipt['runId']) is not None,'Invalid comparison run ID')
    need(replay['GuestTimeoutSeconds']==300 and replay['CLITransportTimeoutSeconds']==330,'Changed command timeouts')
    modules['replay'].compare_completed(replay,replay)
    jobs=replay['jobs'];bindings=value['bindings'];ids={j['sandboxId'] for j in jobs}
    template=pair['readyReceipts'][node]['templateId']
    need(len(jobs)==len(ids)==receipt['guests']==2 and set(bindings)==ids,'Current pin requires two local Guests, not sixteen')
    need({(j['templateId'],j['slot']) for j in jobs}=={(template,0),(template,1)},'Different first-template scope')
    need(len(receipt['templateSignature'])==1 and receipt['templateSignature'][0][0]==template,'Template signature differs')
    signature=receipt['templateSignature'][0]
    need(len(signature)==5 and signature[3]=={'cpu_count':2,'memory_mib':4096},'Template signature/resources malformed')
    layers=signature[4]
    expected_layers={(r['layerDigest'],r['fileBytes']) for r in pair['historicalIsolation']['aWritten']['boundReplicas']}
    need(len(layers)==8 and {(r['digest'],r['size']) for r in layers}==expected_layers,'Template lower scope differs from accepted shared base')
    lower_hash=hashlib.sha256(json.dumps([(r['digest'],r['size']) for r in layers],separators=(',',':')).encode()).hexdigest()
    nonzero=completed=0
    for job in jobs:
        row=bindings[job['sandboxId']]
        need(job['catalogSha256']==signature[1] and job['replaySha256']==signature[2]
             and job['lowerContentSha256']==lower_hash,'Job is not bound to declared catalog/lower/replay')
        need(row['sandboxId']==job['sandboxId'] and row['variant']==variant
             and row['lowerContentSha256']==job['lowerContentSha256'] and row['rootfsMaxSectorsKiB']==256,'Actual binding differs')
        for identity in ('fcIdentity','daemonIdentity'):modules['pair'].process(row[identity])
        need(job['resources']=={'cpu_count':2,'memory_mib':4096},'Resources differ')
        need(1<=integer(job['expectedCommands'],'expected command count')<=2048,'Invalid command scope')
        for index,result in enumerate(job['results']):
            need(result['commandIndex']==index and result['guestExitCode'] not in (124,137),'Missing or timed-out command')
            integer(result['guestExitCode'],'Guest exit code');need(result['guestExitCode']<=255,'Invalid exit code')
            elapsed(result['elapsedSeconds'])
        count=sum(result['guestExitCode']!=0 for result in job['results'])
        need(job['nonzeroCommands']==count,'Job failure count differs')
        completed+=len(job['results']);nonzero+=count
    need(completed==replay['completedCommands']==receipt['completedCommands']
         and nonzero==replay['nonzeroCommands']==receipt['nonzeroCommands'],'Phase command counters differ')
    need(receipt['elapsedSeconds']==replay['elapsedSeconds'],'Elapsed summary differs')
    cases=receipt['lifecycleJournals'];need(len(cases)==1,'Different lifecycle scope')
    created=[]
    for case in cases:
        need(case['phase']=='quiesced' and not case['sandboxIds'] and not case['openRequests'] and not case['outcomeUncertain'],'Unresolved lifecycle')
        created.extend(sid for op in case['operations'] if op['kind']=='create' and op['httpStatus']==201 for sid in op['ack']['sandboxIds'])
    released=receipt['cleanup']['released']
    need(receipt['cleanup']['ownedGuestsReleased'] is True and len(created)==len(set(created))==2
         and set(created)==ids and len(released)==2 and {r['sandboxId'] for r in released}==ids
         and all(r['fcExitConfirmed'] for r in released),'Release does not match actual creation')
    status=receipt['providerStatus']
    need(all(status.get(key)==0 for key in ('activeLeases','activePayloadResponses','payloadFailures')),'Unreleased/failed provider')
    if variant=='full':
        server=pair['readyReports'][node]['serverIdentity']
        need((context['pid'],context['startTicks'])==(server['pid'],server['startTicks']),'Full Runtime changed since pair acceptance')
        need(all(r['requiredUBDeviceExitConfirmed'] for r in released),'Required private device remains')
        need(set(receipt['actualUBReads'])==ids,'Every full Guest needs actual backend reads')
        allowed={r['layerDigest'] for r in pair['historicalIsolation']['aWritten']['boundReplicas']}
        for sid,trace in receipt['actualUBReads'].items():
            modules['pair'].trace(trace,bindings[sid])
            need(trace['digestsRead'] and set(trace['digestsRead'])<=allowed,'Trace read a different lower')
    else:need(not receipt['actualUBReads'],'Original claims UB backend reads')
    baseline=totals(value['baseline'],node,variant,context['bootId'],ledger,bindings)
    final=totals(value['final'],node,variant,context['bootId'],ledger,bindings)
    before=totals(value['beforeGuestCreate'],node,'before-'+variant,context['bootId'],ledger,{},idle=True)
    need(before['endNs']<=baseline['beginNs'],'Creation/replay baseline ordering differs')
    need(baseline['endNs']<=final['beginNs'],'Baseline/final ordering differs')
    return {'guests':2,'templates':1,'completedCommands':completed,'nonzeroCommands':nonzero,
            'elapsedSeconds':elapsed(replay['elapsedSeconds']),'restoreSeconds':elapsed(receipt['restoreSeconds']),
            'periodicSamplesReported':replay.get('samples'),'sampleOverrunsReported':replay.get('sampleOverruns'),
            'beforeGuestCreate':before,'baseline':baseline,'final':final,
            'fileResidentDeltaBytes':{key:difference(baseline['fileResidentBytes'][key],final['fileResidentBytes'][key]) for key in CATEGORIES},
            'fileResidentDeltaSinceBeforeCreateBytes':{key:difference(before['fileResidentBytes'][key],final['fileResidentBytes'][key]) for key in CATEGORIES},
            'hostCachedDeltaBytes':difference(baseline['hostMemoryBytes'].get('Cached'),final['hostMemoryBytes'].get('Cached')),
            'hostCachedDeltaSinceBeforeCreateBytes':difference(before['hostMemoryBytes'].get('Cached'),final['hostMemoryBytes'].get('Cached')),
            'context':context,'guestIds':sorted(ids),'sharedLowerInodeAliases':receipt.get('sharedLowerInodeAliases',[])}

def verify(nodes,pair,allocation,modules):
    need(set(nodes)=={'a','b'},'Both nodes required')
    accepted=modules['pair'].verify(pair,EXIT_CONTROLLER_PIN)
    ledger=modules['sampler'].ub_reservation(allocation)
    ready=pair['readyReceipts']['a']
    need(allocation['ownerId']==ready['ownerId'] and allocation['manifestSha256']==ready['manifestSha256'],'Pool identity differs')
    objects={r['objectName'] for r in pair['historicalIsolation']['aWritten']['boundReplicas']}
    need({r['objectName'] for r in allocation['objects']}==objects and ledger['uniqueExportRegions']==19
         and ledger['reportedReservationBytesCountedOnce']==2432*1024**2,'Current fixed pool scope differs')
    rows={};local={};ids=set();run=None;signature=None;workload=None
    for node in ('a','b'):
        need(set(nodes[node])=={'original','full'},'Both actual variants required')
        rows[node]={}
        for variant in ('original','full'):
            value=nodes[node][variant];r=value['receipt']
            if run is None:run=r['runId'];signature=r['templateSignature'];workload=value['replay']['workloadSha256']
            need(r['runId']==run and r['templateSignature']==signature and value['replay']['workloadSha256']==workload,'Cross-node inputs differ')
            row=phase(value,node,variant,accepted,pair,ledger,modules)
            need(not ids.intersection(row['guestIds']),'Guest ID reused across nodes or variants');ids.update(row['guestIds'])
            rows[node][variant]=row
        need(rows[node]['original']['context']['bootId']==rows[node]['full']['context']['bootId'],'Node rebooted between variants')
        need(rows[node]['original']['final']['endNs']<rows[node]['full']['baseline']['beginNs'],'Local phase order differs')
        local[node]=modules['replay'].compare_completed(nodes[node]['original']['replay'],nodes[node]['full']['replay'])
    need(rows['a']['full']['context']['bootId']!=rows['b']['full']['context']['bootId'],'Two distinct boot namespaces required')
    need(all(region['exportNode']=='a' and region['exportBootId']==rows['a']['full']['context']['bootId']
             for obj in allocation['objects'] for region in obj['regions']),'Export allocation epoch differs')
    # Recompute cross-node command comparisons as well as trusting no hash-only claim.
    cross={}
    for variant in ('original','full'):
        comparison=modules['replay'].compare_completed(nodes['a'][variant]['replay'],nodes['b'][variant]['replay'])
        cross[variant]={'allCommandExitCodesMatch':comparison['allCommandExitCodesMatch'],
            'nodeAElapsedSeconds':comparison['originalElapsedSeconds'],'nodeBElapsedSeconds':comparison['fullElapsedSeconds'],
            'exitCodeMismatches':[{**{k:v for k,v in row.items() if k not in ('originalExit','fullExit')},
                'nodeAExit':row['originalExit'],'nodeBExit':row['fullExit']} for row in comparison['exitCodeMismatches']]}
    outcomes=all(r['allCommandExitCodesMatch'] for r in (*local.values(),*cross.values()))
    cache={node:difference(rows[node]['full']['fileResidentDeltaBytes']['rootfs-lower-ub-source'],
                          rows[node]['original']['fileResidentDeltaBytes']['rootfs-lower-original']) for node in rows}
    return {'status':('COMPLETED_FIRST_TEMPLATE_COMPARISON_RECEIPTS_VERIFIED' if outcomes else
                      'COMPLETED_RECEIPTS_WITH_COMMAND_OUTCOME_DIFFERENCES'),'runId':run,
        'nodes':rows,'localOutcomeComparisons':local,'crossNodeOutcomeComparisons':cross,'allCommandExitCodesMatch':outcomes,
        'guestsPerVariantAcrossNodes':4,'templates':1,'sixteenGuestTargetCompleted':False,
        'commandsPerVariant':{v:sum(rows[n][v]['completedCommands'] for n in rows) for v in ('original','full')},
        'nonzeroCommandsPerVariant':{v:sum(rows[n][v]['nonzeroCommands'] for n in rows) for v in ('original','full')},
        'elapsedChangePercentByNode':{node:{metric:(100*(rows[node]['full'][metric]/rows[node]['original'][metric]-1)
            if rows[node]['original'][metric]>0 else None) for metric in ('elapsedSeconds','restoreSeconds')} for node in rows},
        'hostLowerCacheGrowthDifferenceOriginalMinusFullByNodeBytes':cache,
        'sumOfSeparateNodeCacheGrowthDifferencesBytes':sum(cache.values()) if all(v is not None for v in cache.values()) else None,
        'uniqueRetainedUBReservation':ledger,'poolRetainedDuringBothVariants':True,
        'crossNodeSynchronizationVerified':False,'simultaneousResidentUnionBytes':None,'accessResidentIntersectionBytes':None,
        'globalWallDurationSeconds':None,'incrementalUBPhysicalChargeBytes':None,'netSavingsBytes':None,
        'rawSamplingTimelineVerified':False,
        'scope':'supplied completed receipts and replay-baseline/final samples; no new hardware run, peak, concurrent sum or net-memory attribution',
        'caveats':['Node baseline/final sampling windows are separate, not an atomic cluster snapshot.',
            'Cached, FC PSS, Guest RAM, device cache and upper overlap and must not be added.',
            'Whole provider/Runtime/daemon PSS includes unseparated buffers/indexes; transient CLI is not independently measured.',
            'Full UB pool remains background occupancy during original too; reservation is not incremental physical charge.',
            'Retained caches and sequential execution can affect the comparison; small differences are not causal proof.'],
        'inputSha256':fingerprint({'nodes':nodes,'pair':pair,'allocation':allocation})}

def load(path):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size<=32*1024**2,'Input type/size differs')
    return json.loads(path.read_bytes())

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--a',type=Path,required=True);parser.add_argument('--b',type=Path,required=True)
    parser.add_argument('--pair-bundle',type=Path,required=True);parser.add_argument('--allocation-ledger',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    nodes={}
    for node,root in (('a',args.a),('b',args.b)):
        nodes[node]={variant:{key:load(root/variant/name) for key,name in (
            ('receipt','receipt.json'),('replay','replay.json'),('bindings','bindings.json'),
            ('baseline','baseline.json'),('final','final-before-release.json'),
            ('beforeGuestCreate','before-guest-create.json'))} for variant in ('original','full')}
    modules={name:dependency(name) for name in ('pair','replay','sampler','admission')}
    result=verify(nodes,load(args.pair_bundle),load(args.allocation_ledger),modules)
    with args.output.open('x',encoding='utf-8') as stream:
        json.dump(result,stream,ensure_ascii=False,indent=2);stream.flush();os.fsync(stream.fileno())
    print(json.dumps({'status':result['status'],'allCommandExitCodesMatch':result['allCommandExitCodesMatch'],
        'guestsPerVariantAcrossNodes':4,'netSavingsBytes':None,'output':str(args.output)},indent=2))

if __name__=='__main__':main()
