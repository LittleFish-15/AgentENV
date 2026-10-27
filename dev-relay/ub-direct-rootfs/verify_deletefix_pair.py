"""Verify retained write isolation plus a fresh fixed-daemon exit pair.

The two runs remain explicitly separate. No old failed DELETE becomes a pass.
The caller supplies a pinned exit-controller digest, not a digest from a receipt.
"""
import hashlib,json,re
CORE='d97d2388e6985e7d28faa3746b91fe54c18aaf60'
LEGACY_CORE='ff1efdd9a2598e19b84cc09b91c8bc1e10ab6254'
LEGACY_CONTROLLER='6c01a15e36a056b29a400e52f33f38981ff0abf3ca939185e6a4074dd9fda1fa'
PINS={'server':'759423e634e25bc2e74067bfaccc16e40720907fc0e717269261dd573f0097df',
 'uvm-ublk-daemon':'5291c267777cd91c4b853c6d40720e8d87200b2a0162024782534c4126cba726',
 'firecracker':'e9588526096f45380b8debf2d41bf33a2fb26f8abea0a9bed841627327782a0b',
 'aenv':'b07e0ad826a6080a4481cb42278023732f21d090edf813f5bedd4438a486e1f2'}
OLD_DAEMON='8bd4952d2c0f524f73bd51b4a4635c3b2af66dfe5af23b94dbfd4d5a6195a17d'

def need(ok,why):
    if not ok:raise ValueError(why)

def fingerprint(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def process(value):
    need(type(value.get('pid')) is int and value['pid']>1 and re.fullmatch('[0-9]+',value.get('startTicks',''))
         and value.get('executable','').startswith('/home/jwk/agent/'),'Missing actual process identity')

def binaries(rows,legacy=False):
    pins={**PINS,**({'uvm-ublk-daemon':OLD_DAEMON} if legacy else {})}
    need(set(rows)==set(pins),'Wrong binary set')
    for key,pin in pins.items():need(rows[key]['sha256']==pin and rows[key]['bytes']>0,'Wrong binary '+key)

def normalized_replicas(rows):
    need(isinstance(rows,list) and len(rows)==8,'Expected eight retained lowers')
    result=[]
    for row in rows:
        need(set(row)=={'brokerSocket','objectName','generation','layerDigest','fileBytes','mappingBytes','allowRepositoryFallback'},'Replica fields differ')
        need(re.fullmatch('aenv_[0-9a-f]{32}',row['objectName']) and re.fullmatch('[0-9a-f]{32}',row['generation'])
             and re.fullmatch('sha256:[0-9a-f]{64}',row['layerDigest']) and row['allowRepositoryFallback'] is False,'Replica identity/fallback differs')
        need(type(row['fileBytes']) is int and row['fileBytes']>0 and type(row['mappingBytes']) is int
             and row['mappingBytes']%4194304==0 and row['mappingBytes']>=row['fileBytes']+4096,'Replica size differs')
        result.append({k:v for k,v in row.items() if k!='brokerSocket'})
    need(len({r['objectName'] for r in rows})==len({r['layerDigest'] for r in rows})==8,'Duplicate replicas')
    return sorted(result,key=lambda r:r['objectName'])

def trace(value,binding):
    need(type(value.get('requests')) is int and value['requests']>0 and value['bytesIncludingRepeatedReads']>0
         and value['source']==binding['imageConfigPath'],'Missing attributed UB read')
    status=value['traceStatus']
    need(status['pid']==binding['daemonIdentity']['pid'] and status.get('read_tracking_version')==1
         and type(status.get('drained_through_ns')) is int,'Trace identity/drain differs')
    need(all(status.get(k)==0 for k in ('errors','dropped_records','unsupported_context_calls','repository_fallback_reads','failed_or_cancelled_reads')),
         'Trace has errors/fallback/loss')

def ready_report(report,node,legacy=False):
    need(report['status']=='DIRECT_UB_ONE_REAL_GUEST_READY_RETAINED' and report['node']==node
         and report['singleGuestReadAndBindingPassed'] is True and report['coreCommit']==(LEGACY_CORE if legacy else CORE),'Wrong ready report')
    binaries(report['binaries'],legacy);process(report['serverIdentity'])
    b=report['binding'];process(b['fcIdentity']);process(b['daemonIdentity'])
    need(b['sandboxId']==report['sandboxId'] and b['bindingVerified'] is True and b['requiredUB'] is True
         and b['upperPrivateVerified'] is True and b['lowerCount']==8,'Missing real Guest binding')
    trace(report['actualUBReads'],b)

def historical_isolation(history):
    need(history['kind']=='retained-original-pair-isolation-only','Historical scope differs')
    ready=history['readyReports'];a=history['aWritten'];b=history['bIsolated']
    for node,row in (('a',a),('b',b)):
        report=ready[node];ready_report(report,node,True)
        need(row['node']==node and row['sandboxId']==report['sandboxId'] and row['runId']==report['pairRunId']
             and row['coreCommit']==LEGACY_CORE and row['controllerSha256']==LEGACY_CONTROLLER
             and row['readyReportSha256']==fingerprint(report),'Historical identity/ready chain differs')
        need(row['serverIdentity']==report['serverIdentity'] and row['binaries']==report['binaries']
             and row['base']==report['base'] and row['ownerId']==report['provider']['ownerId']
             and row['manifestSha256']==report['provider']['manifestSha256'],'Historical source differs')
        for key in ('fcIdentity','daemonIdentity','imageConfigSha256','imageConfigPath','rootfsDevice'):
            need(row['bindingEvidence'][key]==report['binding'][key],'Historical binding changed')
    need(a['kind']=='a-written' and b['kind']=='peer-isolated' and b['peerReceiptSha256']==fingerprint(a),'Historical write-to-peer chain differs')
    need(all(a[k]==b[k] for k in ('runId','ownerId','manifestSha256','templateId','base','written'))
         and a['sandboxId']!=b['sandboxId'],'Historical cross-node context differs')
    need(a['written']['path']==a['base']['path'] and re.fullmatch('[0-9a-f]{64}',a['written']['sha256'])
         and a['written']['sha256']!=a['base']['sha256'],'A private write absent')
    changed=False
    for key in ('data','index'):
        before,after=a['upperBefore'][key],a['upperAfter'][key]
        need(all(before[k]==after[k] for k in ('path','dev','inode')),'Upper identity changed')
        changed|=before['bytes']!=after['bytes'] or before['mtimeNs']!=after['mtimeNs']
    need(changed,'No private upper change')
    replicas=normalized_replicas(a['boundReplicas']);need(normalized_replicas(b['boundReplicas'])==replicas,'Historical replicas differ')
    base=b['baseVerification']
    need(b['baseContentVerified'] is True and b['baseChecksumVerificationPending'] is False
         and base['status']=='CURRENT_UB_STORED_BASE_CONTENT_VERIFIED' and base['sourceFileReads'] is False
         and base['SDKAllocationCalled'] is False and len(base['layers'])==8,'Historical UB checksum incomplete')
    expected={(r['objectName'],r['generation'],r['layerDigest'],r['fileBytes']) for r in replicas}
    need({(r['objectName'],r['generation'],r['sha256'],r['bytes']) for r in base['layers']}==expected
         and base['bytesVerified']==sum(r['fileBytes'] for r in replicas),'Historical UB content differs')
    return {'replicas':replicas,'ownerId':a['ownerId'],'manifestSha256':a['manifestSha256'],
            'templateId':a['templateId'],'base':a['base'],'oldRunId':a['runId']}

def released(receipt,node,origin,initial,controller_sha):
    need(receipt['kind']==node+'-released' and receipt['node']==node and receipt['runId']==initial['runId']
         and receipt['sandboxId']==initial['sandboxId'] and receipt['controllerSha256']==controller_sha,
         'Fresh release identity differs')
    need(receipt['readyReportSha256']==fingerprint(origin) and receipt['readyReceiptSha256']==fingerprint(initial)
         and receipt['serverIdentity']==origin['serverIdentity'] and receipt['binaries']==origin['binaries']
         and receipt['coreCommit']==CORE and receipt['unit']==origin['unit'] and receipt['apiPort']==origin['apiPort'],
         'Fresh release source chain differs')
    for key in ('fcIdentity','daemonIdentity','imageConfigSha256','imageConfigPath','rootfsDevice'):
        need(receipt['bindingEvidence'][key]==origin['binding'][key],'Fresh release Guest binding changed')
    need(receipt['deleteHttpStatus'] in (200,204) and all(receipt.get(k) is True for k in
        ('guestExitConfirmed','privateRootfsDeviceRemoved','localReaderLeasesReleased'))
        and receipt['sharedObjectsRetired'] is False and receipt['forcedCleanupUsed'] is False,'Normal fresh release incomplete')
    memory=receipt['memoryRelease'];need(memory['guestReferenceReleased'] is True and memory['state'] in ('removed','idle-on-placeholder'),'Memory Guest reference unconfirmed')
    provider=receipt['providerStatus']
    need(provider['ownerId']==initial['ownerId'] and provider['manifestSha256']==initial['manifestSha256']
         and provider['activeLeases']==provider['activePayloadResponses']==0,'Fresh provider drain differs')
    life=receipt['journal'];ops=life['operations']
    need(life['runId']==initial['runId'] and life['phase']=='quiesced' and life['sandboxIds']==life['openRequests']==[]
         and life['outcomeUncertain'] is False and life['snapshots']==[],'Fresh lifecycle unresolved')
    need(len(ops)==2 and ops[0]['kind']=='create' and ops[0]['httpStatus']==201
         and ops[0]['ack']['sandboxIds']==[initial['sandboxId']] and ops[1]['kind']=='delete'
         and ops[1]['route']=='/sandboxes/'+initial['sandboxId'] and ops[1]['httpStatus']==receipt['deleteHttpStatus'],
         'Fresh lifecycle ACKs incomplete')

def verify(bundle,controller_sha256):
    need(re.fullmatch('[0-9a-f]{64}',controller_sha256 or '') and bundle.get('kind')=='deletefix-composite-pair-v1',
         'Pinned controller and explicit composite scope required')
    history=historical_isolation(bundle['historicalIsolation'])
    ready=bundle['readyReports'];initial=bundle['readyReceipts'];phases=bundle['exitReceipts']
    need(set(ready)==set(initial)=={'a','b'} and set(phases)=={'a-released','b-released'},'Two fresh ready and release sets required')
    for node in ('a','b'):
        report=ready[node];i=initial[node];ready_report(report,node)
        need(i['node']==node and i['kind']=='ready' and i['runId']==report['pairRunId']
             and i['sandboxId']==report['sandboxId'] and i['base']==report['base'],'Fresh ready context differs')
        need(i['runId']!=history['oldRunId'] and all(i[k]==history[k] for k in ('ownerId','manifestSha256','templateId','base')),
             'Fresh pair did not reuse verified shared base')
        need(report['provider']['ownerId']==i['ownerId'] and report['provider']['manifestSha256']==i['manifestSha256'], 'Fresh provider differs')
        need(normalized_replicas(bundle['boundReplicas'][node])==history['replicas'],'Shared object generation changed')
        released(phases[node+'-released'],node,report,i,controller_sha256)
        command=bundle['commandResults'][node]['base-read']
        need(command['exitCode']==0 and command['timedOut'] is False and command['result']==i['base'],'Fresh base read failed')
    need(initial['a']['runId']==initial['b']['runId'] and initial['a']['sandboxId']!=initial['b']['sandboxId'],'Fresh pair IDs differ')
    need(ready['a']['provider']['providerProcess']['bootId']!=ready['b']['provider']['providerProcess']['bootId'],'Distinct nodes required')
    a,b=phases['a-released'],phases['b-released']
    need(a['peerReadyReportSha256']==fingerprint(ready['b']) and a['peerReadyReceiptSha256']==fingerprint(initial['b'])
         and b['peerReleaseSha256']==fingerprint(a),'B ready -> A release -> B read causal chain differs')
    preparation=b['postExitReadPreparation']
    need(preparation['status']=='PRIVATE_ROOTFS_BLOCK_CACHE_FLUSHED'
         and preparation['device']==ready['b']['binding']['rootfsDevice']
         and preparation['major']==ready['b']['binding']['rootfsDeviceMajor']
         and preparation['minor']==ready['b']['binding']['rootfsDeviceMinor'], 'Fresh-read preparation targets another device')
    before,after=b['beforePostExitRead'],b['afterPeerExitRead'];trace(before,ready['b']['binding']);trace(after,ready['b']['binding'])
    need(before['trace']==after['trace'] and after['requests']>before['requests']
         and after['bytesIncludingRepeatedReads']>before['bytesIncludingRepeatedReads']
         and b['newBackendRequests']==after['requests']-before['requests'],'No new B UB read after A release')
    command=bundle['commandResults']['b']['b-after-a-exit']
    need(command['exitCode']==0 and command['timedOut'] is False and command['result']==initial['b']['base'],'B post-exit content/read failed')
    return {'status':'RETAINED_ISOLATION_AND_FRESH_DELETEFIX_EXIT_PAIR_VERIFIED','bundleSha256':fingerprint(bundle),
        'pairRunId':initial['a']['runId'],'historicalIsolationRunId':history['oldRunId'],'coreCommit':CORE,
        'controllerSha256':controller_sha256,'sharedObjects':8,'readerLeasesReleased':True,
        'sharedObjectsRetainedForComparison':True,'sharedObjectsRetired':False,'independentHardwareReobservation':False,
        'oldFailedDeleteReclassified':False,'evidenceFromMultipleExplicitRuns':True,
        'netSavingsBytes':None,'sixteenGuestComparisonAccepted':False,
        'scope':'retained actual write isolation plus fresh normal two-node exit/read chain; not a single-run full repeat or measured benefit'}
