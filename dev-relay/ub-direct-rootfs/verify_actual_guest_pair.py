"""Offline acceptance gate for complete target receipts, not synthetic evidence.

No target connection, SDK call or mutation. Missing evidence fails validation.
Contract verification does not independently re-observe the target hardware.
"""
import argparse,hashlib,json,re
from pathlib import Path
CORE='ff1efdd9a2598e19b84cc09b91c8bc1e10ab6254'
EXPECTED_CONTROLLER_SHA='6c01a15e36a056b29a400e52f33f38981ff0abf3ca939185e6a4074dd9fda1fa'
PINS={'server':'759423e634e25bc2e74067bfaccc16e40720907fc0e717269261dd573f0097df',
      'uvm-ublk-daemon':'8bd4952d2c0f524f73bd51b4a4635c3b2af66dfe5af23b94dbfd4d5a6195a17d',
      'firecracker':'e9588526096f45380b8debf2d41bf33a2fb26f8abea0a9bed841627327782a0b',
      'aenv':'b07e0ad826a6080a4481cb42278023732f21d090edf813f5bedd4438a486e1f2'}

def need(ok,why):
    if not ok:raise ValueError(why)

def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def process(value):
    need(type(value.get('pid')) is int and value['pid']>1
         and re.fullmatch('[0-9]+',value.get('startTicks',''))
         and value.get('executable','').startswith('/home/jwk/agent/'),'Missing process identity')

def binaries(rows):
    need(set(rows)==set(PINS),'Wrong binary set')
    for name,pin in PINS.items():
        need(rows[name]['sha256']==pin and type(rows[name]['bytes']) is int and rows[name]['bytes']>0,'Wrong binary '+name)

def normalized_replicas(rows):
    need(isinstance(rows,list) and len(rows)==8,'Expected selected template eight lowers')
    values=[]
    for row in rows:
        need(set(row)=={'brokerSocket','objectName','generation','layerDigest','fileBytes','mappingBytes','allowRepositoryFallback'},'Replica schema differs')
        need(row['allowRepositoryFallback'] is False and re.fullmatch('aenv_[0-9a-f]{32}',row['objectName'])
             and re.fullmatch('[0-9a-f]{32}',row['generation']) and re.fullmatch('sha256:[0-9a-f]{64}',row['layerDigest']), 'Bad replica identity/fallback')
        need(type(row['fileBytes']) is int and row['fileBytes']>0
             and type(row['mappingBytes']) is int and row['mappingBytes']%4194304==0
             and row['mappingBytes']>=row['fileBytes']+4096,'Bad replica lengths')
        values.append({k:v for k,v in row.items() if k!='brokerSocket'})
    need(len({r['objectName'] for r in values})==8 and len({r['layerDigest'] for r in values})==8,'Duplicate replica')
    return sorted(values,key=lambda r:r['objectName'])

def trace(value,binding):
    need(type(value.get('requests')) is int and value['requests']>0
         and type(value.get('bytesIncludingRepeatedReads')) is int and value['bytesIncludingRepeatedReads']>0,'Missing real backend reads')
    need(value['source']==binding['imageConfigPath'],'Trace belongs to another Guest image')
    status=value['traceStatus']
    need(status['pid']==binding['daemonIdentity']['pid'] and status.get('read_tracking_version')==1
         and type(status.get('drained_through_ns')) is int,'Trace incarnation/drain evidence missing')
    need(all(status.get(k)==0 for k in ('errors','dropped_records','unsupported_context_calls','repository_fallback_reads','failed_or_cancelled_reads')),'Trace incomplete or fallback')

def verify(bundle,controller_sha256):
    need(controller_sha256==EXPECTED_CONTROLLER_SHA,'Published v2 controller pin required')
    need(bundle.get('version')==1 and set(bundle['readyReports'])=={'a','b'} and set(bundle['readyReceipts'])=={'a','b'},'Two ready reports/receipts required')
    ready=bundle['readyReports'];initial=bundle['readyReceipts'];phases=bundle['phaseReceipts']
    need(set(phases)=={'a-written','peer-isolated','a-released','b-released'},'Complete four-stage receipts required')
    common=('runId','ownerId','manifestSha256','templateId','base')
    for node in ('a','b'):
        r=ready[node];i=initial[node]
        need(r['status']=='DIRECT_UB_ONE_REAL_GUEST_READY_RETAINED' and r['singleGuestReadAndBindingPassed'] is True
             and r['node']==i['node']==node and r['coreCommit']==CORE,'Ready phase not confirmed')
        need(i['version']==1 and i['kind']=='ready' and i['runId']==r['pairRunId'] and i['sandboxId']==r['sandboxId']
             and i['base']==r['base'],'Ready report/receipt mismatch')
        need(i['ownerId']==r['provider']['ownerId'] and i['manifestSha256']==r['provider']['manifestSha256'],'Ready provider context mismatch')
        binaries(r['binaries']);process(r['serverIdentity'])
        binding=r['binding'];process(binding['fcIdentity']);process(binding['daemonIdentity'])
        need(binding['sandboxId']==i['sandboxId'] and binding['bindingVerified'] is True and binding['requiredUB'] is True
             and binding['upperPrivateVerified'] is True and binding['lowerCount']==8,'Actual Guest binding missing')
        trace(r['actualUBReads'],binding)
    need(initial['a']['sandboxId']!=initial['b']['sandboxId'] and all(initial['a'][k]==initial['b'][k] for k in common),'Different pair/base context')
    written=phases['a-written']['written']
    need(written['path']==initial['a']['base']['path'] and written['sha256']!=initial['a']['base']['sha256']
         and re.fullmatch('[0-9a-f]{64}',written['sha256']),'A did not produce a distinct private value')
    for kind,node,peer in (('a-written','a',initial['b']),('peer-isolated','b',phases['a-written']),
                           ('a-released','a',phases['peer-isolated']),('b-released','b',phases['a-released'])):
        r=phases[kind];i=initial[node];origin=ready[node]
        need(r['version']==1 and r['kind']==kind and r['node']==node and r['sandboxId']==i['sandboxId']
             and all(r[k]==i[k] for k in common),'Phase identity differs: '+kind)
        need(r['controllerSha256']==controller_sha256 and r['coreCommit']==CORE
             and r['readyReportSha256']==fingerprint(origin) and r['readyReceiptSha256']==fingerprint(i)
             and r['peerReceiptSha256']==fingerprint(peer),'Broken receipt chain: '+kind)
        need(r['written']==written and r['serverIdentity']==origin['serverIdentity'] and r['binaries']==origin['binaries']
             and r['unit']==origin['unit'] and r['apiPort']==origin['apiPort'],'Runtime/write changed: '+kind)
        for key in ('fcIdentity','daemonIdentity','imageConfigSha256','imageConfigPath','rootfsDevice'):
            need(r['bindingEvidence'][key]==origin['binding'][key],'Guest binding changed: '+kind)
        need(r['sharedBaseRetired'] is False,'Comparison base unexpectedly retired')
    replicas=normalized_replicas(phases['a-written']['boundReplicas'])
    for r in phases.values():need(normalized_replicas(r['boundReplicas'])==replicas,'Different bound objects or generations')
    changed=False
    for key in ('data','index'):
        before=phases['a-written']['upperBefore'][key];after=phases['a-written']['upperAfter'][key]
        need(all(before[k]==after[k] for k in ('path','dev','inode')),'A upper identity changed')
        changed|=before['bytes']!=after['bytes'] or before['mtimeNs']!=after['mtimeNs']
    need(changed,'No A upper change observed')
    base=phases['peer-isolated']['baseVerification']
    expected={(r['objectName'],r['generation'],r['layerDigest'],r['fileBytes']) for r in replicas}
    need(base['status']=='CURRENT_UB_STORED_BASE_CONTENT_VERIFIED' and base['sourceFileReads'] is False
         and base['SDKAllocationCalled'] is False and len(base['layers'])==8,'Missing actual UB base checksum')
    need({(r['objectName'],r['generation'],r['sha256'],r['bytes']) for r in base['layers']}==expected
         and base['bytesVerified']==sum(r['fileBytes'] for r in replicas),'Base content identity differs')
    for kind in ('peer-isolated','a-released','b-released'):
        r=phases[kind]
        need(r['baseContentVerified'] is True and r['baseChecksumVerificationPending'] is False and r['baseVerification']==base,'Base checksum chain differs')
    for node,kind,end in (('a','a-released','a-released'),('b','b-released','b-released')):
        r=phases[kind]
        need(all(r.get(k) is True for k in ('guestExitConfirmed','deviceExitConfirmed','localReaderLeasesReleased','providerRetained')),'Release incomplete')
        status=r['providerStatus'];need(status['ownerId']==initial[node]['ownerId']
             and status['manifestSha256']==initial[node]['manifestSha256']
             and status['activeLeases']==0 and status['activePayloadResponses']==0,'Reader release/provider identity differs')
        j=bundle['phaseJournals'][node];life=bundle['lifecycleJournals'][node]
        need(j['phase']==end and 'pending' not in j and 'error' not in j,'Unresolved phase journal')
        required=['write-a','release-a'] if node=='a' else ['check-b','survive-release-b']
        need([e['phase'] for e in j['events']]==required,'Phase ordering incomplete')
        need(life['runId']==initial[node]['runId'] and life['sandboxIds']==[] and life['openRequests']==[]
             and life['outcomeUncertain'] is False and life['snapshots']==[],'Unresolved API lifecycle')
        ops=life['operations'];need(len(ops)==2 and [o['kind'] for o in ops]==['create','delete'],'Unexpected lifecycle mutations')
        need(ops[0]['httpStatus']==201 and ops[0]['ack']['sandboxIds']==[initial[node]['sandboxId']]
             and ops[1]['route']=='/sandboxes/'+initial[node]['sandboxId'] and ops[1]['httpStatus'] in (200,204,404),'Lifecycle acknowledgements incomplete')
    final=phases['b-released'];before=final['beforePostExitRead'];after=final['afterPeerExitRead'];binding=ready['b']['binding']
    trace(before,binding);trace(after,binding)
    need(before['trace']==after['trace'] and after['requests']>before['requests']
         and after['bytesIncludingRepeatedReads']>before['bytesIncludingRepeatedReads']
         and final['newBackendRequests']==after['requests']-before['requests'],'No fresh B backend read after A release')
    commands=bundle['commandResults']
    for node,label,expected_value in (('a','base-read',initial['a']['base']),('b','base-read',initial['b']['base']),
                                     ('a','a-private-write',written),('b','b-after-a-write',initial['b']['base']),
                                     ('b','b-after-a-exit',initial['b']['base'])):
        result=commands[node][label]
        need(result['exitCode']==0 and result['timedOut'] is False and result['result']==expected_value,'Missing/failed Guest command '+label)
    return {'status':'COMPLETE_TWO_NODE_GUEST_RECEIPT_CHAIN_VERIFIED','pairRunId':initial['a']['runId'],
            'coreCommit':CORE,'controllerSha256':controller_sha256,'bundleSha256':fingerprint(bundle),
            'nodes':2,'templates':1,'guests':2,'verifiedGuestCommands':5,'sharedObjects':8,
            'readerLeasesReleased':True,'sharedObjectsRetainedForComparison':True,'sharedObjectsRetired':False,
            'independentHardwareReobservation':False,'physicalMappingFreshness':'requires separate export/import mapping evidence',
            'sixteenGuestComparisonAccepted':False,'scaleExperimentAuthorized':False,'netSavingsBytes':None,
            'scope':'complete target receipt contract, not a new hardware run, capacity authorization or performance comparison'}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('bundle',type=Path)
    parser.add_argument('--controller-sha256',required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    need(not args.output.exists(),'Output already exists; preserve it')
    need(args.bundle.stat().st_size<=16*1024**2,'Bundle oversized')
    result=verify(json.loads(args.bundle.read_bytes()),args.controller_sha256)
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
