"""Synthetic contract fixtures only; never save these as target reports."""
import copy,unittest
from verify_actual_guest_pair import CORE,PINS,EXPECTED_CONTROLLER_SHA,fingerprint,verify
PIN=EXPECTED_CONTROLLER_SHA

def fixture():
    base={'path':'/etc/os-release','sha256':'a'*64};written={**base,'sha256':'b'*64}
    bundle={'version':1,'readyReports':{},'readyReceipts':{},'phaseReceipts':{},'phaseJournals':{},'lifecycleJournals':{},'commandResults':{}}
    def identity(pid,name):return {'pid':pid,'startTicks':'12345','executable':'/home/jwk/agent/'+name}
    replicas=[{'brokerSocket':'/home/jwk/agent/data.sock','objectName':'aenv_'+format(i,'032x'),
        'generation':'d'*32,'layerDigest':'sha256:'+format(i,'064x'),'fileBytes':1234,'mappingBytes':4194304,
        'allowRepositoryFallback':False} for i in range(8)]
    for node in ('a','b'):
        sid='sid-'+node
        binding={'sandboxId':sid,'fcIdentity':identity(100,'fc'),'daemonIdentity':identity(101,'daemon'),
                 'bindingVerified':True,'upperPrivateVerified':True,'requiredUB':True,'lowerCount':8,
                 'imageConfigPath':'/home/jwk/agent/'+node+'/overlaybd/image.json','imageConfigSha256':'e'*64,'rootfsDevice':'/dev/ublkb7'}
        trace={'requests':10,'bytesIncludingRepeatedReads':100,'source':binding['imageConfigPath'],
               'trace':'/trace/'+node,'traceStatus':{'pid':101,'read_tracking_version':1,'drained_through_ns':1,
               **{k:0 for k in ('errors','dropped_records','unsupported_context_calls','repository_fallback_reads','failed_or_cancelled_reads')}}}
        report={'status':'DIRECT_UB_ONE_REAL_GUEST_READY_RETAINED','singleGuestReadAndBindingPassed':True,
            'node':node,'coreCommit':CORE,'pairRunId':'r','sandboxId':sid,'base':base,
            'provider':{'ownerId':'o','manifestSha256':'m'},'binaries':{k:{'sha256':v,'bytes':1} for k,v in PINS.items()},
            'serverIdentity':identity(102,'server'),'unit':'unit-'+node,'apiPort':18085,'binding':binding,'actualUBReads':trace}
        initial={'version':1,'node':node,'kind':'ready','sandboxId':sid,'base':base,'runId':'r','ownerId':'o','manifestSha256':'m','templateId':'t'}
        bundle['readyReports'][node]=report;bundle['readyReceipts'][node]=initial
        bundle['phaseJournals'][node]={'phase':'a-released' if node=='a' else 'b-released',
            'events':[{'phase':p} for p in (['write-a','release-a'] if node=='a' else ['check-b','survive-release-b'])]}
        bundle['lifecycleJournals'][node]={'runId':'r','sandboxIds':[],'openRequests':[],'snapshots':[],
            'outcomeUncertain':False,'operations':[{'kind':'create','httpStatus':201,'ack':{'sandboxIds':[sid]}},
                                               {'kind':'delete','httpStatus':204,'route':'/sandboxes/'+sid}]}
        bundle['commandResults'][node]={'base-read':{'exitCode':0,'timedOut':False,'result':base}}
    base_verify={'status':'CURRENT_UB_STORED_BASE_CONTENT_VERIFIED','sourceFileReads':False,'SDKAllocationCalled':False,
        'bytesVerified':1234*8,'layers':[{'objectName':r['objectName'],'generation':r['generation'],'sha256':r['layerDigest'],'bytes':r['fileBytes']} for r in replicas]}
    phases=bundle['phaseReceipts']
    for kind,node,peer_kind in (('a-written','a','ready-b'),('peer-isolated','b','a-written'),('a-released','a','peer-isolated'),('b-released','b','a-released')):
        r=bundle['readyReports'][node];initial=bundle['readyReceipts'][node]
        peer=bundle['readyReceipts']['b'] if peer_kind=='ready-b' else phases[peer_kind]
        item={**copy.deepcopy(initial),'kind':kind,'written':written,'controllerSha256':PIN,'coreCommit':CORE,
              'peerReceiptSha256':fingerprint(peer),'readyReceiptSha256':fingerprint(initial),'readyReportSha256':fingerprint(r),
              **{k:r[k] for k in ('binaries','serverIdentity','unit','apiPort')},'bindingEvidence':r['binding'],
              'boundReplicas':copy.deepcopy(replicas),'sharedBaseRetired':False}
        if kind=='a-written':
            item['upperBefore']={k:{'path':k,'dev':1,'inode':i,'bytes':10,'mtimeNs':1} for i,k in enumerate(('data','index'))}
            item['upperAfter']=copy.deepcopy(item['upperBefore']);item['upperAfter']['data']['mtimeNs']=2
        else:item.update(baseContentVerified=True,baseChecksumVerificationPending=False,baseVerification=base_verify)
        if kind in ('a-released','b-released'):
            item.update(guestExitConfirmed=True,deviceExitConfirmed=True,localReaderLeasesReleased=True,providerRetained=True,
                        providerStatus={'ownerId':'o','manifestSha256':'m','activeLeases':0,'activePayloadResponses':0})
        if kind=='b-released':
            item['beforePostExitRead']=copy.deepcopy(r['actualUBReads']);item['afterPeerExitRead']=copy.deepcopy(r['actualUBReads'])
            item['afterPeerExitRead'].update(requests=11,bytesIncludingRepeatedReads=120);item['newBackendRequests']=1
        phases[kind]=item
    for node,label,value in (('a','a-private-write',written),('b','b-after-a-write',base),('b','b-after-a-exit',base)):
        bundle['commandResults'][node][label]={'exitCode':0,'timedOut':False,'result':value}
    return bundle

class ReceiptGate(unittest.TestCase):
    def test_complete_synthetic_contract_has_no_scale_or_net_claim(self):
        result=verify(fixture(),PIN)
        self.assertEqual(result['verifiedGuestCommands'],5)
        self.assertFalse(result['sixteenGuestComparisonAccepted']);self.assertFalse(result['scaleExperimentAuthorized'])
        self.assertIsNone(result['netSavingsBytes']);self.assertFalse(result['independentHardwareReobservation'])

    def test_missing_or_failed_command_does_not_pass(self):
        for value in (None,{'exitCode':1,'timedOut':False,'result':{}},{'exitCode':0,'timedOut':True,'result':{}}):
            data=fixture();data['commandResults']['b']['b-after-a-exit']=value
            with self.assertRaises((ValueError,TypeError,KeyError)):verify(data,PIN)

    def test_unknown_post_empty_inventory_cannot_pass(self):
        data=fixture();data['lifecycleJournals']['a']['openRequests']=[{'kind':'create'}]
        with self.assertRaises(ValueError):verify(data,PIN)

    def test_bad_or_stale_receipt_chain_cannot_pass(self):
        for key,value in (('peerReceiptSha256','f'*64),('readyReportSha256','f'*64),('controllerSha256','f'*64)):
            data=fixture();data['phaseReceipts']['b-released'][key]=value
            with self.assertRaises(ValueError):verify(data,PIN)

    def test_cached_or_wrong_daemon_post_exit_read_cannot_pass(self):
        data=fixture();r=data['phaseReceipts']['b-released'];r['afterPeerExitRead']=copy.deepcopy(r['beforePostExitRead'])
        with self.assertRaises(ValueError):verify(data,PIN)
        data=fixture();data['phaseReceipts']['b-released']['afterPeerExitRead']['traceStatus']['pid']=999
        with self.assertRaises(ValueError):verify(data,PIN)

    def test_generation_fallback_and_live_lease_cannot_pass(self):
        mutations=[lambda d:d['phaseReceipts']['b-released']['boundReplicas'][0].update(generation='e'*32),
                   lambda d:d['phaseReceipts']['b-released']['boundReplicas'][0].update(allowRepositoryFallback=True),
                   lambda d:d['phaseReceipts']['b-released']['providerStatus'].update(activeLeases=1),
                   lambda d:d['phaseJournals']['b'].update(pending={'phase':'survive-release-b'})]
        for mutate in mutations:
            data=fixture();mutate(data)
            with self.assertRaises(ValueError):verify(data,PIN)

if __name__=='__main__':unittest.main()
