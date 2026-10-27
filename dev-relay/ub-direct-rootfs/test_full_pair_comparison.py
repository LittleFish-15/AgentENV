"""In-memory synthetic contracts only; never field measurements."""
import copy,hashlib,json,unittest
import full_pair_comparison_body as subject
import full_comparison_admission as admission
import native_group_replay as replay
import scoped_comparison_sample as sampler
import verify_actual_guest_pair as pair_gate
from test_verify_actual_guest_pair import fixture as pair_fixture

MODULES={'pair':pair_gate,'replay':replay,'sampler':sampler,'admission':admission}

def inputs():
    pair=pair_fixture();accepted=pair_gate.verify(pair,pair_gate.EXPECTED_CONTROLLER_SHA)
    refs=pair['phaseReceipts']['a-written']['boundReplicas']
    allocation={'version':1,'mode':'full-stored','presence':'retained','ownerId':'o','manifestSha256':'m','objects':[]}
    counter=0
    for ref,count in zip(refs,(2,3,4,1,1,6,1,1)):
        regions=[]
        for _ in range(count):
            counter+=1
            regions.append({'role':'export','exportNode':'a','exportBootId':'boot-a','exportRegionId':str(counter),'bytes':128*1024**2})
        allocation['objects'].append({'objectName':ref['objectName'],'regions':regions})
    ledger=sampler.ub_reservation(allocation);nodes={}
    layers=[{'digest':r['layerDigest'],'size':r['fileBytes']} for r in refs]
    lower_hash=hashlib.sha256(json.dumps([(r['digest'],r['size']) for r in layers],separators=(',',':')).encode()).hexdigest()
    resources={'cpu_count':2,'memory_mib':4096}
    for node in ('a','b'):
        nodes[node]={}
        for variant in ('original','full'):
            jobs=[];bindings={};reads={}
            for slot in (0,1):
                sid=node+'-'+variant+'-'+str(slot)
                jobs.append({'templateId':'t','slot':slot,'sandboxId':sid,'catalogSha256':'b'*64,'replaySha256':'a'*64,
                    'lowerContentSha256':lower_hash,'resources':resources,'status':'COMPLETED','expectedCommands':1,'nonzeroCommands':1,
                    'results':[{'commandIndex':0,'actionSha256':'c'*64,'requestedDelaySeconds':0,'transportExitCode':0,
                        'guestExitCode':1,'timedOut':False,'elapsedSeconds':1}]})
                process=lambda pid:{'pid':pid,'startTicks':'12345','executable':'/home/jwk/agent/bin/fixed'}
                bindings[sid]={'sandboxId':sid,'variant':variant,'lowerContentSha256':lower_hash,'rootfsMaxSectorsKiB':256,
                    'fcIdentity':process(200+slot),'daemonIdentity':process(300),'imageConfigPath':'/home/jwk/agent/'+sid+'/overlaybd/image.json'}
                if variant=='full':
                    trace=copy.deepcopy(pair['readyReports'][node]['actualUBReads'])
                    trace.update(source=bindings[sid]['imageConfigPath'],digestsRead=[refs[0]['layerDigest']])
                    trace['traceStatus']['pid']=300;reads[sid]=trace
            report={'status':'LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED','workloadSha256':'e'*64,'jobs':jobs,'pendingCommands':0,
                'sampleErrors':[],'elapsedSeconds':10 if variant=='original' else 12,'completedCommands':2,'nonzeroCommands':2,
                'GuestTimeoutSeconds':300,'CLITransportTimeoutSeconds':330}
            version=admission.VERSIONS[variant]
            context={'node':node,'variant':variant,'verifiedCommit':version['commit'],'bootId':'boot-'+node,
                'binaries':{key:version[key] for key in ('server','uvm-ublk-daemon','aenv')},
                'pid':102,'startTicks':'12345'}
            ids=[j['sandboxId'] for j in jobs]
            receipt={'status':'LOCAL_COMPARISON_PHASE_RELEASED','node':node,'variant':variant,'runId':'1'*32,
                'controllerSha256':subject.CONTROLLER,'pairBundleSha256':accepted['bundleSha256'],
                'sharedObjectsRetired':False,'crossNodeSynchronizationVerified':False,'context':context,
                'guests':2,'templateSignature':[['t','b'*64,'a'*64,resources,layers]],'completedCommands':2,'nonzeroCommands':2,
                'elapsedSeconds':report['elapsedSeconds'],'restoreSeconds':2,
                'lifecycleJournals':[{'phase':'quiesced','sandboxIds':[],'openRequests':[],'outcomeUncertain':False,
                    'operations':[{'kind':'create','httpStatus':201,'ack':{'sandboxIds':ids}}]}],
                'cleanup':{'ownedGuestsReleased':True,'released':[{'sandboxId':sid,'fcExitConfirmed':True,
                    'requiredUBDeviceExitConfirmed':variant=='full'} for sid in ids]},
                'providerStatus':{'activeLeases':0,'activePayloadResponses':0,'payloadFailures':0},'actualUBReads':reads}
            def sample(final=False):
                start=(100 if variant=='original' else 300)+(50 if final else 0)
                rows=[]
                for i,category in enumerate(subject.CATEGORIES):
                    value=100 if final and category=='rootfs-lower-original' else 0
                    if node=='b' and variant=='full' and final and category=='rootfs-lower-ub-source':value=200
                    rows.append({'identity':{'dev':1,'inode':i},'category':category,'residentBytes':value,'stableDuringSample':True})
                processes=[{'role':role,'pid':pid,'startTicks':'12345','metricsBytes':{'Pss':10}} for role,pid in
                    [('fc',200),('fc',201),('runtime',102),('daemon',300),('provider',400),('collector',500)]]
                return {'node':node,'group':variant,'bootId':'boot-'+node,'cacheEvictionPerformed':False,'atomicGlobalSnapshot':False,
                    'beginNs':start,'endNs':start+1,'uniqueUBReservation':copy.deepcopy(ledger),'processes':processes,
                    'hostMemoryBytes':{'Cached':1000 if final else 500},'ordinaryFiles':{'available':True,'uniqueFiles':rows},
                    'blockDevices':None,'authoritativeGuestRam':None,'actualUpperModes':{sid:'logStructured' for sid in ids}}
            before=sample();before['group']='before-'+variant
            before['beginNs']-=20;before['endNs']-=20
            before['processes']=[row for row in before['processes'] if row['role']!='fc']
            before['processes'].append({'role':'runtime','pid':103,'startTicks':'12345','metricsBytes':{'Pss':10}})
            nodes[node][variant]={'receipt':receipt,'replay':report,'bindings':bindings,'baseline':sample(),
                'final':sample(True),'beforeGuestCreate':before}
    return nodes,pair,allocation

class Verify(unittest.TestCase):
    def check(self,values):return subject.verify(*values,MODULES)
    def test_complete_small_scope_preserves_negative_submetric_and_na_net(self):
        result=self.check(inputs())
        self.assertEqual(result['guestsPerVariantAcrossNodes'],4)
        self.assertFalse(result['sixteenGuestTargetCompleted'])
        self.assertEqual(result['nonzeroCommandsPerVariant'],{'original':4,'full':4})
        self.assertEqual(result['hostLowerCacheGrowthDifferenceOriginalMinusFullByNodeBytes'],{'a':100,'b':-100})
        self.assertEqual(result['sumOfSeparateNodeCacheGrowthDifferencesBytes'],0)
        self.assertEqual(result['uniqueRetainedUBReservation']['reportedReservationBytesCountedOnce'],2432*1024**2)
        self.assertIsNone(result['netSavingsBytes']);self.assertIsNone(result['globalWallDurationSeconds'])
        self.assertAlmostEqual(result['elapsedChangePercentByNode']['a']['elapsedSeconds'],20)
        self.assertNotIn('originalElapsedSeconds',result['crossNodeOutcomeComparisons']['full'])

    def test_outcome_difference_is_retained_not_ignored(self):
        data=inputs();data[0]['b']['full']['replay']['jobs'][0]['results'][0]['guestExitCode']=2
        result=self.check(data)
        self.assertFalse(result['allCommandExitCodesMatch'])
        self.assertEqual(result['status'],'COMPLETED_RECEIPTS_WITH_COMMAND_OUTCOME_DIFFERENCES')

    def test_missing_file_measurement_is_na_not_zero(self):
        data=inputs();data[0]['a']['full']['final']['ordinaryFiles']={'available':False}
        result=self.check(data)
        self.assertIsNone(result['hostLowerCacheGrowthDifferenceOriginalMinusFullByNodeBytes']['a'])
        self.assertIsNone(result['sumOfSeparateNodeCacheGrowthDifferencesBytes'])

    def test_modified_original_unknown_post_wrong_counts_and_fake_scale_rejected(self):
        mutations=[lambda v:v['receipt']['context']['binaries'].update(server=admission.VERSIONS['full']['server']),
            lambda v:v['receipt']['lifecycleJournals'][0].update(openRequests=['pending']),
            lambda v:v['receipt'].update(completedCommands=9),lambda v:v['receipt'].update(guests=8),
            lambda v:v['replay'].update(CLITransportTimeoutSeconds=600),
            lambda v:v['receipt']['context'].update(bootId='changed')]
        for mutate in mutations:
            data=inputs();mutate(data[0]['a']['original'])
            with self.assertRaises(ValueError):self.check(data)

    def test_trace_fallback_or_missing_release_rejected(self):
        for kind in ('trace','release'):
            data=inputs();row=data[0]['b']['full']['receipt']
            if kind=='trace':next(iter(row['actualUBReads'].values()))['traceStatus']['repository_fallback_reads']=1
            else:row['cleanup']['released'][0]['requiredUBDeviceExitConfirmed']=False
            with self.assertRaises(ValueError):self.check(data)

    def test_duplicate_process_inode_or_foreign_export_epoch_rejected(self):
        for kind in ('process','file','epoch'):
            data=inputs();sample=data[0]['a']['original']['baseline']
            if kind=='process':sample['processes'].append(copy.deepcopy(sample['processes'][0]))
            elif kind=='file':sample['ordinaryFiles']['uniqueFiles'].append(copy.deepcopy(sample['ordinaryFiles']['uniqueFiles'][0]))
            else:data[2]['objects'][0]['regions'][0]['exportBootId']='other'
            with self.assertRaises(ValueError):self.check(data)

    def test_guest_ram_device_and_pss_are_not_added(self):
        data=inputs();sample=data[0]['a']['original']['final']
        sample['authoritativeGuestRam']={'fixtureBytes':10000};sample['blockDevices']=[{'residentBytes':99999}]
        result=self.check(data)
        self.assertIsNone(result['nodes']['a']['original']['final']['disjointTotalBytes'])
        self.assertIsNone(result['incrementalUBPhysicalChargeBytes'])

    def test_creation_and_replay_baselines_are_distinct(self):
        data=inputs()
        rows=data[0]['a']['original']['beforeGuestCreate']['ordinaryFiles']['uniqueFiles']
        rows[0]['residentBytes']=25
        result=self.check(data)['nodes']['a']['original']
        self.assertEqual(result['fileResidentDeltaBytes']['rootfs-lower-original'],100)
        self.assertEqual(result['fileResidentDeltaSinceBeforeCreateBytes']['rootfs-lower-original'],75)
        self.assertEqual(result['beforeGuestCreate']['processCountsByRole']['runtime'],2)

if __name__=='__main__':unittest.main()
