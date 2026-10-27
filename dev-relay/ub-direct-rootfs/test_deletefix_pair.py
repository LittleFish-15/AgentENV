"""Synthetic receipts only; no fixtures are saved as real experimental results."""
import copy,importlib.util,json,sys,types,unittest
from pathlib import Path
HERE=Path(__file__).parent
def imported(name,file):
 spec=importlib.util.spec_from_file_location(name,HERE/file);value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
legacy=imported('verify_actual_guest_pair','verify_actual_guest_pair.py')
fixtures=imported('legacy_contract_fixture','test_verify_actual_guest_pair.py')
v=imported('verify_deletefix_pair','verify_deletefix_pair.py')
PIN='c'*64

def fixture():
 old=fixtures.fixture()
 history={'kind':'retained-original-pair-isolation-only','readyReports':old['readyReports'],
          'aWritten':old['phaseReceipts']['a-written'],'bIsolated':old['phaseReceipts']['peer-isolated']}
 ready=copy.deepcopy(old['readyReports']);initial=copy.deepcopy(old['readyReceipts']);releases={};commands={}
 for node in ('a','b'):
  sid='fresh-'+node;r=ready[node];i=initial[node]
  r.update(coreCommit=v.CORE,pairRunId='f'*32,sandboxId=sid)
  r['binaries']={key:{'sha256':pin,'bytes':1} for key,pin in v.PINS.items()}
  r['binding']['sandboxId']=sid;r['binding'].update(rootfsDeviceMajor=259,rootfsDeviceMinor=7);r['provider']['providerProcess']={'bootId':'boot-'+node}
  i.update(runId='f'*32,sandboxId=sid)
  life=copy.deepcopy(old['lifecycleJournals'][node]);life.update(phase='quiesced',runId='f'*32)
  life['operations'][0]['ack']['sandboxIds']=[sid];life['operations'][1]['route']='/sandboxes/'+sid
  release={'kind':node+'-released','node':node,'runId':'f'*32,'sandboxId':sid,'controllerSha256':PIN,
    'readyReportSha256':v.fingerprint(r),'readyReceiptSha256':v.fingerprint(i),
    **{key:r[key] for key in ('coreCommit','serverIdentity','binaries','unit','apiPort')},
    'bindingEvidence':r['binding'],'deleteHttpStatus':204,'guestExitConfirmed':True,'privateRootfsDeviceRemoved':True,
    'localReaderLeasesReleased':True,'sharedObjectsRetired':False,'forcedCleanupUsed':False,
    'memoryRelease':{'guestReferenceReleased':True,'state':'idle-on-placeholder'},
    'providerStatus':{'ownerId':i['ownerId'],'manifestSha256':i['manifestSha256'],'activeLeases':0,'activePayloadResponses':0},'journal':life}
  releases[node+'-released']=release;commands[node]={'base-read':{'exitCode':0,'timedOut':False,'result':i['base']}}
 a=releases['a-released'];b=releases['b-released']
 a.update(peerReadyReportSha256=v.fingerprint(ready['b']),peerReadyReceiptSha256=v.fingerprint(initial['b']))
 before=copy.deepcopy(ready['b']['actualUBReads']);after=copy.deepcopy(before);after.update(requests=11,bytesIncludingRepeatedReads=120)
 b.update(peerReleaseSha256=v.fingerprint(a),beforePostExitRead=before,afterPeerExitRead=after,newBackendRequests=1)
 b['postExitReadPreparation']={'status':'PRIVATE_ROOTFS_BLOCK_CACHE_FLUSHED','device':ready['b']['binding']['rootfsDevice'],'major':259,'minor':7}
 commands['b']['b-after-a-exit']={'exitCode':0,'timedOut':False,'result':initial['b']['base']}
 return {'kind':'deletefix-composite-pair-v1','historicalIsolation':history,'readyReports':ready,'readyReceipts':initial,
  'boundReplicas':{node:copy.deepcopy(history['aWritten']['boundReplicas']) for node in ('a','b')},
  'exitReceipts':releases,'commandResults':commands}

class CompositeGate(unittest.TestCase):
 def test_explicit_multi_run_scope_no_benefit_claim(self):
  result=v.verify(fixture(),PIN)
  self.assertTrue(result['evidenceFromMultipleExplicitRuns']);self.assertFalse(result['oldFailedDeleteReclassified']);self.assertIsNone(result['netSavingsBytes'])
 def test_no_cached_only_peer_success(self):
  data=fixture();b=data['exitReceipts']['b-released'];b['afterPeerExitRead']=copy.deepcopy(b['beforePostExitRead'])
  with self.assertRaises(ValueError):v.verify(data,PIN)
 def test_forced_or_unacknowledged_release_fails(self):
  for key,value in [('forcedCleanupUsed',True),('deleteHttpStatus',404),('privateRootfsDeviceRemoved',False)]:
   data=fixture();data['exitReceipts']['b-released'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):v.verify(data,PIN)
 def test_wrong_generation_or_old_daemon_fails(self):
  data=fixture();data['boundReplicas']['b'][0]['generation']='e'*32
  with self.assertRaises(ValueError):v.verify(data,PIN)
  data=fixture();data['readyReports']['b']['binaries']['uvm-ublk-daemon']['sha256']=v.OLD_DAEMON
  with self.assertRaises(ValueError):v.verify(data,PIN)
 def test_missing_or_mismatched_historical_base_fails(self):
  data=fixture();data['historicalIsolation']['bIsolated']['baseVerification']['sourceFileReads']=True
  with self.assertRaises(ValueError):v.verify(data,PIN)
 def test_broken_causal_chain_fails(self):
  data=fixture();data['exitReceipts']['b-released']['peerReleaseSha256']='0'*64
  with self.assertRaises(ValueError):v.verify(data,PIN)
 def test_unknown_lifecycle_fails(self):
  data=fixture();data['exitReceipts']['b-released']['journal']['openRequests']=[{'kind':'delete'}]
  with self.assertRaises(ValueError):v.verify(data,PIN)

if __name__=='__main__':unittest.main()
