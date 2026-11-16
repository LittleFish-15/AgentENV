"""Publish the already verified038 assets using the entry's native Git fetch."""
import ast,datetime,importlib.util,json
from pathlib import Path
H=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('yc',H.parent/'y-jwk-aenv-20261107/controller.py');c=importlib.util.module_from_spec(sp);sp.loader.exec_module(c);c.H=H;c.SOURCE_PATH='dev-relay/host-pmem/y-debian-clean-20261111/'
def main():
 if (H/'debian-runtime038-publication.private.json').exists():print('DIAGNOSIS038_ALREADY_PUBLISHED');return
 previous=json.loads((H/'debian-runtime037-publication.private.json').read_text());old=previous['jobs'][0]
 receipt=json.loads((H/'collected-private'/old['jobId']/'report.json').read_text());assert receipt['state']=='completed' and receipt['exitCode']==0 and json.loads((H/'results037/receipt-summary.json').read_text())['success']
 worker=(H/'Y_diagnose038_bound.py').read_bytes();tree=ast.parse(worker,feature_version=(3,11));values={}
 for n in tree.body:
  if isinstance(n,ast.Assign):
   for t in n.targets:
    if isinstance(t,ast.Name) and t.id in ('BUNDLE','ASSETS','BUILD'):values[t.id]=ast.literal_eval(n.value)
 assert len(worker)<=256*1024 and values['BUILD']==json.loads((H/'diagnostic038-build-proof.json').read_text())
 # Reuse byte-identical assets from the completed source publication. The
 # previous attempt stopped before a control commit, at its128KiB file guard.
 client=c.client();prefix='root-entry-v1/'+old['sessionId'];qpath=prefix+'/queues/node-y.json'
 code,raw,_=client.contents(c.c.CONTROL_REPO,qpath,'main');assert code==200 and json.loads(raw)==previous['queue'],'Previous queue changed; preserve it'
 commit,files=c.upload(client,['Y_diagnose038_bound.py','publish_diagnosis038b.py'],'diagnostic: use native hash-pinned Git source fetch within existing control document bound')
 now=datetime.datetime.now(datetime.timezone.utc)
 job={**old,'jobId':'y-debian-no-anchor-diagnosis-20261116-038-node-y','scope':'approved-root-operation','entry':files['Y_diagnose038_bound.py'],'seconds':10800,'argv':[],'notBefore':(now-datetime.timedelta(minutes=2)).isoformat(),'expiresAt':(now+datetime.timedelta(days=3)).isoformat()};job.pop('sourceInlineBase64',None)
 job['authorizationBasis']='User explicitly authorizes experiment now on Y via the original unified manual root entry while X runs1:8 overcommit. No SSH/API access to X. Preserve exact machine/boot/entry/server/config pins and manual-run lock; require empty API inventory, ready native Wikidata2vCPU4GiB, natural stable own FC pool300..1000/cgroup/nofile1M. No anchor, real template-device opener/mincore/prefetch, kernel install/reboot, sysctl/THP/NUMA/neighbor changes or global cache clearing. Read running host kernel config/provenance/runtime memory/PSI/schedstats. Receive pinned linuxamd64 Go1.27.4 trimpath binary parts using existing private-root control client, validate everypart/fullSHA/ELF; no Go toolchain install/download or X build. Historical G6 request implementation byte-identical, only UID1002 and stage hooks outside SDK timers. Temporary38 dropin enables own service JSONclose/debug without envdTRACE, always remove own dropin and restore prior logging/service state. One separate100 full lifecycle prewarm then builtin singleton and one formal100/100 create/pause/resume/delete diagnostic; no performance gate/retry/selection. Scope perf99Hz cpu-clock:kH FP to own unit, capture FC/TID starttime-bound CPU/fault/schedstat, map measured targets separately from background pool. Record non-atomic counter-read intervals, crop perf by client CLOCK_MONOTONIC phase windows; rawperf retainedY withSHA, bounded text returned. Report missing instrumentation as partial, not workload failure or kernel proof. After full cleanup run only own dedicated deterministic64MiB ordinary file,100 fresh readonly MAP_PRIVATE workers and fixed4096 offsets percase,3 cold/hot pairs; fadviseDONTNEED ownfile only and mincore validates cold/hot after worker readiness. No retry of invalid cache states. Record CPU/fault/touchwall/memory overhead, bounded process-group cleanup and dev/inode-verified file deletion. Root may read existing private credentials to receive pinned binary parts and upload only this task evidence to private results evidence-v1/'+old['sessionId']+'/node-y/diagnosis038/ as immutable <=800000byteparts plus manifest/fullSHA; credentials never enter childenv/log/source. Tiny stdout keeps original output/control bounds. Source fetched by existing entry Git pin; remove unused duplicate sourceInlineBase64 only. Preserve all partial data/errors and clean only confirmed own run-tagged IDs. No public benchmark repository or historical-table changes. Y-only results do not prove simultaneous X/Y or kernel causality.'
 assert len(c.wire(job))<=128*1024
 queue={**previous['queue'],'jobIds':[job['jobId']]};docs={qpath:queue,prefix+'/jobs/'+job['jobId']+'.json':job};c.c.HERE=H
 control=c.c.control_commit(client,{'name':c.c.CONTROL_REPO,'id':1438089258,'branch':'main'},docs,'Y only: no-anchor100 diagnosis and bounded host mmap cold/hot evidence')
 for path,value in docs.items():
  code,raw,_=client.contents(c.c.CONTROL_REPO,path,'main');assert code==200 and json.loads(raw)==value
 c.save('debian-runtime038-publication.private.json',{'jobs':[job],'queue':queue,'sourceCommit':commit,'controlCommit':control,'targetExecuted':False,'anchor':False,'diagnosticRounds':1,'mmapPairs':3})
 print('Y_DIAGNOSIS038_READY diagnosticRounds=1 concurrency=100 mmapPairs=3 targetExecuted=false')
if __name__=='__main__':main()
