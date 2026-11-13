"""Six consecutive Y no-anchor rounds; preserve036 single-round evidence."""
from pathlib import Path
import ast,base64,datetime,importlib.util,json
H=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('yc',H.parent/'y-jwk-aenv-20261107/controller.py');c=importlib.util.module_from_spec(sp);sp.loader.exec_module(c);c.H=H;c.SOURCE_PATH='dev-relay/host-pmem/y-debian-clean-20261111/'
def main():
 if (H/'debian-runtime037-publication.private.json').exists():print('NO_ANCHOR037_ALREADY_PUBLISHED');return
 previous=json.loads((H/'debian-runtime036-publication.private.json').read_text());old=previous['jobs'][0]
 receipt=json.loads((H/'collected-private'/old['jobId']/'report.json').read_text());assert receipt['state']=='completed' and receipt['exitCode']==0
 assert json.loads((H/'results036/receipt-summary.json').read_text())['success']
 source=(H/'Y_no_anchor036_bound.py').read_text(encoding='utf-8')
 changes={"g6-no-anchor-20261113-036":"g6-no-anchor-six-20261113-037","36-g6-no-anchor.conf":"37-g6-no-anchor-six.conf","Existing036 logging task preserved":"Existing037 logging task preserved","Y-no-anchor-single":"Y-no-anchor-six","formalRounds=1":"formalRounds=6","client,tag=launch(d,1,True)":"client,tag=launch(d,6,True)","summary['rounds_succeeded']==(1)":"summary['rounds_succeeded']==6","summary[phase]['succeeded']==100":"summary[phase]['succeeded']==600"}
 for before,after in changes.items():assert before in source,before;source=source.replace(before,after)
 ast.parse(source,feature_version=(3,11));worker=source.encode();assert len(worker)<256*1024
 # The per-request implementation is the exact previous byte-hash pinned binary.
 def bundle(s):return ast.literal_eval(next(n.value for n in ast.parse(s).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BUNDLE' for t in n.targets)))
 assert bundle(source)==bundle((H/'Y_no_anchor036_bound.py').read_text(encoding='utf-8'))
 assert source.count('launch(d,6,True)')==1 and source.count("launch(d/'prewarm100',1,False)")==1 and "for mode in ('formal',):" in source
 (H/'Y_no_anchor037_bound.py').write_bytes(worker)
 client=c.client();prefix='root-entry-v1/'+old['sessionId'];qpath=prefix+'/queues/node-y.json'
 code,data,_=client.contents(c.c.CONTROL_REPO,qpath,'main');assert code==200 and json.loads(data)==previous['queue']
 commit,files=c.upload(client,['Y_no_anchor037_bound.py','publish_no_anchor037.py'],'experiment: six consecutive Y no-anchor100-concurrency rounds with exact archived G6 client')
 now=datetime.datetime.now(datetime.timezone.utc)
 job={**old,'jobId':'y-debian-g6-no-anchor-six-20261113-037-node-y','entry':files['Y_no_anchor037_bound.py'],'seconds':7200,'sourceInlineBase64':base64.b64encode(worker).decode(),'notBefore':(now-datetime.timedelta(minutes=2)).isoformat(),'expiresAt':(now+datetime.timedelta(days=3)).isoformat()}
 job['authorizationBasis']='Latest user explicitly requests six rounds instead of only one, with every round displayed. Continue agreed Y no-anchor protocol versus archived X G6.036 is verified completed successfully with400operations and stableFC600, preserve its data. New037 unique directory/dropin and immutable task, reuse exact existing Go1.27.4 nativeamd64 historical G6 client (UID-only source adaptation), no binary download/rebuild/generic GitCode client. Same original server/config/boot/hash checks, empty API inventory/manual lock, native Wikidata2vCPU4GiB, neighbor16384/32768/65536, own one-time compactwarn logging restart, low300/high1000 unchanged. Exactly one separate full100 lifecycle prewarm plus built-in singletons; then one Go invocation -rounds6 -barriertrue, six consecutive100/100 formal rounds with create/pause/resume/delete barriers, complete deletion before next round, no explicit round gaps. Do not restart/re-prewarm per round or retain any anchor; no perf/TRACE/detail logs/cache prefetch/flush, no poll gate, no changing workload/request timing. Stable actualFC count recorded,600 reference explicit, no forcing pool or killing entries. Verify six valid rounds,600success eachphase,total2400formaloperations, empty inventory. Failed/interrupted round stops later rounds according to original client; preserve partial rows and failure, no retries or dropping bad rounds to select six. Return raw per-request JSONL, per-round phase stats/wall, manifest and bounded compressed archive, root collection success0 is not experiment success. Final analysis must independently check all six round IDs/counters/wall against raw operations and show six separate rows plus overall mean; include request mean/P50/P95/max in detailed data, do not show only aggregate. No table overwrite or existing036/G7 changes. Same entry guard/private credentials and exact node/boot pins retained.'
 queue={**previous['queue'],'jobIds':[job['jobId']]};docs={qpath:queue,prefix+'/jobs/'+job['jobId']+'.json':job};c.c.HERE=H
 control=c.c.control_commit(client,{'name':c.c.CONTROL_REPO,'id':1438089258,'branch':'main'},docs,'Y only: six consecutive no-anchor lifecycle100/100 rounds, preserve all per-round results')
 for path,value in docs.items():
  code,data,_=client.contents(c.c.CONTROL_REPO,path,'main');assert code==200 and json.loads(data)==value
 c.save('debian-runtime037-publication.private.json',{'jobs':[job],'queue':queue,'sourceCommit':commit,'controlCommit':control,'targetExecuted':False,'anchor':False,'formalRounds':6})
 print('Y_NO_ANCHOR037_READY formalRounds=6 concurrency=100 targetExecuted=false')
if __name__=='__main__':main()
