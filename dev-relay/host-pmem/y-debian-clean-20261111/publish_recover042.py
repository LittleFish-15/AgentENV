"""Deliver two read-only evidence parts through the proven small receipt channel."""
import ast,base64,datetime,importlib.util,json
from pathlib import Path
H=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('yc',H.parent/'y-jwk-aenv-20261107/controller.py');c=importlib.util.module_from_spec(s);s.loader.exec_module(c);c.H=H;c.SOURCE_PATH='dev-relay/host-pmem/y-debian-clean-20261111/'
def main():
 if (H/'debian-runtime042-publication.private.json').exists():print('RECOVERY042_ALREADY_PUBLISHED');return
 previous=json.loads((H/'debian-runtime041-publication.private.json').read_text());old=previous['jobs'][0]
 parent=json.loads((H/'collected-private'/old['jobId']/'report.json').read_text());wrapper=json.loads((H/'results041/wrapper-summary.json').read_text());receipt=wrapper['diagnosticReceipt']
 assert parent['state']=='completed' and parent['exitCode']==0 and wrapper['restorationSuccess'] and wrapper['diagnosticSuccess'] and wrapper['baselineHealthy']
 assert receipt['success'] and receipt['archiveBytes']==1021774 and receipt['archiveSha256']=='d117835140cfe8e710200f7ccbb54a08d40039b40c433f199f6ade8ba308f112'
 raw=(H/'Y_recover042.py').read_bytes();ast.parse(raw,feature_version=(3,11));assert len(raw)<16384
 cl=c.client();prefix='root-entry-v1/'+old['sessionId'];qpath=prefix+'/queues/node-y.json'
 code,data,_=cl.contents(c.c.CONTROL_REPO,qpath,'main');assert code==200 and json.loads(data)==previous['queue'],'Queue changed; preserve it'
 commit,files=c.upload(cl,['Y_recover042.py','publish_recover042.py'],'evidence: read two fixed bounded parts of completed Y diagnostic archive, never rerun experiment')
 now=datetime.datetime.now(datetime.timezone.utc);jobs=[]
 for index in (0,1):
  job={**old,'jobId':'y-debian-evidence-part-20261116-042-%02d-node-y'%index,'scope':'read-only-diagnosis','entry':files['Y_recover042.py'],'sourceInlineBase64':base64.b64encode(raw).decode(),'argv':[str(index)],'seconds':600,'notBefore':(now-datetime.timedelta(minutes=2)).isoformat(),'expiresAt':(now+datetime.timedelta(days=3)).isoformat()}
  job['authorizationBasis']='Continue user-authorized Y diagnosis data collection through the same unified entry only.041 verified runtime restored and diagnostic controller reported success/evidencecomplete/baselinehealthy, but large custom evidence upload failedHTTP0. Existing archive size1021774 SHA d117835140cfe8e710200f7ccbb54a08d40039b40c433f199f6ade8ba308f112 is retained on Y. Both old custom parts are confirmed absent in private results. Read only this exact regular root-owned archive with no symlink, fullSHA and unchanged inode/size/mtime checks; emit fixed part index'+str(index)+' of512000 rawbytes through original entry stdout<700000bytes, preserving1MiB local/2MiB report/128chunks limits. Two independent read-only jobs fit queue2<=4 and execute in same root-start invocation. Use installed inline007 path, same boot/machine/entry/sourceSHA/blob checks and credential isolation. Do not start/stop/reload service, mutate any file/sysctl/template/sandbox, capture new perf or repeat any benchmark. Never contact X. Only original root entry privately uploads these bounded receipts; local collector must verify all parent hashes/identities, both offsets/partSHA and archivefullSHA, then safely extract while preserving old partial summaries. No original041 source/job/evidence or performance result is overwritten.'
  assert len(c.wire(job))<=128*1024;jobs.append(job)
 queue={**previous['queue'],'jobIds':[job['jobId'] for job in jobs]};docs={qpath:queue,**{prefix+'/jobs/'+job['jobId']+'.json':job for job in jobs}};c.c.HERE=H
 control=c.c.control_commit(cl,{'name':c.c.CONTROL_REPO,'id':1438089258,'branch':'main'},docs,'Y only: recover completed diagnostic archive via two bounded original-entry receipts; no experiment rerun')
 for path,value in docs.items():
  code,data,_=cl.contents(c.c.CONTROL_REPO,path,'main');assert code==200 and json.loads(data)==value
 c.save('debian-runtime042-publication.private.json',{'jobs':jobs,'queue':queue,'sourceCommit':commit,'controlCommit':control,'targetExecuted':False,'readOnlyRecovery':True,'experimentRerun':False,'archiveBytes':receipt['archiveBytes'],'archiveSha256':receipt['archiveSha256']})
 print('Y_RECOVERY042_READY readOnly=true jobs=2 sameEntry=true experimentRerun=false')
if __name__=='__main__':main()
