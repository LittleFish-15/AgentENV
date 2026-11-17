"""Install a small quick-test wrapper only; no benchmark or service operation."""
import ast,base64,datetime,importlib.util,json
from pathlib import Path
M=Path(__file__).resolve().parent;Y=M.parent/'y-debian-clean-20261111'
s=importlib.util.spec_from_file_location('yc',Y.parent/'y-jwk-aenv-20261107/controller.py');c=importlib.util.module_from_spec(s);s.loader.exec_module(c);c.H=M;c.SOURCE_PATH='dev-relay/host-pmem/y-debian-clean-20261111/'
def main():
 if (Y/'debian-runtime054-publication.private.json').exists():print('Y_QUICK054_ALREADY_PUBLISHED');return
 previous=json.loads((Y/'debian-runtime053-publication.private.json').read_text(encoding='utf-8'));old=previous['jobs'][0];receipt=json.loads((Y/'collected-private'/old['jobId']/'report.json').read_text(encoding='utf-8'));assert receipt['state']=='completed' and receipt['exitCode']==0
 raw=(M/'install_quick054.py').read_bytes();ast.parse(raw,feature_version=(3,11));client=c.client();prefix='root-entry-v1/'+old['sessionId'];qpath=prefix+'/queues/node-y.json';code,data,_=client.contents(c.c.CONTROL_REPO,qpath,'main');assert code==200 and json.loads(data)==previous['queue'],'Queue changed; preserve it'
 commit,files=c.upload(client,['install_quick054.py','memory-quick.sh','publish_y054.py'],'tool: small repeatable memory bandwidth and latency quick-test wrapper')
 now=datetime.datetime.now(datetime.timezone.utc);job={**old,'jobId':'y-debian-install-memory-quick-20261117-054-node-y','entry':files['install_quick054.py'],'sourceInlineBase64':base64.b64encode(raw).decode(),'argv':[],'seconds':60,'notBefore':(now-datetime.timedelta(minutes=2)).isoformat(),'expiresAt':(now+datetime.timedelta(days=3)).isoformat()}
 job['authorizationBasis']='User asks to use existing native memory tools for a simple bandwidth/latency test in one or two commands. Install only /home/jwk/memory-quick.sh rootowned0755, same contents as X. Preserve existing different file or symlink, no overwrite. Wrapper reuses existing046 verified native binary/helper/manifest; no software install, no benchmark execution in this task, no service/process/sysctl/frequency/aenv mutation. Root user can later run bash /home/jwk/memory-quick.sh for read16threads fixedTOTAL1GiB and singlepointer1GiB latency,3samples each, approximately30seconds; optional read/copy/latency/all modes. Same16physicalCPU NUMA0binding/4KiB-related arguments and arithmeticChasAVG parsing as paired study. Childminimalenvironment, source/nativeSHA checks,90secondtimeout, own childgroupcleanup only. Original inline rootentry and all identity/source/output guards unchanged. Publication only, user triggers original Y root-start.sh. Fourphase diagnostic objective remains separate and this does not start it.'
 assert len(c.wire(job))<=128*1024
 queue={**previous['queue'],'jobIds':[job['jobId']]};docs={qpath:queue,prefix+'/jobs/'+job['jobId']+'.json':job};c.c.HERE=Y;control=c.c.control_commit(client,{'name':c.c.CONTROL_REPO,'id':1438089258,'branch':'main'},docs,'Y only: install quick memory wrapper without executing a workload')
 for path,value in docs.items():
  code,data,_=client.contents(c.c.CONTROL_REPO,path,'main');assert code==200 and json.loads(data)==value
 c.H=Y;c.save('debian-runtime054-publication.private.json',{'jobs':[job],'queue':queue,'sourceCommit':commit,'controlCommit':control,'targetExecuted':False,'installOnly':True});print('Y_QUICK054_READY installOnly=true path=/home/jwk/memory-quick.sh')
if __name__=='__main__':main()
