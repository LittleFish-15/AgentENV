"""Publish a read-only post-reboot audit through the same pinned Y entry."""
import ast,datetime,importlib.util,json
from pathlib import Path
H=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('yc',H.parent/'y-jwk-aenv-20261107/controller.py');c=importlib.util.module_from_spec(s);s.loader.exec_module(c);c.H=H;c.SOURCE_PATH='dev-relay/host-pmem/y-debian-clean-20261111/'
def main():
 if (H/'debian-runtime039-publication.private.json').exists():print('BOOT039_ALREADY_PUBLISHED');return
 previous=json.loads((H/'debian-runtime038-publication.private.json').read_text());old=previous['jobs'][0]
 audit=json.loads((H/'diagnosis038-entry-status.private.json').read_text());identity=audit['latestIdentity'];original=old['identity']
 assert audit['queuedJobMatches'] and identity['bootId']!=original['bootId'] and all(identity[k]==original[k] for k in original if k!='bootId'),'Only a verified reboot on the same pinned host may be rebound'
 assert identity['bootId']=='d005bda4-518d-4766-b704-259df7bae4f9'
 source=(H/'Y_boot039.py').read_bytes();ast.parse(source,feature_version=(3,11));assert len(source)<=256*1024
 cl=c.client();prefix='root-entry-v1/'+old['sessionId'];qpath=prefix+'/queues/node-y.json'
 code,raw,_=cl.contents(c.c.CONTROL_REPO,qpath,'main');assert code==200 and json.loads(raw)==previous['queue'],'Current queue changed; preserve it'
 code,raw,_=cl.contents(c.c.RESULT_REPO,'root-results-v1/'+old['sessionId']+'/node-y/'+old['jobId']+'/result.json','main');assert code==404,'038 produced a receipt; read it before proceeding'
 commit,files=c.upload(cl,['Y_boot039.py','publish_boot039.py'],'diagnostic: read-only audit of Y after verified reboot; preserve exact entry and host checks')
 now=datetime.datetime.now(datetime.timezone.utc)
 job={**old,'jobId':'y-debian-post-reboot-audit-20261116-039-node-y','identity':identity,'scope':'read-only-diagnosis','entry':files['Y_boot039.py'],'argv':[],'seconds':900,'notBefore':(now-datetime.timedelta(minutes=2)).isoformat(),'expiresAt':(now+datetime.timedelta(days=3)).isoformat()};job.pop('sourceInlineBase64',None)
 job['authorizationBasis']='User authorizes Y experiment through existing unified root entry while X is busy, and reports038 stopped with task node/boot differs. Read-only existing-entry boot registrations verified same machineId/hostname/kernel6.6.122ublk+/x86_64/entrySHA, only boot changed to d005bda4-518d-4766-b704-259df7bae4f9.038 never passed validation and has no execution receipt; preserve its immutable job/source, no claiming it completed and no relaxing original checks. New039 exact fresh identity and same trusted entry. Audit only own existing jwk deployment and current host facts: unit/proxy/relay/broker state and properties, own paths/device-node metadata, current host-context boot/ns, server/config SHA, current module capacity/neighbor/THP/NUMA/schedstats, FC count/limits/cgroup and benchmark-process presence, authenticated localhost API health/inventory counts using existing key without printing/copying secret values. Write only unique boot-audit output JSON in existing private deployment, print bounded summary. No service start/stop/reload, unit creation, device permission/module/sysctl changes, cache touching, sandbox mutations, benchmark or X contact. This identifies necessary reboot recovery before authorized test; root-entry/source/credential/output limits unchanged.'
 assert len(c.wire(job))<=128*1024
 queue={**previous['queue'],'jobIds':[job['jobId']]};docs={qpath:queue,prefix+'/jobs/'+job['jobId']+'.json':job};c.c.HERE=H
 control=c.c.control_commit(cl,{'name':c.c.CONTROL_REPO,'id':1438089258,'branch':'main'},docs,'Y only: fresh-boot read-only runtime audit;038 remains unexecuted')
 for path,value in docs.items():
  code,raw,_=cl.contents(c.c.CONTROL_REPO,path,'main');assert code==200 and json.loads(raw)==value
 c.save('debian-runtime039-publication.private.json',{'jobs':[job],'queue':queue,'sourceCommit':commit,'controlCommit':control,'targetExecuted':False,'supersedesUnexecutedJob':old['jobId'],'rebootOnly':True})
 print('Y_BOOT039_READY readOnly=true experimentStarted=false exactFreshBootPinned=true')
if __name__=='__main__':main()
