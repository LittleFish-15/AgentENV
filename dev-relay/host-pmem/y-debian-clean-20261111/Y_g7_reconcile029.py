"""One-time, authenticated026 receipt reconciliation, then ordinary guarded entry."""
import fcntl,hashlib,http.client,importlib.util,json,os,pathlib,time
P=pathlib.Path;B=P('/home/jwk/aenv-y-clean-20261111');S=B.parent/'y-aenv-control/relay-debian-clean-20261111'
OLD='y-debian-anchor-memory-ab-20261112-026-node-y'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 assert os.geteuid()==0;os.umask(0o077)
 entry=S/'entry.py';assert sha(entry.read_bytes())=='a60349eb2679f241e4f5fb46a6b88c8b6f51a6c48f80660d1848988718a9619d'
 spec=importlib.util.spec_from_file_location('trusted_entry',entry);e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
 creds=json.loads(e.read(S/'credentials.json',8192));control=e.API.GitHub(creds['controlToken']);results=e.API.GitHub(creds['resultToken'])
 control.private_repo(e.CONTROL,1438089258);results.private_repo(e.RESULTS,1438089386)
 plan=e.fetch(control,'root-entry-v1/'+e.SESSION+'/manual-reconciliations/g7-029.json')
 assert plan['sourceSha256']==sha(P(__file__).read_bytes()) and plan['humanApproved'] is True
 current=e.identity();assert current['bootId']=='f05c9a4f-bf8b-49f2-a3ea-4cdd0b5fc581'
 job=e.fetch(control,'root-entry-v1/'+e.SESSION+'/jobs/'+OLD+'.json');assert sha(e.wire(job))==plan['oldJobSha256']
 fd=os.open(S/'operation.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 lock=os.open(B/'scripts/.run.lock',os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  d=S/'jobs'/OLD;reportpath=d/'report.json';statepath=d/'state.json'
  if reportpath.exists():
   prior=json.loads(reportpath.read_text());assert prior.get('exitCodeOrigin')=='administrative_receipt_reconciliation_g7' and prior['jobSha256']==plan['oldJobSha256']
  else:
   raw=statepath.read_bytes();assert sha(raw)==plan['oldStateSha256'] and sha((d/'task.py').read_bytes())==job['entry']['sha256']
   assert sha((d/'stdout.log').read_bytes())==plan['oldStdoutSha256']
   result=json.loads((B/'diagnostic026/result.json').read_text());worker=json.loads((B/'anchor026/result.json').read_text())
   assert result['success'] and result['workerExitCode']==0 and worker['success'] and worker['finalInventoryCount']==0
   assert result['archive']['sha256']=='4e36784332ca3a841bfc916dc28b0da6fb2f91077e9397eac18c52eb66bc0404'
   for p in P('/proc').iterdir():
    if not p.name.isdigit():continue
    try:
     args=(p/'cmdline').read_bytes().decode(errors='replace').split('\0')
     assert not any(a in (str(d/'task.py'),str(B/'diagnostic026/anchor026_worker.py')) for a in args),'Old experiment process still alive'
    except OSError:pass
   key=(B/'config/api-key').read_text().strip()
   for state in ('running','paused'):
    c=http.client.HTTPConnection('127.0.0.1',18080,timeout=20)
    try:
     c.request('GET','/v2/sandboxes?limit=1&state='+state,headers={'X-API-Key':key});r=c.getresponse();assert r.status==200 and json.loads(r.read())==[]
    finally:c.close()
   code,_,_=results.contents(e.RESULTS,'root-results-v1/'+e.SESSION+'/node-y/'+OLD+'/result.json','main');assert code==404,'Existing immutable026 receipt preserved'
   backup=d/'state.before-g7-reconciliation029.json'
   with backup.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
   message='026 experiment successful data recovered through027. Entry process exit status was not recovered after stdout bound failure. Administrative code125 closes only the orphan receipt; original source, logs and state backup preserved.'
   data=(message+'\n').encode();report={'schema':1,'jobId':OLD,'jobSha256':plan['oldJobSha256'],'identity':current,'state':'completed','exitCode':125,'originalProcessExitCode':None,'exitCodeOrigin':'administrative_receipt_reconciliation_g7','savedExperimentSuccess':True,'originalStateSha256':sha(raw),'logs':{'stdout.log':{'text':data.decode(),'bytes':len(data),'sha256':sha(data),'redacted':False}}}
   e.save(reportpath,report);e.save(statepath,{'state':'administratively_reconciled','exitCode':125,'originalProcessExitCode':None,'originalStateSha256':sha(raw)})
  e.publish_report(results,'node-y',job,json.loads(reportpath.read_text()))
  print('026_RECEIPT_RECONCILED_ORIGINAL_LOGS_PRESERVED',flush=True)
 finally:os.close(lock);os.close(fd)
 os.execv('/bin/bash',['bash',str(S.parent/'root-start.sh')])
if __name__=='__main__':main()
