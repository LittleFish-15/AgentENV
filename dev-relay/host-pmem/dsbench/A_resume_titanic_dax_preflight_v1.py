"""Resume A after the exact pre-SDK GitHub receipt conflict; no preparation retry."""
import hashlib,json,os,sys,time,types
from pathlib import Path
OLD=Path('/home/jwk/root/relay/jobs/titanic-dax-services-20261102-013-node-a/task.py')
PIN='445e26e1f239c5244f0e2957b2b94742039dc5d2398ca04cb167d94f230837f9'
PREVIOUS_JOB_SHA='37ca087f962925401b808a60a557ac5a5ed7a20b226250a2f3fc2d99a13251d7'

def need(ok,why):
    if not ok:raise RuntimeError(why)

def main():
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='server1','A root only')
    raw=OLD.read_bytes();need(OLD.resolve()==OLD and OLD.stat().st_uid==0 and hashlib.sha256(raw).hexdigest()==PIN,'Original fixed source differs')
    report=json.loads((OLD.parent/'report.json').read_text());need(report['state']=='completed' and report['exitCode']==1 and report['jobSha256']==PREVIOUS_JOB_SHA,'Previous root report differs')
    need('HTTP 409' in report['logs']['stdout.log']['text'] and "self.event('prerequisites-ready'" in report['logs']['stderr.log']['text'],'Not the confirmed preflight-receipt conflict')
    m=types.ModuleType('titanic_original');m.__file__=str(OLD);exec(compile(raw,str(OLD),'exec'),m.__dict__)
    api=m.module('api');tokens=json.loads(m.read(m.CREDS,8192,owners=(1204,)));result=api.GitHub(tokens['resultToken']);result.private_repo(m.RESULTS,1438089386)
    app=m.Start('node-a',api,result,'status');s=app.state
    need(s['phase']=='stopped_preserve_resources' and s.get('failure')=={'errorType':'Network','reason':'GitHub request unavailable (HTTP 409)'} and s['SDK_called'] is False and s['units']=={} and set(s['steps'])=={'export_code'} and s['steps']['export_code']['state']=='done' and not (app.active/'provider').exists(),'Mutation may have occurred; refuse implicit resume')
    original=result.immutable_result
    def bounded_receipt(repo,rid,branch,path,payload):
        for attempt in range(5):
            try:return original(repo,rid,branch,path,payload)
            except api.Network as error:
                if error.status not in (409,422) or attempt==4:raise
                # Read at a fixed fresh commit: ACK may have been lost. Only the
                # same immutable metadata bytes may be retried, never SDK calls.
                code,ref,_=result.request('GET','/repos/'+repo+'/git/ref/heads/'+branch+'?verify='+str(time.time_ns()))
                need(code==200,'Receipt branch unavailable');code,existing,_=result.contents(repo,path,ref['object']['sha'])
                if code==200:
                    need(existing==payload,'Existing immutable receipt differs; preserve');return
                need(code==404,'Cannot establish receipt absence')
                print('RECEIPT_WRITE_CONFLICT_RECONCILED_ABSENT attempt='+str(attempt+1),flush=True);time.sleep(min(2**attempt,4))
    result.immutable_result=bounded_receipt
    backup=m.BASE/'private/pre-receipt-resume-state.json';m.put(backup,m.wire(s)+b'\n',mode=0o600)
    s['resumeReason']='pre-SDK immutable receipt HTTP409 only';app.mark('preflight_receipt_transport_resume')
    try:app.start()
    except Exception as error:
        s['failure']={'errorType':type(error).__name__,'reason':str(error)[:500]};app.mark('stopped_preserve_resources')
        print(json.dumps({'status':'TITANIC_DAX_RESUME_STOPPED_PRESERVE_RESOURCES','errorType':type(error).__name__,'reason':str(error)[:500],'SDKPhase':s.get('steps',{}).get('sdk'),'automaticSDKRetry':False}));raise
if __name__=='__main__':main()
