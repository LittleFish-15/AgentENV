"""Read existing two-round evidence and bounded failure tails; never rerun tasks.

Only the user-run A entry contacts the already authorized B SSH account. No API,
SDK, Guest, service, signal, cache advice, deletion or permission operation.
"""
import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess
import time
import uuid

ROOT=Path('/home/jwk/agent')
WORK=ROOT/'r/lazy-four-rollout-v1'
D=ROOT/'deployments/agentenv-lazy-four-32ce41c'


def need(ok,message):
    if not ok:raise RuntimeError(message)


def redact(text):
    text=re.sub(r'e2b_[A-Za-z0-9._~-]+','[REDACTED]',text)
    return re.sub(r'(?i)(["\x27]?(?:token|password|api_key)["\x27]?\s*[:=]\s*)["\x27]?[^\s,"\x27}]+',r'\1[REDACTED]',text)


def read_file(path,limit=16*1024**2,tail=False):
    need(path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Unexpected readback path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204,'Unexpected evidence owner/type')
        if tail:stream.seek(max(0,before.st_size-limit))
        else:need(before.st_size<=limit,'Evidence exceeds bounded read')
        raw=stream.read(limit+1)
        after=os.fstat(stream.fileno())
    need(len(raw)<=limit,'Evidence read exceeds bound')
    return raw,{'fileBytes':before.st_size,'readBytes':len(raw),
                'changedDuringRead':(before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns),
                'sha256OfReadBytes':hashlib.sha256(raw).hexdigest()}


def checkpoint(sample):
    if not isinstance(sample,dict):return None
    lower=sample.get('rootfsLowerFiles',sample.get('lower',{}))
    provider=sample.get('provider',{})
    return {'phase':sample.get('phase'),'startNs':sample.get('startNs'),'endNs':sample.get('endNs'),
            'lowerResidentBytes':lower.get('residentBytes') if lower.get('available') is True else None,
            'lowerFileCount':len(lower.get('files',[])) if lower.get('available') is True else None,
            'provider':{k:provider.get(k) for k in ('available','enabled','errorType','pid','startTicks','cacheId','pool',
                'sdkReportedBackingCoverageBytes','logicalRequestBudgetBytes','counters','wholeProcess','cgroup')},
            'host':sample.get('host'),'scope':'observed_checkpoint_not_full_run_or_physical_net_savings'}


def report_summary(report):
    jobs=report.get('jobs',[])
    need(isinstance(jobs,list) and len(jobs)<=8,'Unexpected cohort size')
    keys=('status','scenario','node','runId','workerExitCode','errorType','reason','ownedGuestsReleased',
          'outcomeUncertain','remainingSandboxIds','temporaryCredentialsRemoved','sampleFile','context')
    result={key:report.get(key) for key in keys}
    result['jobs']=[{key:job.get(key) for key in ('index','templateIndex','slot','sandboxId','instanceId','state',
        'stepsCompleted','failedCommands','errorType','replayStartedUnix','replayFinishedUnix','privateUpperIsolationPassed')} for job in jobs]
    result['actionsCompleted']=sum(j.get('stepsCompleted',0) for j in jobs)
    result['expectedActionsPerNode']=382
    result['completedGuests']=sum(j.get('state')=='REPLAY_COMPLETED' for j in jobs)
    result['bindingStatus']={key:report.get(key,{}).get('status') for key in ('rootfsBindingEvidence','finalRootfsBindingEvidence')}
    result['gates']={key:report.get(key,{}).get('status') for key in ('admissionGate','completedGate')}
    result['sampleCount']=report.get('measurementSummary',{}).get('sampleCount')
    result['admission']=checkpoint(report.get('admissionSample'))
    result['completed']=checkpoint(report.get('completedSample'))
    checkpoints=report.get('rootfsCheckpoints',[])
    result['lastRootfsCheckpoint']=checkpoint(checkpoints[-1]) if checkpoints else None
    result['hostObservations']=report.get('measurementSummary',{}).get('hostObservations')
    result['templateMemoryRows']=[row for row in report.get('measurementSummary',{}).get('templateRows',[])
                                  if row.get('phase') in ('both_replaying','after_replay')]
    result['operationCountsByTemplate']={index:len(rows) for index,rows in report.get('operationsByTemplate',{}).items()}
    result['fullComparisonAccepted']=False
    return result


def collect_node(node):
    need(os.getuid()==os.geteuid()==1204 and socket.gethostname()==('server1' if node=='node-a' else 'agent1'),
         'Use declared ordinary jwk node')
    output={'node':node,'readOnlyTargetOperations':True,'reports':{},'readErrors':[],'readAtUnixNs':time.time_ns()}
    def get_json(path):
        raw,meta=read_file(path)
        need(not meta['changedDuringRead'],'Final report changed during read')
        return json.loads(raw),meta
    for mode in ('off','lazy'):
        path=WORK/(mode+'-'+node+'.json')
        try:
            report,meta=get_json(path)
            output['reports'][mode]={'summary':report_summary(report),'source':str(path),'sourceEvidence':meta}
            if mode=='lazy':
                failures=[]
                for job in report.get('jobs',[]):
                    if job.get('state')=='REPLAY_COMPLETED':continue
                    index=job.get('index');need(type(index) is int and 0<=index<8,'Unexpected command-log index')
                    commands=D/'four-cohort/lazy/commands'
                    event=commands/(str(index)+'-events.jsonl')
                    row={'index':index,'sandboxId':job.get('sandboxId')}
                    try:
                        raw,meta=read_file(event,8192,True)
                        parsed=[]
                        for line in raw.decode(errors='replace').splitlines():
                            try:parsed.append(json.loads(line))
                            except ValueError:continue
                        row['lastCompletedCommandEvents']=parsed[-3:]
                    except OSError as error:row['eventError']=type(error).__name__
                    # stderr/stdout for the last two attempted steps; no source
                    # trace, credentials, environment or arbitrary path reads.
                    paths=[]
                    for path in commands.glob(str(index)+'-step-*.stderr'):
                        match=re.fullmatch(str(index)+r'-step-(\d+)\.stderr',path.name)
                        if match:paths.append((int(match[1]),path))
                    row['lastAttemptedCommandLogs']=[]
                    for step,stderr in sorted(paths)[-2:]:
                        for path in (stderr,stderr.with_suffix('.stdout')):
                            try:
                                raw,meta=read_file(path,4096,True)
                                row['lastAttemptedCommandLogs'].append({'step':step,'file':path.name,'evidence':meta,
                                                                       'tail':redact(raw.decode(errors='replace'))})
                            except OSError as error:row['lastAttemptedCommandLogs'].append({'file':path.name,'errorType':type(error).__name__})
                    failures.append(row)
                output['lazyFailedJobEvidence']=failures
        except (OSError,ValueError,RuntimeError,KeyError) as error:
            output['readErrors'].append({'file':str(path),'errorType':type(error).__name__,
                                         'reason':str(error)[:200] if isinstance(error,RuntimeError) else 'Read/shape unavailable'})
    for name,path in [('cohortState',D/'cohort-state.json'),('lazyCaseState',D/'four-cohort/lazy/state.json'),
                      ('rootClientState',WORK/'root-mailbox/client-state.json')]:
        try:
            value,meta=get_json(path)
            if name=='lazyCaseState':
                value={index:{k:state.get(k) for k in ('phase','runId','sandboxIds','openRequests','outcomeUncertain')}
                       for index,state in value['cases'].items()}
            output[name]=value
        except (OSError,ValueError,RuntimeError,KeyError) as error:output[name]={'unavailable':type(error).__name__}
    session=ROOT/('r/lazy4-a-v1' if node=='node-a' else 'r/lazy4-b-v1')
    try:
        value,meta=get_json(session/'provider/owner.json')
        output['providerJournal']={k:value.get(k) for k in ('state','mode','role','cacheId','pool','backingCoverageBytes',
              'errorType','creationConfirmed','deleteAcknowledged','finalizeAcknowledged','poolBytes','startupPayloadBytes')}
    except (OSError,ValueError,RuntimeError) as error:output['providerJournal']={'unavailable':type(error).__name__}
    for name,path in [('providerLog',session/'service.log'),('runtimeLog',D/'logs/ublk-daemon.log')]:
        try:
            raw,meta=read_file(path,6144,True)
            output[name]={'evidence':meta,'tail':redact(raw.decode(errors='replace'))}
        except (OSError,RuntimeError) as error:output[name]={'unavailable':type(error).__name__}
    return output


def remote_read():
    names=(need,redact,read_file,checkpoint,report_summary,collect_node)
    code='import hashlib,json,os,re,socket,stat,time\nfrom pathlib import Path\n'
    code+="ROOT=Path('/home/jwk/agent');WORK=ROOT/'r/lazy-four-rollout-v1';D=ROOT/'deployments/agentenv-lazy-four-32ce41c'\n"
    code+='\n\n'.join(inspect.getsource(fn) for fn in names)
    code+="\nprint(json.dumps(collect_node('node-b'),ensure_ascii=False))\n"
    ssh=['/usr/bin/ssh','-F','/dev/null','-i','/home/jwk/.ssh/agentenv-native-four/id_ed25519',
         '-oIdentitiesOnly=yes','-oIdentityAgent=none','-oBatchMode=yes','-oStrictHostKeyChecking=yes',
         '-oUserKnownHostsFile=/home/jwk/.ssh/agentenv-native-four/known_hosts','-oGlobalKnownHostsFile=/dev/null',
         '-oUpdateHostKeys=no','-oHostKeyAlgorithms=ssh-ed25519','-oForwardAgent=no','-oClearAllForwardings=yes',
         '-oRequestTTY=no','-oConnectTimeout=10','jwk@agent1',shlex.join(['/usr/bin/python3','-I','-B','-c',code])]
    result=subprocess.run(ssh,stdin=subprocess.DEVNULL,capture_output=True,timeout=90)
    need(result.returncode==0 and len(result.stdout)<=2*1024**2,'B readback unavailable; A evidence still retained')
    return json.loads(result.stdout)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');a=p.parse_args()
    if not a.run:print('READBACK_PLAN_ONLY');return
    os.umask(0o077)
    value={'status':'EXISTING_FOUR_COHORT_EVIDENCE_NOT_A_SUCCESS_CLAIM','A':collect_node('node-a')}
    try:value['B']=remote_read()
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
        value['B']={'readbackFailed':type(error).__name__}
    for mode in ('off','lazy'):
        path=WORK/(mode+'-gates.json')
        try:
            raw,_=read_file(path)
            gate=json.loads(raw)
            value[mode+'Gates']={k:gate.get(k) for k in ('status','errorType','reason','abortErrors','epochs')}
        except (OSError,ValueError,RuntimeError) as error:value[mode+'Gates']={'unavailable':type(error).__name__}
    output=WORK/('readback-'+uuid.uuid4().hex[:12]);output.mkdir(mode=0o700)
    value['reportDirectory']=str(output)
    raw=json.dumps(value,ensure_ascii=False,indent=2)
    (output/'existing-evidence.json').write_text(raw,encoding='utf-8')
    print('BEGIN_EXISTING_LAZY_FOUR_EVIDENCE');print(raw);print('END_EXISTING_LAZY_FOUR_EVIDENCE')


if __name__=='__main__':main()
