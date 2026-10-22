"""One read-only A/B preparation review using retained results, no new trials."""
import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import shlex
import socket
import stat
import subprocess
import time
import uuid

ROOT=Path('/home/jwk/agent')
OLD=ROOT/'r/lazy-four-rollout-v1'
D=ROOT/'deployments/agentenv-lazy-four-32ce41c'


def need(ok,reason):
    if not ok:raise RuntimeError(reason)


def read(path,limit=16*1024**2):
    need(path.resolve(strict=True)==path and path.is_relative_to(ROOT),'Unexpected retained evidence path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_uid==1204 and 0<a.st_size<=limit,'Unexpected retained evidence')
        value=f.read(limit+1);b=os.fstat(f.fileno())
    need(len(value)==a.st_size and (a.st_ino,a.st_size,a.st_mtime_ns)==(b.st_ino,b.st_size,b.st_mtime_ns),'Evidence changed')
    return value


def summarize(report):
    curves=[]
    for item in report.get('rootfsCheckpoints',[]):
        lower=item.get('lower',{});provider=item.get('provider',{});host=item.get('host',{})
        curves.append({'phase':item.get('phase'),'startNs':item.get('startNs'),'endNs':item.get('endNs'),
                       'lowerResidentBytes':lower.get('residentBytes') if lower.get('available') else None,
                       'hostMemoryBytes':host.get('memoryBytes',{}),'hostAvailableFlag':host.get('available'),
                       'providerCounters':provider.get('counters'),'sdkCoverageBytes':provider.get('sdkReportedBackingCoverageBytes'),
                       'states':{row['sandboxId']:row['state'] for row in item.get('states',[])}})
    discontinuities=[]
    for previous,current in zip(curves,curves[1:]):
        before,after=previous['lowerResidentBytes'],current['lowerResidentBytes']
        if type(before) is int and type(after) is int and before>=16*1024**2 and after<before//2:
            discontinuities.append({'fromNs':previous['endNs'],'toNs':current['endNs'],'beforeBytes':before,'afterBytes':after,
                'hostCachedBefore':previous['hostMemoryBytes'].get('Cached'),'hostCachedAfter':current['hostMemoryBytes'].get('Cached'),
                'causeEstablished':False})
    return {'status':report.get('status'),'runId':report.get('runId'),'node':report.get('node'),'scenario':report.get('scenario'),
            'ownedGuestsReleased':report.get('ownedGuestsReleased'),'outcomeUncertain':report.get('outcomeUncertain'),
            'jobs':[{key:job.get(key) for key in ('index','instanceId','slot','stepsCompleted','failedCommands','state',
                       'replayStartedUnix','replayFinishedUnix')} for job in report.get('jobs',[])],
            'sampleCount':report.get('measurementSummary',{}).get('sampleCount'),'curves':curves,
            'largeResidencyDrops':discontinuities,'oldBaselineComparabilityEstablished':False}


def node_review(node):
    need(os.getuid()==os.geteuid()==1204 and socket.gethostname()==('server1' if node=='node-a' else 'agent1'),'Use declared ordinary node')
    result={'node':node,'readOnly':True,'reports':{},'currentUnits':{},'errors':[]}
    for mode in ('off','lazy'):
        path=OLD/(mode+'-'+node+'.json');raw=read(path)
        result['reports'][mode]={'sha256':hashlib.sha256(raw).hexdigest(),'summary':summarize(json.loads(raw))}
    for unit in ('jwk-aenv-lazy-four-32ce41c-'+node+'.service','jwk-ub-lazy-four-'+node+'-v1.service'):
        r=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,MainPID'],capture_output=True,text=True,timeout=10)
        value=dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
        need(r.returncode==0 or value.get('LoadState')=='not-found','Own unit status unreadable')
        result['currentUnits'][unit]=value
    session=ROOT/('r/lazy4-a-v1/provider' if node=='node-a' else 'r/lazy4-b-v1/provider')
    owner=json.loads(read(session/'owner.json'))
    result['releasedProvider']={key:owner.get(key) for key in ('state','cacheId','pool','finalizeAcknowledged','deleteAcknowledged')}
    result['runtimeJournal']=json.loads(read(D/'cohort-state.json'))
    for name,path in (('cgroupMounts',Path('/proc/self/mountinfo')),('processCgroups',Path('/proc/self/cgroup'))):
        try:
            text=path.read_text()
            result[name]=[line for line in text.splitlines() if 'cgroup' in line] if name=='cgroupMounts' else text.splitlines()
        except OSError as error:result['errors'].append({'component':name,'errorType':type(error).__name__})
    result['pressureFiles']={name:(Path('/proc/pressure')/name).exists() for name in ('cpu','memory','io')}
    result['newReplayStarted']=False
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');args=p.parse_args()
    if not args.run:print('READONLY_PREPARATION_PLAN');return
    need(os.getuid()==os.geteuid()==1204 and socket.gethostname()=='server1','Run ordinary A entry')
    os.umask(0o077)
    entry=ROOT/'lazy-four/lazy_four_rollout.py';raw=read(entry)
    need(hashlib.sha256(raw).hexdigest()=='4f39e88e30c342c8f270fe01d8b2e0f80181d40289e83489ad4ba2f2d69efc7b','Retained coordinator changed')
    scope={'__name__':'read_only_transport','__file__':str(entry)};exec(compile(raw,str(entry),'exec'),scope)
    a=node_review('node-a')
    code="import hashlib,json,os,socket,stat,subprocess\nfrom pathlib import Path\nROOT=Path('/home/jwk/agent');OLD=ROOT/'r/lazy-four-rollout-v1';D=ROOT/'deployments/agentenv-lazy-four-32ce41c'\n"
    code+='\n\n'.join(inspect.getsource(fn) for fn in (need,read,summarize,node_review))
    code+="\nprint(json.dumps(node_review('node-b')))\n"
    child=subprocess.run(scope['SSH']+[shlex.join(['/usr/bin/python3','-I','-B','-c',code])],
                         stdin=subprocess.DEVNULL,capture_output=True,timeout=90)
    need(child.returncode==0 and len(child.stdout)<=2*1024**2,'B retained review unavailable; no target mutation attempted')
    b=json.loads(child.stdout)
    cleanup=json.loads(read(OLD/'stop-and-release-v1.json'))
    result={'status':'RETAINED_CURVES_AND_CLEANUP_REVIEW_NO_NEW_TEST','A':a,'B':b,
            'cleanupStatus':cleanup.get('status'),'preparedAtUnixNs':time.time_ns(),'hardwareAcceptanceClaimed':False}
    output=ROOT/'r'/('lazy-evening-review-'+uuid.uuid4().hex[:12]);output.mkdir(mode=0o700)
    result['reportDirectory']=str(output)
    (output/'review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print('BEGIN_EVENING_REVIEW');print(json.dumps(result,ensure_ascii=False));print('END_EVENING_REVIEW')


if __name__=='__main__':main()
