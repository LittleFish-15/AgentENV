"""Actual CLI replay and concurrent sampling for an admitted local cohort.

The caller supplies already-owned Guests and frozen replay/sampler adapters.
This module never creates or deletes Guests, transports peer receipts, changes
services, clears caches or authorizes an experiment on its own.
"""
import concurrent.futures,copy,hashlib,json,math,os,re,subprocess,threading,time,uuid
from pathlib import Path

def need(ok,why):
    if not ok:raise RuntimeError(why)

def action_digest(action):return hashlib.sha256(action.encode()).hexdigest()

def exit_marker(text,marker):
    matches=re.findall(r'(?m)^'+re.escape(marker)+r' ([0-9]+)\s*$',text)
    need(len(matches)==1,'Missing or repeated Guest exit marker; result uncertain')
    value=int(matches[0]);need(0<=value<=255,'Invalid Guest exit status')
    return value

def workload_signature(jobs):
    return sorted((j['templateId'],j['slot'],j['catalogSha256'],j['replaySha256'],j['lowerContentSha256'],
                   j['resources']['cpu_count'],j['resources']['memory_mib'],
                   tuple((action_digest(s['action']),s['delay']) for s in j['steps'])) for j in jobs)

def compare_completed(original,full):
    need(original['status']==full['status']=='LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED','Both local replays must complete')
    need(original['workloadSha256']==full['workloadSha256'],'Workload/catalog/resources/lower identity changed')
    for report in (original,full):
        need(report['pendingCommands']==0 and not report['sampleErrors'],'Incomplete transport or sampling')
        need(type(report['elapsedSeconds']) in (int,float) and math.isfinite(report['elapsedSeconds'])
             and report['elapsedSeconds']>=0,'Invalid elapsed time')
    a={(j['templateId'],j['slot']):j for j in original['jobs']}
    b={(j['templateId'],j['slot']):j for j in full['jobs']}
    need(set(a)==set(b) and len(a)==len(original['jobs'])==len(full['jobs']),'Different/duplicate Guest job scope')
    mismatches=[]
    for key in sorted(a):
        left,right=a[key],b[key]
        need(left['status']==right['status']=='COMPLETED' and 'pendingCommand' not in left and 'pendingCommand' not in right,'Unfinished job')
        need(left['replaySha256']==right['replaySha256'] and left['expectedCommands']==right['expectedCommands'],'Replay input changed')
        la,lb=left['results'],right['results']
        need(len(la)==len(lb)==left['expectedCommands'],'Incomplete command histories')
        for index,(x,y) in enumerate(zip(la,lb)):
            need(x['commandIndex']==y['commandIndex']==index and x['transportExitCode']==y['transportExitCode']==0
                 and x['timedOut'] is False and y['timedOut'] is False,'Invalid command ordering/transport completion')
            need((x['actionSha256'],x['requestedDelaySeconds'])==(y['actionSha256'],y['requestedDelaySeconds']), 'Command/delay differs')
            if x['guestExitCode']!=y['guestExitCode']:mismatches.append({'templateId':key[0],'slot':key[1],'commandIndex':index,'originalExit':x['guestExitCode'],'fullExit':y['guestExitCode']})
    return {'sameWorkload':True,'allCommandExitCodesMatch':not mismatches,'exitCodeMismatches':mismatches,
            'localGuestsPerGroup':len(a),'commandsPerGroup':sum(len(j['results']) for j in a.values()),
            'originalElapsedSeconds':original['elapsedSeconds'],'fullElapsedSeconds':full['elapsedSeconds'],
            'crossNodeSynchronizationVerified':False,'netSavingsBytes':None,
            'scope':'completed local replay comparison only; cross-node schedule and memory accounting require separate evidence'}

class NativeGroupReplay:
    def __init__(self,work,cli,env,jobs,shell_command,owned,collect,persist,*,launcher=subprocess.Popen,clock=time.monotonic):
        self.work=Path(work);self.cli=Path(cli);self.env=dict(env);self.jobs=copy.deepcopy(jobs)
        self.shell_command,self.owned,self.collect,self.persist=shell_command,owned,collect,persist
        self.launcher,self.clock=launcher,clock
        self.stop=threading.Event();self.sampling_stop=threading.Event();self.lock=threading.RLock()
        self.state={'version':1,'status':'PREPARED','jobs':[],'samples':0,'sampleOverruns':0,'sampleErrors':[],
                    'GuestTimeoutSeconds':300,'CLITransportTimeoutSeconds':330,'automaticGuestCleanup':False,
                    'crossNodeSynchronizationVerified':False,'netSavingsBytes':None,
                    'CLITransportProcessPssBytes':None,
                    'measurementBoundary':'sampler coverage is supplied by caller; transient CLI memory is not independently accounted by this module'}
        need(len(jobs) in (2,8) and len({j['sandboxId'] for j in jobs})==len(jobs),'Explicit two/eight distinct local Guests required')
        need(len({(j['templateId'],j['slot']) for j in jobs})==len(jobs),'Duplicate template/slot')
        for job in jobs:
            need(job['slot'] in (0,1) and re.fullmatch('[A-Za-z0-9_-]{1,128}',job['sandboxId']),'Invalid owned Guest scope')
            need(re.fullmatch('[0-9a-f]{64}',job['replaySha256']) and 1<=len(job['steps'])<=2048,'Invalid bounded replay')
            need(re.fullmatch('[0-9a-f]{64}',job['catalogSha256']) and re.fullmatch('[0-9a-f]{64}',job['lowerContentSha256'])
                 and job['resources']=={'cpu_count':2,'memory_mib':4096},'Invalid fixed snapshot/lower/resource identity')
            for step in job['steps']:
                need(isinstance(step['action'],str) and 0<len(step['action'].encode())<=1024**2
                     and type(step['delay']) in (int,float) and math.isfinite(step['delay']) and 0<=step['delay']<3600,'Invalid command/delay')
            self.state['jobs'].append({k:job[k] for k in ('templateId','slot','sandboxId','replaySha256','catalogSha256','lowerContentSha256','resources')})
            self.state['jobs'][-1].update(status='READY',expectedCommands=len(job['steps']),results=[],nonzeroCommands=0)
        self.state['workloadSha256']=hashlib.sha256(json.dumps(workload_signature(jobs),separators=(',',':')).encode()).hexdigest()

    def checkpoint(self):
        # Lock must be held across persistence so snapshots cannot reorder.
        self.persist(copy.deepcopy(self.state))

    def command(self,index,step_index,step):
        job=self.jobs[index];sid=job['sandboxId']
        need(not self.stop.is_set() and self.owned(sid),'Guest lost ownership or group cancelled')
        marker='AENV_FULL_REPLAY_END_'+uuid.uuid4().hex
        shell=self.shell_command(step['action'],marker)
        # Only the known frozen shell helper supplies 300-second Guest timeout.
        need('/agentenv/bin/busybox timeout -s TERM -k 5 300 ' in shell,'Unexpected Guest timeout shell contract')
        stem=self.work/'commands'/f'{index}-{step_index}'
        outpath=stem.with_suffix('.stdout');errpath=stem.with_suffix('.stderr')
        intent={'commandIndex':step_index,'actionSha256':action_digest(step['action']),
                'requestedDelaySeconds':step['delay'],'startedUnixNs':time.time_ns()}
        with self.lock:
            need('pendingCommand' not in self.state['jobs'][index],'Unresolved command cannot be retried')
            self.state['jobs'][index]['pendingCommand']=intent;self.checkpoint()
        argv=[str(self.cli),'exec',sid,'/bin/bash','-c',shell]
        if os.geteuid()==0:
            argv=['/usr/bin/setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all',
                  '--ambient-caps=-all','--bounding-set=-all','--no-new-privs',*argv]
        child=None;began=self.clock()
        try:
            with outpath.open('xb') as out,errpath.open('xb') as err:
                child=self.launcher(argv,env=self.env,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
                while child.poll() is None:
                    need(not self.stop.is_set(),'Group cancelled while command outcome uncertain')
                    need(self.clock()-began<330,'CLI transport exceeded 330 seconds')
                    need(outpath.stat().st_size+errpath.stat().st_size<=16*1024**2,'CLI output budget exceeded')
                    self.stop.wait(.2)
            need(child.returncode==0,'CLI transport failed; command outcome retained')
            need(outpath.stat().st_size+errpath.stat().st_size<=16*1024**2,'Completed CLI output budget exceeded')
            with outpath.open('rb') as stream:
                stream.seek(max(0,outpath.stat().st_size-8192));tail=stream.read().decode(errors='replace')
            code=exit_marker(tail,marker)
            result={**intent,'guestExitCode':code,'transportExitCode':child.returncode,'elapsedSeconds':self.clock()-began,
                    'finishedUnixNs':time.time_ns(),'stdout':str(outpath),'stderr':str(errpath),'timedOut':code in (124,137)}
            # Record a known timeout/nonzero result before deciding group status.
            with self.lock:
                row=self.state['jobs'][index];row['results'].append(result);row['nonzeroCommands']+=int(code!=0)
                del row['pendingCommand'];self.checkpoint()
            need(code not in (124,137),'Guest timeout/killed status; group failed without extending time')
            need(self.owned(sid),'Guest identity changed during command')
            return result
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)

    def replay_one(self,index):
        try:
            with self.lock:self.state['jobs'][index]['status']='REPLAYING';self.checkpoint()
            for step_index,step in enumerate(self.jobs[index]['steps']):
                need(not self.stop.wait(step['delay']),'Replay cancelled during recorded delay')
                self.command(index,step_index,step)
            with self.lock:self.state['jobs'][index]['status']='COMPLETED';self.checkpoint()
        except BaseException as error:
            self.stop.set()
            with self.lock:
                self.state['jobs'][index].update(status='FAILED',errorType=type(error).__name__,reason=str(error)[:600]);self.checkpoint()
            raise

    def sampling(self):
        next_sample=self.clock();last_files=None
        try:
            while not self.sampling_stop.is_set() and not self.stop.is_set():
                now=self.clock();files=last_files is None or now-last_files>=15
                record=self.collect(include_files=files)
                if files:last_files=now
                with self.lock:
                    record['jobStates']=[{k:r[k] for k in ('sandboxId','status')} for r in self.state['jobs']]
                    self.state['samples']+=1
                path=self.work/'samples.jsonl'
                need(not path.exists() or path.stat().st_size<256*1024**2,'Sampling log budget exceeded')
                with path.open('ab') as out:
                    out.write((json.dumps(record)+'\n').encode());out.flush();os.fsync(out.fileno())
                next_sample+=1
                if self.clock()>next_sample:
                    with self.lock:self.state['sampleOverruns']+=1
                    next_sample=self.clock()
                self.sampling_stop.wait(max(0,next_sample-self.clock()))
        except BaseException as error:
            self.stop.set()
            with self.lock:
                self.state['sampleErrors'].append({'type':type(error).__name__,'reason':str(error)[:600]});self.checkpoint()

    def run(self):
        need(self.work.resolve(strict=True)==self.work,'Replay output directory must already be scoped and canonical')
        command_dir=self.work/'commands';command_dir.mkdir(mode=0o700,exist_ok=False)
        need(not (self.work/'samples.jsonl').exists(),'Prior sample log preserved')
        need(all(self.owned(j['sandboxId']) for j in self.jobs),'Missing owned Guest before replay')
        started=self.clock()
        with self.lock:self.state['status']='RUNNING';self.checkpoint()
        sampler=None
        try:
            # Baseline captured before any workload command, with no cache action.
            baseline=self.collect(include_files=True)
            with (self.work/'baseline.json').open('x',encoding='utf-8') as out:
                json.dump(baseline,out);out.flush();os.fsync(out.fileno())
            sampler=threading.Thread(target=self.sampling,name='scoped-memory-sampler');sampler.start()
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.jobs)) as pool:
                futures=[pool.submit(self.replay_one,index) for index in range(len(self.jobs))]
                for future in concurrent.futures.as_completed(futures):future.result()
            self.sampling_stop.set();sampler.join()
            need(not self.stop.is_set() and not self.state['sampleErrors'],'Sampling or workload failed')
            final=self.collect(include_files=True)
            with (self.work/'final-before-release.json').open('x',encoding='utf-8') as out:
                json.dump(final,out);out.flush();os.fsync(out.fileno())
            with self.lock:self.state['status']='LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED'
        except BaseException as error:
            self.stop.set()
            with self.lock:self.state.update(status='LOCAL_REPLAY_FAILED_STATE_PRESERVED',errorType=type(error).__name__,reason=str(error)[:600])
        finally:
            self.sampling_stop.set()
            if sampler is not None and sampler.ident is not None:sampler.join()
            with self.lock:
                self.state['elapsedSeconds']=self.clock()-started
                self.state['completedCommands']=sum(len(r['results']) for r in self.state['jobs'])
                self.state['nonzeroCommands']=sum(r['nonzeroCommands'] for r in self.state['jobs'])
                self.state['pendingCommands']=sum('pendingCommand' in r for r in self.state['jobs'])
                self.checkpoint()
        return copy.deepcopy(self.state)
