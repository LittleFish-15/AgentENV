"""Unified-entry front end: one explicitly approved cancellation before normal lock."""
import fcntl,hashlib,importlib.util,json,os,pathlib,signal,time
P=pathlib.Path;ROOT=P('/home/jwk/y-aenv-control');S=ROOT/'relay'
PLAN='root-entry-v1/y-aenv-20261107-v1/entry-dispatch/stop007.json'
def need(ok,msg):
    if not ok:raise RuntimeError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def info(pid):
    p=P('/proc')/str(pid)
    try:
        v=(p/'stat').read_text().rsplit(')',1)[1].split()
        return {'pid':pid,'uid':p.stat().st_uid,'status':v[0],'ppid':int(v[1]),'start_ticks':int(v[19]),
          'cwd':str((p/'cwd').resolve()),'exe':str((p/'exe').resolve()),'args':(p/'cmdline').read_bytes().decode(errors='replace').split('\0')}
    except (OSError,ValueError,IndexError):return None
def alive(v):return v is not None and v['status'] not in ('Z','X')
def snapshot():
    result={}
    for p in P('/proc').iterdir():
        if p.name.isdigit():
            v=info(int(p.name))
            if alive(v):result[v['pid']]=v
    return result
def within(text,base):return text==base or text.startswith(base+'/')
def related(v,task,base):
    if P(v['exe']).name in ('tail','watch','stat','cat','less','head'):return False
    return task in v['args'] or within(v['cwd'],base) or within(v['exe'],base) or any(within(a,base) for a in v['args'])
def terminal_record(e,job,current,code,message,**extra):
    raw=(message+'\n').encode()
    return {'schema':1,'jobId':job['jobId'],'jobSha256':sha(e.wire(job)),'identity':current,'state':'completed','exitCode':code,
      'logs':{'stdout.log':{'text':raw.decode(),'sha256':sha(raw),'bytes':len(raw),'redacted':False}},**extra}
def main():
    need(os.geteuid()==0,'Use the root unified entry');os.umask(0o077)
    entry=S/'entry.py';need(entry.resolve()==entry and entry.stat().st_uid==0,'Installed entry is not trusted')
    spec=importlib.util.spec_from_file_location('installed_entry',entry);e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
    creds=json.loads(e.read(S/'credentials.json',8192));control=e.API.GitHub(creds['controlToken']);results=e.API.GitHub(creds['resultToken'])
    control.private_repo(e.CONTROL,1438089258);results.private_repo(e.RESULTS,1438089386)
    code,raw,_=control.contents(e.CONTROL,PLAN,'main');need(code in (200,404),'Dispatch plan unavailable')
    if code==404:os.execv('/usr/bin/python3',['python3','-I','-B',str(entry)])
    plan=json.loads(raw);job=plan['job'];current=e.identity();pin=sha(entry.read_bytes())
    profile=e.fetch(control,f'root-entry-v1/{e.SESSION}/profiles/node-y.json')
    need(profile['entrySha256']==pin and all(current[k]==profile['identity'][k] for k in ('machineId','hostname','kernel','architecture')),'Y profile/entry binding differs')
    directory=S/'jobs'/job['jobId'];report_path=directory/'report.json'
    cancel_lock=os.open(S/'cancel-dispatch.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(cancel_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    fds=[];operation_lock=None
    try:
        if report_path.exists():
            report=json.loads(e.read(report_path,2*1024**2));need(report['jobSha256']==sha(e.wire(job)) and report['exitCode']==0,'Prior dispatch outcome needs review')
            e.publish_report(results,'node-y',job,report)
        else:
            e.validate(job,current,'node-y',pin)
            need(job['entry']['sha256']==sha(P(__file__).read_bytes()),'Dispatcher source digest differs')
            target=e.fetch(control,f'root-entry-v1/{e.SESSION}/jobs/{plan["targetJobId"]}.json')
            need(sha(e.wire(target))==plan['targetJobSha256'] and target['identity']==current,'Target task descriptor differs')
            target_dir=S/'jobs'/target['jobId'];task=str(target_dir/'task.py');base=plan['targetBuildBase']
            prior_report=target_dir/'report.json';prior_state=target_dir/'state.json';actions=[]
            if prior_state.exists():
                need(sha(e.read(target_dir/'task.py'))==target['entry']['sha256'],'Running target source differs')
                state_raw=e.read(prior_state);state=json.loads(state_raw)
                need(prior_report.exists() or state.get('jobSha256')==sha(e.wire(target)),'Target state binding differs')
            else:state_raw=None
            procs=snapshot();managers=[v for v in procs.values() if task in v['args']]
            need(len(managers)<=1,'Ambiguous target manager')
            managers=[v for v in managers if v['uid']==0 and v['cwd']==str(target_dir)]
            allowed={}
            if managers:
                manager=managers[0];allowed[manager['pid']]=manager
                # Do not interrupt an RPM/DNF transaction. This task already installed
                # dependencies before its Rust-download stage, but verify actual state.
                status_path=P(base)/'build-status.json'
                if status_path.exists():
                    status=json.loads(status_path.read_text());stages=status.get('stages',[])
                    need(not stages or stages[-1]['name']!='install-build-dependencies' or 'exit_code' in stages[-1],
                      'Package transaction still active; cancellation deferred without signals')
                for _ in range(32):
                    more={pid:v for pid,v in procs.items() if v['ppid'] in allowed};n=len(allowed);allowed.update(more)
                    if n==len(allowed):break
                monitor=procs.get(manager['ppid'])
                if monitor and monitor['uid']==0 and str(entry) in monitor['args']:allowed[monitor['pid']]=monitor
            candidates=[v for v in procs.values() if related(v,task,base)]
            # Unknown orphan children need a diagnostic rather than name-based pkill.
            need(all(v['pid'] in allowed for v in candidates),'Orphan outside verified target ancestry; fresh diagnosis required')
            need(len(allowed)<=256 and all(v['uid'] in (0,1000) and v['pid'] not in (1,os.getpid(),os.getppid()) for v in allowed.values()),'Cancellation scope differs')
            # Freeze the entry monitor and task parents first, then bind all signals to pidfds.
            order=sorted(allowed.values(),key=lambda v:(str(entry) not in v['args'],task not in v['args'],v['pid']))
            for v in order:
                try:fd=os.pidfd_open(v['pid'])
                except ProcessLookupError:continue
                now=info(v['pid']);need(not alive(now) or now['start_ticks']==v['start_ticks'],'PID reuse detected')
                if not alive(now):os.close(fd);continue
                fds.append((v,fd))
                try:signal.pidfd_send_signal(fd,signal.SIGSTOP)
                except ProcessLookupError:pass
            latest=snapshot()
            need(all(v['pid'] in allowed and allowed[v['pid']]['start_ticks']==v['start_ticks'] for v in latest.values() if related(v,task,base)),
              'Target process set changed during cancellation; state preserved')
            for v,fd in reversed(fds):
                try:signal.pidfd_send_signal(fd,signal.SIGTERM);signal.pidfd_send_signal(fd,signal.SIGCONT)
                except ProcessLookupError:pass
                actions.append({'pid':v['pid'],'start_ticks':v['start_ticks'],'uid':v['uid'],'signal':'SIGTERM'})
            deadline=time.monotonic()+20
            while time.monotonic()<deadline and any(related(v,task,base) for v in snapshot().values()):time.sleep(.3)
            need(not any(related(v,task,base) for v in snapshot().values()),'Target processes remain; state not closed')
            operation_lock=os.open(S/'operation.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
            fcntl.flock(operation_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if state_raw is not None and not prior_report.exists():
                backup=target_dir/'state.before-stop007.json'
                if backup.exists():need(e.read(backup)==state_raw,'Existing state backup differs')
                else:e.save(backup,json.loads(state_raw))
                closed=terminal_record(e,target,current,125,'Cancelled by explicit user request; source/logs preserved. Code125 is the controller cancellation outcome, not a recovered original exit status.',
                  outcome='cancelled_by_user_via_unified_entry',buildSucceeded=False,originalProcessExitCode=None,
                  exitCodeOrigin='controller_cancellation',reconciliationJobId=job['jobId'],originalStateSha256=sha(state_raw))
                e.save(prior_report,closed);e.save(prior_state,{'state':'cancelled_by_user','exitCode':125,'jobSha256':sha(e.wire(target))})
            e.mkdir(directory)
            report=terminal_record(e,job,current,0,json.dumps({'targetJob':target['jobId'],'targetProcessesAbsent':True,
              'cancelledProcesses':actions,'existingTargetReportPreserved':prior_report.exists(),'oldFilesPreserved':True}))
            e.save(report_path,report);e.save(directory/'state.json',{'state':'executed_upload_pending','exitCode':0})
            e.publish_report(results,'node-y',job,report);e.save(directory/'state.json',{'state':'result_uploaded','exitCode':0})
            print('Y_CURRENT_BUILD_STOPPED_AND_RECORDED',flush=True)
    finally:
        for v,fd in fds:
            try:signal.pidfd_send_signal(fd,signal.SIGCONT)
            except ProcessLookupError:pass
            os.close(fd)
        if operation_lock is not None:os.close(operation_lock)
        os.close(cancel_lock)
    os.execv('/usr/bin/python3',['python3','-I','-B',str(entry)])
if __name__=='__main__':main()
