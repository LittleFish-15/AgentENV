"""One-time, evidence-bound cancellation of superseded build002, then normal entry."""
import fcntl,hashlib,importlib.util,json,os,pathlib,signal,time
P=pathlib.Path
ROOT=P('/home/jwk/y-aenv-control');S=ROOT/'relay'
PLAN_PATH='root-entry-v1/y-aenv-20261107-v1/manual-reconciliations/005.json'
OLD='y-download-build-20261107-002-node-y'
OLD_BASE=P('/data/jwk/aenv-y-20261107')
SELF='y-reconcile-superseded-20261107-005-node-y'
def need(ok,msg):
    if not ok:raise RuntimeError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def proc_info(pid):
    root=P('/proc')/str(pid)
    try:
        fields=(root/'stat').read_text().rsplit(')',1)[1].split()
        return {'pid':pid,'uid':root.stat().st_uid,'status':fields[0],'ppid':int(fields[1]),
          'start_ticks':int(fields[19]),'exe':str((root/'exe').resolve()),'cwd':str((root/'cwd').resolve()),
          'args':(root/'cmdline').read_bytes().decode(errors='replace').split('\0')}
    except (OSError,ValueError,IndexError):return None
def live(info):return info is not None and info['status'] not in ('Z','X')
def under(text,root):return text==str(root) or text.startswith(str(root)+'/')
def old_related(info,old_task):
    return info and (old_task in info['args'] or under(info['cwd'],OLD_BASE) or under(info['exe'],OLD_BASE)
       or any(under(x,OLD_BASE) for x in info['args']))
def scan_related(old_task):
    result=[]
    for p in P('/proc').iterdir():
        if p.name.isdigit():
            v=proc_info(int(p.name))
            if live(v) and old_related(v,old_task):result.append(v)
    return result
def main():
    need(os.geteuid()==0,'Use a root terminal');os.umask(0o077)
    entry=S/'entry.py';need(entry.resolve()==entry and entry.stat().st_uid==0,'Untrusted installed entry')
    spec=importlib.util.spec_from_file_location('installed_y_entry',entry);e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
    credentials=json.loads(e.read(S/'credentials.json',8192))
    control=e.API.GitHub(credentials['controlToken']);results=e.API.GitHub(credentials['resultToken'])
    control.private_repo(e.CONTROL,1438089258);results.private_repo(e.RESULTS,1438089386)
    plan=e.fetch(control,PLAN_PATH);job=plan['job'];current=e.identity();pin=sha(entry.read_bytes())
    e.validate(job,current,'node-y',pin)
    need(job['jobId']==SELF and job['entry']['sha256']==sha(P(__file__).read_bytes()),'Manual reconciliation source binding differs')
    profile=e.fetch(control,f'root-entry-v1/{e.SESSION}/profiles/node-y.json')
    need(profile['entrySha256']==pin and profile['identity']==current,'Y identity or profile differs')
    lock=os.open(S/'operation.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fds=[];stopped=[]
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        old_dir=S/'jobs'/OLD;old_state=old_dir/'state.json';old_report=old_dir/'report.json'
        old_job=e.fetch(control,f'root-entry-v1/{e.SESSION}/jobs/{OLD}.json')
        need(sha(e.wire(old_job))==plan['oldJobSha256'],'Superseded job descriptor changed')
        need(sha(e.read(old_dir/'task.py'))==old_job['entry']['sha256']==plan['oldTaskSha256'],'Superseded task source differs')
        diagnosis=e.read(S/'jobs'/plan['diagnosisJobId']/'report.json',2*1024**2)
        need(sha(diagnosis)==plan['diagnosisReportSha256'],'Reviewed diagnosis receipt changed')
        dr=json.loads(diagnosis)
        need(dr['state']=='completed' and dr['exitCode']==0 and dr['identity']==current,'Diagnosis not successful on this boot')
        if old_report.exists():
            closed=json.loads(e.read(old_report,2*1024**2))
            need(closed.get('outcome')=='cancelled_superseded_after_verified_diagnosis' and closed['jobSha256']==plan['oldJobSha256'],
                 'Old task already has a different report; preserve and review')
        else:
            state_raw=e.read(old_state)
            need(sha(state_raw)==plan['oldStateSha256'],'Old root task state differs from reviewed evidence')
            status=json.loads((OLD_BASE/'build-status.json').read_text())
            stages=status.get('stages',[])
            need(any(x['name']=='install-build-dependencies' and x.get('exit_code')==0 for x in stages),
                 'Package transaction not confirmed finished; do not interrupt it')
            manager=proc_info(plan['manager']['pid'])
            manager_live=live(manager) and manager['start_ticks']==plan['manager']['start_ticks']
            if manager_live:
                need(manager['uid']==0 and manager['cwd']==str(old_dir) and str(old_dir/'task.py') in manager['args'],
                     'Old manager process binding differs')
            candidates=scan_related(str(old_dir/'task.py'))
            # Every candidate must descend from the verified manager or match an exact
            # previously observed orphan identity. Nothing is selected by process name.
            all_procs={}
            for p in P('/proc').iterdir():
                if p.name.isdigit():
                    v=proc_info(int(p.name))
                    if live(v):all_procs[v['pid']]=v
            descendants=set()
            if manager_live:
                descendants.add(manager['pid'])
                for _ in range(32):
                    more={pid for pid,v in all_procs.items() if v['ppid'] in descendants}
                    before=len(descendants);descendants.update(more)
                    if len(descendants)==before:break
            observed={(v['pid'],v['start_ticks'],v['uid']) for v in plan['observedProcesses']}
            allowed={pid:all_procs[pid] for pid in descendants if pid in all_procs}
            for v in candidates:
                need(v['pid'] in descendants or (v['pid'],v['start_ticks'],v['uid']) in observed,
                     'Unexpected related process; obtain fresh diagnosis before cancellation')
                allowed[v['pid']]=v
            need(len(allowed)<=128,'Cancellation process bound exceeded')
            need(all(v['uid'] in (0,1000) and v['pid'] not in (1,os.getpid(),os.getppid()) for v in allowed.values()),
                 'Cancellation escaped the known task user/process boundary')
            # pidfds prevent a reused PID from receiving a signal.
            order=sorted(allowed.values(),key=lambda v:v['pid']!=plan['manager']['pid'])
            for v in order:
                try:fd=os.pidfd_open(v['pid'])
                except ProcessLookupError:continue
                current_proc=proc_info(v['pid'])
                need(not live(current_proc) or current_proc['start_ticks']==v['start_ticks'],'PID reused while opening pidfd')
                if not live(current_proc):os.close(fd);continue
                fds.append((v,fd));signal.pidfd_send_signal(fd,signal.SIGSTOP);stopped.append(fd)
            # Fail safely if a child appeared while the task was being frozen.
            remaining=scan_related(str(old_dir/'task.py'))
            need(all(v['pid'] in allowed and v['start_ticks']==allowed[v['pid']]['start_ticks'] for v in remaining),
                 'Task process set changed; preserve state and refresh diagnosis')
            for v,fd in reversed(fds):
                try:signal.pidfd_send_signal(fd,signal.SIGTERM);signal.pidfd_send_signal(fd,signal.SIGCONT)
                except ProcessLookupError:pass
            deadline=time.monotonic()+15
            while time.monotonic()<deadline and scan_related(str(old_dir/'task.py')):time.sleep(.3)
            need(not scan_related(str(old_dir/'task.py')),'Old task processes remain; do not resolve state')
            # Preserve the original state bytes and all original logs/source. The terminal
            # report explicitly records administrative cancellation, never build success.
            backup=old_dir/'state.before-reconciliation005.json'
            if backup.exists():need(e.read(backup)==state_raw,'Prior state backup differs')
            else:e.save(backup,json.loads(state_raw))
            message=('Superseded build002 was administratively cancelled after verified diagnosis. '
              'This is not a successful build. exitCode 125 is the controller cancellation outcome; '
              'the original orphan process wait status is unavailable. All prior source, state backup and logs are preserved.\n')
            raw=message.encode();logs={'stdout.log':{'text':message,'sha256':sha(raw),'bytes':len(raw),'redacted':False}}
            closed={'schema':1,'jobId':OLD,'jobSha256':plan['oldJobSha256'],'identity':current,'state':'completed',
              'exitCode':125,'exitCodeOrigin':'controller_administrative_cancellation_not_original_wait_status',
              'originalProcessExitCode':None,'outcome':'cancelled_superseded_after_verified_diagnosis','buildSucceeded':False,
              'reconciliationJobId':SELF,'diagnosisReportSha256':plan['diagnosisReportSha256'],
              'originalStateSha256':sha(state_raw),'managerObservedAlive':bool(manager_live),
              'signalledProcesses':[{'pid':v['pid'],'start_ticks':v['start_ticks'],'uid':v['uid']} for v,fd in fds],
              'logs':logs,'finishedUnixNs':time.time_ns()}
            e.save(old_report,closed)
            e.save(old_state,{'state':'cancelled_superseded_reconciled','jobSha256':plan['oldJobSha256'],
                             'exitCode':125,'reconciliationJobId':SELF,'buildSucceeded':False})
        # Publish a separate reconciliation receipt, preserving any older immutable result.
        directory=S/'jobs'/SELF;e.mkdir(directory)
        report_path=directory/'report.json'
        if report_path.exists():report=json.loads(e.read(report_path,2*1024**2))
        else:
            text=json.dumps({'oldJob':OLD,'outcome':closed['outcome'],'buildSucceeded':False,
              'oldReportSha256':sha(e.read(old_report,2*1024**2)),'oldProcessesAbsent':True})+'\n'
            raw=text.encode();report={'schema':1,'jobId':SELF,'jobSha256':sha(e.wire(job)),'identity':current,
              'state':'completed','exitCode':0,'logs':{'stdout.log':{'text':text,'sha256':sha(raw),'bytes':len(raw),'redacted':False}}}
            e.save(report_path,report)
        e.publish_report(results,'node-y',job,report)
        e.save(directory/'state.json',{'state':'result_uploaded','exitCode':0})
        print('Y_OLD_BUILD_CANCELLED_AND_RECONCILIATION_UPLOADED',flush=True)
    finally:
        # On any failed precondition, resume tasks frozen by this helper before stopping.
        for v,fd in fds:
            try:signal.pidfd_send_signal(fd,signal.SIGCONT)
            except ProcessLookupError:pass
            os.close(fd)
        os.close(lock)
    print('STARTING_ORIGINAL_AE9C626_NO_PATCH_BUILD',flush=True)
    os.execv('/bin/bash',['bash',str(ROOT/'root-start.sh')])
if __name__=='__main__':main()
