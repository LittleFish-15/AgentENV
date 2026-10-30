"""Manual A/B root task entry. New tasks arrive only through the private queue."""
import argparse,base64,fcntl,hashlib,json,os,platform,re,stat,subprocess,sys,time,types,zlib
from pathlib import Path
ROOT=Path('/home/jwk/root');STATE=ROOT/'relay'
SESSION='relay-20261029-0d032371'
CONTROL='LittleFish-15/AgentENV-relay-control';RESULTS='LittleFish-15/AgentENV-relay-results'

def need(ok,reason):
    if not ok:raise RuntimeError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def wire(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def identity():
    return {'hostname':platform.node(),'machineId':Path('/etc/machine-id').read_text().strip(),
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel':platform.release(),'architecture':platform.machine()}
def read(path,limit=512*1024,owner=0):
    need(path.resolve()==path and not path.is_symlink(),'Redirected local input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());need(stat.S_ISREG(st.st_mode) and st.st_uid==owner and st.st_size<=limit,'Local file owner/type/size differs')
        data=f.read(limit+1);need(len(data)<=limit,'Input exceeds bound');return data
def save(path,value):
    raw=wire(value);tmp=path.with_name(path.name+'.next')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def mkdir(path,mode=0o700):
    need(path.parent.resolve()==path.parent and not path.is_symlink(),'Redirected state directory')
    if not path.exists():path.mkdir(mode=mode)
    st=path.stat();need(st.st_uid==0 and stat.S_ISDIR(st.st_mode) and not st.st_mode&0o022,'Untrusted root state directory')
def fetch(client,path):
    code,raw,_=client.contents(CONTROL,path,'main');need(code==200,'Private task document unavailable');return json.loads(raw)
def put(client,path,raw):
    for attempt in range(5):
        try:client.immutable_result(RESULTS,1438089386,'main',path,raw);return
        except API.Network as error:
            if error.status not in (0,409,422) or attempt==4:raise
            time.sleep(2+attempt)
def validate(job,current,node,pin):
    need(job['schema']==1 and job['sessionId']==SESSION and job['node']==node and job['identity']==current,'Task node/boot differs')
    need(re.fullmatch('[a-z0-9-]{1,96}',job['jobId']) and job['rootEntrySha256']==pin,'Task entry binding differs')
    need(job['humanApproved'] is True and job['scope'] in ('read-only-diagnosis','approved-root-operation'),'Task has no explicit authorization')
    need(API.timestamp(job['notBefore'])<=time.time()<API.timestamp(job['expiresAt']),'Task authorization expired')
    entry=job['entry'];need(entry['repo']=='LittleFish-15/AgentENV' and re.fullmatch('dev-relay/host-pmem/[A-Za-z0-9_./-]+\\.py',entry['path'])
        and '..' not in Path(entry['path']).parts,'Task source path outside reviewed experiment source')
    need(all(re.fullmatch('[0-9a-f]{40}',entry[k]) for k in ('commit','blob')) and re.fullmatch('[0-9a-f]{64}',entry['sha256'])
        and type(entry['bytes']) is int and 0<entry['bytes']<=256*1024,'Invalid task source descriptor')
    need(type(job['seconds']) is int and 1<=job['seconds']<=10800 and isinstance(job['argv'],list) and len(job['argv'])<=16
        and all(isinstance(x,str) and len(x)<=512 for x in job['argv']),'Invalid bounded Python invocation')
def publish_report(client,node,job,report):
    raw=wire(report);compressed=zlib.compress(raw,9);chunks=[];digest=sha(compressed)
    need(len(raw)<=2*1024**2 and len(compressed)<=2*1024**2,'Task report exceeds bound')
    for i,start in enumerate(range(0,len(compressed),16384)):
        piece=compressed[start:start+16384];path=f'root-results-v1/{SESSION}/{node}/{job["jobId"]}/chunks/{digest}/{i}.json'
        put(client,path,wire({'sha256':sha(piece),'dataBase64':base64.b64encode(piece).decode()}));chunks.append({'path':path,'sha256':sha(piece),'bytes':len(piece)})
    manifest={'schema':1,'node':node,'sessionId':SESSION,'jobId':job['jobId'],'identity':report['identity'],
        'jobSha256':sha(wire(job)),'entrySha256':job['entry']['sha256'],'exitCode':report.get('exitCode'),
        'state':report['state'],'compressedSha256':digest,'rawSha256':sha(raw),'rawBytes':len(raw),'chunks':chunks}
    put(client,f'root-results-v1/{SESSION}/{node}/{job["jobId"]}/result.json',wire(manifest))
def run_task(control,results,node,current,pin):
    queue=fetch(control,f'root-entry-v1/{SESSION}/queues/{node}.json')
    need(queue['node']==node and queue['sessionId']==SESSION and queue['mode']=='manual','Queue identity/mode differs')
    if queue.get('stop') or not queue.get('jobIds'):print('ROOT_QUEUE_EMPTY_NO_ACTION');return
    need(len(queue['jobIds'])<=4 and len(set(queue['jobIds']))==len(queue['jobIds']),'Invalid queue bounds')
    for job_id in queue['jobIds']:
        need(re.fullmatch('[a-z0-9-]{1,96}',job_id),'Invalid queued task name')
        job=fetch(control,f'root-entry-v1/{SESSION}/jobs/{job_id}.json')
        need(job['jobId']==job_id,'Queue/task differs')
        directory=STATE/'jobs'/job_id;mkdir(directory)
        result_path=directory/'report.json';state_path=directory/'state.json'
        if result_path.exists():
            report=json.loads(read(result_path,2*1024**2));need(report['jobSha256']==sha(wire(job)),'Completed task descriptor changed')
            publish_report(results,node,job,report);print('ROOT_TASK_ALREADY_DONE_REPORT_RESENT='+job_id);continue
        validate(job,current,node,pin)
        if state_path.exists():
            report={'state':'unknown_after_interruption_no_retry','identity':current,'jobSha256':sha(wire(job)),
                'previousState':json.loads(read(state_path)),'exitCode':None}
            publish_report(results,node,job,report);print('ROOT_TASK_UNKNOWN_NO_RETRY='+job_id);return
        for previous in (STATE/'jobs').glob('*/state.json'):
            if previous==state_path:continue
            prior_report=previous.parent/'report.json'
            unresolved=not prior_report.exists() or json.loads(read(prior_report,2*1024**2)).get('state')!='completed'
            if unresolved and job['scope']!='read-only-diagnosis':
                raise RuntimeError('Unconfirmed earlier root task; only approved diagnosis may proceed')
        entry=job['entry'];code,raw,_=control.contents(entry['repo'],entry['path'],entry['commit'])
        need(code==200 and len(raw)==entry['bytes'] and sha(raw)==entry['sha256']
            and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==entry['blob'],'Pinned Python source differs')
        path=directory/'task.py'
        if path.exists():need(read(path)==raw,'Prior downloaded source differs; preserved')
        else:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        save(state_path,{'state':'running','jobSha256':sha(wire(job)),'identity':current,'startedUnixNs':time.time_ns()})
        print('ROOT_APPROVED_TASK_STARTED='+job_id,flush=True)
        start=time.monotonic();timed_out=False
        with (directory/'stdout.log').open('xb') as out,(directory/'stderr.log').open('xb') as err:
            p=subprocess.Popen(['/usr/bin/python3','-I','-B',str(path),*job['argv']],stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'},cwd=directory)
            while p.poll() is None:
                if time.monotonic()-start>job['seconds'] or sum((directory/n).stat().st_size for n in ('stdout.log','stderr.log'))>1024**2:
                    timed_out=True;p.terminate()
                    try:p.wait(timeout=5)
                    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
                    break
                time.sleep(.25)
        logs={}
        for name in ('stdout.log','stderr.log'):
            raw=(directory/name).read_bytes();need(len(raw)<=1024**2,'Local output exceeded safety bound')
            redacted=API.redact(raw,[control.token,results.token]);logs[name]={'text':redacted.decode(errors='replace'),
                'sha256':sha(redacted),'bytes':len(redacted),'redacted':redacted!=raw}
        report={'schema':1,'jobId':job_id,'jobSha256':sha(wire(job)),'identity':current,'exitCode':p.returncode,
            'state':'interrupted_outcome_requires_reconciliation' if timed_out else 'completed','logs':logs,'elapsedSeconds':time.monotonic()-start}
        save(result_path,report);save(state_path,{'state':'executed_upload_pending','exitCode':p.returncode})
        publish_report(results,node,job,report);save(state_path,{'state':'result_uploaded','exitCode':p.returncode})
        print('ROOT_TASK_RESULT_UPLOADED_EXIT='+str(p.returncode),flush=True)
        if p.returncode!=0:return

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--install-run',action='store_true');args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0 and platform.system()=='Linux','Use A/B root terminal');os.umask(0o077)
    node={'server1':'node-a','agent1':'node-b'}.get(platform.node());need(node,'Only A/B')
    current=identity();pin=sha(Path(__file__).read_bytes())
    credential_path=Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json')
    need(not credential_path.stat().st_mode&0o077,'Existing credential permissions differ')
    tokens=json.loads(read(credential_path,8192,1204))
    control=API.GitHub(tokens['controlToken']);results=API.GitHub(tokens['resultToken'])
    control.private_repo(CONTROL,1438089258);results.private_repo(RESULTS,1438089386)
    profile=fetch(control,f'root-entry-v1/{SESSION}/profiles/{node}.json')
    need(profile['node']==node and profile['sessionId']==SESSION and profile['entrySha256']==pin,'Unified entry profile differs')
    need(all(current[k]==profile['identity'][k] for k in ('machineId','hostname','kernel','architecture')),'Different machine/kernel')
    if not ROOT.exists():ROOT.mkdir(mode=0o711)
    need(ROOT.resolve()==ROOT and ROOT.stat().st_uid==0 and not ROOT.stat().st_mode&0o022,'Untrusted root artifact directory')
    mkdir(STATE);mkdir(STATE/'jobs')
    if args.install_run:
        for target,raw,mode in [(STATE/'entry.py',Path(__file__).read_bytes(),0o600),
            (ROOT/'root-start.sh',b'#!/bin/bash\nset -eu\numask 077\nexec /usr/bin/python3 -I -B /home/jwk/root/relay/entry.py\n',0o700)]:
            if target.exists():need(read(target)==raw,'Unknown existing unified entry; preserved')
            else:
                fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
                with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        print('ROOT_FIXED_ENTRY_READY=bash /home/jwk/root/root-start.sh',flush=True)
    fd=os.open(STATE/'operation.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        save(STATE/'current-boot.json',{'node':node,'identity':current,'entrySha256':pin})
        put(results,f'root-entry-v1/{SESSION}/{node}/boots/{current["bootId"]}/{pin}.json',wire({'node':node,'identity':current,'entrySha256':pin}))
        run_task(control,results,node,current,pin)
    finally:os.close(fd)


raw=zlib.decompress(base64.b64decode('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'))
need(sha(raw)=='b958c459c09db2fe72d508762e8bdab06bd642bfc2f33c6723462ac45353fdcd','Pinned transport differs')
API=types.ModuleType('root_transport');exec(compile(raw,'<root-transport>','exec'),API.__dict__)

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'ROOT_UNIFIED_ENTRY_STOPPED_PRESERVE_STATE','errorType':type(error).__name__,
            'reason':str(error)[:400] if isinstance(error,RuntimeError) else type(error).__name__}),flush=True)
        raise SystemExit(1)
