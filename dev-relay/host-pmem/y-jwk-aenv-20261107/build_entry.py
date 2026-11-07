"""Adapt the reviewed A/B root transport to an isolated Y enrollment namespace."""
import ast, hashlib, json
from pathlib import Path
H=Path(__file__).resolve().parent
ORIGINAL=Path('C:/2026/Agent/AgentENV跨节点CoW/outputs/host-dax-four-sandbox-20261030/AB_root_entry_v2.py')
MAIN='''
def main():
    import getpass,pwd
    parser=argparse.ArgumentParser();parser.add_argument('--install-run',action='store_true');args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0 and platform.system()=='Linux','Run the Y entry using sudo/root')
    need(platform.machine()=='x86_64','Y requires native x86_64')
    need('AMD EPYC 9654' in Path('/proc/cpuinfo').read_text(),'Unexpected Y CPU; preserve state and report inventory')
    pwd.getpwnam('jwk');os.umask(0o077)
    need(Path('/home/jwk').resolve()==Path('/home/jwk'),'Unexpected home directory symlink')
    if not ROOT.exists():ROOT.mkdir(mode=0o711)
    need(ROOT.resolve()==ROOT and ROOT.stat().st_uid==0 and not ROOT.stat().st_mode&0o022,'Untrusted Y entry directory')
    mkdir(STATE);mkdir(STATE/'jobs')
    credential_path=STATE/'credentials.json'
    if credential_path.exists():
        need(not credential_path.stat().st_mode&0o077,'Credential permissions differ')
        tokens=json.loads(read(credential_path,8192))
    else:
        need(args.install_run and sys.stdin.isatty(),'First installation needs an interactive terminal for hidden GitHub tokens')
        print('Provide fine-grained control Contents:read and results Contents:write tokens. Tokens are never task arguments.',flush=True)
        tokens={'controlToken':getpass.getpass('GitHub control-read token: '),'resultToken':getpass.getpass('GitHub results-write token: ')}
        need(all(isinstance(v,str) and 20<len(v)<4096 for v in tokens.values()),'Empty or invalid token')
    control=API.GitHub(tokens['controlToken']);results=API.GitHub(tokens['resultToken'])
    control.private_repo(CONTROL,1438089258);results.private_repo(RESULTS,1438089386)
    if not credential_path.exists():save(credential_path,tokens)
    current=identity();node='node-y';pin=sha(Path(__file__).read_bytes())
    if args.install_run:
        for target,raw,mode in [(STATE/'entry.py',Path(__file__).read_bytes(),0o600),
            (ROOT/'root-start.sh',b'#!/bin/bash\\nset -eu\\numask 077\\nexec /usr/bin/python3 -I -B /home/jwk/y-aenv-control/relay/entry.py\\n',0o700)]:
            if target.exists():need(read(target)==raw,'Existing Y entry differs; preserved')
            else:
                fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
                with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        print('Y_FIXED_ENTRY_READY=sudo bash /home/jwk/y-aenv-control/root-start.sh',flush=True)
    fd=os.open(STATE/'operation.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        code,raw,_=control.contents(CONTROL,f'root-entry-v1/{SESSION}/profiles/{node}.json','main')
        need(code in (200,404),'Y profile unavailable')
        if code==200:
            profile=json.loads(raw)
            need(profile['node']==node and profile['sessionId']==SESSION and profile['entrySha256']==pin,'Y entry profile differs')
            need(all(current[k]==profile['identity'][k] for k in ('machineId','hostname','kernel','architecture')),'Different Y machine/kernel; reconcile before running')
        enrollment={'node':node,'sessionId':SESSION,'identity':current,'entrySha256':pin}
        put(results,f'root-entry-v1/{SESSION}/{node}/boots/{current["bootId"]}/{pin}.json',wire(enrollment))
        if code==404:
            # First enrollment is pinned to this immutable read-only program. It cannot deploy.
            put(results,f'root-entry-v1/{SESSION}/{node}/enrollment.json',wire(enrollment))
            save(STATE/'enrollment.json',enrollment)
            job={'schema':1,'sessionId':SESSION,'node':node,'jobId':'y-inventory-20261107-001-node-y',
                'identity':current,'rootEntrySha256':pin,'humanApproved':True,'scope':'read-only-diagnosis',
                'authorizationBasis':'User requested provisioning the Y jwk AgentENV service and run.sh tests through GitHub. First enrollment only reads Y prerequisites; deployment follows review of the real receipt.',
                'notBefore':'2026-11-06T00:00:00+00:00','expiresAt':'2026-11-21T00:00:00+00:00',
                'entry':BOOTSTRAP,'argv':[],'seconds':300}
            queue={'node':node,'sessionId':SESSION,'mode':'manual','stop':False,'jobIds':[job['jobId']]}
            run_task(control,results,node,current,pin,{'queue':queue,'job':job})
            print('Y_INVENTORY_UPLOADED_AWAITING_REVIEW_NO_DEPLOYMENT',flush=True)
        else:run_task(control,results,node,current,pin)
    finally:os.close(fd)
'''

def build():
    descriptor=json.loads((H/'inventory-source.json').read_text())
    body=ORIGINAL.read_text(encoding='utf-8')
    body=body.replace("ROOT=Path('/home/jwk/root')", "ROOT=Path('/home/jwk/y-aenv-control')")
    body=body.replace("SESSION='relay-20261029-0d032371'", "SESSION='y-aenv-20261107-v1'")
    body=body.replace('Manual A/B root task entry.','Manual Y root task entry, adapted from the A/B entry.')
    body=body.replace('def run_task(control,results,node,current,pin):','def run_task(control,results,node,current,pin,documents=None):')
    body=body.replace("queue=fetch(control,f'root-entry-v1/{SESSION}/queues/{node}.json')", "queue=documents['queue'] if documents else fetch(control,f'root-entry-v1/{SESSION}/queues/{node}.json')")
    body=body.replace("job=fetch(control,f'root-entry-v1/{SESSION}/jobs/{job_id}.json')", "job=documents['job'] if documents else fetch(control,f'root-entry-v1/{SESSION}/jobs/{job_id}.json')")
    # Stop whole task process groups on a timeout, including bounded subprocesses.
    body=body.replace('import argparse,base64,fcntl,hashlib,json,os,platform,re,stat,subprocess,sys,time,types,zlib',
        'import argparse,base64,fcntl,hashlib,json,os,platform,re,signal,stat,subprocess,sys,time,types,zlib')
    body=body.replace('env=child_environment(os.environ),cwd=directory)', 'env=child_environment(os.environ),cwd=directory,start_new_session=True)')
    body=body.replace('timed_out=True;p.terminate()', 'timed_out=True;os.killpg(p.pid,signal.SIGTERM)')
    body=body.replace('except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)', 'except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)')
    start=body.index('def main():');end=body.index('\nraw=zlib.decompress',start)
    body=body[:start]+'BOOTSTRAP='+repr(descriptor)+'\n'+MAIN+body[end:]
    # Refuse initial inventory being silently treated as successful on exit failure.
    body=body.replace("if p.returncode!=0:return", "if p.returncode!=0:raise RuntimeError('Task failed; read uploaded receipt before proceeding')")
    body=body.replace("publish_report(results,node,job,report);print('ROOT_TASK_ALREADY_DONE_REPORT_RESENT='+job_id);continue",
        "publish_report(results,node,job,report);print('ROOT_TASK_ALREADY_DONE_REPORT_RESENT='+job_id);need(report.get('state')=='completed' and report.get('exitCode')==0,'Prior task failed or interrupted; receipt preserved');continue")
    body=body.replace("publish_report(results,node,job,report);print('ROOT_TASK_UNKNOWN_NO_RETRY='+job_id);return", "publish_report(results,node,job,report);raise RuntimeError('Unknown prior outcome; no retry')")
    ast.parse(body,feature_version=(3,11));raw=body.encode()
    (H/'Y_root_entry_v1.py').write_bytes(raw)
    return {'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'sourceOriginalSha256':hashlib.sha256(ORIGINAL.read_bytes()).hexdigest()}

if __name__=='__main__':print(json.dumps(build()))
