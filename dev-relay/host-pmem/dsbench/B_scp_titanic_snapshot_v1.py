"""B pulls five pinned snapshot files directly from A using existing SSH trust."""
import hashlib,json,os,re,shutil,stat,subprocess
from pathlib import Path
HOST='141.61.84.83';PORT=22;USER='jwk'
SID='01a19b76-130a-75c2-bf0a-76b49acc1943'
SOURCE='/home/jwk/agent/dsbench-20261102/candidate-a/seed/repository'
DEST=Path('/home/jwk/agent/r/hpt-b-v1/seed/repository')
SSH_CONTROL=Path('/home/jwk/root/titanic-scp-20261102')
FILES={'managed-layers/sha256_3b92c077e27c3bdb0361f9629e05827626ee11a884c29dcbbffeb08a0ee49fbb.overlaybd.commit': {'bytes': 444424192, 'sha256': '3b92c077e27c3bdb0361f9629e05827626ee11a884c29dcbbffeb08a0ee49fbb'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/vm_state.bin': {'bytes': 12137, 'sha256': '3363f3f8cb0f8883a180ad359626f3f22e8431d65c6ac7b225c6d0424c45333a'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/firecracker-manifest.json': {'bytes': 243, 'sha256': 'f41e714129f9351d9987ba0395f6c8d4a52b6805f6c3d341226f6ca74262c411'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/commit': {'bytes': 9, 'sha256': 'cc962289af2873dd6dad32931554372a7d2d2de5bd5859c8265eb58b5197a88e'}, 'catalog/records/01a19b76-130a-75c2-bf0a-76b49acc1943.json': {'bytes': None, 'sha256': 'bf645afa402a35cd92eca1310672ce2a2c4dfac79e7ffb234afaf5228457a92e'}}
def need(ok,why):
    if not ok:raise RuntimeError(why)
def file_sha(path):
    need(path.resolve()==path and stat.S_ISREG(path.lstat().st_mode),'File path/type differs')
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024**2),b''):h.update(b)
    return h.hexdigest()
def folder(path):
    need(path.is_relative_to(DEST.parents[1]),'Destination outside snapshot scope')
    if not path.parent.exists():folder(path.parent)
    if not path.exists():path.mkdir(mode=0o700);os.chown(path,1204,1205);os.chmod(path,0o700)
    need(path.resolve()==path and path.stat().st_uid==1204,'Destination directory differs')
def main():
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='agent1','B root only');os.umask(0o077)
    need(shutil.disk_usage('/home/jwk/agent').free>2*1024**3,'Insufficient transfer disk headroom')
    try:
        tty=os.open('/dev/tty',os.O_RDWR);os.close(tty)
    except OSError:
        raise RuntimeError('Run the fixed root entry in a foreground terminal for native SSH password input')
    if not SSH_CONTROL.exists():SSH_CONTROL.mkdir(mode=0o700)
    need(SSH_CONTROL.resolve()==SSH_CONTROL and SSH_CONTROL.stat().st_uid==0 and not SSH_CONTROL.stat().st_mode&0o077,'SSH control directory differs')
    rows=[]
    for relative,spec in sorted(FILES.items(),key=lambda x:(x[0].startswith('catalog/'),x[0].endswith('/commit'),x[0])):
        need(re.fullmatch(r'[A-Za-z0-9_./-]+',relative) and '..' not in relative.split('/'),'Unsafe snapshot path')
        target=DEST/relative;folder(target.parent)
        if os.path.lexists(target):
            need(file_sha(target)==spec['sha256'] and (spec['bytes'] is None or target.stat().st_size==spec['bytes']),'Existing different destination preserved')
            rows.append({'path':relative,'sha256':spec['sha256'],'bytes':target.stat().st_size,'reused':True});continue
        temporary=target.with_name(target.name+'.scp-partial')
        if os.path.lexists(temporary):
            need(temporary.resolve()==temporary and stat.S_ISREG(temporary.lstat().st_mode) and temporary.stat().st_uid in (0,1204),'Partial identity differs')
            if file_sha(temporary)==spec['sha256'] and (spec['bytes'] is None or temporary.stat().st_size==spec['bytes']):
                os.chown(temporary,1204,1205);os.chmod(temporary,0o600);os.rename(temporary,target)
                rows.append({'path':relative,'bytes':target.stat().st_size,'sha256':spec['sha256'],'reused':True});continue
            temporary=target.with_name(target.name+'.scp-retry-partial');need(not os.path.lexists(temporary),'Previous attempts preserved; no repeated overwrite')
        # Root-local OpenSSH connects as remote jwk; password input stays on /dev/tty.
        args=['/usr/bin/scp','-P',str(PORT),'-oBatchMode=no','-oNumberOfPasswordPrompts=1',
            '-oStrictHostKeyChecking=yes','-oConnectTimeout=10','-oServerAliveInterval=15','-oServerAliveCountMax=3',
            '-oControlMaster=auto','-oControlPersist=60','-oControlPath='+str(SSH_CONTROL/'connection'),
            USER+'@'+HOST+':'+SOURCE+'/'+relative,str(temporary)]
        print('SCP_RECEIVE='+relative,flush=True)
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1800,
            env={'HOME':'/root','PATH':'/usr/bin:/bin','LC_ALL':'C'})
        if result.returncode:
            error=result.stderr.decode(errors='replace')[-2000:]
            kind='SSH_AUTH_REQUIRED' if 'Permission denied' in error else 'SSH_HOST_TRUST_REQUIRED' if 'Host key verification failed' in error else 'SCP_TRANSPORT_FAILED'
            print(json.dumps({'status':kind,'exitCode':result.returncode,'stderr':error,'source':USER+'@'+HOST,'rootfsCopied':False}),flush=True)
            raise SystemExit(1)
        os.chown(temporary,1204,1205);os.chmod(temporary,0o600)
        need(file_sha(temporary)==spec['sha256'] and (spec['bytes'] is None or temporary.stat().st_size==spec['bytes']),'SCP artifact checksum differs')
        need(not os.path.lexists(target),'Destination appeared during transfer');os.rename(temporary,target)
        rows.append({'path':relative,'bytes':target.stat().st_size,'sha256':spec['sha256'],'reused':False})
    subprocess.run(['/usr/bin/ssh','-p',str(PORT),'-S',str(SSH_CONTROL/'connection'),'-O','exit',USER+'@'+HOST],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,env={'HOME':'/root','PATH':'/usr/bin:/bin','LC_ALL':'C'})
    print(json.dumps({'status':'TITANIC_B_SCP_FILES_VERIFIED_NOT_GUEST_ACCEPTANCE','templateId':SID,'files':rows,
        'rootfsCopied':False,'GuestCreated':False,'SDKCalled':False,'UBAllocated':False},indent=2))
if __name__=='__main__':main()
