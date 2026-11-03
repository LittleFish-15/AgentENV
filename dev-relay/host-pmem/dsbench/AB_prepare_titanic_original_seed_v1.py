"""Prepare genuine-original ordinary seed only; A reuses files, B SCP rootfs, no services."""
import hashlib,json,os,re,shutil,stat,subprocess
from pathlib import Path
HOST='141.61.84.83';PORT=22;USER='jwk'
SID='01a19b76-130a-75c2-bf0a-76b49acc1943'
SOURCE='/home/jwk/agent/dsbench-20261102/candidate-a/seed/repository'
NODE={'server1':'a','agent1':'b'}.get(__import__('socket').gethostname())
DEST=Path('/home/jwk/agent/r')/('hpo-'+str(NODE)+'-v1/seed/repository')
SSH_CONTROL=Path('/home/jwk/root/titanic-original-scp-v1')
FILES={'managed-layers/sha256_d32b65a48bc49a4219e1ed5f0b6ce58d5e44925953b7f7ff23736d2d20e368c1.overlaybd.commit': {'bytes': 181881856, 'sha256': 'd32b65a48bc49a4219e1ed5f0b6ce58d5e44925953b7f7ff23736d2d20e368c1'}, 'managed-layers/sha256_b00d5f996bb062f65e74ade8679fe29ba647d4839f24859321265882ba448b11.overlaybd.commit': {'bytes': 74634240, 'sha256': 'b00d5f996bb062f65e74ade8679fe29ba647d4839f24859321265882ba448b11'}, 'managed-layers/sha256_13c5c59ee93c48b9f207dcaab3c76c04a4dbb602ae00c3038b32ffb0990a2e47.overlaybd.commit': {'bytes': 119854080, 'sha256': '13c5c59ee93c48b9f207dcaab3c76c04a4dbb602ae00c3038b32ffb0990a2e47'}, 'managed-layers/sha256_1c671d7f88ffa8f88bb299b896dafadbc45547b297cc3538f32415a5273507c2.overlaybd.commit': {'bytes': 67687424, 'sha256': '1c671d7f88ffa8f88bb299b896dafadbc45547b297cc3538f32415a5273507c2'}, 'managed-layers/sha256_de53270e689dceffa03f7862b27bcc699836610ed1627a1d97915cfdd625b91c.overlaybd.commit': {'bytes': 71619584, 'sha256': 'de53270e689dceffa03f7862b27bcc699836610ed1627a1d97915cfdd625b91c'}, 'managed-layers/sha256_d21b0a6fcafeb4318eac115c31b832cae1eb92a951c93ccbe6ebd12e1c0d27c1.overlaybd.commit': {'bytes': 1113510912, 'sha256': 'd21b0a6fcafeb4318eac115c31b832cae1eb92a951c93ccbe6ebd12e1c0d27c1'}, 'managed-layers/sha256_9e249d26c98eaf37f564f73c1893b65e2d38f3050da0b55a17b0ea77276e0d8a.overlaybd.commit': {'bytes': 67556352, 'sha256': '9e249d26c98eaf37f564f73c1893b65e2d38f3050da0b55a17b0ea77276e0d8a'}, 'managed-layers/sha256_9813e159c96968c3fa00b7995c2176603dd4c074064412dde5bbdcf29571d250.overlaybd.commit': {'bytes': 67425280, 'sha256': '9813e159c96968c3fa00b7995c2176603dd4c074064412dde5bbdcf29571d250'}, 'managed-layers/sha256_a228bcf176c8abc5736fffb67b3b7583211b22c08f5e4b4380d03f85cd6d405d.overlaybd.commit': {'bytes': 67687424, 'sha256': 'a228bcf176c8abc5736fffb67b3b7583211b22c08f5e4b4380d03f85cd6d405d'}, 'managed-layers/sha256_316c899ed59bd1fed1b1c0e9d73c53a140f0f7eb9f65ffcf8fe4bd33753742b6.overlaybd.commit': {'bytes': 24576, 'sha256': '316c899ed59bd1fed1b1c0e9d73c53a140f0f7eb9f65ffcf8fe4bd33753742b6'}}
LOCAL_FILES={'managed-layers/sha256_3b92c077e27c3bdb0361f9629e05827626ee11a884c29dcbbffeb08a0ee49fbb.overlaybd.commit': {'bytes': 444424192, 'sha256': '3b92c077e27c3bdb0361f9629e05827626ee11a884c29dcbbffeb08a0ee49fbb'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/vm_state.bin': {'bytes': 12137, 'sha256': '3363f3f8cb0f8883a180ad359626f3f22e8431d65c6ac7b225c6d0424c45333a'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/firecracker-manifest.json': {'bytes': 243, 'sha256': 'f41e714129f9351d9987ba0395f6c8d4a52b6805f6c3d341226f6ca74262c411'}, 'snapshots/01a19b76-130a-75c2-bf0a-76b49acc1943/commit': {'bytes': 9, 'sha256': 'cc962289af2873dd6dad32931554372a7d2d2de5bd5859c8265eb58b5197a88e'}, 'catalog/records/01a19b76-130a-75c2-bf0a-76b49acc1943.json': {'bytes': None, 'sha256': 'bf645afa402a35cd92eca1310672ce2a2c4dfac79e7ffb234afaf5228457a92e'}}
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
    need(os.getuid()==os.geteuid()==0 and NODE in ('a','b'),'A/B root only');os.umask(0o077)
    need(shutil.disk_usage('/home/jwk/agent').free>4*1024**3,'Less than 4GiB disk headroom')
    rows=[]
    # Link the existing verified memory/VM/catalog locally; no source payload copy.
    local=Path(SOURCE) if NODE=='a' else Path('/home/jwk/agent/r/hpt-b-v1/seed/repository')
    for relative,spec in sorted(LOCAL_FILES.items(),key=lambda x:x[0].startswith('catalog/')):
        source=local/relative;target=DEST/relative;folder(target.parent)
        need(source.resolve()==source and source.is_file() and source.stat().st_uid==1204 and (spec['bytes'] is None or source.stat().st_size==spec['bytes']),'Previously verified local input identity differs')
        if not os.path.lexists(target):os.link(source,target)
        need(target.resolve()==target and target.stat().st_ino==source.stat().st_ino and target.stat().st_dev==source.stat().st_dev,'Local seed hardlink differs')
        rows.append({'path':relative,'bytes':target.stat().st_size,'expectedSha256':spec['sha256'],'sameVerifiedLocalInode':True})
    for rel in ('catalog/aliases','volumes','volumes/aliases','volumes/records'):
        folder(DEST/rel)
    if NODE=='b':
        tty=os.open('/dev/tty',os.O_RDWR);os.close(tty)
        if not SSH_CONTROL.exists():SSH_CONTROL.mkdir(mode=0o700)
        need(SSH_CONTROL.resolve()==SSH_CONTROL and SSH_CONTROL.stat().st_uid==0 and not SSH_CONTROL.stat().st_mode&0o077,'SSH control directory differs')
    for relative,spec in sorted(FILES.items(),key=lambda x:(x[0].startswith('catalog/'),x[0].endswith('/commit'),x[0])):
        need(re.fullmatch(r'[A-Za-z0-9_./-]+',relative) and '..' not in relative.split('/'),'Unsafe snapshot path')
        target=DEST/relative;folder(target.parent)
        if NODE=='a' and not os.path.lexists(target):
            source=Path(SOURCE)/relative;need(source.resolve()==source and source.stat().st_uid==1204 and source.stat().st_size==spec['bytes'],'Captured rootfs file differs');os.link(source,target)
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
            print(json.dumps({'status':kind,'exitCode':result.returncode,'stderr':error,'source':USER+'@'+HOST,'rootfsCopyMayBePartial':True,'ordinaryBaselineOnly':True}),flush=True)
            raise SystemExit(1)
        os.chown(temporary,1204,1205);os.chmod(temporary,0o600)
        need(file_sha(temporary)==spec['sha256'] and (spec['bytes'] is None or temporary.stat().st_size==spec['bytes']),'SCP artifact checksum differs')
        need(not os.path.lexists(target),'Destination appeared during transfer');os.rename(temporary,target)
        rows.append({'path':relative,'bytes':target.stat().st_size,'sha256':spec['sha256'],'reused':False})
    if NODE=='b':subprocess.run(['/usr/bin/ssh','-p',str(PORT),'-S',str(SSH_CONTROL/'connection'),'-O','exit',USER+'@'+HOST],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,env={'HOME':'/root','PATH':'/usr/bin:/bin','LC_ALL':'C'})
    print(json.dumps({'status':'TITANIC_ORIGINAL_SEED_PREPARED_NOT_GUEST_ACCEPTANCE','templateId':SID,'files':rows,
        'rootfsCopied':NODE=='b','ordinaryBaselineOnly':True,'node':NODE,'GuestCreated':False,'SDKCalled':False,'UBAllocated':False},indent=2))
if __name__=='__main__':main()
