"""Repair only the confirmed A modified inside-proxy restart defect.

Run as jwk. --apply-reviewed archives only a verified refused own socket,
patches the guard with backups, and prints a fixed root reactivation block.
No snapshot copy, Guest creation, process kill, UB call or original-unit change.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import tempfile

ROOT=Path('/home/jwk/agent')
MOD=ROOT/'deployments/agentenv-ub-b019f27'
RUNTIME=ROOT/'r/ub-a-b019'
UNIT='jwk-aenv-ub-b019f27-node-a.service'
OLD_UNIT='jwk-aenv-ae9c626-node-a.service'
PREP=ROOT/'relay/cow-modified-prepare-node-a.json'
RECOVERY=ROOT/'relay/cow-modified-proxy-recovery-node-a.json'
COMPARE_SHA='0b16daa0ae68cb10c378af2752481f1503c7efa6deb33dab9875d536e4527029'
GUARD_SOURCE='def prepare_inside_socket(unix, lock, archive=True):\n    """Archive only our refused socket while holding the exact inside-proxy lock."""\n    import errno\n    import fcntl\n    require(os.getuid() == os.geteuid() == 1204, \'Ordinary proxy owner required\')\n    require(unix == RUNTIME / \'api.sock\', \'Unexpected proxy endpoint\')\n    lock_path = safe(RUNTIME / \'proxy-inside.lock\', True)\n    lm = os.fstat(lock)\n    require(stat.S_ISREG(lm.st_mode) and lm.st_uid == 1204\n            and (lm.st_dev, lm.st_ino) == (lock_path.stat().st_dev, lock_path.stat().st_ino),\n            \'Inside proxy lock identity differs\')\n    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)\n    safe(unix)\n    if not unix.exists():\n        return None\n    before = unix.lstat()\n    require(stat.S_ISSOCK(before.st_mode) and before.st_uid == 1204, \'Unknown endpoint preserved\')\n    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:\n        client.settimeout(1)\n        try:\n            client.connect(str(unix))\n        except OSError as error:\n            require(error.errno == errno.ECONNREFUSED, \'Socket status uncertain; preserved\')\n        else:\n            raise RuntimeError(\'Live API socket preserved\')\n    after = unix.lstat()\n    require((before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_mtime_ns)\n            == (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_mtime_ns),\n            \'API socket changed; preserved\')\n    if not archive:\n        return \'REFUSED_SOCKET_VERIFIED\'\n    backup = safe(RUNTIME / (\'api-stale-\' + secrets.token_hex(12) + \'.sock\'))\n    require(not backup.exists(), \'Socket archive collision\')\n    os.rename(unix, backup)\n    print(\'STALE_API_SOCKET_ARCHIVED=\' + str(backup), flush=True)\n    return str(backup)\n'
H=S=R=None

def load(path,digest,name):
    raw=path.read_bytes()
    if path.resolve(strict=True)!=path or hashlib.sha256(raw).hexdigest()!=digest:raise RuntimeError('Pinned helper differs')
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def absent():
    result=subprocess.run(['/usr/bin/systemctl','show',UNIT,'--property=LoadState,ActiveState,MainPID'],
                          capture_output=True,text=True,timeout=10,check=True)
    fields=dict(x.split('=',1) for x in result.stdout.splitlines() if '=' in x)
    H.need(fields.get('LoadState')=='not-found' and fields.get('ActiveState')=='inactive' and fields.get('MainPID')=='0',
           'Modified unit is not absent; preserve existing service')
    return fields

def patched_launcher(raw):
    text=raw.decode()
    old="require(not unix.exists() and not unix.is_symlink(), 'New API socket already exists; preserved')"
    H.need(text.count(old)==1 and text.count('async def proxy(side):')==1 and 'def prepare_inside_socket(' not in text,
           'Unknown/already patched launcher; no overwrite')
    new=text.replace(old,'prepare_inside_socket(unix, lock)',1).replace('async def proxy(side):',GUARD_SOURCE+'\n\nasync def proxy(side):',1)
    ast.parse(new);return new.encode()

def guard_namespace():
    def safe(path,exists=False):
        H.safe(path)
        if exists:H.need(path.exists(),'Missing guard lock')
        return path
    env={'require':H.need,'os':os,'socket':socket,'stat':stat,'secrets':secrets,
         'RUNTIME':RUNTIME,'safe':safe}
    exec(GUARD_SOURCE,env);return env

ROOT_START=r'''
import hashlib,json,os,pathlib,pwd,grp,stat,subprocess
def need(ok,why):
    if not ok:raise SystemExit('STOP: '+why)
need(os.geteuid()==0 and os.uname().nodename=='server1','A existing root only')
need(pwd.getpwnam('jwk').pw_uid==1204 and pwd.getpwnam('jwk').pw_gid==1205,'User identity differs')
need(grp.getgrnam('kvm').gr_gid==36 and grp.getgrnam('aenv').gr_gid==982,'Group identity differs')
need(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==scope['boot_id'],'Boot changed')
base=pathlib.Path('/home/jwk/agent/deployments/agentenv-ub-b019f27')
need(pathlib.Path('/sys/module/ublk_drv').is_dir(),'Existing ublk module missing')
for name in ('/dev/kvm','/dev/ublk-control','/dev/net/tun'):
    need(stat.S_ISCHR(os.stat(name).st_mode),'Existing device missing')
for rel,expected in scope['files'].items():
    need(rel in ('config/runtime.toml','libexec/deploy_a_ub.py','installation.json'),'Unexpected file selector')
    p=base/rel
    need(p.resolve(strict=True)==p,'Redirected input')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        m=os.fstat(f.fileno());need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_size<131072,'Input metadata differs')
        raw=f.read(131072);need(hashlib.sha256(raw).hexdigest()==expected,'Input changed')
def props(unit):
    r=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,MainPID,User,Group'],
                     capture_output=True,text=True,check=True,timeout=10)
    return dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
def original():
    p=props('jwk-aenv-ae9c626-node-a.service')
    need(p.get('ActiveState')=='active' and p.get('User')==p.get('Group')=='jwk','Original unit changed')
    pid=int(p['MainPID']);ticks=pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
    need([pid,ticks]==scope['original'],'Original process changed')
original()
unit='jwk-aenv-ub-b019f27-node-a.service'
p=props(unit)
need(p.get('LoadState')=='not-found' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0','Modified unit already exists; no restart')
endpoint=pathlib.Path('/home/jwk/agent/r/ub-a-b019/api.sock')
need(not endpoint.exists() and not endpoint.is_symlink(),'Socket reappeared; preserve it')
properties=['Description=jwk AgentENV UB b019f27 node-a','User=jwk','Group=jwk',
            'SupplementaryGroups=kvm aenv','CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN',
            'AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN','NoNewPrivileges=yes','RestrictSUIDSGID=yes',
            'PrivateNetwork=yes','PrivateMounts=yes','Type=exec','Restart=no','KillMode=control-group',
            'TimeoutStopSec=90s','LimitNOFILE=65536','WorkingDirectory='+str(base),'StandardOutput=null','StandardError=null']
args=['/usr/bin/systemd-run','--unit='+unit,'--collect']+['--property='+x for x in properties]
args+=['/usr/bin/python3','-I','-B',str(base/'libexec/deploy_a_ub.py'),'inside']
subprocess.run(args,check=True,timeout=30)
original()
print('A_MODIFIED_REACTIVATION_SUBMITTED_RUN_EXISTING_COMPARISON')
'''

def recover(work,apply):
    H.need(not RECOVERY.exists(),'Recovery receipt exists; no repeat patch/start')
    H.need(not S.PENDING.exists(),'Experiment pending exists; review before service recovery')
    absent()
    before_prep=H.read(PREP);prior=json.loads(before_prep)
    H.need(prior['status']=='MODIFIED_TEMPLATE_READY_CONFIG_APPLIED_RESTART_REQUIRED','Unexpected comparison preparation')
    H.need(S.state(OLD_UNIT)==prior['original_process'],'Original process differs')
    paths={'config/runtime.toml':prior['config_after_sha256'],'libexec/deploy_a_ub.py':prior['launcher_after_sha256'],
           'installation.json':prior['installation_after_sha256']}
    originals={}
    for rel,digest in paths.items():
        raw=H.read(MOD/rel);H.need(hashlib.sha256(raw).hexdigest()==digest,'Prepared input changed: '+rel);originals[rel]=raw
    installed=json.loads(originals['installation.json'])
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    H.need(installed['boot_id']==boot and installed['node']=='node-a' and installed['unit']==UNIT
           and installed['runtime']==str(RUNTIME),'Installation context differs')
    H.need(installed['host_netns']==os.stat('/proc/self/ns/net').st_ino
           and installed['host_mntns']==os.stat('/proc/self/ns/mnt').st_ino,'Host namespaces changed')
    for name,digest in S.BINARIES.items():H.need(S.digest_file(MOD/'bin'/name)[0]==digest,'Runtime binary differs')
    launcher=patched_launcher(originals['libexec/deploy_a_ub.py'])
    new_installed=dict(installed,launcher_sha256=hashlib.sha256(launcher).hexdigest())
    installed_raw=(json.dumps(new_installed,indent=2)+'\n').encode()
    new_prep=dict(prior,launcher_after_sha256=new_installed['launcher_sha256'],
                  installation_after_sha256=hashlib.sha256(installed_raw).hexdigest(),
                  proxy_recovery_report=str(work))
    namespace=guard_namespace()
    report={'revision':'a-modified-proxy-recovery-v1','report_directory':str(work),'original_process':prior['original_process'],
            'configuration_changed':False,'runtime_binaries_changed':False,'template_files_changed':False,
            'service_started':False,'SDK_called':False,'B_accessed':False,'socket_archived':None,
            'launcher_changed':False,'status':'RECOVERY_PREPARED_NO_CHANGE'}
    lock_path=H.safe(RUNTIME/'proxy-inside.lock')
    fd=os.open(lock_path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        report['socket_check']=namespace['prepare_inside_socket'](RUNTIME/'api.sock',fd,False)
        for rel,raw in originals.items():
            backup=work/rel;backup.parent.mkdir(parents=True,exist_ok=True);backup.write_bytes(raw)
        (work/'comparison-preparation-before.json').write_bytes(before_prep)
        (work/'launcher-proposed.py').write_bytes(launcher)
        if not apply:return report
        report['status']='RECOVERY_IN_PROGRESS';H.save(RECOVERY,report)
        absent();H.need(S.state(OLD_UNIT)==prior['original_process'],'Original process changed')
        for rel,raw in originals.items():H.need(H.read(MOD/rel)==raw,'Concurrent change: '+rel)
        H.need(H.read(PREP)==before_prep,'Comparison receipt changed')
        report['socket_archived']=namespace['prepare_inside_socket'](RUNTIME/'api.sock',fd)
        H.save(RECOVERY,report)
        for path,raw in ((MOD/'libexec/deploy_a_ub.py',launcher),(MOD/'installation.json',installed_raw)):
            temp=path.with_name(path.name+'.'+work.name+'.tmp')
            with temp.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
            os.replace(temp,path)
        H.save(PREP,new_prep)
        report.update(launcher_changed=True,status='A_MODIFIED_PROXY_REPAIRED_UNIT_NOT_STARTED')
        H.save(RECOVERY,report)
        scope={'boot_id':boot,'original':prior['original_process'],
               'files':{'config/runtime.toml':prior['config_after_sha256'],
                        'libexec/deploy_a_ub.py':new_installed['launcher_sha256'],
                        'installation.json':new_prep['installation_after_sha256']}}
        command="/usr/bin/python3 -I -B - <<'A_MODIFIED_REACTIVATE'\nscope="+repr(scope)+'\n'+ROOT_START+'\nA_MODIFIED_REACTIVATE'
        (work/'root-reactivation-review.txt').write_text(command)
        print('BEGIN_REVIEWED_REACTIVATION_COPY_BODY_ONLY');print(command);print('END_REVIEWED_REACTIVATION_COPY_BODY_ONLY',flush=True)
        return report
    finally:os.close(fd)

def main():
    global S,H,R
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply-reviewed',action='store_true');args=parser.parse_args()
    if not(socket.gethostname()=='server1' and os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205):raise RuntimeError('A ordinary jwk only')
    caps=re.findall(r'^Cap(?:Inh|Prm|Eff|Amb):\s*(\w+)$',Path('/proc/self/status').read_text(),re.M)
    if len(caps)!=4 or any(int(x,16) for x in caps):raise RuntimeError('Capability-free session required')
    S=load(ROOT/'cow_modified_d2285fe.py',COMPARE_SHA,'comparison')
    C=load(ROOT/'cow_controlled_engine.py',S.ENGINE_SHA,'engine')
    P=C.load(ROOT/'cow_marker_prepare_e5b9050.py',C.PREPARE_SHA,'parent_marker')[0]
    H=P.load_parent();C.H=H;S.H=H
    R=C.load(ROOT/'cow_ram_readonly.py',C.COLLECTOR_SHA,'reader')[0];S.R=R
    os.umask(0o077);import fcntl
    with open(H.safe(ROOT/'relay/cow-modified-node-a.lock'),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        work=Path(tempfile.mkdtemp(prefix='node-a-proxy-recovery-',dir=H.safe(ROOT/'relay/reports')))
        try:report=recover(work,args.apply_reviewed)
        except (Exception,KeyboardInterrupt) as e:
            report={'status':'STOPPED_MODIFIED_PROXY_RECOVERY','report_directory':str(work),'error_type':type(e).__name__,
                    'reason':str(e) if isinstance(e,RuntimeError) else 'Preserve files and receipts; no retry'}
        H.save(work/'return.json',report)
        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
        return 1 if report['status'].startswith('STOPPED') else 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_PROXY_RECOVERY_ENTRY','error_type':type(e).__name__,
              'reason':str(e) if isinstance(e,RuntimeError) else 'Entry failed'}));print('END_RETURN_REPORT');raise SystemExit(1)
