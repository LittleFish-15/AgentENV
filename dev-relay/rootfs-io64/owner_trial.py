"""Owner-side preparation; no service restart or root execution here."""
import hashlib, json, os, shutil, stat
from pathlib import Path

CORE_COMMIT='9a2fcf6571a0266dc22a65315a3fbfbd96a562b2'
SERVER_SHA='118fac40d567b07e236f6fcdff90bc8b8aa99bf2c1ae0e7998c7b608726d0517'
DAEMON_SHA='3d6af078dc4b4ce5ad8531cfb1cb91242745bbfd300757a3197cce45e64cb3d0'
BASELINE_RUN='de320ed9ad9b4b8b9aa037ee9d4dcc8e'


def need(ok, why):
    if not ok:raise RuntimeError(why)


def reconcile(m,identity,api):
    old=m.B.read_json(m.ROOT/'relay/cow4-global-cache-v2-node-a.pending.json')
    need(old['run_id']==BASELINE_RUN and old['status']=='COW4_POST_DROP_BASELINE_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED','Previous 256 KiB baseline differs')
    need(old['all_cohort_guests_released'] and not old['restore_outcome_uncertain'],'Previous Guest cleanup uncertain')
    need(old['replay_completed_guests']==8 and len(old['jobs'])==8,'Previous cohort incomplete')
    prior=old['root_session']
    need(all(prior.get(k) for k in ('original_configuration_restored','original_service_healthy','other_services_unchanged','observer_exit_confirmed','bound_guest_processes_exited')),'Previous restoration incomplete')
    need(tuple(prior['restored_identity'])==tuple(identity),'Original Runtime changed since baseline restoration')
    for job in old['jobs']:need(api.call('GET','/sandboxes/'+job['sandbox_id'])[0]==404,'Previous Guest remains')
    return {'baseline_run_id':BASELINE_RUN,'baseline_report_directory':old['report_directory'],'prior_receipt_preserved':True,
            'previous_guests_http404':True,'change':'Original rootfs ublk max I/O only: 256 to 64 KiB',
            'baseline_template_ids':sorted({j['template_id'] for j in old['jobs']})}


def prepare_server(m,work,receipt,identity):
    source=Path(receipt['server_candidate']);expected=Path(receipt['work_directory'])/'observer/server-rootfs-io64'
    need(source==expected and receipt['server_sha256']==SERVER_SHA and receipt['core_commit']==CORE_COMMIT,'Server build receipt differs')
    need(receipt.get('UB_code_included') is False,'Expected original-only build')
    candidate=work/'observer/server-rootfs-io64'
    raw=m.H.read(source,256*1024**2);need(hashlib.sha256(raw).hexdigest()==SERVER_SHA,'Server candidate changed')
    with candidate.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.chmod(candidate,0o700)
    installed=m.BASE/'bin/server';need(installed.resolve(strict=True)==installed,'Redirected original server')
    old=m.H.read(installed,256*1024**2);s=installed.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid==1204 and s.st_mode&0o111 and not s.st_mode&0o022,'Unexpected original server mode/owner')
    need(m.H.runtime_pid()==identity,'Runtime changed during backup')
    backup=work/'server.original';os.link(installed,backup,follow_symlinks=False)
    b=backup.stat();need((s.st_dev,s.st_ino,s.st_size)==(b.st_dev,b.st_ino,b.st_size),'Backup inode differs')
    need(m.H.read(backup,256*1024**2)==old,'Original bytes changed during backup')
    return {'server_candidate':str(candidate),'server_sha256':SERVER_SHA,'core_commit':CORE_COMMIT,
            'original_server_backup':str(backup),'original_server_sha256':hashlib.sha256(old).hexdigest(),
            'original_server_metadata':{'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size}}
