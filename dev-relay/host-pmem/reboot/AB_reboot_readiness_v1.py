"""Read-only reboot reconciliation for the Host pmem/DAX full-load deployment.

Does not enroll, alter old boot records, call SDK, open device data, or start services.
Uses existing private relay credentials only to upload a bounded private receipt.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path('/home/jwk/agent')
RELAY = ROOT / 'github-relay'
PRIVATE = Path('/home/jwk/.local/state/agentenv-github-relay')
RUNNER_SHA = 'b958c459c09db2fe72d508762e8bdab06bd642bfc2f33c6723462ac45353fdcd'
SESSION = 'relay-20261029-0d032371'
CONTROL = ('LittleFish-15/AgentENV-relay-control', 1438089258)
RESULTS = ('LittleFish-15/AgentENV-relay-results', 1438089386)
HASH_BUDGET = 768 * 1024**2


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def read(path, limit=256*1024):
    path = Path(path)
    need(path.resolve(strict=True) == path, 'Redirected input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        a = os.fstat(f.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_size <= limit, 'Input size/type differs')
        raw = f.read(limit+1)
        b = os.fstat(f.fileno())
        need(len(raw) <= limit and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns) ==
             (b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns), 'Input changed')
        return raw


def observed(path):
    try:
        return {'value': read(path).decode().strip()}
    except (OSError, RuntimeError, UnicodeError) as e:
        return {'unavailable': type(e).__name__}


def file_info(path, full_hash=False, budget=None):
    p = Path(path)
    try:
        need(p.resolve(strict=True) == p, 'Redirected file')
        a = p.lstat()
        need(stat.S_ISREG(a.st_mode), 'Not regular')
        row = {'path': str(p), 'bytes': a.st_size, 'uid': a.st_uid, 'gid': a.st_gid,
               'mode': oct(stat.S_IMODE(a.st_mode)), 'device': a.st_dev, 'inode': a.st_ino,
               'mtimeNs': a.st_mtime_ns, 'sha256': None, 'hashStatus': 'metadata_only'}
        if full_hash and a.st_size <= 128*1024**2 and budget[0] >= a.st_size:
            budget[0] -= a.st_size
            h = hashlib.sha256()
            fd = os.open(p, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            with os.fdopen(fd, 'rb') as f:
                first = os.fstat(f.fileno())
                need((first.st_dev,first.st_ino,first.st_size,first.st_mtime_ns,first.st_ctime_ns) ==
                     (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns), 'Input changed before hash')
                for block in iter(lambda:f.read(1024**2), b''):
                    h.update(block)
                b = os.fstat(f.fileno())
            need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns) ==
                 (b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns), 'Input changed while hashing')
            row.update(sha256=h.hexdigest(), hashStatus='full_stable_hash')
        return row
    except (OSError, RuntimeError) as e:
        return {'path': str(p), 'unavailable': type(e).__name__, 'sha256': None}


def unit(name):
    props = 'LoadState,ActiveState,SubState,MainPID,User,Group,Result,ExecMainStatus,FragmentPath'
    try:
        p = subprocess.run(['/usr/bin/systemctl','show',name,'--no-pager','--property='+props],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=8, text=True)
        return {'exitCode':p.returncode, 'properties':dict(line.split('=',1) for line in
                p.stdout.splitlines() if '=' in line)}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {'unavailable':type(e).__name__}


def json_projection(path):
    row = file_info(path)
    if 'unavailable' in row:
        return row
    try:
        data = json.loads(read(path, 2*1024**2))
        # No arbitrary config/state contents, credentials, tokens, or payloads.
        keys = ('status','phase','state','version','node','bootId','coreCommit','epoch',
                'runId','outcomeUncertain','SDK_called','Guest_created','ownerId',
                'manifestSha256','moduleReady','logicalUbRequestBytes')
        row['summary'] = {k:data[k] for k in keys if k in data and isinstance(data[k],
                         (str,int,bool,type(None)))}
    except (OSError, ValueError, RuntimeError) as e:
        row['summaryUnavailable'] = type(e).__name__
    return row


def inspect(api, config):
    current = api.identity()
    old = config['identity']
    node = config['node']
    need(node in ('node-a','node-b') and config['sessionId'] == SESSION, 'Not enrolled A/B session')
    need(current['hostname'] == old['hostname'] == {'node-a':'server1','node-b':'agent1'}[node]
         and current['machineId'] == old['machineId'] and current['gid'] == old['gid'] == 1205,
         'Physical node/user differs; no re-enrollment attempted')
    need(current['architecture'] == 'aarch64', 'ARM64 required')
    n = node[-1]
    budget = [HASH_BUDGET]
    row = {'schema':1, 'status':'AB_HOST_DAX_REBOOT_READINESS_ONLY', 'node':node,
           'sessionId':SESSION, 'identity':current, 'previousIdentity':old,
           'bootChanged':current['bootId'] != old['bootId'],
           'servicesStarted':False, 'SDKCalled':False, 'GuestCreated':False,
           'oldEnrollmentChanged':False, 'twoNodeAccepted':False, 'netSavingsBytes':None,
           'scope':'read-only prerequisites for full-load UB/OBMM/Host pmem/DAX; not direct-UB',
           'units':{}, 'modules':{}, 'files':[], 'journals':[], 'devices':[]}
    names = ['ubse.service','ubsmd.service', 'aenv-hpmem-v2-node-'+n+'-sdk.service',
        'aenv-hpmem-v2-node-'+n+'-sdk-journal.service','aenv-hpmem-v2-node-'+n+'-view.service',
        'aenv-hpd4-'+n+'-dax.service','aenv-hpd4-'+n+'-original.service',
        'jwk-aenv-direct-ub-guest-v1-node-'+n+'.service',
        'jwk-aenv-direct-ub-deletefix-v1-node-'+n+'.service',
        'jwk-aenv-ae9c626-node-'+n+'.service',
        'jwk-aenv-dsec-hostfile-v1-node-'+n+'.service']
    row['units'] = {name:unit(name) for name in names}
    for name in ('obmm','ublk_drv','kvm'):
        base = Path('/sys/module')/name
        row['modules'][name] = {'present':base.exists(), 'srcversion':observed(base/'srcversion'),
                               'refcnt':observed(base/'refcnt')}
    row['modules']['obmm']['parameters'] = {key:observed(Path('/sys/module/obmm/parameters')/key)
        for key in ('pmem_ro_enable','mempool_size','mem_allocator_granu','mempool_allocator','skip_cache_maintain')}
    row['kernelTaint'] = observed('/proc/sys/kernel/tainted')
    row['ipForward'] = observed('/proc/sys/net/ipv4/ip_forward')
    for pattern in ('ublk*','obmm*','kvm','net/tun'):
        for path in sorted(Path('/dev').glob(pattern))[:128]:
            try:
                a = path.lstat()
                row['devices'].append({'path':str(path),'uid':a.st_uid,'gid':a.st_gid,
                    'mode':oct(stat.S_IMODE(a.st_mode)), 'rdev':a.st_rdev,
                    'readable':os.access(path,os.R_OK),'writable':os.access(path,os.W_OK)})
            except OSError:
                pass
    paths = [ROOT/'r'/('hpd4-'+n+'-v1')/'prepared.json',
             ROOT/'r'/('hpd4-'+n+'-v1')/'runtime-stage/staged.json',
             ROOT/'r'/('hpmem-'+n+'-v1')/'prepared.json',
             ROOT/'r'/('hpmem-'+n+'-v1')/'provider/owner.json',
             ROOT/'r'/('hpmem-'+n+'-v1')/'provider/release.json',
             Path('/var/lib/agentenv-hpmem-demo-v2')/node/'workflow.json',
             Path('/var/lib/agentenv-host-pmem-'+n+'-v2/journal.json')]
    row['journals'] = [json_projection(p) for p in paths]
    # Only fixed executable names; never print config TOML/API credentials.
    for base in (ROOT/'deployments/agentenv-direct-ub-guest-v1',
                 ROOT/'deployments/agentenv-direct-ub-deletefix-v1',
                 ROOT/'r'/('hpd4-'+n+'-v1')/'runtime-stage/dax'):
        for rel in ('bin/server','bin/aenv','bin/uvm-ublk-daemon',
                    'deps/firecracker/1.15.1-patch-v3/firecracker'):
            row['files'].append(file_info(base/rel,True,budget))
    for p in (ROOT/'ub-host-pmem-build-2c1768644257/kernel-obmm/obmm.ko',
              ROOT/'r'/('hpmem-'+n+'-v1')/'obmm.ko',
              ROOT/'r'/('lazy4-'+n+'-v1')/'libaenv-ub.so',
              Path('/usr/lib64/libubsm_sdk.so')):
        row['files'].append(file_info(p,True,budget))
    # GiB container: metadata only. Does not claim SHA attestation or warm all data.
    row['files'].append(file_info(ROOT/'r'/('hpd4-'+n+'-v1')/'rootfs-lowers.ext4'))
    row['hashBytesRead'] = HASH_BUDGET-budget[0]
    row['globalObjectOutcome'] = 'unconfirmed_after_reboot; no SDK query or allocation attempted'
    return row


def main():
    need(sys.platform=='linux' and os.getuid()==os.geteuid()==1204, 'Run as ordinary jwk, not root')
    os.umask(0o077)
    p = RELAY/('runner-'+RUNNER_SHA[:12]+'.py')
    raw = read(p, 65536)
    need(hashlib.sha256(raw).hexdigest()==RUNNER_SHA, 'Installed relay version differs')
    spec = importlib.util.spec_from_file_location('pinned_relay_readonly',p)
    api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    config = api.load(PRIVATE/'config.json', True)
    need(config['controlRepo']==CONTROL[0] and config['controlRepoId']==CONTROL[1]
         and config['resultRepo']==RESULTS[0] and config['resultRepoId']==RESULTS[1], 'Repository binding differs')
    current = api.identity()
    # Explicit read-only observation of a changed boot, NOT a change to enrollment.
    need(re.fullmatch(r'[0-9a-f-]{36}',current['bootId']) is not None, 'Boot format differs')
    output = api.secure_dir(RELAY/'reboot-readiness-v1')
    target = output/(current['bootId']+'.json')
    if target.exists():
        report = api.load(target,True)
        need(report['identity']==current and report['sessionId']==SESSION, 'Saved receipt differs')
    else:
        report = inspect(api,config)
        api.atomic(target,report,replace=False)
    tokens = api.load(PRIVATE/'credentials.json',True)
    control,result = api.GitHub(tokens['controlToken']),api.GitHub(tokens['resultToken'])
    control.private_repo(*CONTROL); result.private_repo(*RESULTS)
    key = 'reboot-readiness/'+SESSION+'/'+report['node']+'/'+current['bootId']+'.json'
    result.immutable_result(RESULTS[0],RESULTS[1],'main',key,api.encoded(report))
    print(json.dumps({'status':'AB_HOST_DAX_REBOOT_READINESS_UPLOADED_NO_SERVICES_CHANGED',
          'node':report['node'],'bootChanged':report['bootChanged'],'resultPath':key,
          'next':'controller reviews exact boot/module/artifacts before approved service recreation'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('AB_REBOOT_READINESS_STOPPED_PRESERVE_STATE errorType='+type(error).__name__)
        raise SystemExit(1)
