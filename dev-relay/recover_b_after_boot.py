"""Refresh only stale B launch context after a verified boot change.

Run as ordinary jwk. No installation, Guest/SDK calls, service management or
permissions changes. Emits exact reviewed root Python text for manual pasting.
"""
import contextlib
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile

ROOT = Path('/home/jwk/agent')
PROFILES = (
    ('original', 'agentenv-ae9c626-baseline', 'node-b', 'jwk-aenv-ae9c626-node-b.service',
     'aenv-offline-install-start-v4', 'ae9c62693839ce7effa2b45df31c0039ae4f9fbc', 18080,
     {'server': '0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff',
      'aenv': 'ac2cf76020ce2ed0cf06f1105e06c34534a35ed8247fca0cb57e2d53269771e1',
      'uvm-ublk-daemon': '13bd2ac381cf877348a39c0b198e2061479ae237c0f54cbcbeae0ab14e700172'}),
    ('modified', 'agentenv-ub-b019f27', 'ub-b-b019', 'jwk-aenv-ub-b019f27-node-b.service',
     'aenv-ub-isolated-b-v1', 'b019f270a6c4359db0ad65ef669dd0e479056603', 18081,
     {'server': 'e8ea6c30704ec511f0b2a479313bb4cd4f71d25adc5acb6548adafe5f980b231',
      'aenv': 'be2c3b339bf077e66d6646c1ecafdf38392a4c2ca327cd6a26ab5433afc66546',
      'uvm-ublk-daemon': '6d73405d4d30777355c43df68361616c9ff2639cbc0347fd8dec4c56b93e5879'}),
)
RUNTIME_NAMES = ('runtime-attestation.json', 'host-proxy.json', 'api.sock', 'ublk.sock', 'ublk-daemon.sock')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def safe(path):
    path = Path(path)
    require(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve() == path,
            'Outside workspace or redirected: ' + str(path))
    return path


def metadata(path):
    m = safe(path).lstat()
    require(m.st_uid == 1204 and not stat.S_ISLNK(m.st_mode), 'Unexpected owner/type: ' + str(path))
    return m


def read(path, limit=65536):
    metadata(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        m = os.fstat(f.fileno())
        require(stat.S_ISREG(m.st_mode) and m.st_uid == 1204 and m.st_size <= limit,
                'Unexpected file metadata: ' + str(path))
        data = f.read(limit + 1)
        require(len(data) <= limit, 'File grew beyond limit')
        return data


def digest(path):
    metadata(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 1204 and before.st_size <= 512 * 1024**2,
                'Unexpected binary metadata')
        h = hashlib.sha256()
        for data in iter(lambda: f.read(1024 * 1024), b''):
            h.update(data)
        after = os.fstat(f.fileno())
        require((before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns), 'File changed during verification')
        return h.hexdigest()


def unit_absent(unit):
    r = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--no-pager',
                        '--property=LoadState,ActiveState,MainPID'], capture_output=True,
                       text=True, timeout=10, stdin=subprocess.DEVNULL)
    values = dict(line.split('=', 1) for line in r.stdout.splitlines() if '=' in line)
    require(values.get('LoadState') == 'not-found' and values.get('ActiveState') == 'inactive'
            and values.get('MainPID') == '0', 'Unit not absent; preserve it: ' + unit)
    return values


def ports_free():
    for port in (18080, 18081):
        with socket.socket() as s:
            s.bind(('127.0.0.1', port))


def socket_inactive(path):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(1)
        try:
            s.connect(str(path))
        except OSError as e:
            require(e.errno == errno.ECONNREFUSED, 'Socket state uncertain; preserved: ' + str(path))
        else:
            raise RuntimeError('Socket has a live listener; preserved: ' + str(path))


def plan_profile(profile, boot, netns, mntns):
    name, folder, runtime_name, unit, revision, commit, port, hashes = profile
    base, runtime = ROOT / 'deployments' / folder, ROOT / 'r' / runtime_name
    before = read(base / 'installation.json')
    receipt = json.loads(before)
    require(receipt.get('revision') == revision and receipt.get('commit') == commit
            and receipt.get('node') == 'node-b', 'Installation identity differs: ' + name)
    require(isinstance(receipt.get('boot_id'), str) and re.fullmatch(r'[0-9a-f-]{36}', receipt['boot_id']), 'Invalid old boot id')
    for binary, expected in hashes.items():
        require(digest(base / 'bin' / binary) == expected, 'Binary differs: ' + name + '/' + binary)
    launcher = Path(receipt.get('launcher', ''))
    if name == 'original':
        require(re.fullmatch(r'/home/jwk/agent/relay/aenv-run-v4-[0-9a-f]+/deployment\.py', str(launcher)), 'Original launcher path differs')
        read(launcher, 256 * 1024)
    else:
        require(launcher == base / 'libexec/deploy_b_ub.py' and receipt.get('unit') == unit
                and receipt.get('runtime') == str(runtime), 'Modified installation paths differ')
        require(digest(launcher) == receipt.get('launcher_sha256'), 'Modified launcher hash differs')
        dependencies = receipt.get('launcher_dependencies', {})
        require(set(dependencies) == {'deploy_a_ub.py'}, 'Modified launcher dependency record differs')
        require(digest(base / 'libexec/deploy_a_ub.py') == dependencies['deploy_a_ub.py'], 'Launcher library differs')
    changed = receipt['boot_id'] != boot
    stale = []
    for filename in RUNTIME_NAMES:
        path = safe(runtime / filename)
        if not path.exists():
            continue
        m = metadata(path)
        if filename.endswith('.json'):
            record = json.loads(read(path))
            require(record.get('revision') == revision, 'Unexpected runtime record preserved: ' + str(path))
        else:
            require(stat.S_ISSOCK(m.st_mode), 'Expected a socket; preserved: ' + str(path))
            socket_inactive(path)
        require(changed, 'Same-boot runtime evidence exists; no stale-state assumption: ' + str(path))
        stale.append((path, (m.st_dev, m.st_ino, m.st_mode, m.st_mtime_ns)))
    after = dict(receipt, boot_id=boot, host_netns=netns, host_mntns=mntns) if changed else receipt
    require(changed or (receipt['host_netns'] == netns and receipt['host_mntns'] == mntns), 'Current-boot host namespace differs')
    return {'name': name, 'base': base, 'runtime': runtime, 'unit': unit, 'before': before,
            'after': after, 'old_boot': receipt['boot_id'], 'changed': changed, 'stale': stale}


def write_new(path, data):
    safe(path)
    with path.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def apply_plan(plans, work, report):
    # All validation completes before any existing state is changed.
    for plan in plans:
        unit_absent(plan['unit'])
        require(read(plan['base'] / 'installation.json') == plan['before'], 'Receipt changed concurrently')
    ports_free()
    for plan in plans:
        backup = work / plan['name']
        backup.mkdir(mode=0o700)
        write_new(backup / 'installation-before.json', plan['before'])
        item = {'old_boot_id': plan['old_boot'], 'current_boot_id': plan['after']['boot_id'],
                'context_refreshed': False, 'archived_runtime_entries': [], 'backup': str(backup)}
        report['profiles'][plan['name']] = item
        for path, expected in plan['stale']:
            unit_absent(plan['unit'])
            m = metadata(path)
            require((m.st_dev, m.st_ino, m.st_mode, m.st_mtime_ns) == expected, 'Runtime entry changed; preserved')
            if stat.S_ISSOCK(m.st_mode):
                socket_inactive(path)
            os.rename(path, backup / path.name)  # Exact known leaf only, never recursive.
            item['archived_runtime_entries'].append(path.name)
        if plan['changed']:
            replacement = backup / 'installation-new.json'
            write_new(replacement, (json.dumps(plan['after'], indent=2) + '\n').encode())
            unit_absent(plan['unit'])
            ports_free()
            require(read(plan['base'] / 'installation.json') == plan['before'], 'Receipt changed before replacement')
            os.replace(replacement, plan['base'] / 'installation.json')
            item['context_refreshed'] = True


# Root executes only this displayed stdlib code. Application code is launched
# exclusively through systemd User=jwk; no shell interpolation or dollar syntax.
ROOT_TEXT = r'''/usr/bin/python3 -I -B - <<'B_REVIEWED_REACTIVATE'
import json, os, pathlib, pwd, grp, re, stat, subprocess
def need(ok, why):
    if not ok: raise SystemExit('STOP: ' + why)
need(os.geteuid() == 0 and os.uname().nodename == 'agent1', 'B root only')
need(pwd.getpwnam('jwk').pw_uid == 1204 and pwd.getpwnam('jwk').pw_gid == 1205, 'Identity differs')
need(grp.getgrnam('kvm').gr_gid == 36 and grp.getgrnam('aenv').gr_gid == 982, 'Groups differ')
need(pathlib.Path('/sys/module/ublk_drv').is_dir(), 'Existing ublk module missing')
for p in ('/dev/kvm','/dev/ublk-control','/dev/net/tun'):
    need(stat.S_ISCHR(os.stat(p).st_mode), 'Existing device missing')
root = pathlib.Path('/home/jwk/agent')
boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
jobs = []
for label, folder, unit in [('original','agentenv-ae9c626-baseline','jwk-aenv-ae9c626-node-b.service'),('modified','agentenv-ub-b019f27','jwk-aenv-ub-b019f27-node-b.service')]:
    base = root / 'deployments' / folder
    path = base / 'installation.json'
    need(path.resolve(strict=True) == path, 'Redirected receipt')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        m = os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == 1204 and m.st_size <= 65536, 'Unexpected receipt')
        data = f.read(65537)
        need(len(data) <= 65536, 'Receipt grew')
        r = json.loads(data)
    need(r.get('node') == 'node-b' and r.get('boot_id') == boot, 'Run ordinary preparation first')
    launcher = r.get('launcher', '')
    if label == 'original':
        need(r.get('revision') == 'aenv-offline-install-start-v4' and re.fullmatch(r'/home/jwk/agent/relay/aenv-run-v4-[0-9a-f]+/deployment\.py', launcher), 'Unexpected original launcher')
    else:
        need(r.get('revision') == 'aenv-ub-isolated-b-v1' and launcher == str(base / 'libexec/deploy_b_ub.py'), 'Unexpected modified launcher')
    p = pathlib.Path(launcher)
    need(p.resolve(strict=True) == p and p.is_file() and p.stat().st_uid == 1204, 'Unexpected launcher file')
    state = subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,MainPID'],capture_output=True,text=True,check=True).stdout
    fields = dict(x.split('=',1) for x in state.splitlines() if '=' in x)
    if fields.get('ActiveState') == 'active':
        print('RETAINED_ACTIVE_UNIT=' + unit)
        continue
    need(fields.get('LoadState') == 'not-found' and fields.get('MainPID') == '0', 'Existing inactive unit preserved: ' + unit)
    jobs.append((unit,base,launcher,label))
for unit,base,launcher,label in jobs:
    args = ['/usr/bin/systemd-run','--unit='+unit,'--collect']
    properties = ['User=jwk','Group=jwk','SupplementaryGroups=kvm aenv','CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN','AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN','NoNewPrivileges=yes','RestrictSUIDSGID=yes','PrivateNetwork=yes','PrivateMounts=yes','Type=exec','Restart=no','KillMode=control-group','TimeoutStopSec=90s','LimitNOFILE=65536','WorkingDirectory='+str(base),'StandardOutput=null','StandardError=null']
    args += ['--property='+v for v in properties]
    args += ['/usr/bin/python3','-I','-B',launcher,'inside']
    if label == 'original': args += ['node-b']
    subprocess.run(args,check=True)
    print('SUBMITTED_UNIT=' + unit)
print('B_BOTH_UNITS_SUBMITTED_RUN_JWK_HEALTH_NEXT')
B_REVIEWED_REACTIVATE'''


def main():
    require(sys.platform == 'linux' and socket.gethostname() == 'agent1' and os.uname().machine == 'aarch64', 'Original B ARM64 only')
    require(os.getuid() == os.geteuid() == 1204 and os.getgid() == os.getegid() == 1205, 'Run as ordinary jwk, not root')
    caps = re.findall(r'^(Cap(?:Inh|Prm|Eff|Amb)):\s*(\w+)$', Path('/proc/self/status').read_text(), re.M)
    require(len(caps) == 4 and all(int(v, 16) == 0 for k, v in caps), 'Ordinary capability-free session required')
    os.umask(0o077)
    import fcntl
    with contextlib.ExitStack() as stack:
        lock = stack.enter_context(open(safe(ROOT / 'relay/aenv-ub-b019f27-install.lock'), 'r'))
        metadata(Path(lock.name))
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        work = Path(tempfile.mkdtemp(prefix='node-b-reboot-restore-', dir=safe(ROOT / 'relay/reports')))
        report = {'revision': 'b-reboot-restore-v1', 'report_directory': str(work), 'profiles': {},
                  'services_started': False, 'SDK_called': False, 'Guest_created': False,
                  'binaries_or_business_data_modified': False}
        try:
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            ports_free()
            for profile in PROFILES:
                unit_absent(profile[3])
                runtime = ROOT / 'r' / profile[2]
                for name in ('proxy-inside.lock', 'proxy-host.lock'):
                    path = safe(runtime / name)
                    if path.exists():
                        metadata(path)
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        handle = stack.enter_context(os.fdopen(fd, 'rb'))
                        require(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), 'Proxy lock is not regular')
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            plans = [plan_profile(p, boot, os.stat('/proc/self/ns/net').st_ino,
                                  os.stat('/proc/self/ns/mnt').st_ino) for p in PROFILES]
            apply_plan(plans, work, report)
            report['status'] = 'B_REBOOT_CONTEXT_PREPARED_NOT_STARTED'
        except Exception as e:
            report['status'] = 'STOPPED_B_REBOOT_PREPARATION'
            report['error'] = {'type': type(e).__name__, 'errno': getattr(e, 'errno', None),
                               'reason': str(e) if type(e) is RuntimeError else 'Preparation failed; backups retained'}
        write_new(work / 'return.json', (json.dumps(report, indent=2) + '\n').encode())
        print('BEGIN_RETURN_REPORT')
        print(json.dumps(report, indent=2))
        print('END_RETURN_REPORT')
        if report['status'] != 'B_REBOOT_CONTEXT_PREPARED_NOT_STARTED':
            return 1
        print('ROOT_SCOPE: exact two B units; User=jwk; kvm/aenv process groups; CAP_SYS_ADMIN/CAP_NET_ADMIN; private namespaces. No host/account/device changes.')
        print('BEGIN_REVIEWED_ROOT_COMMANDS_COPY_BODY_ONLY')
        print(ROOT_TEXT)
        print('END_REVIEWED_ROOT_COMMANDS_COPY_BODY_ONLY')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as e:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'STOPPED_B_REBOOT_ENTRY', 'error_type': type(e).__name__,
                          'detail': str(e) if type(e) is RuntimeError else 'Entry failed', 'services_started': False}))
        print('END_RETURN_REPORT')
        raise SystemExit(1)
