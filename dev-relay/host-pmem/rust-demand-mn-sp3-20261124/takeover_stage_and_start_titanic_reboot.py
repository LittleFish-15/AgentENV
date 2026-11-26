"""Stage and start a fresh checked Titanic Provider generation after reboot."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import time
import traceback
import uuid
from pathlib import Path


PROVIDER = Path('/opt/aenv/bin/agentenv-ub-provider-5ecfe105')
PROVIDER_SHA = '5ecfe105521b583e3e419bdf6da09258144a5a4e63834de6612b4bcf880647d8'
ROOT = Path('/etc/aenv/ub')
SDK = Path('/var/lib/aenv-ub-sdk')
HOST_WORK = Path('/home/jwk/agent/sp3-mn')
APP = HOST_WORK / 'aenv-tit-d02'
OWNER_SNAPSHOT_STORE = HOST_WORK / 'mn-tcap-004/h/snapshot-store'
IMPORTER_SNAPSHOT_STORE = HOST_WORK / 'aenv-tit-d01/h/snapshot-store'
OWNER_IMAGE = Path('/root/aenv-pmem/mn-titanic-share-001-fprbb53_/lowers.ext4')
BOOT_PATH = Path('/proc/sys/kernel/random/boot_id')
SRCVERSION = '29F10664C1EE59D7127F8C7'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C', 'LC_ALL': 'C'}
ROLE_ENV = {key: ENV[key] for key in ('PATH', 'LANG', 'LC_ALL')}
UID, GID = 1204, 1205


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def file_sha(path):
    state = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            state.update(block)
    return state.hexdigest()


def record_json(path, maximum=2 * 1024 * 1024):
    need(path.resolve(strict=True) == path and path.is_file() and path.stat().st_size <= maximum,
         'Unexpected staged JSON input: ' + str(path))
    return json.loads(path.read_bytes())


def direct_dir(path, allowed_owners):
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode) and
         info.st_uid in allowed_owners and not info.st_mode & 0o022, 'Unexpected directory: ' + str(path))


def newdir(path, uid, gid, mode):
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    path.chmod(mode)


def save(path, data, uid, gid, mode):
    with path.open('xb') as stream:
        os.fchown(stream.fileno(), uid, gid)
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def as_jwk(action):
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([])
            os.setgid(GID)
            os.setuid(UID)
            action()
        except BaseException:
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    need(status == 0, 'Private staging as jwk failed')


def create_app():
    APP.mkdir(mode=0o700)
    (APP / 'h').mkdir(mode=0o700)
    (APP / 'r').mkdir(mode=0o700)


def declared_lowers(record, template):
    need(record['id'] == template and record['alias'] == 'mn-titanic-verify-001', 'Snapshot identity differs')
    committed = record['committed']
    layers = [layer['Managed'] for layer in committed['rootfs_layers']]
    memory = committed['memory_layers']
    need(len(layers) == 10 and len(memory) == 1 and not committed['attached_drives']
         and sum(row['size'] for row in layers) == 1831881728, 'Expected original committed template layers')
    need(all(re.fullmatch(r'sha256:[a-f0-9]{64}', row['digest']) and row['size'] > 0 for row in layers + memory),
         'Invalid committed layer descriptor')
    lowers = [{'name': row['digest'].replace(':', '_') + '.overlaybd.commit',
               'digest': row['digest'], 'bytes': row['size']} for row in layers]
    return lowers, memory[0]


def json_file(path):
    need(path.resolve(strict=True) == path and path.is_file() and path.stat().st_size <= 2 * 1024 * 1024,
         'Unexpected configuration or journal file: ' + str(path))
    return json.loads(path.read_bytes())


def start(label, argv, home, logs):
    output = logs / (label + '.log')
    with output.open('xb') as stream:
        child = subprocess.Popen(argv, env={**ROLE_ENV, 'HOME': home}, cwd='/', stdin=subprocess.DEVNULL,
                                 stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
                                 close_fds=True)
    print(json.dumps({'event': 'role_dispatched', 'role': label, 'launcherPid': child.pid,
                      'log': str(output)}), flush=True)
    return child


def print_tail(label, path):
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - 4096))
        raw = stream.read(4096).decode('utf-8', 'replace')
    lines = [line for line in raw.splitlines()
             if not re.search(r'(?i)password|authorization|private.key|token', line)]
    print(json.dumps({'event': 'current_role_log', 'role': label, 'tail': lines[-20:]}), flush=True)


def start_provider(args, host):
    run = args.run
    root_dir = Path('/etc/aenv/ub') / ('relay-' + run)
    sdk_dir = Path('/var/lib/aenv-ub-sdk') / ('relay-' + run)
    root_cfg, sdk_cfg = root_dir / 'device-root.json', sdk_dir / 'device-sdk.json'
    root, sdk = json_file(root_cfg), json_file(sdk_cfg)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    for cfg in (root, sdk):
        need(cfg['run'] == run and cfg['node'] == host and cfg['manifestSha256'] == args.manifest_sha
             and cfg['device']['bootId'] == boot and cfg['device']['kernelRelease'] == os.uname().release,
             'Staged generation differs from the running node')
    need(root['device'] == sdk['device'] and root['rootSocket'] == sdk['rootSocket']
         and root['sdkSocket'] == sdk['sdkSocket'] and root['sdk'] == sdk['sdk'],
         'Provider roles have conflicting staged configuration')
    need(root['rootSocket'] == str(root_dir / 'rootctl/root.sock') and
         root['sdkSocket'] == str(sdk_dir / 'sdk.sock') and
         root['device']['brokerSocket'] == str(root_dir / 'broker/broker.sock') and
         root['device']['index'] == str(root_dir / 'index/stable-index.json') and
         root['device']['stateDir'] == str(root_dir / 'device-state') and
         root['sdk']['stateDir'] == str(sdk_dir / 'state'), 'Unexpected generation paths')
    fresh_paths = (root['rootSocket'], root['sdkSocket'], root['device']['brokerSocket'],
                   root['device']['index'], root_dir / 'device-state/root.json', sdk_dir / 'state')
    need(not any(os.path.lexists(path) for path in fresh_paths), 'Prior generation activity requires reconciliation')
    need(PROVIDER.resolve(strict=True) == PROVIDER and PROVIDER.is_file()
         and hashlib.sha256(PROVIDER.read_bytes()).hexdigest() == PROVIDER_SHA,
         'Provider build differs')
    for process in Path('/proc').iterdir():
        if process.name.isdecimal():
            try:
                executable = Path(os.readlink(process / 'exe')).name
            except OSError:
                continue
            need(not executable.startswith('agentenv-ub-provider'), 'A Provider process is already active')

    logs = root_dir / 'launch-evidence'
    logs.mkdir(mode=0o700)
    sdk_role = start('sdk', ['/usr/sbin/runuser', '-u', 'jwk', '--', str(PROVIDER),
                             'sdk', str(sdk_cfg)], '/home/jwk', logs)
    root_role = None
    try:
        socket_deadline = time.monotonic() + 15
        while time.monotonic() < socket_deadline:
            need(sdk_role.poll() is None, 'SDK exited before its socket appeared')
            try:
                if stat.S_ISSOCK((sdk_dir / 'sdk.sock').lstat().st_mode):
                    break
            except FileNotFoundError:
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError('SDK socket did not appear')
        root_role = start('root', [str(PROVIDER), 'root', str(root_cfg)], '/root', logs)
        deadline = time.monotonic() + 155
        while time.monotonic() < deadline:
            need(sdk_role.poll() is None and root_role.poll() is None, 'A Provider role exited during startup')
            index_path = root_dir / 'index/stable-index.json'
            if index_path.is_file():
                index = json_file(index_path)
                journal = json_file(root_dir / 'device-state/root.json')
                if journal.get('phase') == 'serving':
                    expected_lowers = [(row['digest'], row['bytes']) for row in root['device']['lowers']]
                    replicas = index['replicas']
                    actual_lowers = [(row['layerDigest'], row['fileBytes']) for row in replicas]
                    need(index['version'] == 3 and index['mode'] == 'host-dax-stable-demand'
                         and index['state'] == 'metadata_ready' and journal['run'] == run
                         and len(expected_lowers) == 10 and len(set(expected_lowers)) == 10
                         and actual_lowers == expected_lowers
                         and all(row['generation'] == run
                                 and row['manifestSha256'] == 'sha256:' + args.manifest_sha
                                 and row['brokerSocket'] == root['device']['brokerSocket']
                                 and row['stablePmem']['imageBytes'] == 2 ** 31
                                 and row['stablePmem']['loadBytes'] == 262144 for row in replicas),
                         'Published index differs from the committed Titanic lower identities')
                    print(json.dumps({'status': 'MN_PROVIDER_SERVING', 'node': host, 'run': run,
                                      'sdkLauncherPid': sdk_role.pid, 'rootPid': root_role.pid,
                                      'index': str(index_path), 'phase': journal['phase'],
                                      'replicas': len(replicas),
                                      'lowerBytes': sum(size for _, size in actual_lowers),
                                      'initialLocalBindings': len(journal['bindings'])}), flush=True)
                    return
            time.sleep(0.5)
        raise RuntimeError('Provider ready index did not appear before the observation deadline')
    except (OSError, RuntimeError, ValueError):
        print_tail('sdk', logs / 'sdk.log')
        if root_role is not None:
            print_tail('root', logs / 'root.log')
        raise


def engine():
    for unit in ('ubse.service', 'ubsmd.service'):
        result = subprocess.run(['/usr/bin/systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'MainPID'],
                                capture_output=True, text=True, env=ENV, check=True, timeout=10)
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        need(values['ActiveState'] == 'active' and int(values['MainPID']) > 0, unit + ' is not active')
        if unit == 'ubse.service':
            pid = int(values['MainPID'])
    return pid


def stage(args, host):
    owner = host == 'agent1'
    boot = BOOT_PATH.read_text().strip()
    need(boot == args.boot_id and os.uname().release == '6.6.0-145.3.34.165.oe2403sp3.aarch64',
         'Boot or kernel changed after the recovery receipt')
    need(Path('/sys/module/obmm/srcversion').read_text().strip() == SRCVERSION
         and Path('/dev/obmm_pmem').is_char_device(), 'Pinned OBMM is not available')
    params = Path('/sys/module/obmm/parameters')
    need(all((params / name).read_text().strip() in ('1', 'Y')
             for name in ('pmem_ro_enable', 'pmem_demand_write_enable')), 'OBMM mode differs')
    engine_pid = engine()
    old_root, old_sdk = ROOT / ('relay-' + args.old_run), SDK / ('relay-' + args.old_run)
    old_configs = (old_root / 'device-root.json', old_sdk / 'device-sdk.json')
    seeds = [record_json(path) for path in old_configs]
    for cfg in seeds:
        need(cfg['run'] == args.old_run and cfg['node'] == host and cfg['ownerNode'] == 'agent1'
             and cfg['manifestSha256'] == args.manifest_sha
             and (cfg['sdk']['uid'], cfg['sdk']['gid']) == (UID, GID) and cfg['device']['bootId'] != boot,
             'Archived seed configuration differs')
    raw = (OWNER_IMAGE.with_name('manifest.json') if owner else old_root / 'manifest.json').read_bytes()
    native = json.loads(raw)
    need(hashlib.sha256(raw).hexdigest() == args.manifest_file_sha and native['sha256'] == args.manifest_sha
         and native['document']['fileBytes'] == 2**31, 'Expected native manifest bytes differ')
    if owner:
        direct_dir(OWNER_IMAGE.parent, (0,))
        image = OWNER_IMAGE.stat()
        mtime_sec, mtime_ns = divmod(image.st_mtime_ns, 10**9)
        ctime_sec, ctime_ns = divmod(image.st_ctime_ns, 10**9)
        need(OWNER_IMAGE.resolve(strict=True) == OWNER_IMAGE and stat.S_ISREG(image.st_mode)
             and native['sourceIdentity'] == {'device': image.st_dev, 'inode': image.st_ino, 'bytes': image.st_size,
                 'mtimeSeconds': mtime_sec, 'mtimeNanos': mtime_ns,
                 'ctimeSeconds': ctime_sec, 'ctimeNanos': ctime_ns}, 'Owner image identity differs')

    store = OWNER_SNAPSHOT_STORE if owner else IMPORTER_SNAPSHOT_STORE
    repo = store / 'repository'
    lower, memory = declared_lowers(record_json(repo / 'catalog/records' / (args.template + '.json')), args.template)
    blob = repo / 'managed-layers' / (memory['digest'].replace(':', '_') + '.overlaybd.commit')
    snapshot = repo / 'snapshots' / args.template
    need(blob.resolve(strict=True) == blob and blob.stat().st_size == memory['size']
         and 'sha256:' + file_sha(blob) == memory['digest']
         and (snapshot / 'commit').read_bytes() == b'committed'
         and all((snapshot / name).is_file() for name in ('vm_state.bin', 'firecracker-manifest.json')),
         'Retained template or ordinary memory layer differs')
    new_root, new_sdk = ROOT / ('relay-' + args.run), SDK / ('relay-' + args.run)
    direct_dir(ROOT, (0,))
    direct_dir(SDK, (0, UID))
    direct_dir(HOST_WORK, (0, UID))
    need(not any(os.path.lexists(path) for path in (APP, new_root, new_sdk)), 'Fresh run paths already exist')
    as_jwk(create_app)
    home, runtime = APP / 'h', APP / 'r'
    newdir(new_root, 0, 0, 0o755)
    newdir(new_sdk, UID, GID, 0o700)
    reader_gid = seeds[0]['device']['readerGid']
    need(seeds[1]['device']['readerGid'] == reader_gid, 'Reader group differs')
    for leaf, group, mode in (('rootctl', GID, 0o750), ('broker', reader_gid, 0o750),
                              ('index', reader_gid, 0o750), ('device-state', 0, 0o700), ('mount', 0, 0o700)):
        newdir(new_root / leaf, 0, group, mode)
    local_manifest = new_root / 'manifest.json'
    save(local_manifest, raw, 0, 0, 0o644)
    root_cfg, sdk_cfg = new_root / 'device-root.json', new_sdk / 'device-sdk.json'
    for data, out, uid, gid in ((seeds[0], root_cfg, 0, 0), (seeds[1], sdk_cfg, UID, GID)):
        data.update(run=args.run, manifest=str(local_manifest), manifestSha256=args.manifest_sha,
                    rootSocket=str(new_root / 'rootctl/root.sock'), sdkSocket=str(new_sdk / 'sdk.sock'))
        data['sdk']['stateDir'] = str(new_sdk / 'state')
        data['device'].update(bootId=boot, enginePid=engine_pid, kernelRelease=os.uname().release,
                              moduleSrcversion=SRCVERSION, stateDir=str(new_root / 'device-state'),
                              mountDir=str(new_root / 'mount'), brokerSocket=str(new_root / 'broker/broker.sock'),
                              index=str(new_root / 'index/stable-index.json'),
                              sourceImage=str(OWNER_IMAGE) if owner else None, lowers=lower)
        save(out, (json.dumps(data, indent=2) + '\n').encode(), uid, gid, 0o600)
    subprocess.run([str(PROVIDER), 'validate', str(root_cfg)], env=ENV, check=True, timeout=16)
    subprocess.run(['/usr/sbin/runuser', '-u', 'jwk', '--', str(PROVIDER), 'validate', str(sdk_cfg)],
                   env=ENV, check=True, timeout=16)

    assets = HOST_WORK / 'relay-guest-assets-001/deps'
    inputs = HOST_WORK / 'artifacts/deps'
    cfg = (f'home_path = "{home}"\nruntime_path = "{runtime}"\ndeps_path = "{assets}"\n'
           'virtualization_mode = "kvm"\n[firecracker]\n'
           f'binary_path = "{inputs}/firecracker/firecracker"\ncgroup_pool_size = 1\n'
           f'[kernel]\nimage_path = "{inputs}/vmlinux-6.1.175-aarch64"\n'
           '[snapshot]\nrepository_backend = "posix_fs"\np2p_enabled = false\nrootfs_backing_mode = "ub_demand"\n'
           f'rootfs_demand_index = "{new_root}/index/stable-index.json"\n'
           f'[backend.posix_fs]\nsnapshot_store = "{store}"\n'
           '[pool.block]\nenabled = false\n[pool.network]\nmaintenance_enabled = false\n'
           '[pool.firecracker]\nenabled = false\n')
    as_jwk(lambda: save(APP / 'config.toml', cfg.encode(), UID, GID, 0o600))
    print(json.dumps({'status': 'MN_REBOOT_TITANIC_CONFIG_STAGED', 'node': host, 'run': args.run,
                      'enginePid': engine_pid, 'templateId': args.template, 'config': str(APP / 'config.toml')}),
          flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('old-run', 'run', 'boot-id', 'template', 'manifest-sha', 'manifest-file-sha'):
        parser.add_argument('--' + option, required=True)
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    need(os.geteuid() == 0 and host in ('agent1', 'agent2')
         and re.fullmatch('[0-9a-f]{32}', args.run) and re.fullmatch('[0-9a-f]{32}', args.old_run)
         and args.run != args.old_run and str(uuid.UUID(args.template)) == args.template, 'Invalid M/N identity')
    need(PROVIDER.resolve(strict=True) == PROVIDER and file_sha(PROVIDER) == PROVIDER_SHA,
         'Retained Provider differs')
    os.umask(0o077)
    stage(args, host)
    start_provider(args, host)
