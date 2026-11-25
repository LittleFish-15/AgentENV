"""Stage the committed Titanic snapshot and gracefully retire the healthy fixture."""

import argparse
import hashlib
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import traceback
import uuid
from pathlib import Path


PROVIDER = Path('/opt/aenv/bin/agentenv-ub-provider-5ecfe105')
PROVIDER_SHA = '5ecfe105521b583e3e419bdf6da09258144a5a4e63834de6612b4bcf880647d8'
ROOT = Path('/etc/aenv/ub')
SDK = Path('/var/lib/aenv-ub-sdk')
HOST_WORK = Path('/home/jwk/agent/sp3-mn')
APP = HOST_WORK / 'aenv-tit-d01'
OWNER_SNAPSHOT_STORE = HOST_WORK / 'mn-tcap-004/h/snapshot-store'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C', 'LC_ALL': 'C'}
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


def unpack_peer(bundle, expected_sha, manifest_sha, template, store):
    direct_dir(bundle.parent, (0,))
    need(bundle.resolve(strict=True) == bundle and bundle.is_file() and bundle.stat().st_uid == 0
         and not bundle.stat().st_mode & 0o022 and bundle.stat().st_size == 87644160
         and file_sha(bundle) == expected_sha, 'SCP bundle bytes or identity differ')
    prefix = 'snapshot-store/repository/'
    record_name = prefix + 'catalog/records/' + template + '.json'
    with tarfile.open(bundle, 'r:') as archive:
        members = archive.getmembers()
        by_name = {member.name: member for member in members}
        need(len(members) == len(by_name) == 7 and all(member.isfile() for member in members),
             'Bundle does not contain exactly seven unique regular files')
        need(by_name[record_name].size <= 2 * 1024 * 1024, 'Snapshot record too large')
        with archive.extractfile(by_name[record_name]) as source:
            record = json.load(source)
        lower, memory = declared_lowers(record, template)
        mem_path = 'managed-layers/' + memory['digest'].replace(':', '_') + '.overlaybd.commit'
        expect = {'catalog/records/' + template + '.json', 'catalog/aliases/mn-titanic-verify-001',
                  'snapshots/' + template + '/commit', 'snapshots/' + template + '/vm_state.bin',
                  'snapshots/' + template + '/firecracker-manifest.json', mem_path}
        need(set(by_name) == {'manifest.json'} | {prefix + name for name in expect}, 'Bundle artifact list differs')
        need(by_name[prefix + mem_path].size == memory['size'], 'Memory layer size differs')
        need(by_name['manifest.json'].size <= 2 * 1024 * 1024, 'Native manifest too large')
        with archive.extractfile(by_name['manifest.json']) as payload:
            raw = payload.read()
        need(hashlib.sha256(raw).hexdigest() == manifest_sha, 'Transferred manifest differs')

        def extract():
            create_app()
            repo = store / 'repository'
            for relative in sorted(expect):
                out = repo / relative
                out.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                with archive.extractfile(by_name[prefix + relative]) as source, out.open('xb') as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
            need(file_sha(repo / mem_path) == memory['digest'][7:] and
                 (repo / 'snapshots' / template / 'commit').read_bytes() == b'committed',
                 'Received memory digest or commit marker differs')

        as_jwk(extract)
        return raw, lower


def stage(args, host):
    owner = host == 'agent1'
    old_root, old_sdk = ROOT / ('relay-' + args.old_run), SDK / ('relay-' + args.old_run)
    roots = (old_root / 'device-root.json', old_sdk / 'device-sdk.json')
    seeds = [record_json(path) for path in roots]
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    for cfg in seeds:
        need(cfg['run'] == args.old_run and cfg['node'] == host and cfg['ownerNode'] == 'agent1'
             and cfg['device']['bootId'] == boot and (cfg['sdk']['uid'], cfg['sdk']['gid']) == (UID, GID),
             'Healthy fixture config identity differs')

    new_root, new_sdk = ROOT / ('relay-' + args.run), SDK / ('relay-' + args.run)
    direct_dir(ROOT, (0,))
    direct_dir(SDK, (0, UID))
    direct_dir(HOST_WORK, (0, UID))
    need(not any(os.path.lexists(path) for path in (APP, new_root, new_sdk)), 'New generation paths already exist')
    home, runtime = APP / 'h', APP / 'r'
    store = OWNER_SNAPSHOT_STORE if owner else home / 'snapshot-store'
    if owner:
        manifest_path = args.artifact
        direct_dir(manifest_path.parent, (0,))
        image = manifest_path.with_name('lowers.ext4')
        need(manifest_path.resolve(strict=True) == manifest_path and manifest_path.is_file() and
             image.resolve(strict=True) == image and image.is_file() and image.stat().st_size == (2 << 30),
             'Existing owner image differs')
        raw = manifest_path.read_bytes()
        record = record_json(store / 'repository/catalog/records' / (args.template + '.json'))
        lower, _ = declared_lowers(record, args.template)
    else:
        raw, lower = unpack_peer(args.artifact, args.bundle_sha, args.manifest_file_sha, args.template, store)
        image = None
    native = json.loads(raw)
    need(hashlib.sha256(raw).hexdigest() == args.manifest_file_sha and native['sha256'] == args.manifest_sha
         and native['document']['fileBytes'] == (2 << 30), 'Expected prepared native manifest')
    if owner:
        info = image.stat()
        mtime_sec, mtime_ns = divmod(info.st_mtime_ns, 10**9)
        ctime_sec, ctime_ns = divmod(info.st_ctime_ns, 10**9)
        need(native['sourceIdentity'] == {'device': info.st_dev, 'inode': info.st_ino, 'bytes': info.st_size,
                                         'mtimeSeconds': mtime_sec, 'mtimeNanos': mtime_ns,
                                         'ctimeSeconds': ctime_sec, 'ctimeNanos': ctime_ns},
             'The verified owner image was replaced or modified')
        as_jwk(create_app)

    newdir(new_root, 0, 0, 0o755)
    newdir(new_sdk, UID, GID, 0o700)
    reader_gid = seeds[0]['device']['readerGid']
    need(seeds[1]['device']['readerGid'] == reader_gid, 'Reader group differs')
    for leaf, gid, mode in (('rootctl', GID, 0o750), ('broker', reader_gid, 0o750),
                            ('index', reader_gid, 0o750), ('device-state', 0, 0o700), ('mount', 0, 0o700)):
        newdir(new_root / leaf, 0, gid, mode)
    local_manifest = new_root / 'manifest.json'
    save(local_manifest, raw, 0, 0, 0o644)
    root_cfg, sdk_cfg = new_root / 'device-root.json', new_sdk / 'device-sdk.json'
    for data, out, uid, gid in ((seeds[0], root_cfg, 0, 0), (seeds[1], sdk_cfg, UID, GID)):
        data.update(run=args.run, manifest=str(local_manifest), manifestSha256=args.manifest_sha,
                    rootSocket=str(new_root / 'rootctl/root.sock'), sdkSocket=str(new_sdk / 'sdk.sock'))
        data['sdk']['stateDir'] = str(new_sdk / 'state')
        data['device'].update(stateDir=str(new_root / 'device-state'), mountDir=str(new_root / 'mount'),
                              brokerSocket=str(new_root / 'broker/broker.sock'),
                              index=str(new_root / 'index/stable-index.json'),
                              sourceImage=str(image) if owner else None, lowers=lower)
        save(out, (json.dumps(data, indent=2) + '\n').encode(), uid, gid, 0o600)
    subprocess.run([str(PROVIDER), 'validate', str(root_cfg)], env=ENV, check=True, timeout=16)
    subprocess.run(['/usr/sbin/runuser', '-u', 'jwk', '--', str(PROVIDER), 'validate', str(sdk_cfg)],
                   env=ENV, check=True, timeout=16)

    assets = HOST_WORK / 'relay-guest-assets-001/deps'
    inputs = HOST_WORK / 'artifacts/deps'
    aenv = (f'home_path = "{home}"\nruntime_path = "{runtime}"\ndeps_path = "{assets}"\n'
            'virtualization_mode = "kvm"\n[firecracker]\n'
            f'binary_path = "{inputs}/firecracker/firecracker"\ncgroup_pool_size = 1\n'
            f'[kernel]\nimage_path = "{inputs}/vmlinux-6.1.175-aarch64"\n'
            '[snapshot]\nrepository_backend = "posix_fs"\np2p_enabled = false\nrootfs_backing_mode = "ub_demand"\n'
            f'rootfs_demand_index = "{new_root}/index/stable-index.json"\n'
            f'[backend.posix_fs]\nsnapshot_store = "{store}"\n'
            '[pool.block]\nenabled = false\n[pool.network]\nmaintenance_enabled = false\n'
            '[pool.firecracker]\nenabled = false\n')
    as_jwk(lambda: save(APP / 'config.toml', aenv.encode(), UID, GID, 0o600))
    print(json.dumps({'status': 'MN_REAL_TITANIC_CONFIG_STAGED', 'run': args.run, 'templateId': args.template,
                      'node': host, 'rootConfig': str(root_cfg), 'sdkConfig': str(sdk_cfg),
                      'aenvConfig': str(APP / 'config.toml'), 'localManagedRootfsCopies': owner}), flush=True)
    return roots, old_sdk


def role_control(action, config):
    return subprocess.run([str(PROVIDER), action, str(config)], env=ENV, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=40, check=False)


def checked_result(action, result):
    if result.returncode:
        raise RuntimeError(action + ': ' + result.stderr[-2400:])
    print('MN_OLD_FIXTURE_' + action.upper() + '=OK', flush=True)


def retire_roles(configs):
    expected = {b'root': configs[0], b'sdk': configs[1]}
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        handle = None
        try:
            args = (path / 'cmdline').read_bytes().split(b'\x00')
            if len(args) < 3 or args[1] not in expected or args[2] != os.fsencode(expected[args[1]]):
                continue
            handle = os.pidfd_open(int(path.name))
            need((path / 'exe').resolve(strict=True) == PROVIDER and
                 (path / 'cmdline').read_bytes().split(b'\x00')[:3] == args[:3], 'Fixture PID changed')
            signal.pidfd_send_signal(handle, signal.SIGTERM)
            waiter = select.poll()
            waiter.register(handle, select.POLLIN)
            need(waiter.poll(15000), 'Fixture role did not exit: ' + path.name)
        except (FileNotFoundError, ProcessLookupError):
            continue
        finally:
            if handle is not None:
                os.close(handle)


def retire_fixture(args, host, configs, old_sdk):
    owner = host == 'agent1'
    root = configs[0]
    if owner:
        checked_result('close', role_control('close', root))
        checked_result('drain', role_control('drain', root))
        journal = old_sdk / ('directory-' + args.old_run + '.json')
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            state = record_json(journal)
            need(state['run'] == args.old_run and state['closed'] is True and not state['faulted'],
                 'Fixture directory became uncertain')
            if set(state['drained']) == {'agent1', 'agent2'}:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Peer drain receipt not observed within 300 seconds')
        checked_result('finish', role_control('finish', root))
        need(record_json(journal)['released'] is True, 'Fixture owner release is not recorded')
    else:
        deadline = time.monotonic() + 240
        while True:
            drained = role_control('drain', root)
            if not drained.returncode or 'close coordinator admission after stopping' not in drained.stderr:
                break
            need(time.monotonic() < deadline, 'Owner did not close fixture admission in time')
            time.sleep(1)
        checked_result('drain', drained)
    retire_roles(configs)
    print(json.dumps({'status': 'MN_FIXTURE_RETIRED_LOCAL', 'node': host, 'oldRun': args.old_run,
                      'globalReleaseVerified': owner}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('run', 'old-run', 'template'):
        parser.add_argument('--' + key, required=True)
    parser.add_argument('--artifact', type=Path, required=True)
    for key in ('bundle-sha', 'manifest-sha', 'manifest-file-sha'):
        parser.add_argument('--' + key, required=True)
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    need(os.geteuid() == 0 and host in ('agent1', 'agent2'), 'Use the M/N root entry')
    need(re.fullmatch(r'[a-f0-9]{32}', args.run) and re.fullmatch(r'[a-f0-9]{32}', args.old_run)
         and args.run != args.old_run and str(uuid.UUID(args.template)) == args.template, 'Invalid generation IDs')
    need(PROVIDER.resolve(strict=True) == PROVIDER and file_sha(PROVIDER) == PROVIDER_SHA,
         'Existing Provider executable differs')
    need(args.artifact.is_absolute() and args.artifact.is_relative_to(Path('/root/aenv-pmem')),
         'Expected a private root staging artifact')
    need(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'Existing Python lacks PIDFD support')
    os.umask(0o077)
    configs, sdk_dir = stage(args, host)
    retire_fixture(args, host, configs, sdk_dir)
