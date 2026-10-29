"""Inventory retained A/B files only; no SDK, Guest, service or source-file changes."""
import base64
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import tomllib
from pathlib import Path

ROOT = Path('/home/jwk/agent')
TEMPLATE = '01a15c9e-54d0-7b92-a50b-0b6ec2e9136b'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def safe(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'Invalid source path')
    real = path.resolve(strict=True)
    need(real.is_relative_to(ROOT), 'Source escapes workspace')
    return real


def read(path, limit=2 * 1024**2):
    real = safe(path)
    fd = os.open(real, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'Invalid metadata type/size')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    need(len(raw) <= limit and (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Metadata changed')
    return raw


def info(path, digest=False):
    result = {'path': str(path), 'present': False, 'contentHashed': False}
    try:
        real = safe(path)
        fd = os.open(real, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as stream:
            a = os.fstat(stream.fileno())
            need(stat.S_ISREG(a.st_mode), 'Not a regular file')
            result.update(present=True, resolved=str(real), bytes=a.st_size, uid=a.st_uid, gid=a.st_gid)
            if digest:
                need(a.st_size <= 128 * 1024**2, 'Inventory hash bound exceeded')
                h = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024**2), b''):
                    h.update(chunk)
                result.update(sha256=h.hexdigest(), contentHashed=True)
            b = os.fstat(stream.fileno())
            need((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) ==
                 (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns), 'File changed')
    except (OSError, ValueError) as error:
        result.update(error=type(error).__name__ + ': ' + str(error), contentHashed=False)
    return result


def runtime(name):
    base = ROOT / 'deployments' / name
    result = {'base': str(base), 'binaries': {n: info(base / 'bin' / n, True)
              for n in ('server', 'uvm-ublk-daemon', 'aenv')}}
    result['retainedTemplateCatalog'] = info(
        base / 'state/snapshot-store/repository/catalog/records' / (TEMPLATE + '.json'), True)
    result['cliFiles'] = [info(base / relative, True) for relative in ('cli/bin/aenv', 'cli/bin/aenv-native')]
    path = base / 'config/runtime.toml'
    result['config'] = info(path, True)
    try:
        config = tomllib.loads(read(path).decode('utf-8'))
        result['firecracker'] = info(config['firecracker']['binary_path'], True)
        deps = safe(config['deps_path'])
        result['depsPath'] = str(deps)
        entries = []
        truncated = False
        for directory, dirs, files in os.walk(deps, followlinks=False):
            dirs.sort()
            files.sort()
            if len(Path(directory).relative_to(deps).parts) >= 4:
                truncated = truncated or bool(dirs)
                dirs[:] = []
            for filename in files:
                if len(entries) >= 256:
                    truncated = True
                    break
                entries.append(info(Path(directory) / filename))
            if len(entries) >= 256:
                truncated = True
                break
        result['dependencyFiles'] = entries
        result['dependencyListingTruncated'] = truncated
        result['depsClosureVerified'] = False
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['configErrorType'] = type(error).__name__
    return result


def replay_inventory(seed, selected):
    directory = safe(seed['inputDirectory'])
    manifest_path = directory / 'manifest.json'
    raw = read(manifest_path)
    need(hashlib.sha256(raw).hexdigest() == seed['sourceManifestSha256'], 'Input manifest changed')
    manifest = json.loads(raw)
    selection_path = directory / 'selection.private.json'
    raw = read(selection_path, 8 * 1024**2)
    need(hashlib.sha256(raw).hexdigest() == manifest['files']['selection.private.json']['sha256'], 'Private selection changed')
    matches = [case for case in json.loads(raw)['selected']
               if case.get('original', {}).get('template_id') == TEMPLATE]
    need(len(matches) == 1, 'Replay template not uniquely found')
    case = matches[0]
    need(case['case']['instance_id'] == selected['instanceId'] and
         case['case']['replay_sha256'] == selected['replaySha256'], 'Replay identity differs')
    payload = base64.b64decode(case['replayBase64'], validate=True)
    need(len(payload) <= 8 * 1024**2 and hashlib.sha256(payload).hexdigest() == selected['replaySha256'],
         'Replay content identity differs')
    return {'manifest': info(manifest_path, True), 'selection': info(selection_path, True),
            'selectedReplaySha256': selected['replaySha256'], 'replayBytes': len(payload),
            'declaredExecutedStepCount': case['executedStepCount'],
            'privateWorkloadContentsPrinted': False, 'replayIdentityVerified': True,
            'replayExecuted': False}


def snapshot():
    seed_path = ROOT / 'deployments/agentenv-lazy-four-32ce41c/rootfs-inputs.json'
    seed = json.loads(read(seed_path))
    selected = [t for t in seed['templates'] if t.get('templateId') == TEMPLATE]
    need(len(selected) == 1, 'Template not uniquely found')
    selected = selected[0]
    repo = safe(seed['repository'])
    record_path = repo / 'catalog/records' / (TEMPLATE + '.json')
    raw = read(record_path)
    need(hashlib.sha256(raw).hexdigest() == selected['catalogSha256'], 'Catalog hash changed')
    record = json.loads(raw)
    need(record.get('id') == TEMPLATE and isinstance(record.get('committed'), dict), 'Uncommitted or mismatched snapshot')
    committed = record['committed']
    groups = {}
    for kind in ('rootfs_layers', 'memory_layers'):
        refs = committed[kind]
        need(isinstance(refs, list), 'Invalid layer list')
        groups[kind] = []
        for layer in refs:
            if kind == 'rootfs_layers':
                need(isinstance(layer, dict) and set(layer) == {'Managed'}, 'External layer needs separate review')
                layer = layer['Managed']
            digest, size = layer['digest'], layer['size']
            need(re.fullmatch('sha256:[0-9a-f]{64}', digest) and type(size) is int and size > 0, 'Invalid layer identity')
            groups[kind].append({'digest': digest, 'declaredBytes': size,
                'file': info(repo / 'managed-layers' / (digest.replace(':', '_') + '.overlaybd.commit'))})
    need(sorted((x['digest'], x['declaredBytes']) for x in groups['rootfs_layers']) ==
         sorted((x['digest'], x['size']) for x in selected['rootfsLayers']), 'Seed and catalog rootfs differ')
    result = {'templateId': TEMPLATE, 'seed': info(seed_path, True), 'catalog': info(record_path, True),
              'repository': str(repo), 'layers': groups,
              'artifacts': {n: info(repo / 'snapshots' / TEMPLATE / n, True)
                  for n in ('commit', 'firecracker-manifest.json', 'vm_state.bin')},
              'runtimeVersions': committed.get('runtime_versions'),
              'attachedDriveCount': len(committed.get('attached_drives', [])),
              'volumeSnapshotCount': len(committed.get('volume_snapshots', [])),
              'payloadContentHashesVerified': False, 'fullRecoveryClosureVerified': False}
    try:
        result['replay'] = replay_inventory(seed, selected)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['replay'] = {'errorType': type(error).__name__, 'replayIdentityVerified': False}
    return result


def main():
    need(platform.system() == 'Linux' and platform.node() in ('server1', 'agent1'), 'Run only on source A/server1 or B/agent1')
    need(os.getuid() == os.geteuid() == 1204, 'Run as ordinary jwk UID1204')
    need(ROOT.resolve(strict=True) == ROOT, 'Source workspace redirected')
    node = 'a' if platform.node() == 'server1' else 'b'
    result = {'status': 'AB_RETAINED_FILES_INVENTORIED_NO_TRANSFER', 'node': node,
        'hostname': platform.node(), 'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'architecture': platform.machine(), 'kernel': platform.release(), 'python': platform.python_version(),
        'SDK_called': False, 'Guest_created': False, 'servicesChanged': False, 'moduleChanged': False,
        'runtimes': [runtime(n) for n in ('agentenv-ae9c626-baseline', 'agentenv-direct-ub-deletefix-v1')]}
    try:
        result['snapshot'] = snapshot()
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['snapshot'] = {'error': type(error).__name__ + ': ' + str(error), 'fullRecoveryClosureVerified': False}
    result['additional'] = [info(ROOT / p, True) for p in (
        'r/lazy4-' + node + '-v1/libaenv-ub.so', 'r/hpmem-' + node + '-v1/obmm.ko',
        'r/hpd4-' + node + '-v1/uvm-ublk-daemon-original-observer', 'r/hpd4-' + node + '-v1/prepared.json')]
    if node == 'a':
        result['additional'].extend(info(ROOT / p, True) for p in (
            'ub-host-pmem-build-2c1768644257/kernel-obmm/obmm.ko',
            'relay/reports/node-a-rootfs-access-build-abcks95d/candidate/uvm-ublk-daemon-observe'))
    result['rootfsContainer'] = info(ROOT / ('r/hpd4-' + node + '-v1/rootfs-lowers.ext4'))
    try:
        prepared = json.loads(read(ROOT / ('r/hpd4-' + node + '-v1/prepared.json')))
        image = prepared.get('image')
        result['historicalPreparedContainer'] = ({k: image.get(k) for k in ('path', 'bytes', 'sha256')}
                                                 if isinstance(image, dict) else None)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['preparedRecordErrorType'] = type(error).__name__
    print('BEGIN_AB_CD_INVENTORY')
    print(json.dumps(result, indent=2))
    print('END_AB_CD_INVENTORY')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'AB_INVENTORY_STOPPED_NO_MUTATIONS', 'error': type(error).__name__ + ': ' + str(error)}))
        raise SystemExit(1)
