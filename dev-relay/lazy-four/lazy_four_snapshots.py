"""Copy exactly four committed snapshots to an independent inactive repository.

All committed rootfs layers (including capture tails) and ordinary memory layers
are retained. No live database, source hardlink, Guest or original service mutation.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

ROOT = Path('/home/jwk/agent')
D = ROOT / 'deployments/agentenv-lazy-four-32ce41c'
LIMIT = 64 * 1024**3


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def layer_name(layer):
    need(set(layer) >= {'digest', 'size'} and re.fullmatch(r'sha256:[0-9a-f]{64}', layer['digest'])
         and type(layer['size']) is int and 0 < layer['size'] <= 8 * 1024**3, 'Invalid managed layer')
    return 'managed-layers/' + layer['digest'].replace(':', '_') + '.overlaybd.commit'


def snapshot_contract(record, manifest):
    sid = record['id']
    need(re.fullmatch('[0-9a-f-]{36}', sid) and record['resources']['memory_mib'] == 4096
         and record['resources']['cpu_count'] == 2, 'Wrong snapshot resources')
    c = record['committed']
    need(c.get('runtime_versions',{}).get('tools_drive_version')=='0.1.1',
         'Selected ordinary snapshots must retain the existing 0.1.1 tools disk')
    need(not any(c.get(k) for k in ('attached_drives', 'volume_snapshots', 'memory_startup')),
         'Additional snapshot dependency requires explicit support')
    need(not manifest.get('nativeRootfs') and manifest['memory']['virtualSize'] == 4096 * 1024**2
         and not manifest.get('attachedDrives'), 'Expected ordinary four-GiB snapshot')
    need(0 < len(c['rootfs_layers']) <= 64 and 0 < len(c['memory_layers']) <= 16, 'Unexpected layer count')
    roots = []
    for row in c['rootfs_layers']:
        need(isinstance(row, dict) and set(row) == {'Managed'}, 'Only local committed managed rootfs supported')
        roots.append(row['Managed'])
    files = {}
    for row in [*roots, *c['memory_layers']]:
        name = layer_name(row)
        desc = {'bytes': row['size'], 'sha256': row['digest'][7:]}
        need(name not in files or files[name] == desc, 'Conflicting layer identity')
        files[name] = desc
    return files, roots


def safe(path):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True) == path,
         'Unexpected or redirected private input')
    return path


def opened(path, limit=8 * 1024**3):
    fd = os.open(safe(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(fd, 'rb')
    m = os.fstat(fd)
    if not (stat.S_ISREG(m.st_mode) and m.st_uid == 1204 and 0 < m.st_size <= limit):
        stream.close(); raise RuntimeError('Invalid owned immutable input')
    return stream, m


def stamp(m):
    return m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns


def consume(stream, length, target=None):
    h = hashlib.sha256()
    left = length
    while left:
        raw = stream.read(min(left, 1024**2)); need(raw, 'Truncated private input')
        h.update(raw); left -= len(raw)
        if target is not None:
            target.write(raw)
    need(not stream.read(1), 'Private input grew')
    return h.hexdigest()


def read(path):
    stream, before = opened(path, 16 * 1024**2)
    with stream:
        raw = stream.read()
        need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Metadata changed')
        return raw


def descriptor(path):
    stream, before = opened(path)
    with stream:
        digest = consume(stream, before.st_size)
        need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Input changed while hashing')
        return {'bytes': before.st_size, 'sha256': digest}


def inventory(repository, selected):
    need(len(selected) == 4, 'Exactly four templates required')
    files, templates = {}, []
    for index, case in enumerate(selected):
        original = case['original']; sid = original['template_id']
        need(re.fullmatch('[0-9a-f-]{36}', sid), 'Invalid selected template')
        record_path = 'catalog/records/' + sid + '.json'
        raw = read(repository / record_path)
        need(hashlib.sha256(raw).hexdigest() == original['catalog_sha256'], 'Historical snapshot changed')
        record = json.loads(raw)
        manifest_path = 'snapshots/' + sid + '/firecracker-manifest.json'
        layers, roots = snapshot_contract(record, json.loads(read(repository / manifest_path)))
        need(record['id'] == sid and read(repository / 'snapshots' / sid / 'commit') == b'committed', 'Snapshot not committed')
        for name, desc in layers.items():
            need(name not in files or files[name] == desc, 'Conflicting shared immutable layer')
            files[name] = desc
        for name in (record_path, manifest_path, 'snapshots/' + sid + '/vm_state.bin', 'snapshots/' + sid + '/commit'):
            files[name] = descriptor(repository / name)
        templates.append({'templateIndex': index, 'templateId': sid, 'catalogSha256': original['catalog_sha256'],
                          'instanceId': case['case']['instance_id'], 'replaySha256': case['case']['replay_sha256'],
                          'resources': original['resources'], 'rootfsLayers': roots})
    need(len({t['templateId'] for t in templates}) == 4, 'Repeated template')
    return files, templates


def valid_manifest(value):
    need(set(value) == {'version', 'kind', 'templates', 'files'} and value['version'] == 1
         and value['kind'] == 'ordinary-four-snapshots' and len(value['templates']) == 4, 'Invalid snapshot archive')
    expected = {'selection.private.json', 'historical-reference.private.json'}
    root_layers = set()
    for index, t in enumerate(value['templates']):
        need(t['templateIndex'] == index and re.fullmatch('[0-9a-f-]{36}', t['templateId']), 'Template identity differs')
        sid = t['templateId']
        expected.update(('catalog/records/' + sid + '.json',))
        expected.update('snapshots/' + sid + '/' + name for name in ('commit', 'vm_state.bin', 'firecracker-manifest.json'))
        root_layers.update(layer_name(layer) for layer in t['rootfsLayers'])
    files = value['files']
    need(len(files) <= 512 and expected | root_layers <= set(files), 'Missing required snapshot files')
    for name, desc in files.items():
        need(name in expected or re.fullmatch(r'managed-layers/sha256_[0-9a-f]{64}\.overlaybd\.commit', name),
             'Unexpected archive path')
        need(set(desc) == {'bytes', 'sha256'} and type(desc['bytes']) is int and 0 < desc['bytes'] <= 8 * 1024**3
             and re.fullmatch('[0-9a-f]{64}', desc['sha256']), 'Invalid archive descriptor')
    need(sum(d['bytes'] for d in files.values()) <= LIMIT, 'Snapshot archive exceeds capacity budget')
    return files


def pack(repository, selection, history, archive):
    selected = json.loads(read(selection))['selected']
    files, templates = inventory(repository, selected)
    files['selection.private.json'] = descriptor(selection)
    files['historical-reference.private.json'] = descriptor(history)
    value = {'version': 1, 'kind': 'ordinary-four-snapshots', 'templates': templates, 'files': files}
    valid_manifest(value)
    need(shutil.disk_usage(ROOT).free >= sum(x['bytes'] for x in files.values()) + 8 * 1024**3, 'Archive disk reserve insufficient')
    safe(archive.parent)
    with archive.open('xb') as output, tarfile.open(fileobj=output, mode='w') as tar:
        raw = json.dumps(value, sort_keys=True).encode()
        item = tarfile.TarInfo('manifest.json'); item.size = len(raw); tar.addfile(item, io.BytesIO(raw))
        for name, desc in files.items():
            path = selection if name == 'selection.private.json' else history if name == 'historical-reference.private.json' else repository / name
            stream, before = opened(path)
            with stream:
                need(before.st_size == desc['bytes'] and consume(stream, before.st_size) == desc['sha256'], 'Snapshot input changed')
                stream.seek(0)
                item = tarfile.TarInfo(name); item.size = before.st_size; item.mode = 0o600
                tar.addfile(item, stream)
                need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Snapshot input changed during copy')
    return value


def receive(archive, pin, target):
    safe(target.parent)
    need(not target.exists() and not target.is_symlink(), 'Existing received snapshot preserved')
    stream, before = opened(archive, LIMIT + 1024**2)
    with stream:
        need(consume(stream, before.st_size) == pin, 'Private archive checksum differs')
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:') as tar:
            members = tar.getmembers()
            need(len(members) <= 513 and all(x.isfile() and not x.issparse() for x in members), 'Unexpected archive member type')
            indexed = {x.name: x for x in members}
            need(len(indexed) == len(members) and 'manifest.json' in indexed and indexed['manifest.json'].size <= 1024**2,
                 'Missing or duplicate archive metadata')
            manifest = json.load(tar.extractfile(indexed['manifest.json']))
            files = valid_manifest(manifest)
            need(set(indexed) == set(files) | {'manifest.json'}, 'Archive member inventory differs')
            need(shutil.disk_usage(ROOT).free >= sum(x['bytes'] for x in files.values()) + 8 * 1024**3, 'Receive disk reserve insufficient')
            target.mkdir(mode=0o700)
            for name, desc in files.items():
                item = indexed[name]; need(item.size == desc['bytes'], 'Member length differs')
                path = target.joinpath(*PurePosixPath(name).parts)
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with tar.extractfile(item) as source, path.open('xb') as output:
                    need(consume(source, item.size, output) == desc['sha256'], 'Snapshot member checksum differs')
                    output.flush(); os.fsync(output.fileno())
        need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Archive changed during receive')
    expected_files = {'selection.private.json', 'historical-reference.private.json'}
    for t in manifest['templates']:
        sid = t['templateId']
        record = json.loads(read(target / 'catalog/records' / (sid + '.json')))
        layers, roots = snapshot_contract(record, json.loads(read(target / 'snapshots' / sid / 'firecracker-manifest.json')))
        need(record['id'] == sid and roots == t['rootfsLayers'] and all(files[name] == desc for name, desc in layers.items())
             and files['catalog/records/' + sid + '.json']['sha256'] == t['catalogSha256']
             and read(target / 'snapshots' / sid / 'commit') == b'committed', 'Snapshot dependency differs')
        expected_files.update(layers)
        expected_files.add('catalog/records/' + sid + '.json')
        expected_files.update('snapshots/' + sid + '/' + name for name in ('commit', 'vm_state.bin', 'firecracker-manifest.json'))
    need(set(files) == expected_files, 'Unreferenced managed payload refused')
    with (target / 'manifest.json').open('x') as output:
        json.dump(manifest, output, indent=2)
    return manifest


def seed(received, node):
    import fcntl
    definition = json.loads(read(D / 'definition-native.json'))
    need(definition['node'] == node and definition.get('rootfsBinding') is None, 'Ordinary isolated Runtime required')
    lock = os.open(D / 'cohort.lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        unit = 'jwk-aenv-lazy-four-32ce41c-' + node + '.service'
        need(subprocess.check_output(['/usr/bin/systemctl', 'show', unit, '--property=LoadState', '--value'], text=True).strip() == 'not-found',
             'Seed only before the new Runtime starts')
        manifest = json.loads(read(received / 'manifest.json')); files = valid_manifest(manifest)
        target = D / 'state/snapshot-store/repository'
        need(not target.exists() and not target.is_symlink(), 'Previous repository preserved')
        target.mkdir(parents=True, mode=0o700)
        # Commit marker and record last. No running service can observe a partial import.
        names = sorted((n for n in files if n not in ('selection.private.json', 'historical-reference.private.json')),
                       key=lambda n: (n.startswith('catalog/records/'), n.endswith('/commit'), n))
        for name in names:
            path = target / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            stream, before = opened(received / name)
            with stream, path.open('xb') as output:
                need(before.st_size == files[name]['bytes'] and consume(stream, before.st_size, output) == files[name]['sha256'],
                     'Received snapshot changed')
                need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Source changed during seeding')
                output.flush(); os.fsync(output.fileno())
            need((before.st_dev, before.st_ino) != (path.stat().st_dev, path.stat().st_ino), 'Source hardlink refused')
        receipt = {'status': 'ORDINARY_FOUR_SNAPSHOTS_SEEDED_NOT_GUEST_ACCEPTANCE', 'node': node,
                   'repository': str(target), 'inputDirectory': str(received), 'templates': manifest['templates'],
                   'sourceManifestSha256': hashlib.sha256(read(received / 'manifest.json')).hexdigest(),
                   'coldCacheClaimed': False, 'SDK_called': False}
        with (D / 'rootfs-inputs.json').open('x') as output:
            json.dump(receipt, output, indent=2)
        return receipt
    finally:
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('pack', 'receive', 'seed'))
    for name in ('repository', 'selection', 'history', 'archive', 'directory'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--node', choices=('node-a', 'node-b'))
    parser.add_argument('--run', action='store_true')
    a = parser.parse_args()
    if not a.run:
        print('PLAN_ONLY_NO_WRITES'); return
    need(os.name == 'posix' and os.getuid() == os.geteuid() == 1204, 'Use ordinary jwk')
    os.umask(0o077)
    if a.mode == 'pack':
        result = pack(a.repository, a.selection, a.history, a.archive)
        print(json.dumps({'status': 'ORDINARY_FOUR_PRIVATE_ARCHIVE_READY', 'templateCount': len(result['templates'])}))
    elif a.mode == 'receive':
        result = receive(a.archive, a.sha256, a.directory)
        print(json.dumps({'status': 'ORDINARY_FOUR_PRIVATE_ARCHIVE_RECEIVED', 'templateCount': len(result['templates'])}))
    else:
        print(json.dumps(seed(a.directory, a.node)))


if __name__ == '__main__':
    main()
