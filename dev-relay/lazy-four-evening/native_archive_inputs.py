"""Private four-image input transfer and inactive-node seeding; no live DBs."""
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
D = ROOT / 'deployments/agentenv-native-archive-v1'
CORE = '32ce41c0ac6436198860f888e07ef9793e58dc40'
TREE = '0e973a6e101c1a1c71b48bf70f2d910f48cd672f'
GIB = 1024**3
LIMIT = 64 * GIB


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def safe(path, exists=True):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=exists) == path,
         'Unexpected or redirected input path')
    return path


def stamp(meta):
    return meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns


def opened(path, limit=8 * GIB):
    fd = os.open(safe(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204 and 0 < meta.st_size <= limit,
             'Unexpected source owner/type/length')
        return os.fdopen(fd, 'rb'), meta
    except BaseException:
        os.close(fd)
        raise


def read(path, limit=16 * 1024**2):
    stream, before = opened(path, limit)
    with stream:
        raw = stream.read(limit + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno())), 'Input changed')
    return raw


def consume(stream, size, destination=None):
    h = hashlib.sha256()
    left = size
    while left:
        part = stream.read(min(left, 1024**2))
        need(bool(part), 'Truncated source')
        h.update(part)
        if destination is not None:
            destination.write(part)
        left -= len(part)
    need(not stream.read(1), 'Source grew beyond bound')
    return h.hexdigest()


def file_identity(path):
    stream, before = opened(path)
    with stream:
        digest = consume(stream, before.st_size)
        need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Source changed while hashing')
    return {'bytes': before.st_size, 'sha256': digest}


def source_identity(layers):
    values = [{k: layer[k] for k in ('digest', 'size')} for layer in layers]
    return 'sha256:' + hashlib.sha256(json.dumps([0, values], separators=(',', ':')).encode()).hexdigest()


def validate_manifest(value):
    need(set(value) == {'version', 'coreCommit', 'coreTree', 'images', 'files'}
         and value['version'] == 1 and value['coreCommit'] == CORE and value['coreTree'] == TREE,
         'Four-source archive release differs')
    images, files = value['images'], value['files']
    need(isinstance(images, list) and len(images) == 4 and isinstance(files, dict) and 2 <= len(files) <= 16384,
         'Four-source manifest count differs')
    allowed = {'selection.private.json', 'historical-reference.private.json'}
    seen, seen_oci = set(), set()
    for index, image in enumerate(images):
        need(image['templateIndex'] == index and image['sourceImage'] == source_identity(image['layers'])
             and image['sourceImage'] not in seen and 0 < len(image['layers']) <= 256,
             'Four-source content/order differs')
        seen.add(image['sourceImage'])
        need(re.fullmatch(r'sha256:[0-9a-f]{64}', image['ociDigest']), 'Invalid OCI identity')
        need(image['ociDigest'] not in seen_oci, 'Four distinct OCI images required for this cohort')
        seen_oci.add(image['ociDigest'])
        allowed.add('images/' + str(index) + '/source-config.json')
        for layer in image['layers']:
            need(re.fullmatch(r'sha256:[0-9a-f]{64}', layer['digest']) and type(layer['size']) is int
                 and 0 < layer['size'] <= 8 * GIB, 'Invalid immutable layer')
            name = 'layers/' + layer['digest'][7:] + '.commit'
            allowed.add(name)
            need(files.get(name) == {'bytes': layer['size'], 'sha256': layer['digest'][7:]}, 'Layer identity differs')
        oci_files = image['ociFiles']
        need(isinstance(oci_files, list) and 2 < len(oci_files) <= 4096 and len(set(oci_files)) == len(oci_files),
             'OCI file inventory differs')
        for relative in oci_files:
            need(relative in ('index.json', 'oci-layout') or re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', relative),
                 'Unexpected OCI member')
            name = 'images/' + str(index) + '/oci/' + relative
            allowed.add(name)
            if relative.startswith('blobs/'):
                need(files.get(name, {}).get('sha256') == relative.rsplit('/', 1)[1], 'OCI blob digest differs')
        need('blobs/sha256/' + image['ociDigest'][7:] in oci_files, 'Selected OCI manifest absent')
    need(set(files) == allowed, 'Unexpected or missing archive member')
    total = 0
    for name, descriptor in files.items():
        path = PurePosixPath(name)
        need(not path.is_absolute() and '..' not in path.parts and set(descriptor) == {'bytes', 'sha256'}
             and type(descriptor['bytes']) is int and 0 < descriptor['bytes'] <= 8 * GIB
             and re.fullmatch('[0-9a-f]{64}', descriptor['sha256']), 'Invalid bounded archive descriptor')
        total += descriptor['bytes']
    need(total <= LIMIT, 'Private input archive exceeds 64GiB budget')
    return files, total


def validate_oci(directory, manifest):
    for image in manifest['images']:
        prefix = 'images/' + str(image['templateIndex']) + '/oci/'
        root = directory / prefix
        need(json.loads(read(root / 'oci-layout')) == {'imageLayoutVersion': '1.0.0'}, 'Unsupported OCI layout')
        need(json.loads(read(root / 'index.json')).get('schemaVersion') == 2, 'Unsupported OCI index')
        value = json.loads(read(root / 'blobs/sha256' / image['ociDigest'][7:], 4 * 1024**2))
        need(value.get('schemaVersion') == 2 and isinstance(value.get('layers'), list)
             and 0 < len(value['layers']) <= 256 and isinstance(value.get('config'), dict), 'Expected one complete OCI image manifest')
        for descriptor in [value['config'], *value['layers']]:
            need(re.fullmatch(r'sha256:[0-9a-f]{64}', descriptor.get('digest', ''))
                 and type(descriptor.get('size')) is int and descriptor['size'] > 0, 'Invalid OCI descriptor')
            name = prefix + 'blobs/sha256/' + descriptor['digest'][7:]
            need(manifest['files'].get(name) == {'bytes': descriptor['size'], 'sha256': descriptor['digest'][7:]},
                 'OCI config or layer is missing from the verified archive')
        config = json.loads(read(root / 'blobs/sha256' / value['config']['digest'][7:], 4 * 1024**2))
        need(config.get('architecture') == 'arm64' and config.get('os') == 'linux', 'Expected original Linux ARM64 OCI config')


def pack(report_path, archive_path):
    report = json.loads(read(report_path))
    need(report.get('status') == 'FOUR_NATIVE_IMAGES_AND_BINARIES_PREPARED_NOT_DEPLOYED'
         and report['coreCommit'] == CORE and report['coreTree'] == TREE, 'Successful four-image preparation required')
    inputs = {name: Path(report_path).parent / name for name in ('selection.private.json', 'historical-reference.private.json')}
    images = []
    for index, case in enumerate(report['cases']):
        need(case['templateIndex'] == index, 'Prepared image order differs')
        inputs['images/' + str(index) + '/source-config.json'] = Path(case['sourceConfig'])
        layers = [{k: layer[k] for k in ('digest', 'size')} for layer in case['layers']]
        for layer in case['layers']:
            name = 'layers/' + layer['digest'][7:] + '.commit'
            if name in inputs:
                need(file_identity(Path(layer['path'])) == {'bytes': layer['size'], 'sha256': layer['digest'][7:]},
                     'Repeated source layer differs')
            else:
                inputs[name] = Path(layer['path'])
        oci = safe(Path(case['ociDirectory']))
        paths = sorted(oci.rglob('*'))
        need(len(paths) <= 8192 and not any(p.is_symlink() for p in paths), 'Unexpected OCI tree')
        relative_files = []
        for path in paths:
            if path.is_dir():
                continue
            relative = path.relative_to(oci).as_posix()
            need(relative in ('index.json', 'oci-layout') or re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', relative),
                 'Unsupported OCI member')
            relative_files.append(relative)
            inputs['images/' + str(index) + '/oci/' + relative] = path
        images.append({'templateIndex': index, 'instanceId': case['instanceId'], 'sourceImage': case['sourceImage'],
                       'layers': layers, 'ociDigest': case['ociDigest'], 'ociFiles': relative_files,
                       'resources': case['resources'], 'replaySha256': case['replaySha256']})
    files = {name: file_identity(path) for name, path in inputs.items()}
    manifest = {'version': 1, 'coreCommit': CORE, 'coreTree': TREE, 'images': images, 'files': files}
    _, total = validate_manifest(manifest)
    need(shutil.disk_usage(ROOT).free >= total + 8 * GIB, 'Archive disk reserve insufficient')
    raw = json.dumps(manifest, sort_keys=True).encode()
    need(len(raw) <= 8 * 1024**2, 'Manifest exceeds bound')
    safe(archive_path.parent)
    with archive_path.open('xb') as output, tarfile.open(fileobj=output, mode='w') as archive:
        item = tarfile.TarInfo('manifest.json')
        item.size, item.mode = len(raw), 0o600
        archive.addfile(item, io.BytesIO(raw))
        for name, path in inputs.items():
            stream, before = opened(path)
            with stream:
                need(before.st_size == files[name]['bytes'], 'Source length changed')
                item = tarfile.TarInfo(name)
                item.size, item.mode = before.st_size, 0o600
                archive.addfile(item, stream)
                need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Source changed during archive creation')
    return {'status': 'FOUR_SOURCE_PRIVATE_ARCHIVE_PREPARED', 'archive': str(archive_path),
            'payloadBytes': total, 'sourceImages': [i['sourceImage'] for i in images],
            'SDK_called': False, 'Guest_created': False}


def receive(archive_path, pin, destination):
    safe(destination.parent)
    need(not destination.exists() and not destination.is_symlink(), 'Existing received input preserved')
    stream, before = opened(archive_path, LIMIT + 128 * 1024**2)
    with stream:
        need(consume(stream, before.st_size) == pin, 'Private archive SHA differs')
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:') as archive:
            entries = archive.getmembers()
            need(len(entries) <= 16385 and all(e.isfile() and not e.issparse() for e in entries), 'Unexpected archive member type')
            by_name = {e.name: e for e in entries}
            need(len(by_name) == len(entries) and 'manifest.json' in by_name and by_name['manifest.json'].size <= 8 * 1024**2,
                 'Duplicate or missing manifest')
            manifest = json.load(archive.extractfile(by_name['manifest.json']))
            files, total = validate_manifest(manifest)
            need(set(by_name) == set(files) | {'manifest.json'}, 'Archive inventory differs')
            need(shutil.disk_usage(ROOT).free >= total + 8 * GIB, 'Receive disk reserve insufficient')
            destination.mkdir(mode=0o700)
            for name, descriptor in files.items():
                item = by_name[name]
                need(item.size == descriptor['bytes'], 'Archive member length differs')
                path = destination.joinpath(*PurePosixPath(name).parts)
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.extractfile(item) as source, path.open('xb') as target:
                    need(consume(source, item.size, target) == descriptor['sha256'], 'Archive member content differs')
                    target.flush()
                    os.fsync(target.fileno())
            need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Archive changed during receive')
    with (destination / 'manifest.json').open('x') as output:
        json.dump(manifest, output, indent=2)
    validate_oci(destination, manifest)
    return {'status': 'FOUR_SOURCE_INPUTS_RECEIVED_NOT_SEEDED', 'inputDirectory': str(destination), 'archiveSha256': pin}


def unit_absent(node):
    result = subprocess.run(['/usr/bin/systemctl', 'show', 'jwk-aenv-native-archive-v1-' + node + '.service',
                             '--property=LoadState', '--value'], capture_output=True, text=True, timeout=10, check=True)
    need(result.stdout.strip() == 'not-found', 'Do not seed a started Runtime')


def seed(directory, node):
    import fcntl
    import tomllib
    directory = safe(directory)
    installation = json.loads(read(D / 'installation.json'))
    need(installation['node'] == node and installation['commit'] == '5e6621c9c9d2e347959a61a46c7f6d99688eeb55', 'Prepared Runtime provenance differs')
    definition = json.loads(read(D / 'definition-native.json'))
    text = read(D / 'config/runtime.toml').decode()
    config = tomllib.loads(text)
    need(definition['config'] == text and config['home_path'] == str(D / 'state')
         and config['image']['cache']['gc']['enabled'] is False and 'root_dir' not in config['image']['cache'],
         'Unexpected Runtime cache configuration')
    lock = os.open(D / 'cohort.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        unit_absent(node)
        need(json.loads(read(D / 'cohort-state.json')) ==
             {'version': 1, 'phase': 'prepared', 'openRequests': [], 'sandboxIds': [], 'outcomeUncertain': False},
             'Initial untouched Runtime required')
        manifest = json.loads(read(directory / 'manifest.json'))
        files, _ = validate_manifest(manifest)
        validate_oci(directory, manifest)
        cache, temporary = D / 'state/image-cache', D / 'state/image-cache-four.partial'
        need(not cache.exists() and not cache.is_symlink() and not temporary.exists() and not temporary.is_symlink(),
             'Prior cache or partial seed preserved')
        layer_names = [name for name in files if name.startswith('layers/')]
        need(shutil.disk_usage(D).free >= sum(files[n]['bytes'] for n in layer_names) + 8 * GIB, 'Seed reserve insufficient')
        temporary.mkdir(mode=0o700)
        (temporary / 'configs').mkdir(mode=0o700)
        (temporary / 'commits').mkdir(mode=0o700)
        for name, descriptor in files.items():
            if not name.startswith('layers/'):
                need(file_identity(directory / name) == descriptor, 'Received metadata/OCI input changed')
        for name in layer_names:
            descriptor = files[name]
            target = temporary / 'commits' / ('sha256-' + descriptor['sha256']) / 'overlaybd.commit'
            target.parent.mkdir(mode=0o700)
            stream, before = opened(directory / name)
            with stream, target.open('xb') as output:
                need(before.st_size == descriptor['bytes'] and consume(stream, before.st_size, output) == descriptor['sha256'],
                     'Received immutable layer changed')
                need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Received layer changed during copy')
                output.flush(); os.fsync(output.fileno())
        images = []
        for image in manifest['images']:
            index = image['templateIndex']
            original = json.loads(read(directory / 'images' / str(index) / 'source-config.json'))
            need(source_identity(original['lowers']) == image['sourceImage'], 'Source config identity differs')
            lowers = []
            for layer, original_layer in zip(image['layers'], original['lowers']):
                row = {'file': str(cache / 'commits' / layer['digest'].replace(':', '-') / 'overlaybd.commit'),
                       'digest': layer['digest'], 'size': layer['size']}
                if original_layer.get('uuid'):
                    row['uuid'] = original_layer['uuid']
                lowers.append(row)
            raw = (json.dumps({'lowers': lowers, 'upper': {}, 'repoBlobUrl': ''}, indent=2) + '\n').encode()
            name = image['ociDigest'].replace(':', '-') + '-image.json'
            with (temporary / 'configs' / name).open('xb') as output:
                output.write(raw); output.flush(); os.fsync(output.fileno())
            images.append({**image, 'sourceConfig': str(cache / 'configs' / name), 'sourceConfigSha256': hashlib.sha256(raw).hexdigest(),
                           'ociReference': 'ocidir://' + str(directory / 'images' / str(index) / 'oci') + '@' + image['ociDigest']})
        unit_absent(node)
        os.rename(temporary, cache)
        receipt = {'status': 'FOUR_ROOTFS_INPUTS_SEEDED_NOT_GUEST_ACCEPTANCE', 'node': node, 'coreCommit': CORE,
                   'coreTree': TREE, 'runtimeCoreCommit': installation['commit'], 'images': images, 'inputDirectory': str(directory),
                   'databaseCopied': False, 'SDK_called': False, 'Guest_created': False, 'coldCacheClaimed': False}
        with (D / 'rootfs-inputs.json').open('x') as output:
            json.dump(receipt, output, indent=2); output.flush(); os.fsync(output.fileno())
        return receipt
    finally:
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('pack', 'receive', 'seed'))
    parser.add_argument('--report', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--node', choices=('node-a', 'node-b'))
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'status': 'PLAN_ONLY', 'mode': args.mode})); return
    need(os.name == 'posix' and os.getuid() == os.geteuid() == 1204, 'Use ordinary experiment user')
    os.umask(0o077)
    if args.mode == 'pack':
        need(args.report and args.archive, 'Pack inputs missing')
        result = pack(args.report, args.archive)
    elif args.mode == 'receive':
        need(args.archive and args.directory and re.fullmatch('[0-9a-f]{64}', args.sha256 or ''), 'Receive inputs missing')
        result = receive(args.archive, args.sha256, args.directory)
    else:
        need(args.directory and args.node, 'Seed inputs missing')
        result = seed(args.directory, args.node)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
