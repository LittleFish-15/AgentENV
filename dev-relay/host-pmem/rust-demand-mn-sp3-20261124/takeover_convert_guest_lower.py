"""Convert the existing pinned OCI layers on M using the native OverlayBD tools."""

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import uuid
from pathlib import Path


BASE = Path('/home/jwk/agent/sp3-mn/relay-guest-assets-001')
OCI = BASE / 'benchmark-oci'
TOOLS = BASE / 'deps/overlaybd/bin'
GLOBAL = BASE / 'home/overlaybd/convert-overlaybd-global.json'
WORK = BASE / 'benchmark-native-lower-001'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(BASE / 'home'),
       'TMPDIR': str(BASE / 'tmp'), 'LANG': 'C', 'LC_ALL': 'C'}
GZIP = 'application/vnd.docker.image.rootfs.diff.tar.gzip'


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def sha(path):
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def local_blob(root, digest, expected_size=None):
    need(isinstance(digest, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', digest), 'Invalid OCI digest')
    path = root / 'blobs' / 'sha256' / digest[7:]
    info = path.lstat()
    need(path.resolve() == path and stat.S_ISREG(info.st_mode) and info.st_uid == 1204 and
         (expected_size is None or info.st_size == expected_size), 'OCI blob metadata differs: ' + digest)
    need('sha256:' + sha(path) == digest, 'OCI blob digest differs: ' + digest)
    return path


def local_inputs(manifest_digest):
    manifest = json.loads(local_blob(OCI, manifest_digest).read_bytes())
    config = manifest['config']
    params = json.loads(local_blob(OCI, config['digest'], config['size']).read_bytes())
    need(params['os'] == 'linux' and params['architecture'] == 'arm64', 'Expected ARM64 Linux OCI config')
    layers = manifest['layers']
    need(len(layers) == 9 and sum(item['size'] for item in layers) == 348128260 and
         all(item['mediaType'] == GZIP for item in layers), 'Reviewed Titanic layer descriptors differ')
    inputs = [(layer, local_blob(OCI, layer['digest'], layer['size'])) for layer in layers]
    return inputs


def layer_uuid(source_digest):
    raw = bytearray(hashlib.sha256(source_digest.encode()).digest()[:16])
    raw[6] = (raw[6] & 0x0f) | 0x80
    raw[8] = (raw[8] & 0x3f) | 0x80
    return uuid.UUID(bytes=bytes(raw))


def write_json(path, value):
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def invoke(step, argv, folder):
    path = folder / (step + '.log')
    with path.open('xb') as output:
        result = subprocess.run([str(x) for x in argv], cwd=folder, env=ENV, stdin=subprocess.DEVNULL,
                                stdout=output, stderr=subprocess.STDOUT, timeout=900, check=False)
    if result.returncode:
        with path.open('rb') as stream:
            stream.seek(max(0, path.stat().st_size - 4096))
            print(stream.read(4096).decode('utf-8', 'replace'), flush=True)
        raise RuntimeError(f'{step} failed in {folder.name}: exit {result.returncode}')


def convert(inputs, manifest_digest):
    WORK.mkdir(mode=0o700)
    ordered = []
    parent = None
    for number, (layer, source) in enumerate(inputs):
        folder = WORK / f'layer-{number:02d}'
        folder.mkdir(mode=0o700)
        upper, index, config = folder / 'upper.data', folder / 'upper.index', folder / 'image.json'
        commit = folder / 'overlaybd.commit'
        identity = layer_uuid(layer['digest'])
        print(f'MN_TITANIC_CONVERT_LAYER={number + 1}/{len(inputs)}', flush=True)
        invoke('create', [TOOLS / 'overlaybd-create', upper, index, '64'], folder)
        write_json(config, {'lowers': [{'file': layer['file']} for layer in ordered],
                            'upper': {'data': str(upper), 'index': str(index)},
                            'resultFile': str(folder / 'result.txt')})
        apply = [TOOLS / 'overlaybd-apply', '--service_config_path=' + str(GLOBAL)]
        if number == 0:
            apply.append('--mkfs')
        invoke('apply', [*apply, source, config], folder)
        command = [TOOLS / 'overlaybd-commit', '--uuid', identity]
        if parent is not None:
            command += ['--parent-uuid', parent]
        invoke('commit', [*command, upper, index, commit], folder)
        need(commit.is_file() and commit.stat().st_size > 0, 'Native commit output missing')
        row = {'sourceDigest': layer['digest'], 'digest': 'sha256:' + sha(commit),
               'file': str(commit), 'bytes': commit.stat().st_size, 'uuid': str(identity),
               'parentUuid': str(parent) if parent is not None else None}
        write_json(folder / 'complete.json', row)
        ordered.append(row)
        parent = identity
    result = {'status': 'MN_TITANIC_COMMITTED_LOWERS_READY', 'ociManifestDigest': manifest_digest,
              'storedLowerBytes': sum(row['bytes'] for row in ordered), 'rootfsLowers': ordered}
    write_json(WORK / 'committed-lowers.json', result)
    print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oci-digest', required=True)
    args = parser.parse_args()
    need(os.geteuid() == 0 and os.uname().nodename.split('.')[0] == 'agent1', 'Use the M root entry')
    os.umask(0o077)
    libc = ctypes.CDLL(None, use_errno=True)
    need(libc.prctl(38, 1, 0, 0, 0) == 0, 'Set no_new_privs failed')
    os.setgroups([])
    os.setgid(1205)
    os.setuid(1204)
    status = Path('/proc/self/status').read_text()
    for cap in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'):
        need(re.search(r'^' + cap + r':\s+0+$', status, re.M), 'Conversion process retained capabilities')
    need(BASE.resolve(strict=True) == BASE and os.access(GLOBAL, os.R_OK)
         and os.access('/etc/overlaybd/overlaybd.json', os.R_OK), 'Existing local OverlayBD configuration unavailable')
    need(shutil.disk_usage(BASE).free >= 6 * 1024**3, 'Need room for private layer commit artifacts')
    print(json.dumps({'uid': os.geteuid(), 'runInput': args.oci_digest}), flush=True)
    convert(local_inputs(args.oci_digest), args.oci_digest)


if __name__ == '__main__':
    main()
