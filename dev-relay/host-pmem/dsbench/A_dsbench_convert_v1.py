"""P2: run the existing native OverlayBD converter on two prepared OCI images.

Same create/apply/commit contract as storage/overlaybd/src/tools/oci.rs.
Only private regular files; no mount, SDK, Guest, service or package installation.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import time
import uuid

ROOT = Path('/home/jwk/agent/dsbench-20261031')
BASE = Path('/home/jwk/agent/deployments/agentenv-ae9c626-baseline')


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def digest(path):
    need(path.resolve() == path and path.is_file(), 'Input file redirected or missing')
    h = hashlib.sha256()
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
        after = os.fstat(stream.fileno())
    need(before.st_uid == 1204 and
         (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'Input changed or owner differs')
    return h.hexdigest()


def folder(path):
    need(path.is_relative_to(ROOT) and path.resolve() == path, 'Private conversion path redirected')
    if not path.exists():
        folder(path.parent)
        path.mkdir(mode=0o700)
    st = path.stat()
    need(st.st_uid == 1204 and stat.S_ISDIR(st.st_mode) and not st.st_mode & 0o022,
         'Private directory owner/type differs')


def put(path, value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2).encode() + b'\n'
    need(path.resolve() == path, 'Output redirected')
    if path.exists():
        need(path.read_bytes() == raw, 'Existing different output preserved')
        return
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def layer_uuid(value):
    data = bytearray(hashlib.sha256(value.encode()).digest()[:16])
    # uuid::Builder::from_custom_bytes sets Version::Custom (v8).
    data[6] = (data[6] & 0x0f) | 0x80
    data[8] = (data[8] & 0x3f) | 0x80
    return str(uuid.UUID(bytes=bytes(data)))


def run_tool(args, directory, label, env):
    log = directory / (label + '.log')
    print('NATIVE_CONVERSION_STEP=' + directory.name[:12] + ':' + label, flush=True)
    with log.open('xb') as output:
        result = subprocess.run(list(map(str, args)), cwd=directory,
                                stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.STDOUT, env=env, timeout=600)
    if result.returncode:
        print('NATIVE_TOOL_FAILURE=' + json.dumps({'step': label, 'exitCode': result.returncode,
              'log': str(log), 'tail': log.read_bytes()[-12000:].decode(errors='replace')}), flush=True)
    need(result.returncode == 0, 'Native tool failed; private intermediate files preserved')


def main():
    need(platform.node() == 'server1', 'Authoritative conversion is A only')
    if os.geteuid() == 0:
        os.setgroups([]); os.setgid(1205); os.setuid(1204)
    need(os.getuid() == os.geteuid() == 1204 and os.getgid() == 1205, 'Run conversion as jwk')
    for line in Path('/proc/self/status').read_text().splitlines():
        if line.startswith(('CapEff:', 'CapPrm:', 'CapAmb:', 'CapInh:')):
            need(int(line.split()[1], 16) == 0, 'Native conversion must have zero capabilities')
    os.umask(0o077); folder(ROOT)
    prepared_path = ROOT / 'prepared-inputs.json'
    digest(prepared_path)
    prepared = json.loads(prepared_path.read_bytes())
    need(prepared['state'] == 'COMPRESSED_OCI_INPUTS_PREPARED_NOT_EXECUTED' and prepared['uid'] == 1204,
         'Prepared image inputs not confirmed')
    work = ROOT / 'native-conversion-v1'; folder(work)
    for name in ('tmp', 'cache', 'docker', 'layers'):
        folder(work / name)
    tools = BASE / 'deps/overlaybd/bin'
    for name, pin in TOOL_PINS.items():
        need(digest(tools / name) == pin and os.access(tools / name, os.X_OK), 'Native OverlayBD tool differs: ' + name)
    selected = [x for x in prepared['sourceManifests'] if x['image'] in IMAGE_PINS]
    need(len(selected) == 2, 'Expected Purple City and Titanic prepared inputs')
    for row in selected:
        need(row['arm64ManifestDigest'] == IMAGE_PINS[row['image']], 'Image identity changed')
    need(shutil.disk_usage(work).free > 20 * 1024**3, 'Less than 20GiB available; no conversion started')
    global_path = work / 'overlaybd.json'
    put(global_path, {'logConfig': {'logLevel': 1, 'logPath': str(work / 'overlaybd.log')},
        'cacheConfig': {'cacheType': 'file', 'cacheDir': str(work / 'cache'), 'cacheSizeGB': 1,
                        'refillSize': 262144, 'blockSize': 65536},
        'credentialFilePath': '', 'credentialConfig': {}, 'ioEngine': 0,
        'p2pConfig': {'enable': False}, 'enableAudit': False, 'registryFsVersion': 'v2'})
    env = {'HOME': '/home/jwk', 'USER': 'jwk', 'LOGNAME': 'jwk', 'LANG': 'C.UTF-8',
           'PATH': str(BASE / 'native/bin') + ':/usr/sbin:/usr/bin:/sbin:/bin',
           'LD_LIBRARY_PATH': str(BASE / 'native/lib') + ':' + str(BASE / 'native/fallback/lib'),
           'TMPDIR': str(work / 'tmp'), 'XDG_CACHE_HOME': str(work / 'cache'),
           'DOCKER_CONFIG': str(work / 'docker')}
    results = []
    for image in selected:
        lowers = []; parent_uuid = None; parent_digest = None
        for index, layer in enumerate(image['layers']):
            source = ROOT / 'oci-blobs' / layer['digest'][7:]
            need(source.stat().st_size == layer['compressedBytes'] and
                 'sha256:' + digest(source) == layer['digest'], 'Prepared compressed layer differs')
            layer_id = layer_uuid(layer['digest'])
            key = {'sourceLayerDigest': layer['digest'], 'parentCommitDigest': parent_digest,
                   'virtualSizeGiB': 64, 'mkfs': index == 0, 'layerUuid': layer_id,
                   'toolPins': TOOL_PINS}
            key_hash = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()
            directory = work / 'layers' / key_hash; folder(directory)
            complete = directory / 'complete.json'; commit = directory / 'layer.commit'
            if complete.exists():
                done = json.loads(complete.read_bytes())
                need(done['key'] == key and done['digest'] == 'sha256:' + digest(commit),
                     'Prior conversion differs; preserved')
            else:
                need(not any(directory.iterdir()), 'Incomplete conversion preserved; reconcile instead of overwriting')
                put(directory / 'intent.json', key)
                upper = directory / 'upper.data'; upper_index = directory / 'upper.index'
                config = directory / 'image.json'
                run_tool([tools / 'overlaybd-create', upper, upper_index, '64'], directory, 'create', env)
                put(config, {'lowers': [{'file': x['file']} for x in lowers],
                             'upper': {'data': str(upper), 'index': str(upper_index)},
                             'resultFile': str(directory / 'result.txt')})
                apply = [tools / 'overlaybd-apply', '--service_config_path=' + str(global_path)]
                if index == 0:
                    apply.append('--mkfs')
                apply.extend([source, config])
                run_tool(apply, directory, 'apply', env)
                seal = [tools / 'overlaybd-commit', '--uuid', layer_id]
                if parent_uuid:
                    seal.extend(['--parent-uuid', parent_uuid])
                seal.extend([upper, upper_index, commit])
                run_tool(seal, directory, 'commit', env)
                done = {'key': key, 'digest': 'sha256:' + digest(commit),
                        'file': str(commit), 'size': commit.stat().st_size, 'uuid': layer_id}
                put(complete, done)
            lowers.append({k: done[k] for k in ('file', 'digest', 'size', 'uuid')})
            parent_uuid = layer_id; parent_digest = done['digest']
        results.append({'image': image['image'], 'imageManifestDigest': image['arm64ManifestDigest'],
                        'rootfsLowers': lowers, 'storedLowerBytes': sum(x['size'] for x in lowers),
                        'virtualDiskBytes': 64 * 1024**3, 'templateSnapshotCaptured': False})
    result = {'state': 'NATIVE_ROOTFS_CONVERSION_COMPLETED_NOT_A_TEMPLATE', 'uid': os.getuid(),
              'images': results, 'toolPins': TOOL_PINS, 'GuestCreated': False, 'SDKCalled': False,
              'nativeCommands': 'existing overlaybd-create/apply/commit; mkfs applies to private virtual files only',
              'temporaryBuildFilesRetained': True, 'next': 'Capture actual AgentENV template and validate dependencies in Guest'}
    put(work / 'converted-rootfs.json', result)
    print('BEGIN_DSBENCH_CONVERSION_REPORT', flush=True)
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    print('END_DSBENCH_CONVERSION_REPORT', flush=True)


# Pins are added below by the local publisher from the previously deployed
# official tools archive and the reviewed image manifest record.

TOOL_PINS = {'overlaybd-create': '68c62104c067d508eb3979117932c14b57dc1d67e10805a9d7ae2b9294efb72c', 'overlaybd-apply': '89c2d0adc300bb93d8d5ae57a39003587d12facfe1b685c9f91f3430500316d5', 'overlaybd-commit': '09b7ed66c074c83cdfd1ef4a316df8d50ce95756041246032a951f81407d0cd1'}
IMAGE_PINS = {'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-analysis-00000011-2014-round-2-purple-city:latest': 'sha256:fc8bfe8dae7e9b28a923e257b2969374e467fd0ea803b2a0c482b3764f5d4d93', 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-modeling-titanic:latest': 'sha256:d287f235d83c213a5bedd22f7e2ff95b5d1e7c5fe7a570da82a53409447e1c1d'}

if __name__ == '__main__':
    main()
