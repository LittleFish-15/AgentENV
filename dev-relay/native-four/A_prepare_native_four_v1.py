"""One preparation batch for the recorded four templates; no SDK or Guest.

Read existing private inputs and immutable source layers, build the matching
release, export four NEW images and compact only those own outputs. No original
Runtime API calls, locks, restarts, live database copies or original file writes.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time

ROOT = Path('/home/jwk/agent')
WORK = ROOT / 'builds/native-four-inputs-v1'
BUILD = ROOT / 'builds/native-four-release-v1'
ORIGINAL = ROOT / 'deployments/agentenv-ae9c626-baseline'
CORE = '32ce41c0ac6436198860f888e07ef9793e58dc40'
TREE = '0e973a6e101c1a1c71b48bf70f2d910f48cd672f'
MIB, GIB = 1024**2, 1024**3
PINS = {'four_contract.py': 'b4a7ddf8eaf0459652a1b10ffd3026d10af8a71106cc9a2598333ca724eb1667', 'four_probe.py': '930b9a6856da480dd95a388bfd11c75104878b594c694a6c0cc328300397f26e', 'A_build_native_four_v1.py': '978707b403f802c75e4085bd038bad7451afb6cc1af03f1d36a05138523a92cb'}
TOOLS = {'e2fsck': 'a37be5aaabeeb8f431719c29875ea41eb07b49f7112fd88413f9c598bf454fb9',
         'resize2fs': 'eb8102cf354f6895dc14df26bf63790016482eed8ecb6a4d7ab1d6e7144084f1',
         'debugfs': 'bc53991ef4ee2d20a8c27b7aeed2e2c59cb40d5291292d1742ee01bd4ca50707'}


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def safe(path):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True) == path,
         'Unexpected or redirected experiment path')
    return path


def stamp(meta):
    return meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns


def read(path, limit=16 * MIB):
    fd = os.open(safe(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 1204 and 0 < before.st_size <= limit,
             'Unexpected file owner/type/length')
        raw = stream.read(limit + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno())), 'Input changed')
    return raw


def load(path):
    return json.loads(read(path))


def digest(path, limit=4 * GIB):
    path = safe(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'Hash budget exceeded')
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
        need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Hash input changed')
    return value


def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def run(argv, name, cwd, allowed=(0,), timeout=1800, env=None):
    print('PHASE=' + name, flush=True)
    with (cwd / (name + '.log')).open('xb') as log:
        child = subprocess.Popen(list(map(str, argv)), cwd=cwd, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT, env=env)
        started = last = time.monotonic()
        try:
            while child.poll() is None:
                need(time.monotonic() - started < timeout, 'Preparation phase timeout; preserve own partial files')
                if time.monotonic() - last >= 30:
                    print('PROGRESS phase=' + name + ' elapsed_s=' + str(int(time.monotonic() - started)), flush=True)
                    need(shutil.disk_usage(ROOT).free >= 8 * GIB, 'Preparation disk reserve reached')
                    last = time.monotonic()
                time.sleep(1)
        except BaseException:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
            raise
    need(child.returncode in allowed, 'Preparation phase failed: ' + name)


def module(name):
    path = ROOT / (name + '.py')
    raw = read(path, 8 * MIB)
    need(hashlib.sha256(raw).hexdigest() == PINS[name + '.py'], 'Preparation helper differs')
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def inputs(contract):
    pending = load(ROOT / 'relay/cow4-access-node-a.pending.json')
    need(pending.get('status') == 'COW4_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED',
         'Completed four-template reference required')
    directory = safe(Path(pending['report_directory']))
    need(directory.is_relative_to(ROOT / 'relay/reports'), 'Historical report outside report tree')
    history_raw = read(directory / 'combined-summary.json')
    history = json.loads(history_raw)
    need(history['run_id'] == pending['run_id'], 'Historical report identity differs')
    private_raw = read(ROOT / 'cow55_inputs.json', 8 * MIB)
    private = json.loads(private_raw)
    build = load(ROOT / 'relay/cow55-template-build-node-a.json')
    need(hashlib.sha256(private_raw).hexdigest() == build['input_sha256'], 'Private workload changed')
    selected = contract.select_four(history, private, build)
    return selected, history_raw, {'historySha256': hashlib.sha256(history_raw).hexdigest(),
                                  'privateInputSha256': hashlib.sha256(private_raw).hexdigest()}


def source(contract, selection, directory):
    built = selection['original']
    repo = ORIGINAL / 'state/snapshot-store/repository'
    record_path = repo / 'catalog/records' / (built['template_id'] + '.json')
    record_raw = read(record_path)
    need(hashlib.sha256(record_raw).hexdigest() == built['catalog_sha256'], 'Original template record changed')
    need(read(repo / 'snapshots' / built['template_id'] / 'commit', 64) == b'committed', 'Uncommitted original template')
    config_path = ORIGINAL / 'state/image-cache/configs' / (built['manifest_digest'].replace(':', '-') + '-image.json')
    raw = read(config_path)
    config = json.loads(raw)
    identity = contract.source_from_record(json.loads(record_raw), config, built)
    layers = []
    for lower in config['lowers']:
        # Catalog-managed immutable files are already retained by the original
        # snapshot. Do not depend on a remote layer dir or mutable cache alias.
        path = repo / 'managed-layers' / (lower['digest'].replace(':', '_') + '.overlaybd.commit')
        safe(path)
        need(path.is_relative_to(ORIGINAL / 'state') and path.stat().st_uid == 1204
             and path.is_file() and path.stat().st_size == lower['size'], 'Original immutable layer differs')
        layers.append({'path': str(path), 'digest': lower['digest'], 'size': lower['size']})
    need(sum(layer['size'] for layer in layers) <= 8 * GIB, 'Per-image source budget exceeds 8GiB')
    snapshot_manifest = load(repo / 'snapshots' / built['template_id'] / 'firecracker-manifest.json')
    virtual_bytes = snapshot_manifest.get('rootfs', {}).get('virtualSize')
    need(type(virtual_bytes) is int and snapshot_manifest.get('memory', {}).get('virtualSize') == 4096 * MIB,
         'Original snapshot memory/disk geometry unavailable')
    need(0 < virtual_bytes <= 64 * GIB, 'Unexpected original virtual disk capacity')
    request = {'version': 1, 'sourceImage': identity['sourceImage'], 'virtualBytes': virtual_bytes,
               'maxInputBytes': 8 * GIB, 'maxWrittenBytes': min(8 * GIB, virtual_bytes), 'layers': layers}
    save(directory / 'export-request.json', request)
    save(directory / 'source-config.json', config)
    oci = safe(Path(built['local_oci_directory']))
    need(oci.is_relative_to(ROOT / 'relay/reports') and oci.is_dir(), 'Original OCI input directory differs')
    manifest_path = oci / 'blobs/sha256' / built['manifest_digest'][7:]
    need(hashlib.sha256(read(manifest_path, 4 * MIB)).hexdigest() == built['manifest_digest'][7:],
         'Original OCI manifest changed')
    return {**identity, 'sourceConfig': str(directory / 'source-config.json'), 'layers': layers,
            'ociDirectory': str(oci), 'ociDigest': built['manifest_digest'],
            'originalCatalogSha256': built['catalog_sha256'], 'resources': built['resources']}


def geometry(image):
    with image.open('rb') as stream:
        stream.seek(1024)
        sb = stream.read(1024)
    need(len(sb) == 1024 and struct.unpack_from('<H', sb, 0x38)[0] == 0xEF53, 'Invalid ext4 image')
    u32 = lambda at: struct.unpack_from('<I', sb, at)[0]
    need(u32(0x18) == 2, 'Expected 4KiB ext4 blocks')
    blocks = u32(4) + ((u32(0x150) << 32) if u32(0x60) & 0x80 else 0)
    need(0 < blocks * 4096 <= 64 * GIB, 'Invalid filesystem length')
    return {'bytes': blocks * 4096, 'uuid': sb[0x68:0x78].hex()}


def compact(directory, tools, env, probe, workdir):
    image = safe(directory / 'raw/rootfs.ext4')
    need(image.stat().st_uid == 1204 and image.stat().st_nlink == 1, 'Only the new private export can be changed')
    before = geometry(image)
    run([tools['e2fsck'], '-fn', image], 'check-export', directory, env=env)
    run([tools['debugfs'], '-R', 'dump -p /etc/passwd before.passwd', image], 'sample-before', directory, env=env)
    original_sample = digest(directory / 'before.passwd', MIB)
    run([tools['e2fsck'], '-fp', image], 'clean-own-export', directory, allowed=(0, 1), env=env)
    run([tools['resize2fs'], '-M', image], 'compact-own-export', directory, env=env)
    after = geometry(image)
    need(before['uuid'] == '0' * 32 or before['uuid'] == after['uuid'], 'Nonzero original filesystem UUID changed')
    need(after['bytes'] <= 4 * GIB, 'Compacted image exceeds the reviewed 4GiB per-image budget')
    aligned = (after['bytes'] + 2 * MIB - 1) // (2 * MIB) * (2 * MIB)
    with image.open('r+b') as stream:
        stream.truncate(aligned)
        stream.flush()
        os.fsync(stream.fileno())
    # debugfs does not execute image programs. Only this new export is writable.
    marker = directory / 'dax-probe'
    marker.write_bytes(b'aenv-native-dax-v3\n')
    run([tools['debugfs'], '-w', '-R', 'write ' + str(marker) + ' /.aenv-dax-probe', image], 'insert-dax-marker', directory, env=env)
    run([tools['debugfs'], '-w', '-R', 'write ' + str(probe) + ' /.aenv-dax-exec', image], 'insert-exec-marker', directory, env=env)
    run([tools['debugfs'], '-w', '-R', 'set_inode_field /.aenv-dax-exec mode 0100555', image], 'mode-exec-marker', directory, env=env)
    run([tools['debugfs'], '-R', 'dump -p /.aenv-dax-exec exec-readback', image], 'verify-exec-marker', directory, env=env)
    need(digest(directory / 'exec-readback', MIB) == digest(probe, MIB), 'Executable marker readback differs')
    need(isinstance(workdir, str) and re.fullmatch(r'/[A-Za-z0-9_./+-]*', workdir), 'Unsupported workload directory syntax')
    run([tools['debugfs'], '-R', 'stat ' + workdir, image], 'workdir-stat', directory, env=env)
    need(b'Type: directory' in read(directory / 'workdir-stat.log', MIB), 'Workload directory absent from image')
    run([tools['debugfs'], '-R', 'dump -p /etc/passwd after.passwd', image], 'sample-after', directory, env=env)
    need(digest(directory / 'after.passwd', MIB) == original_sample, 'Sample changed during compaction')
    run([tools['e2fsck'], '-fn', image], 'check-final', directory, env=env)
    return {'path': str(image), 'bytes': image.stat().st_size, 'sha256': 'sha256:' + digest(image),
            'filesystemBefore': before, 'filesystemAfter': after,
            'scope': 'fsck_and_sample_check_not_full_tree_equivalence_or_Guest_acceptance'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'status': 'PLAN_ONLY', 'templates': 4, 'singleGuests': 8, 'dualGuests': 16,
                          'SDK_called': False, 'servicesChanged': False})); return 0
    need(sys.platform == 'linux' and os.uname().machine == 'aarch64' and socket.gethostname() == 'server1'
         and os.getuid() == os.geteuid() == 1204, 'Use ordinary ARM64 node A')
    caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(caps[key].strip(), 16) == 0 for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')),
         'Capability-free preparation required')
    os.umask(0o077)
    import fcntl
    lock = os.open(ROOT / 'relay/native-four-prepare.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    contract = module('four_contract')
    selected, history, provenance = inputs(contract)
    need(not WORK.exists() and not WORK.is_symlink(), 'Prior four-image preparation preserved; no blind repeat')
    need(shutil.disk_usage(ROOT).free >= 96 * GIB, 'Need 96GiB preparation reserve; no source/device cleanup')
    WORK.mkdir(mode=0o700)
    report = {'status': 'PREPARING_FOUR_NATIVE_IMAGES', 'coreCommit': CORE, 'coreTree': TREE,
              'SDK_called': False, 'Guest_created': False, 'servicesChanged': False,
              'historicalReferenceOnly': True, 'memfilePrivateCowImplemented': False, 'cases': []}
    try:
        (WORK / 'historical-reference.private.json').write_bytes(history)
        save(WORK / 'selection.private.json', {'selected': selected, 'provenance': provenance})
        need(digest(ROOT / 'A_build_native_four_v1.py', 8 * MIB) == PINS['A_build_native_four_v1.py'], 'Builder pin differs')
        if not (BUILD / 'return.json').exists():
            run([sys.executable, '-I', '-B', ROOT / 'A_build_native_four_v1.py', '--run'], 'build-release', WORK, timeout=10800)
        build = load(BUILD / 'return.json')
        need(build.get('status') == 'COORDINATED_CANDIDATE_BINARIES_BUILT_NOT_DEPLOYED'
             and build.get('release', {}).get('coreCommit') == CORE and build['release']['tree'] == TREE,
             'Matching four-image build required')
        exporter = Path(build['rootfsExporter']['path'])
        need(digest(exporter, 256 * MIB) == build['rootfsExporter']['sha256'], 'Exporter changed')
        native = ROOT / 'deployments/agentenv-native-fe63038/native'
        tools = {name: safe(native / 'bin' / name) for name in TOOLS}
        need(all(digest(path, 32 * MIB) == TOOLS[name] for name, path in tools.items()), 'Filesystem tools changed')
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(Path.home()), 'LANG': 'C', 'LC_ALL': 'C',
               'TMPDIR': str(WORK), 'LD_LIBRARY_PATH': str(native / 'lib') + ':' + str(native / 'fallback/lib')}
        assembly = BUILD / 'core-source/agentenv-native-core/components/firecracker-native-pmem/guest-exec-probe.S'
        need(digest(assembly, MIB) == build['release']['execSourceSha256'], 'Executable source changed')
        probe = WORK / 'dax-exec'
        run(['/usr/bin/gcc', '-nostdlib', '-static', '-no-pie', '-Wl,--build-id=none',
             '-Wl,-z,max-page-size=4096', '-o', probe, assembly], 'build-dax-exec', WORK, env=env)
        module('four_probe').inspect_probe(read(probe, MIB))
        for index, case in enumerate(selected):
            directory = WORK / ('case-' + str(index))
            directory.mkdir(mode=0o700)
            information = source(contract, case, directory)
            run([exporter, directory / 'export-request.json', directory / 'raw'], 'export-source', directory, env=env)
            information['nativeImage'] = compact(directory, tools, env, probe, case['case']['workdir'])
            information.update(templateIndex=index, instanceId=case['case']['instance_id'],
                               replaySha256=case['case']['replay_sha256'])
            report['cases'].append(information)
            save(directory / 'prepared.json', information)
        report.update(status='FOUR_NATIVE_IMAGES_AND_BINARIES_PREPARED_NOT_DEPLOYED',
                      singleJobs=contract.scenario_jobs(selected, 'single-a'),
                      dualJobs=contract.scenario_jobs(selected, 'dual-ab'),
                      logicalNativeImageBytes=sum(c['nativeImage']['bytes'] for c in report['cases']))
    except BaseException as error:
        report.update(status='STOPPED_FOUR_PREPARATION_PRESERVE_INPUTS', errorType=type(error).__name__,
                      reason=str(error)[:1000] if isinstance(error, (RuntimeError, ValueError)) else 'Inspect complete phase logs')
    finally:
        save(WORK / 'return.json', report)
        os.close(lock)
        print('BEGIN_NATIVE_FOUR_PREPARATION_REPORT')
        print(json.dumps(report, indent=2))
        print('END_NATIVE_FOUR_PREPARATION_REPORT')
    return 0 if report['status'] == 'FOUR_NATIVE_IMAGES_AND_BINARIES_PREPARED_NOT_DEPLOYED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
