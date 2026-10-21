"""Compact only a new private copy of the verified rootfs. No mount, SDK or Guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import stat
import struct
import subprocess
import time

ROOT = Path('/home/jwk/agent')
PREVIOUS = ROOT / 'builds/rootfs-export-v1'
SOURCE = PREVIOUS / 'raw/rootfs.ext4'
WORK = ROOT / 'builds/rootfs-compact-v1'
NATIVE = ROOT / 'deployments/agentenv-native-fe63038/native'
BASE_SHA = '1dccd99cbf5d1ae8f316a2f03c1551676deabdb49cd157b384985aab082a53b7'
SOURCE_IMAGE = 'sha256:cf786498f77bf4ba6235156ab8540d0b9335e874e70b95efbeb53168e0dce68d'
GIB = 1024 ** 3
ALIGN = 2 * 1024 ** 2
SAMPLES = ('/pypika/pypika/__init__.py', '/pypika/pypika/queries.py', '/etc/passwd')


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def stamp(meta):
    return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def safe(path):
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True) == path,
         'Unexpected redirected path')
    return path


def read(path, limit=2 * 1024 ** 2):
    safe(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, 'Unexpected input file type/size')
        data = stream.read(limit + 1)
        need(stamp(before) == stamp(os.fstat(stream.fileno())) and len(data) == before.st_size, 'Input changed while reading')
    return data


def sha_file(path, limit, copy_to=None):
    safe(path)
    digest = hashlib.sha256()
    zeros = b'\0' * (1024 * 1024)
    output = None
    total = written = 0
    last = started = time.monotonic()
    try:
        if copy_to is not None:
            need(not copy_to.exists() and copy_to.parent == WORK, 'New own copy required')
            output = copy_to.open('xb')
        with path.open('rb') as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'Hash input exceeds bound')
            while True:
                chunk = stream.read(len(zeros))
                if not chunk:
                    break
                digest.update(chunk)
                if output is not None:
                    if chunk == zeros[:len(chunk)]:
                        output.seek(len(chunk), os.SEEK_CUR)
                    else:
                        need(written + len(chunk) <= 4 * GIB, 'Sparse copy written-data budget exceeded')
                        output.write(chunk)
                        written += len(chunk)
                total += len(chunk)
                need(total <= limit, 'Growing input exceeds bound')
                if time.monotonic() - last >= 20:
                    need(shutil.disk_usage(ROOT).free >= 4 * GIB, 'Free-space floor reached')
                    need(time.monotonic() - started < 900, 'Hash/copy time budget exceeded')
                    print('PROGRESS hash_or_copy_bytes=' + str(total), flush=True)
                    last = time.monotonic()
            need(total == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno()))
                 and stamp(path.stat()) == stamp(before), 'Input changed during hash/copy')
        if output is not None:
            output.truncate(total)
            output.flush()
            os.fsync(output.fileno())
        return digest.hexdigest()
    finally:
        if output is not None:
            output.close()


def superblock(path):
    with path.open('rb') as stream:
        stream.seek(1024)
        sb = stream.read(1024)
    need(len(sb) == 1024 and struct.unpack_from('<H', sb, 0x38)[0] == 0xEF53, 'Invalid ext4 superblock')
    u32 = lambda offset: struct.unpack_from('<I', sb, offset)[0]
    need(u32(0x18) == 2, 'Expected 4096-byte filesystem blocks')
    incompat = u32(0x60)
    blocks = u32(0x04) + ((u32(0x150) << 32) if incompat & 0x80 else 0)
    free = u32(0x0c) + ((u32(0x158) << 32) if incompat & 0x80 else 0)
    need(0 < blocks <= 64 * GIB // 4096 and free <= blocks, 'Invalid ext4 geometry')
    need(u32(0x10) <= u32(0x00), 'Invalid inode counts')
    return {'blockBytes': 4096, 'blocks': blocks, 'filesystemBytes': blocks * 4096,
            'usedBytes': (blocks - free) * 4096, 'allocatedInodes': u32(0x00) - u32(0x10),
            'uuid': sb[0x68:0x78].hex()}


def padded_length(filesystem_bytes):
    need(type(filesystem_bytes) is int and 0 < filesystem_bytes <= 4 * GIB, 'Compacted filesystem exceeds 4 GiB publication preparation budget')
    return (filesystem_bytes + ALIGN - 1) // ALIGN * ALIGN


def own_copy(target):
    safe(target)
    need(target == WORK / 'rootfs.ext4' and target.parent.stat().st_uid == os.getuid()
         and stat.S_ISREG(target.stat().st_mode) and target.stat().st_nlink == 1
         and not os.path.samefile(target, SOURCE), 'Mutation target is not the new private copy')


def run(argv, name, env, report, timeout=900):
    print('PHASE=' + name, flush=True)
    log = WORK / (name + '.log')
    with log.open('xb') as stream:
        child = subprocess.Popen(argv, cwd=WORK, env=env, stdin=subprocess.DEVNULL,
                                 stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        started = last = time.monotonic()
        try:
            while True:
                try:
                    code = child.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    need(time.monotonic() - started < timeout, 'Tool time budget exceeded: ' + name)
                    need(log.stat().st_size <= 8 * 1024 ** 2, 'Tool log budget exceeded')
                    need(shutil.disk_usage(ROOT).free >= 4 * GIB, 'Free-space floor reached')
                    if time.monotonic() - last >= 20:
                        print('PROGRESS phase=' + name + ' seconds=' + str(int(time.monotonic() - started)), flush=True)
                        last = time.monotonic()
        except BaseException:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            raise
    report['phases'][name] = {'exitCode': code, 'seconds': round(time.monotonic() - started, 2)}
    if code:
        with log.open('rb') as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 12000))
            report['failureLogTail'] = stream.read().decode(errors='replace')
        raise RuntimeError('Tool failed; no subsequent operation: ' + name)


def samples(debugfs, image, label, env, report):
    result = {}
    for index, guest_path in enumerate(SAMPLES):
        target = WORK / (label + '-sample-' + str(index))
        run([str(debugfs), '-R', 'dump ' + guest_path + ' ' + str(target), str(image)],
            label + '-sample-' + str(index), env, report, 30)
        # debugfs may exit zero even on command failure: require a real payload.
        try:
            raw = read(target, 4 * 1024 ** 2)
        except Exception:
            log = WORK / (label + '-sample-' + str(index) + '.log')
            with log.open('rb') as stream:
                report['failureLogTail'] = stream.read(12000).decode(errors='replace')
            raise RuntimeError('Sample extraction missing/invalid: ' + guest_path) from None
        result[guest_path] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    report = {'revision': 'A-rootfs-compact-v1', 'status': 'PLAN_ONLY', 'workDirectory': str(WORK),
              'SDK_called': False, 'Guest_created': False, 'ublkDevicesCreated': 0,
              'servicesChanged': False, 'mounted': False, 'UB_published': False,
              'nativeBindingAccepted': False, 'phases': {},
              'scope': 'Shrink a new own ext4 copy; filesystem consistency and three sample file hashes, not complete file-tree equivalence or Guest acceptance'}
    made = False
    if not args.run:
        print(json.dumps(report, indent=2))
        return 0
    try:
        need(platform.system() == 'Linux' and platform.machine() == 'aarch64' and socket.gethostname() == 'server1', 'Use ARM64 node A')
        need(os.getuid() == os.geteuid() == 1204 and os.getgid() == os.getegid() == 1205, 'Use ordinary jwk without sudo')
        caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        need(all(int(caps[k].strip(), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), 'Zero capabilities required')
        safe(WORK.parent)
        need(not WORK.exists() and not WORK.is_symlink(), 'Existing compact attempt preserved; do not rerun')
        need(shutil.disk_usage(ROOT).free >= 12 * GIB, '12 GiB free disk required')
        previous = json.loads(read(PREVIOUS / 'return.json'))
        receipt = json.loads(read(PREVIOUS / 'raw/export.json'))
        need(previous.get('status') == 'NATIVE_TESTS_PASSED_REAL_ROOTFS_EXPORTED_NOT_PUBLISHED_TO_UB'
             and receipt == previous.get('export') and receipt.get('sourceImage') == SOURCE_IMAGE
             and receipt.get('sha256') == 'sha256:' + BASE_SHA and receipt.get('virtualBytes') == 64 * GIB
             and receipt.get('output') == str(SOURCE), 'Successful export receipts differ')
        original = safe(SOURCE).stat()
        need(stat.S_ISREG(original.st_mode) and original.st_size == 64 * GIB and original.st_uid == 1204, 'Unexpected source image')
        need(original.st_dev == WORK.parent.stat().st_dev, 'Use the same already-tested sparse output filesystem')
        tools = {name: safe(NATIVE / 'bin' / name) for name in ('e2fsck', 'resize2fs', 'debugfs')}
        report['tools'] = {name: {'path': str(path), 'sha256': sha_file(path, 64 * 1024 ** 2)} for name, path in tools.items()}
        os.umask(0o077)
        WORK.mkdir(mode=0o700)
        made = True
        env = {'PATH': str(NATIVE / 'bin') + ':/usr/bin:/bin', 'HOME': str(Path.home()),
               'LANG': 'C', 'LC_ALL': 'C', 'TMPDIR': str(WORK),
               'LD_LIBRARY_PATH': str(NATIVE / 'lib') + ':' + str(NATIVE / 'fallback/lib')}
        target = WORK / 'rootfs.ext4'
        print('PHASE=hash_and_sparse_copy_verified_64GiB_source', flush=True)
        need(sha_file(SOURCE, 64 * GIB, target) == BASE_SHA, 'Source image digest changed; own partial copy retained')
        own_copy(target)
        print('PHASE=verify_own_copy_digest', flush=True)
        need(sha_file(target, 64 * GIB) == BASE_SHA, 'Private copy differs before any filesystem changes')
        report['sourceImage'] = SOURCE_IMAGE
        report['sourceSha256'] = BASE_SHA
        report['before'] = superblock(target)
        need(report['before']['filesystemBytes'] == 64 * GIB, 'Original filesystem geometry differs')
        run([str(tools['e2fsck']), '-f', '-n', str(target)], 'readonly-fsck-before', env, report)
        before_samples = samples(tools['debugfs'], target, 'before', env, report)
        own_copy(target)
        # Record a successful full check on this copy for resize2fs. Do not
        # accept repair exit code 1: the prior readonly full check must be clean.
        run([str(tools['e2fsck']), '-f', '-p', str(target)], 'record-clean-check-on-own-copy', env, report)
        own_copy(target)
        run([str(tools['resize2fs']), '-M', str(target)], 'resize-own-copy-minimum', env, report)
        after = superblock(target)
        need(after['uuid'] == report['before']['uuid'] and after['allocatedInodes'] == report['before']['allocatedInodes'],
             'Filesystem identity or allocated inode count changed')
        final_bytes = padded_length(after['filesystemBytes'])
        need(target.stat().st_size >= after['filesystemBytes'], 'Resized container is shorter than filesystem')
        run([str(tools['e2fsck']), '-f', '-n', str(target)], 'readonly-fsck-after-resize', env, report)
        own_copy(target)
        # Geometry is already resized and fsck-clean. Only now adjust the
        # container length, preserving the complete filesystem and 2 MiB padding.
        with target.open('r+b') as stream:
            stream.truncate(final_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        run([str(tools['e2fsck']), '-f', '-n', str(target)], 'readonly-fsck-final-padded-image', env, report)
        after_samples = samples(tools['debugfs'], target, 'after', env, report)
        need(before_samples == after_samples, 'Workload sample files changed during resize')
        report['sampleFiles'] = after_samples
        report['sampleFilesUnchanged'] = True
        report['after'] = after
        report['finalImage'] = {'path': str(target), 'bytes': final_bytes,
                                'sha256': 'sha256:' + sha_file(target, 4 * GIB),
                                'allocatedFileBytes': target.stat().st_blocks * 512,
                                'paddingBytes': final_bytes - after['filesystemBytes']}
        need(stamp(safe(SOURCE).stat()) == stamp(original), 'Original image metadata changed')
        report['originalImageUnchanged'] = True
        report['status'] = 'REAL_ROOTFS_COMPACTED_FSCK_AND_SAMPLE_HASHES_PASSED_NOT_UB_PUBLISHED'
        report['next'] = 'Size-aware UB publication and actual Guest workload validation; snapshot/Fork and memfile private CoW remain outstanding'
    except BaseException as error:
        report.update(status='STOPPED_COMPACTION_PRESERVE_ORIGINAL_AND_PARTIAL_COPY',
                      errorType=type(error).__name__, reason=str(error)[:1500])
    finally:
        if made:
            with (WORK / 'return.json').open('x') as stream:
                json.dump(report, stream, indent=2)
        print('BEGIN_A_ROOTFS_COMPACT_REPORT')
        print(json.dumps(report, indent=2))
        print('END_A_ROOTFS_COMPACT_REPORT')
    return 0 if report['status'] == 'REAL_ROOTFS_COMPACTED_FSCK_AND_SAMPLE_HASHES_PASSED_NOT_UB_PUBLISHED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
