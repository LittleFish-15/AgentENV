#!/usr/bin/env python3
"""Prepare a NEW pmem-capable tools ext4; never alter the supplied original.

No mounts, Docker, installation, elevation, network, services, SDK or Guest.
Default is a read-only plan. --run requires existing native Linux tools.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import threading


MAX_IMAGE = 512 * 1024 * 1024
MAX_SOURCE = 256 * 1024
MAX_LOG = 256 * 1024
_SAFE_DEBUGFS = re.compile(r'/[A-Za-z0-9_./-]+\Z')

SELFTEST_INIT = b'''#!/agentenv/bin/busybox sh
BB=/agentenv/bin/busybox
die() { echo "AENV_DAX_SELFTEST_FAIL $*" >&2; exec $BB poweroff -f; }
$BB mount -n -t proc proc /proc || die mount_proc
$BB mount -n -t sysfs sysfs /sys || die mount_sys
PMEM_COUNT=""
PMEM_FSTYPE="erofs"
EXPECTED_PMEM_FSTYPE=$PMEM_FSTYPE
PMEM_FSTYPE_SEEN=""
for ARG in $($BB cat /proc/cmdline); do
    case "$ARG" in
        aenv_pmem_rootfs=*)
            [ -z "$PMEM_COUNT" ] || die duplicate_pmem_argument
            PMEM_COUNT="${ARG#aenv_pmem_rootfs=}" ;;
        aenv_pmem_fstype=*)
            [ -z "$PMEM_FSTYPE_SEEN" ] || die duplicate_pmem_filesystem
            PMEM_FSTYPE_SEEN=1
            PMEM_FSTYPE="${ARG#aenv_pmem_fstype=}" ;;
    esac
done
[ -n "$PMEM_COUNT" ] || die missing_pmem_argument
[ "$PMEM_FSTYPE" = "$EXPECTED_PMEM_FSTYPE" ] || die unexpected_pmem_filesystem
. /agentenv/pmem-rootfs
if [ -f /mnt/user/common-data.bin ]; then
    COMMON="$($BB sha256sum /mnt/user/common-data.bin)" || die common_read_hash
    echo "AENV_DAX_SELFTEST_COMMON $COMMON"
fi
BEFORE="$($BB sha256sum /mnt/ro0/.aenv-dax-probe)" || die lower_hash_before
printf 'AgentENV private upper write\\n' > /mnt/user/.aenv-dax-probe || die private_write
[ -s /mnt/write/.agentenv-overlay/upper/.aenv-dax-probe ] || die missing_copyup
AFTER="$($BB sha256sum /mnt/ro0/.aenv-dax-probe)" || die lower_hash_after
[ "$BEFORE" = "$AFTER" ] || die lower_changed
echo "AENV_DAX_SELFTEST_PASS pmem_count=$PMEM_COUNT lower_unchanged=1 private_copyup=1"
echo "AENV_DAX_SELFTEST_BASE $AFTER"
$BB sync
exec $BB poweroff -f
'''


def stamp(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def stable_read(path, limit, capture=False):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('Expected a nonempty bounded regular input: ' + path.name)
        digest, total, data = hashlib.sha256(), 0, bytearray()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            total += len(chunk)
            if total > before.st_size or total > limit:
                raise ValueError('Input grew while reading: ' + path.name)
            digest.update(chunk)
            if capture:
                data.extend(chunk)
        after = os.fstat(stream.fileno())
    if total != before.st_size or stamp(before) != stamp(after) or stamp(path.stat()) != stamp(after):
        raise ValueError('Input changed while reading: ' + path.name)
    return {'sha256': digest.hexdigest(), 'bytes': total, 'identity': list(stamp(after))}, bytes(data)


def debugfs_token(path):
    text = str(path)
    if not _SAFE_DEBUGFS.fullmatch(text) or '//' in text or '..' in Path(text).parts:
        raise ValueError('debugfs paths must be absolute ASCII paths using letters, digits, _, ., / and -')
    return text


def elf_arch(path):
    with Path(path).open('rb') as stream:
        header = stream.read(64)
    if len(header) < 20 or header[:4] != b'\x7fELF' or header[4] != 2 or header[5] != 1:
        raise ValueError('Expected a 64-bit little-endian ELF: ' + Path(path).name)
    return struct.unpack_from('<H', header, 18)[0]


def debugfs_argv(binary, command, target, original, writable=False):
    target, original = Path(target), Path(original)
    if '\n' in command or '\r' in command or '\0' in command:
        raise ValueError('Refusing multiline/NUL debugfs commands')
    if writable and (target == original or not target.is_file()
                     or os.path.samefile(target, original)):
        raise RuntimeError('Refusing a debugfs write to the original image')
    return [str(binary)] + (['-w'] if writable else []) + ['-R', command, str(target)]


def run_local(argv, logfile, env, timeout):
    """Bound child output and lifetime; no shell is involved."""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, cwd=str(Path(logfile).parent), env=env)
    output, overflow = bytearray(), threading.Event()
    def drain():
        try:
            while True:
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                left = MAX_LOG - len(output)
                output.extend(chunk[:max(0, left)])
                if len(chunk) > left:
                    overflow.set()
                    process.kill()
                    break
        except (OSError, ValueError):
            pass
    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait(timeout=5)
    thread.join(timeout=2)
    if thread.is_alive():
        raise RuntimeError('A child retained the output pipe; child supervision is incomplete')
    process.stdout.close()
    Path(logfile).write_bytes(output)
    if timed_out or overflow.is_set() or process.returncode:
        raise RuntimeError('Local tool failed or exceeded its bound; inspect ' + Path(logfile).name)
    return bytes(output).decode('utf-8', 'replace')


def validate(args):
    if getattr(args, 'lower_filesystem', 'erofs') not in ('erofs', 'ext4'):
        raise ValueError('Lower filesystem must be explicitly erofs or ext4')
    image, source, output = Path(args.tools_image), Path(args.source), Path(args.output)
    if (not all(path.is_absolute() for path in (image, source, output))
            or output.resolve() != output or output.exists()
            or not output.parent.is_dir() or image.resolve(strict=True) != image
            or source.resolve(strict=True) != source):
        raise ValueError('Use existing absolute nonredirected inputs and a new output directory')
    debugfs_token(output)
    if output.is_relative_to(source):
        raise ValueError('Output must be outside the core source tree')
    if not re.fullmatch(r'[0-9a-f]{64}', args.tools_sha256):
        raise ValueError('Expected an exact lowercase SHA256')
    if not re.fullmatch(r'0|[1-9][0-9]*', args.tools_version.split('.')[0]):
        raise ValueError('Expected a distinct custom SemVer tools version')
    if not re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-[0-9A-Za-z.-]+', args.tools_version):
        raise ValueError('Use a distinct prerelease tools version, for example 0.1.1-native-pmem.1')
    info, _ = stable_read(image, MAX_IMAGE)
    if info['sha256'] != args.tools_sha256:
        raise ValueError('Original tools SHA256 differs; no output created')
    sources = {}
    for name in ('init', 'pivot-init', 'pmem-rootfs', 'dax-check.go'):
        path = source / 'tools-image' / name
        entry, data = stable_read(path, MAX_SOURCE, capture=True)
        sources[name] = {'metadata': entry, 'data': data}
    prebuilt = getattr(args, 'dax_check', None)
    if bool(args.go) == bool(prebuilt):
        raise ValueError('Choose exactly one existing Go compiler or pinned prebuilt DAX checker')
    checker = None
    if prebuilt:
        path = Path(prebuilt)
        expected = getattr(args, 'dax_check_sha256', None)
        if (not path.is_absolute() or path.resolve(strict=True) != path
                or not expected or not re.fullmatch(r'[0-9a-f]{64}', expected)):
            raise ValueError('Prebuilt DAX checker requires an absolute real path and exact SHA256')
        entry, _ = stable_read(path, 32 * 1024 * 1024)
        if entry['sha256'] != expected or elf_arch(path) != 183:
            raise ValueError('Prebuilt DAX checker digest or ARM64 ELF differs')
        checker = {'path': str(path), **entry}
    binaries = {}
    for name in (('go', 'debugfs') if args.go else ('debugfs',)):
        path = Path(getattr(args, name))
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('Use an absolute real executable path for ' + name)
        entry, _ = stable_read(path, 256 * 1024 * 1024)
        binaries[name] = {'path': str(path), **entry}
    return image, source, output, info, sources, binaries, checker


def prepare(args):
    image, source, output, original, sources, binaries, prebuilt = validate(args)
    receipt = {'revision': 'guest-tools-private-copy-v1', 'mode': args.mode,
               'lowerFilesystem': getattr(args, 'lower_filesystem', 'erofs'),
               'status': 'PLAN_NO_BUILD_OR_IMAGE_WRITE', 'original': original,
               'originalPath': str(image), 'output': str(output), 'toolsVersion': args.tools_version,
               'inputs': {name: item['metadata'] for name, item in sources.items()},
               'localTools': binaries, 'prebuiltChecker': prebuilt,
               'GuestCreated': False, 'SDKCalled': False,
               'servicesChanged': False, 'networkCalled': False,
               'requires': ['existing Guest kernel with virtio-pmem/selected-filesystem/DAX/OverlayFS',
                            'separate private ext4 disk attached as /dev/vdb',
                            'patched FC and actual Guest DAX validation'],
               'acceptance': 'tools preparation only, not KVM/DAX/cross-node or memory-benefit acceptance'}
    if not args.run:
        return receipt
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise RuntimeError('--run requires an ordinary existing Linux account')
    for line in Path('/proc/self/status').read_text().splitlines():
        if line.split(':', 1)[0] in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb') and int(line.split()[1], 16):
            raise RuntimeError('Use an ordinary zero-capability process')
    host_arch = {'x86_64': 62, 'aarch64': 183}.get(os.uname().machine)
    for name, binary in binaries.items():
        if host_arch is None or elf_arch(binary['path']) != host_arch:
            raise ValueError('Build-tool ELF does not match the existing host architecture: ' + name)
    if shutil.disk_usage(output.parent).free < 2 * original['bytes'] + 512 * 1024 * 1024:
        raise ValueError('Insufficient space for a new tools copy and private build cache')
    os.umask(0o077)
    output.mkdir(mode=0o700)
    receipt['status'] = 'PREPARING_NEW_PRIVATE_IMAGE'
    new_image = output / 'tools-native-pmem.ext4'
    env = dict(os.environ)
    env.update(CGO_ENABLED='0', GOOS='linux', GOARCH='arm64',
               GO111MODULE='off', GOWORK='off', GOFLAGS='', GOTOOLCHAIN='local',
               GOPROXY='off', GOSUMDB='off', LC_ALL='C',
               GOCACHE=str(output / 'go-cache'), TMPDIR=str(output / 'tmp'))
    (output / 'tmp').mkdir(mode=0o700)
    counter = 0
    def debug(command, writable=False, old=False):
        nonlocal counter
        target = image if old else new_image
        if writable and old:
            raise RuntimeError('Refusing a debugfs write to the original image')
        counter += 1
        argv = debugfs_argv(binaries['debugfs']['path'], command, target, image, writable)
        return run_local(argv, output / ('debugfs-%03d.log' % counter), env, 30)
    try:
        old_version = output / 'original-tools-drive-version'
        debug('dump /agentenv/tools-drive-version ' + debugfs_token(old_version), old=True)
        _, raw_version = stable_read(old_version, 1024, capture=True)
        receipt['originalToolsVersion'] = raw_version.decode('ascii').strip()
        if receipt['originalToolsVersion'] == args.tools_version:
            raise ValueError('Changed tools bytes require a different immutable tools version')
        # Build the checked source with the existing local Go toolchain only.
        for name, item in sources.items():
            (output / name).write_bytes(item['data'])
        if prebuilt is not None:
            meta, data = stable_read(prebuilt['path'], 32 * 1024 * 1024, capture=True)
            if meta != {key: prebuilt[key] for key in ('sha256', 'bytes', 'identity')}:
                raise ValueError('Prebuilt DAX checker changed before staging')
            (output / 'dax-check').write_bytes(data)
        else:
            run_local([binaries['go']['path'], 'version'], output / 'go-version.log', env, 10)
            run_local([binaries['go']['path'], 'build', '-trimpath', '-ldflags=-s -w',
                       '-o', str(output / 'dax-check'), str(output / 'dax-check.go')],
                      output / 'go-build.log', env, 180)
        if elf_arch(output / 'dax-check') != 183:
            raise ValueError('DAX checker was not built as ARM64')
        # Read-only extraction proves existing required binaries are present.
        reused = {}
        for name, guest in [('busybox', '/agentenv/bin/busybox'), ('envd', '/agentenv/envd')]:
            dumped = output / ('reused-' + name)
            try:
                debug('dump ' + guest + ' ' + debugfs_token(dumped), old=True)
                meta, _ = stable_read(dumped, 256 * 1024 * 1024)
                if elf_arch(dumped) != 183:
                    raise ValueError('Existing Guest binary is not ARM64')
                reused[name] = {'guestPath': guest, **meta}
            except (OSError, ValueError, RuntimeError) as error:
                if name != 'envd' or args.mode != 'dax-selftest':
                    raise RuntimeError('Required existing Guest binary is unavailable: ' + name) from error
                reused[name] = {'guestPath': guest, 'available': False,
                                'error': type(error).__name__}
        receipt['reusedGuestBinaries'] = reused
        with image.open('rb') as incoming, new_image.open('xb') as outgoing:
            before = os.fstat(incoming.fileno())
            digest, total = hashlib.sha256(), 0
            for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
                total += len(chunk)
                if total > original['bytes']:
                    raise ValueError('Original image grew while copying')
                digest.update(chunk)
                outgoing.write(chunk)
            outgoing.flush()
            os.fsync(outgoing.fileno())
            if (total != original['bytes'] or digest.hexdigest() != original['sha256']
                    or stamp(before) != tuple(original['identity'])
                    or stamp(before) != stamp(os.fstat(incoming.fileno()))):
                raise ValueError('Original image changed before private copy completed')
        if args.mode == 'dax-selftest':
            selected = receipt['lowerFilesystem'].encode('ascii')
            (output / 'init').write_bytes(SELFTEST_INIT.replace(
                b'PMEM_FSTYPE="erofs"', b'PMEM_FSTYPE="' + selected + b'"', 1))
            receipt['selftest'] = {'serialPassMarker': 'AENV_DAX_SELFTEST_PASS',
                'serialFailMarker': 'AENV_DAX_SELFTEST_FAIL', 'envdRequired': False,
                'checks': ['all lower/visible nonempty regular files report STATX_ATTR_DAX',
                           'writing visible probe creates private upper copy',
                           'lower probe hash unchanged after private write'],
                'notProven': ['cross-node physical allocation identity',
                              'net memory benefit', 'full AgentENV launch integration']}
        (output / 'tools-drive-version').write_text(args.tools_version + '\n')
        directories = ['/mnt', '/mnt/user', '/mnt/write'] + ['/mnt/ro' + str(i) for i in range(8)]
        for guest in directories:
            debug('mkdir ' + guest, writable=True)
            observed = debug('stat ' + guest)
            if not re.search(r'Type:\s+directory\b', observed):
                raise RuntimeError('Required Guest directory was not created: ' + guest)
        entries = [('init', '/init', '0100755'),
                   ('pivot-init', '/agentenv/pivot-init', '0100755'),
                   ('pmem-rootfs', '/agentenv/pmem-rootfs', '0100755'),
                   ('dax-check', '/agentenv/dax-check', '0100755'),
                   ('tools-drive-version', '/agentenv/tools-drive-version', '0100644')]
        verified = {}
        for name, guest, mode in entries:
            debug('rm ' + guest, writable=True)
            debug('write ' + debugfs_token(output / name) + ' ' + guest, writable=True)
            for field, value in [('mode', mode), ('uid', '0'), ('gid', '0')]:
                debug('set_inode_field ' + guest + ' ' + field + ' ' + value, writable=True)
            observed = debug('stat ' + guest)
            if not re.search(r'Type:\s+regular\b', observed):
                raise RuntimeError('Injected Guest file is not regular: ' + guest)
            expected_mode = '0' + mode[-3:]
            if not re.search(r'Mode:\s+' + expected_mode + r'\b', observed):
                raise RuntimeError('Injected Guest file mode differs: ' + guest)
            if not re.search(r'User:\s+0\s+Group:\s+0\b', observed):
                raise RuntimeError('Injected Guest file ownership differs: ' + guest)
            dumped = output / ('verified-' + name)
            debug('dump ' + guest + ' ' + debugfs_token(dumped))
            expected, _ = stable_read(output / name, MAX_SOURCE if name != 'dax-check' else 32 * 1024 * 1024)
            actual, _ = stable_read(dumped, 32 * 1024 * 1024)
            if expected['bytes'] != actual['bytes'] or expected['sha256'] != actual['sha256']:
                raise RuntimeError('debugfs dump differs from injected file: ' + guest)
            verified[guest] = {**actual, 'mode': mode, 'uid': 0, 'gid': 0}
        for name, original_binary in reused.items():
            if original_binary.get('available') is False:
                continue
            dumped = output / ('verified-reused-' + name)
            debug('dump ' + original_binary['guestPath'] + ' ' + debugfs_token(dumped))
            actual, _ = stable_read(dumped, 256 * 1024 * 1024)
            if any(actual[key] != original_binary[key] for key in ('sha256', 'bytes')):
                raise RuntimeError('Reused Guest binary changed in the private image: ' + name)
            original_binary['unchangedInNewImage'] = True
        debug('stats')
        new_meta, _ = stable_read(new_image, MAX_IMAGE)
        receipt.update(status='PRIVATE_TOOLS_IMAGE_PREPARED_NOT_GUEST_ACCEPTANCE',
                       imagePath=str(new_image), image=new_meta, verifiedFiles=verified)
    except BaseException as error:
        receipt.update(status='PREPARATION_FAILED_NO_ACTIVATION',
                       errorType=type(error).__name__, reason=str(error)[:1000])
        raise
    finally:
        try:
            after, _ = stable_read(image, MAX_IMAGE)
            receipt['originalAfter'] = after
            receipt['originalUnchanged'] = (after == original)
            if not receipt['originalUnchanged']:
                receipt['status'] = 'FAILED_ORIGINAL_CHANGED_EXTERNALLY'
        except (OSError, ValueError) as error:
            receipt.update(originalUnchanged=None, originalRecheckError=type(error).__name__,
                           status='FAILED_ORIGINAL_RECHECK_UNKNOWN')
        (output / 'return.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if receipt.get('originalUnchanged') is not True:
        raise RuntimeError('Original tools recheck failed; inspect return.json')
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools-image', required=True)
    parser.add_argument('--tools-sha256', required=True)
    parser.add_argument('--source', required=True, help='clean core checkout containing tools-image/')
    parser.add_argument('--output', required=True, help='NEW absolute safe-ASCII directory outside source')
    checker_input = parser.add_mutually_exclusive_group(required=True)
    checker_input.add_argument('--go', help='existing real native Go executable')
    checker_input.add_argument('--dax-check', help='existing prebuilt ARM64 checker; no Go execution')
    parser.add_argument('--dax-check-sha256', help='required exact SHA256 with --dax-check')
    parser.add_argument('--debugfs', required=True, help='existing real native debugfs executable')
    parser.add_argument('--tools-version', required=True, help='distinct custom prerelease SemVer')
    parser.add_argument('--mode', choices=['runtime', 'dax-selftest'], default='runtime')
    parser.add_argument('--lower-filesystem', choices=['erofs', 'ext4'], default='erofs')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args(argv)
    result = prepare(args)
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    main()
