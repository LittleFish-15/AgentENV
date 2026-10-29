"""Bounded read-only discovery of current kernel build materials; never load modules."""
import argparse
from collections import deque
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import time

FLAGS = ('CONFIG_ARM64', 'CONFIG_MODULES', 'CONFIG_MODVERSIONS', 'CONFIG_BLK_DEV_UBLK',
         'CONFIG_KVM', 'CONFIG_DAX', 'CONFIG_FS_DAX', 'CONFIG_FS_DAX_LIMITED', 'CONFIG_EXT4_FS',
         'CONFIG_LOCALVERSION', 'CONFIG_MODULE_SIG_FORCE')
FILES = ('.config', 'Module.symvers', 'include/generated/utsrelease.h',
         'drivers/ub/obmm/obmm_core.c', 'drivers/ub/obmm/obmm_shm_dev.c',
         'drivers/block/ublk_drv.c')


def read(path, limit=2 * 1024**2):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as stream:
        a = os.fstat(stream.fileno())
        if not stat.S_ISREG(a.st_mode) or a.st_size > limit:
            raise ValueError('Unsupported read-only metadata type/size')
        raw = stream.read(limit + 1)
        b = os.fstat(stream.fileno())
    if len(raw) > limit or (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) != (
            b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns):
        raise ValueError('Metadata changed or exceeds limit')
    return raw


def config_fields(raw):
    text = raw.decode('utf-8', 'replace')
    return {name: (match.group(1) if (match := re.search(r'^' + name + r'=(.*)$', text, re.M))
                   else 'n' if re.search(r'^# ' + name + r' is not set$', text, re.M) else None)
            for name in FLAGS}


def config_info(path):
    try:
        raw = read(path)
        if str(path).endswith('.gz'):
            # Bound expansion; do not blindly decompress arbitrary-size input.
            import io
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                raw = stream.read(2 * 1024**2 + 1)
            if len(raw) > 2 * 1024**2:
                raise ValueError('Config expansion exceeds limit')
        return {'path': str(path), 'present': True, 'sha256': hashlib.sha256(raw).hexdigest(),
                'flags': config_fields(raw)}
    except (OSError, ValueError, EOFError) as error:
        return {'path': str(path), 'present': False, 'errorType': type(error).__name__}


def candidate(directory):
    p = Path(directory)
    present = {name: (p / name).is_file() for name in FILES}
    source = (p / 'Makefile').is_file() and (p / 'Kconfig').is_file() and (p / 'include/linux').is_dir()
    build = present['Module.symvers'] or present['include/generated/utsrelease.h']
    if not (source or build):
        return None
    result = {'path': str(p), 'resolved': str(p.resolve()), 'sourceCandidate': source,
              'buildCandidate': build, 'files': present, 'matchesRunningKernelConfirmed': False}
    if present['.config']:
        result['config'] = config_info(p / '.config')
    for name in ('include/generated/utsrelease.h', 'include/config/kernel.release'):
        try:
            result[name] = read(p / name, 4096).decode('utf-8', 'replace').strip()
        except (OSError, ValueError):
            pass
    return result


def search(roots, max_dirs=256, seconds=12):
    queue = deque((Path(root), 0) for root in roots)
    checked = set()
    found = []
    skipped = 0
    bounded = False
    end = time.monotonic() + seconds
    excluded = {'.git', '.cache', 'node_modules', 'target', 'snapshots', 'managed-layers', '__pycache__'}
    while queue and len(checked) < max_dirs and time.monotonic() < end:
        p, depth = queue.popleft()
        if p.is_symlink() or not p.is_dir():
            continue
        canonical = str(p.resolve())
        if canonical in checked:
            continue
        checked.add(canonical)
        try:
            hit = candidate(p)
            if hit:
                found.append(hit)
                continue
            if depth >= 3:
                continue
            with os.scandir(p) as entries:
                for i, entry in enumerate(entries):
                    if i >= 512:
                        bounded = True
                        break
                    if entry.name in excluded or entry.name.startswith('.') or not entry.is_dir(follow_symlinks=False):
                        continue
                    if depth < 2 or re.search(r'linux|kernel|src|source|build|repo|work|git|org1028', entry.name, re.I):
                        queue.append((Path(entry.path), depth + 1))
        except (OSError, ValueError):
            skipped += 1
    return {'roots': [str(x) for x in roots], 'candidateTrees': found, 'directoriesChecked': len(checked),
            'errorsOrDeniedDirectories': skipped, 'budgetReached': bounded or bool(queue),
            'coverage': 'Bounded metadata search, depth <=3; no result does not prove source absent'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-host', required=True)
    parser.add_argument('--expected-kernel', required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise RuntimeError('Run as root for read-only metadata access')
    if platform.node() != args.expected_host or platform.release() != args.expected_kernel:
        raise RuntimeError('Current host or kernel differs; preserve state')
    release = platform.release()
    base = Path('/lib/modules') / release
    result = {'status': 'D_KERNEL_MATERIALS_INSPECTED_NO_ACTION', 'hostname': platform.node(),
              'kernel': release, 'kernelBuildDescription': platform.version(),
              'SDK_called': False, 'moduleLoaded': False, 'servicesChanged': False, 'filesModified': False,
              'configs': [config_info('/boot/config-' + release), config_info('/proc/config.gz')],
              'standardTrees': {}, 'ublk': {}}
    for name in ('build', 'source'):
        path = base / name
        result['standardTrees'][name] = {'exists': path.exists(), 'resolved': str(path.resolve()),
                                         'candidate': candidate(path) if path.is_dir() else None}
    for name in ('modules.builtin', 'modules.dep'):
        try:
            result['ublk'][name] = [line for line in read(base / name, 4 * 1024**2).decode('utf-8', 'replace').splitlines()
                                    if 'ublk' in line][:32]
        except (OSError, ValueError) as error:
            result['ublk'][name] = {'errorType': type(error).__name__}
    result['ublk']['moduleSysfsPresent'] = Path('/sys/module/ublk_drv').is_dir()
    result['ublk']['controlDevicePresent'] = Path('/dev/ublk-control').exists()
    result['ublk']['controlSysfsPresent'] = Path('/sys/class/misc/ublk-control').exists()
    result['installedModuleDirectories'] = sorted(p.name for p in Path('/lib/modules').iterdir() if p.is_dir())[:32]
    result['search'] = search(('/usr/src', '/root', '/home', '/opt', '/data', '/data1', '/workspace', '/build'))
    print('BEGIN_D_KERNEL_MATERIALS')
    print(json.dumps(result, indent=2))
    print('END_D_KERNEL_MATERIALS')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'D_KERNEL_INSPECTION_STOPPED_NO_ACTION', 'errorType': type(error).__name__, 'reason': str(error)}))
        raise SystemExit(1)
