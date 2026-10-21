"""Prepare an unpublished own rootfs copy with the v3 DAX execution marker.

No SDK, mount, Guest, service operation or kernel modification. The tiny Guest
executable is compiled and inspected here, but is executed only by Runtime
readiness inside the eventual Guest. Existing input images remain unchanged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import struct
import sys

ROOT = Path('/home/jwk/agent')
WORK = ROOT / 'builds/rootfs-exec-v3'
FINISH = ROOT / 'builds/rootfs-compact-finish-v2/return.json'
HELPER_PIN = '0e75934e9ea96dfa31a30fca4196fd17e8c7305d7cfbff965052e37df100a17b'
TOOL_PINS = {'e2fsck': 'a37be5aaabeeb8f431719c29875ea41eb07b49f7112fd88413f9c598bf454fb9',
             'debugfs': 'bc53991ef4ee2d20a8c27b7aeed2e2c59cb40d5291292d1742ee01bd4ca50707'}


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def inspect_probe(data):
    need(64 <= len(data) <= 1024**2 and data[:6] == b'\x7fELF\x02\x01', 'Expected bounded little-endian ELF64')
    need(data[6] == 1 and struct.unpack_from('<I', data, 20)[0] == 1, 'Unsupported ELF version')
    need(struct.unpack_from('<HH', data, 16) == (2, 183), 'Expected static AArch64 executable')
    entry, phoff = struct.unpack_from('<QQ', data, 24)
    phentsize, phnum = struct.unpack_from('<HH', data, 54)
    need(phoff >= 64 and phentsize == 56 and 0 < phnum <= 16 and phoff + phnum * phentsize <= len(data), 'Invalid program headers')
    entries = []
    for i in range(phnum):
        kind, flags, offset, va, _, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)
        need(kind != 3, 'Interpreter dependency is not allowed')
        if kind == 1:
            need(not flags & 2 and offset + filesz <= len(data) and filesz <= memsz, 'Writable or invalid load segment')
            if flags & 1 and va <= entry < va + filesz:
                entries.append(offset + entry - va)
    need(len(entries) == 1, 'Unique executable entry required')
    instructions = data[entries[0]:entries[0] + 12]
    need(instructions == struct.pack('<III', 0xd2800920, 0xd2800ba8, 0xd4000001), 'Probe is not exactly exit(73) at entry')
    return {'machine': 'aarch64', 'entry': entry, 'expectedExit': 73, 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(), 'hostExecuted': False, 'GuestExecuted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='Reviewed released assembly source')
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    report = {'revision': 'A-exec-image-v1', 'status': 'PLAN_ONLY', 'workDirectory': str(WORK),
              'SDK_called': False, 'Guest_created': False, 'servicesChanged': False, 'mounted': False,
              'UB_published': False, 'nativeBindingAccepted': False, 'phases': {}}
    if not args.run:
        print(json.dumps(report, indent=2)); return 0
    made = False
    try:
        need(platform.system() == 'Linux' and platform.machine() == 'aarch64' and socket.gethostname() == 'server1', 'Use ARM64 node A')
        need(os.getuid() == os.geteuid() == 1204 and os.getgid() == os.getegid() == 1205, 'Use ordinary jwk')
        caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        need(all(int(caps[k].strip(), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), 'Zero capabilities required')
        helper = ROOT / 'A_compact_real_rootfs_v1.py'
        need(helper.resolve(strict=True) == helper and helper.stat().st_size == 14380, 'Prior helper differs')
        raw = helper.read_bytes(); need(hashlib.sha256(raw).hexdigest() == HELPER_PIN, 'Helper pin differs')
        m = {'__name__': 'verified_helpers'}; exec(compile(raw, str(helper), 'exec'), m)
        m['WORK'] = WORK
        finish = json.loads(m['read'](FINISH))
        need(finish.get('status') == 'REAL_ROOTFS_READY_FOR_UB_PUBLICATION_NOT_YET_PUBLISHED'
             and finish.get('UB_published') is False and finish.get('sampleFilesUnchanged') is True,
             'Successful unpublished image finish required')
        source = Path(finish['finalImage']['path']); m['safe'](source)
        need(source == ROOT / 'builds/rootfs-compact-v1/rootfs.ext4', 'Unexpected image source')
        source_stamp = m['stamp'](source.stat())
        need(0 < source.stat().st_size <= 4 * 1024**3 and source.stat().st_size == finish['finalImage']['bytes'], 'Source length differs')
        code = m['read'](args.source, 16384)
        need(hashlib.sha256(code).hexdigest() == args.source_sha256, 'Assembly source pin differs')
        need(WORK.parent.resolve(strict=True) == WORK.parent and not WORK.exists() and not WORK.is_symlink(), 'New output directory required')
        need(shutil.disk_usage(ROOT).free >= 8 * 1024**3, '8 GiB disk headroom required')
        tools = {name: m['NATIVE'] / 'bin' / name for name in TOOL_PINS}
        for name, path in tools.items(): need(m['sha_file'](path, 64 * 1024**2) == TOOL_PINS[name], 'Installed tool changed: ' + name)
        cc = shutil.which('gcc', path='/usr/local/bin:/usr/bin:/bin')
        need(cc is not None, 'Existing native compiler required')
        os.umask(0o077); WORK.mkdir(mode=0o700); made = True
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(Path.home()), 'LANG': 'C', 'LC_ALL': 'C',
               'TMPDIR': str(WORK), 'LD_LIBRARY_PATH': str(m['NATIVE'] / 'lib') + ':' + str(m['NATIVE'] / 'fallback/lib')}
        run = lambda argv, name: m['run'](argv, name, env, report)
        probe = WORK / 'dax-exec'
        run([cc, '-nostdlib', '-static', '-no-pie', '-Wl,--build-id=none', '-Wl,-z,max-page-size=4096',
             str(args.source), '-o', str(probe)], 'compile-guest-execution-probe')
        probe_bytes = m['read'](probe, 1024**2); report['probe'] = inspect_probe(probe_bytes)
        target = WORK / 'rootfs.ext4'
        print('PHASE=copy_verified_compact_image_not_64GiB_source', flush=True)
        need('sha256:' + m['sha_file'](source, 4 * 1024**3, target) == finish['finalImage']['sha256'], 'Compacted input changed')
        run([str(tools['e2fsck']), '-f', '-n', str(target)], 'readonly-image-check-before')
        run([str(tools['debugfs']), '-R', 'stat /.aenv-dax-exec', str(target)], 'existing-executable-stat')
        text = (WORK / 'existing-executable-stat.log').read_text(errors='replace')
        if 'File not found by ext2_lookup' in text:
            run([str(tools['debugfs']), '-w', '-R', 'write ' + str(probe) + ' /.aenv-dax-exec', str(target)], 'write-own-image-executable')
        else:
            need('Type: regular' in text, 'Reserved executable path already has a nonregular inode')
        copied = WORK / 'verified-dax-exec'
        run([str(tools['debugfs']), '-R', 'dump /.aenv-dax-exec ' + str(copied), str(target)], 'readback-executable')
        need(m['read'](copied, 1024**2) == probe_bytes, 'Reserved executable differs or image has insufficient space')
        run([str(tools['debugfs']), '-w', '-R', 'set_inode_field /.aenv-dax-exec mode 0100555', str(target)], 'set-executable-mode')
        run([str(tools['debugfs']), '-R', 'stat /.aenv-dax-exec', str(target)], 'verify-executable-mode')
        import re
        inode = (WORK / 'verify-executable-mode.log').read_text(errors='replace')
        need('Type: regular' in inode and re.search(r'Mode:\s+0?555\b', inode), 'Executable mode not verified')
        run([str(tools['e2fsck']), '-f', '-n', str(target)], 'readonly-image-check-final')
        samples = m['samples'](tools['debugfs'], target, 'final', env, report)
        need(samples == finish['sampleFiles'], 'Workload samples changed while inserting executable')
        need(m['stamp'](source.stat()) == source_stamp, 'Input image metadata changed')
        need(target.stat().st_size % (2 * 1024**2) == 0, 'Final image lost pmem alignment')
        report.update(sourceImage=finish['sourceImage'], sampleFiles=samples, sourcePreserved=True,
                      finalImage={'path': str(target), 'bytes': target.stat().st_size,
                                  'sha256': 'sha256:' + m['sha_file'](target, 4 * 1024**3),
                                  'allocatedFileBytes': target.stat().st_blocks * 512},
                      status='V3_EXECUTABLE_IMAGE_PREPARED_GUEST_EXECUTION_PENDING')
    except BaseException as error:
        report.update(status='STOPPED_EXEC_IMAGE_PRESERVE_ALL_INPUTS', errorType=type(error).__name__, reason=str(error)[:1500])
    finally:
        if made:
            with (WORK / 'return.json').open('x') as stream: json.dump(report, stream, indent=2)
        print('BEGIN_EXEC_IMAGE_REPORT'); print(json.dumps(report, indent=2)); print('END_EXEC_IMAGE_REPORT')
    return 0 if report['status'] == 'V3_EXECUTABLE_IMAGE_PREPARED_GUEST_EXECUTION_PENDING' else 1


if __name__ == '__main__': raise SystemExit(main())
