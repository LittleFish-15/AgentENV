"""Continue after successful resize; do not copy/hash 64 GiB or resize again."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import stat

ROOT = Path('/home/jwk/agent')
OLD = ROOT / 'builds/rootfs-compact-v1'
OUT = ROOT / 'builds/rootfs-compact-finish-v2'
TARGET = OLD / 'rootfs.ext4'
SCRIPT_SHA = '0e75934e9ea96dfa31a30fca4196fd17e8c7305d7cfbff965052e37df100a17b'
PINS = {'e2fsck': 'a37be5aaabeeb8f431719c29875ea41eb07b49f7112fd88413f9c598bf454fb9',
        'resize2fs': 'eb8102cf354f6895dc14df26bf63790016482eed8ecb6a4d7ab1d6e7144084f1',
        'debugfs': 'bc53991ef4ee2d20a8c27b7aeed2e2c59cb40d5291292d1742ee01bd4ca50707'}


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def check_prior(value):
    need(value.get('revision') == 'A-rootfs-compact-v1'
         and value.get('status') == 'STOPPED_COMPACTION_PRESERVE_ORIGINAL_AND_PARTIAL_COPY'
         and value.get('reason') == 'Filesystem identity or allocated inode count changed'
         and value.get('workDirectory') == str(OLD), 'Different prior attempt; preserved')
    required = ('readonly-fsck-before', 'before-sample-0', 'before-sample-1', 'before-sample-2',
                'record-clean-check-on-own-copy', 'resize-own-copy-minimum')
    need(set(value.get('phases', {})) == set(required)
         and all(value['phases'][x].get('exitCode') == 0 for x in required), 'Prior resize did not complete cleanly')
    need(value.get('sourceSha256') == '1dccd99cbf5d1ae8f316a2f03c1551676deabdb49cd157b384985aab082a53b7'
         and value.get('sourceImage') == 'sha256:cf786498f77bf4ba6235156ab8540d0b9335e874e70b95efbeb53168e0dce68d',
         'Prior image differs')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    report = {'revision': 'A-finish-compact-rootfs-v2', 'status': 'PLAN_ONLY', 'workDirectory': str(OUT),
              'SDK_called': False, 'Guest_created': False, 'servicesChanged': False, 'mounted': False,
              'ublkDevicesCreated': 0, 'UB_published': False, 'nativeBindingAccepted': False,
              'resizeRepeated': False, 'full64GiBCopyOrHashRepeated': False, 'phases': {}}
    if not args.run:
        print(json.dumps(report, indent=2)); return 0
    made = False
    try:
        need(platform.system() == 'Linux' and platform.machine() == 'aarch64' and socket.gethostname() == 'server1', 'Use ARM64 node A')
        need(os.getuid() == os.geteuid() == 1204 and os.getgid() == os.getegid() == 1205, 'Use ordinary jwk')
        caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        need(all(int(caps[k].strip(), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), 'Zero capabilities required')
        helper = ROOT / 'A_compact_real_rootfs_v1.py'
        need(helper.resolve(strict=True) == helper and helper.is_file() and helper.stat().st_size == 14380, 'Prior helper identity differs')
        raw = helper.read_bytes()
        need(hashlib.sha256(raw).hexdigest() == SCRIPT_SHA, 'Prior helper hash differs')
        m = {'__name__': 'verified_compaction_helpers'}
        exec(compile(raw, str(helper), 'exec'), m)
        read, safe, stamp = m['read'], m['safe'], m['stamp']
        prior = check_prior(json.loads(read(OLD / 'return.json')))
        safe(TARGET)
        original_stamp = stamp(safe(m['SOURCE']).stat())
        target_stamp = TARGET.stat()
        need(stat.S_ISREG(target_stamp.st_mode) and target_stamp.st_uid == 1204 and target_stamp.st_nlink == 1
             and not os.path.samefile(TARGET, m['SOURCE']), 'Not the separate owned resized copy')
        need(OUT.parent.resolve(strict=True) == OUT.parent and not OUT.exists() and not OUT.is_symlink(), 'Finish output already exists')
        need(m['shutil'].disk_usage(ROOT).free >= 4 * 1024**3, '4 GiB free disk required')
        for name, pin in PINS.items():
            need(m['sha_file'](m['NATIVE'] / 'bin' / name, 64 * 1024**2) == pin, 'Installed filesystem tool changed')
        os.umask(0o077); OUT.mkdir(mode=0o700); made = True
        m['WORK'] = OUT
        report['beforeResize'] = prior['before']
        after = m['superblock'](TARGET)
        report['afterResize'] = after
        report['allocatedInodeCountDeltaObserved'] = after['allocatedInodes'] - prior['before']['allocatedInodes']
        report['uuidChangedObserved'] = after['uuid'] != prior['before']['uuid']
        # resize2fs may normalize an all-zero UUID. A preexisting nonzero identity
        # must not change. Counts are observations; fsck and content checks decide.
        need(not report['uuidChangedObserved'] or prior['before']['uuid'] == '0' * 32,
             'Nonzero filesystem UUID changed; inspection required')
        m['padded_length'](after['filesystemBytes'])
        env = {'PATH': str(m['NATIVE'] / 'bin') + ':/usr/bin:/bin', 'HOME': str(Path.home()), 'LANG': 'C',
               'LC_ALL': 'C', 'TMPDIR': str(OUT), 'LD_LIBRARY_PATH': str(m['NATIVE'] / 'lib') + ':' + str(m['NATIVE'] / 'fallback/lib')}
        run = lambda argv, name: m['run'](argv, name, env, report)
        fsck, debug = m['NATIVE'] / 'bin/e2fsck', m['NATIVE'] / 'bin/debugfs'
        run([str(fsck), '-f', '-n', str(TARGET)], 'readonly-check-resized-copy')
        source_samples = m['samples'](debug, m['SOURCE'], 'source', env, report)
        copied_samples = m['samples'](debug, TARGET, 'resized', env, report)
        need(source_samples == copied_samples, 'Workload content differs after resize')
        for index, guest_path in enumerate(m['SAMPLES']):
            old_sample = read(OLD / ('before-sample-' + str(index)), 4 * 1024**2)
            need(hashlib.sha256(old_sample).hexdigest() == source_samples[guest_path]['sha256'], 'Prior sample changed')
        report['sampleFiles'] = copied_samples
        report['sampleFilesUnchanged'] = True
        # Add the required nonempty DAX test marker only if absent. No other
        # guest file is modified, and original source remains immutable.
        run([str(debug), '-R', 'stat /.aenv-dax-probe', str(TARGET)], 'probe-stat')
        probe_stat = (OUT / 'probe-stat.log').read_text(errors='replace')
        if 'File not found by ext2_lookup' in probe_stat:
            probe = OUT / 'dax-probe'
            probe.write_bytes(b'AgentENV immutable DAX rootfs probe v1\n')
            run([str(debug), '-w', '-R', 'write ' + str(probe) + ' /.aenv-dax-probe', str(TARGET)], 'add-own-copy-dax-probe')
            expected_probe = hashlib.sha256(probe.read_bytes()).hexdigest()
            report['daxProbeAdded'] = True
        else:
            need('Type: regular' in probe_stat, 'Existing DAX marker is not a regular file')
            expected_probe = None
            report['daxProbeAdded'] = False
        probe_copy = OUT / 'verified-dax-probe'
        run([str(debug), '-R', 'dump /.aenv-dax-probe ' + str(probe_copy), str(TARGET)], 'verify-dax-probe')
        probe_data = read(probe_copy, 1024 * 1024)
        probe_sha = hashlib.sha256(probe_data).hexdigest()
        need(expected_probe is None or probe_sha == expected_probe, 'DAX probe write failed')
        report['daxProbeSha256'] = probe_sha
        run([str(fsck), '-f', '-n', str(TARGET)], 'readonly-check-with-probe')
        after = m['superblock'](TARGET)
        length = m['padded_length'](after['filesystemBytes'])
        need(TARGET.stat().st_size >= after['filesystemBytes'], 'Container shorter than resized filesystem')
        with TARGET.open('r+b') as stream:
            stream.truncate(length); stream.flush(); os.fsync(stream.fileno())
        run([str(fsck), '-f', '-n', str(TARGET)], 'readonly-check-aligned-final')
        report['finalImage'] = {'path': str(TARGET), 'bytes': length, 'sha256': 'sha256:' + m['sha_file'](TARGET, 4 * 1024**3),
                                'filesystemBytes': after['filesystemBytes'], 'allocatedFileBytes': TARGET.stat().st_blocks * 512}
        need(stamp(safe(m['SOURCE']).stat()) == original_stamp, 'Original source metadata changed')
        report['originalImageUnchangedDuringFinish'] = True
        report['sourceImage'] = prior['sourceImage']
        report['scope'] = 'Clean filesystem, three workload sample hashes and added/preserved DAX marker; not full-tree equivalence or Guest acceptance'
        report['status'] = 'REAL_ROOTFS_READY_FOR_UB_PUBLICATION_NOT_YET_PUBLISHED'
    except BaseException as error:
        report.update(status='STOPPED_FINISH_PRESERVE_ALL_EVIDENCE', errorType=type(error).__name__, reason=str(error)[:1500])
    finally:
        if made:
            with (OUT / 'return.json').open('x') as stream: json.dump(report, stream, indent=2)
        print('BEGIN_A_ROOTFS_FINISH_REPORT'); print(json.dumps(report, indent=2)); print('END_A_ROOTFS_FINISH_REPORT')
    return 0 if report['status'] == 'REAL_ROOTFS_READY_FOR_UB_PUBLICATION_NOT_YET_PUBLISHED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
