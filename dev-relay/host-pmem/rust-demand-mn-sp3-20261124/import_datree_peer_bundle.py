import argparse
import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

WORK = Path('/opt/aenv-datree-import-001')
STORE = WORK / 'snapshot-store'
REPO = STORE / 'repository'
REMOTE = 'jwk@90.96.12.112:/opt/aenv-datree-relay-001/datree-peer.tar'
BUNDLE = {'bytes': 77189120, 'sha256': '32b74ecd535e7f197a9bbe86f3894dfd6c8927a4ddc5a676f3cdd6c168761721', 'members': {'catalog/aliases/datree-mn-n': {'bytes': 38, 'sha256': 'b373186ff776b42dde34e394905f2aba5368941bc9f940d57cf5b91f9a085be4'}, 'catalog/records/01a21c5a-b2bf-7400-94a3-f860187d7df7.json': {'bytes': 3583, 'sha256': '9d1e1c460e67f8c9edd8a22680e88c1d2c0e7758205cdcd6fd61365f97b62974'}, 'managed-layers/sha256_b305d5528b9adc7f36e597eec3e3c4d85f32733c0a4e446da1164fbfe2bd74fc.overlaybd.commit': {'bytes': 77123584, 'sha256': 'b305d5528b9adc7f36e597eec3e3c4d85f32733c0a4e446da1164fbfe2bd74fc'}, 'managed-layers/sha256_c767eb485d3227ea45728d33be9ef6de57437c40aabf9a737f600f67bcdfc658.overlaybd.commit': {'bytes': 28672, 'sha256': 'c767eb485d3227ea45728d33be9ef6de57437c40aabf9a737f600f67bcdfc658'}, 'snapshots/01a21c5a-b2bf-7400-94a3-f860187d7df7/commit': {'bytes': 9, 'sha256': 'cc962289af2873dd6dad32931554372a7d2d2de5bd5859c8265eb58b5197a88e'}, 'snapshots/01a21c5a-b2bf-7400-94a3-f860187d7df7/firecracker-manifest.json': {'bytes': 243, 'sha256': 'e7256f788f0f6a70115fac26646859c15a497388bab46a44d781e244713c6fcc'}, 'snapshots/01a21c5a-b2bf-7400-94a3-f860187d7df7/vm_state.bin': {'bytes': 12024, 'sha256': 'ac556b4ce8c885e79603f0317be29cc636928302cad519f13352340e3dd2fb0d'}}, 'templateId': '01a21c5a-b2bf-7400-94a3-f860187d7df7'}
SHARED = [('/home/jwk/agent/sp3-mn/mn-tcap-004/h/snapshot-store/repository/managed-layers/sha256_a9aa9dd5b3f33e978a4d289b59f1b08a367e0247005aa18da5336ab26afc1187.overlaybd.commit', 151735296, 'a9aa9dd5b3f33e978a4d289b59f1b08a367e0247005aa18da5336ab26afc1187'), ('/home/jwk/agent/sp3-mn/mn-tcap-004/h/snapshot-store/repository/managed-layers/sha256_f24ba1ad4d02e8ae08b6ba86d4ae66321c95e495ab7acbc8dbfe0ac2a689ae37.overlaybd.commit', 385143808, 'f24ba1ad4d02e8ae08b6ba86d4ae66321c95e495ab7acbc8dbfe0ac2a689ae37'), ('/home/jwk/agent/sp3-mn/mn-tcap-004/h/snapshot-store/repository/managed-layers/sha256_ac6c75b85ae40dfa6a1cfc1276f348944aedfcad36520aa6169c5575e5c2f0ea.overlaybd.commit', 451728384, 'ac6c75b85ae40dfa6a1cfc1276f348944aedfcad36520aa6169c5575e5c2f0ea'), ('/home/jwk/agent/sp3-mn/mn-tcap-004/h/snapshot-store/repository/managed-layers/sha256_977e2cd00fcf337e5a15eb35a2f0f312711aea8f1ea9d60744ec03dbf88b4dbe.overlaybd.commit', 46080, '977e2cd00fcf337e5a15eb35a2f0f312711aea8f1ea9d60744ec03dbf88b4dbe'), ('/home/jwk/agent/sp3-mn/mn-tcap-004/h/snapshot-store/repository/managed-layers/sha256_b31884184b792e2316a4758d9a93027b79fcaa2dbe904e3c953220a2677a5ab4.overlaybd.commit', 68604928, 'b31884184b792e2316a4758d9a93027b79fcaa2dbe904e3c953220a2677a5ab4'), ('/home/jwk/agent/sp3-mn/mn-tcap-004/h/snapshot-store/repository/managed-layers/sha256_fee8796bb532008aa4fdc0d093cb5ff3010431feeac6024a9741348a7ce8c752.overlaybd.commit', 760665088, 'fee8796bb532008aa4fdc0d093cb5ff3010431feeac6024a9741348a7ce8c752'), ('/home/jwk/agent/sp3-mn/mn-tcap-004/h/snapshot-store/repository/managed-layers/sha256_9557eff6b8cc215acd2e7c544eb49c9938a2b622cf3ea3d62b9c6a863671ec8e.overlaybd.commit', 46080, '9557eff6b8cc215acd2e7c544eb49c9938a2b622cf3ea3d62b9c6a863671ec8e')]


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    state = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            state.update(block)
    return state.hexdigest()


def verify(path, size, digest):
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
         and info.st_size == size and sha(path) == digest, 'File verification failed: ' + str(path))


def main():
    parser = argparse.ArgumentParser(description='Fetch and import the N Datree snapshot on M')
    for option in ('node', 'boot-id', 'machine-id'):
        parser.add_argument('--' + option, required=True)
    args = parser.parse_args()
    need(os.geteuid() == 0 and args.node == os.uname().nodename.split('.')[0] == 'agent1'
         and args.boot_id == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
         and args.machine_id == Path('/etc/machine-id').read_text().strip(), 'M identity differs')
    user = pwd.getpwnam('jwk')
    need((user.pw_uid, user.pw_gid) == (1204,1205), 'Unexpected SCP account')
    os.umask(0o077)
    info = WORK.parent.lstat()
    need(WORK.parent.resolve(strict=True) == WORK.parent and stat.S_ISDIR(info.st_mode)
         and info.st_uid == 0 and not info.st_mode & 0o022, 'Unexpected staging parent')
    need(not os.path.lexists(WORK), 'Datree staging already exists; preserve it for reconciliation')
    need(shutil.disk_usage(WORK.parent).free > sum(x[1] for x in SHARED) + 2 * BUNDLE['bytes'] + 32*1024**2,
         'Insufficient space for separate Datree snapshot store')
    with open('/dev/tty', 'r+b', buffering=0) as tty:
        WORK.mkdir(mode=0o700)
        intake = WORK / 'incoming'
        intake.mkdir(mode=0o700)
        os.chown(intake, user.pw_uid, user.pw_gid)
        os.chown(WORK, 0, user.pw_gid)
        WORK.chmod(0o750)
        bundle = intake / 'datree-peer.tar'
        tty.write(b'Pulling Datree bundle from N as jwk; enter the N SSH password if prompted.\n')
        subprocess.run(['/usr/sbin/runuser', '-u', 'jwk', '--', '/usr/bin/scp',
                        '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15',
                        '--', REMOTE, str(bundle)], stdin=tty, stdout=tty, stderr=tty,
                       check=True, timeout=480)
    protected = WORK / 'datree-peer.tar'
    with os.fdopen(os.open(bundle, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size == BUNDLE['bytes'],
             'SCP bundle type or size differs')
        with protected.open('xb') as destination:
            remaining = BUNDLE['bytes']
            while remaining:
                block = source.read(min(1024*1024, remaining))
                need(block, 'SCP bundle was truncated')
                destination.write(block)
                remaining -= len(block)
            need(not source.read(1), 'SCP bundle grew')
    verify(protected, BUNDLE['bytes'], BUNDLE['sha256'])

    REPO.mkdir(parents=True)
    expected = BUNDLE['members']
    seen = set()
    with tarfile.open(protected, 'r:') as archive:
        for member in archive:
            need(member.name in expected and member.name not in seen and member.isfile(),
                 'Unexpected or duplicate bundle member')
            facts = expected[member.name]
            need(member.size == facts['bytes'], 'Bundle member size differs')
            dest = REPO / member.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, dest.open('xb') as out:
                shutil.copyfileobj(source, out, 1024 * 1024)
            verify(dest, facts['bytes'], facts['sha256'])
            seen.add(member.name)
    need(seen == set(expected), 'Bundle member set is incomplete')
    for source_path, size, digest in SHARED:
        source = Path(source_path)
        dest = REPO / 'managed-layers' / source.name
        need(source.resolve(strict=True) == source and stat.S_ISREG(source.lstat().st_mode),
             'Unexpected shared lower source')
        with source.open('rb') as stream, dest.open('xb') as out:
            shutil.copyfileobj(stream, out, 1024 * 1024)
        verify(dest, size, digest)

    for path in sorted(STORE.rglob('*'), reverse=True):
        os.chown(path, user.pw_uid, user.pw_gid)
    os.chown(STORE, user.pw_uid, user.pw_gid)
    print(json.dumps({'status': 'MN_DATREE_CANONICAL_IMPORTED', 'node': args.node,
                      'templateId': BUNDLE['templateId'], 'store': str(STORE),
                      'bundleSha256': BUNDLE['sha256'], 'verifiedLowerCount': len(SHARED) + 1}),
          flush=True)


if __name__ == '__main__':
    main()
