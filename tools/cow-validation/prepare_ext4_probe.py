"""Create new regular-file ext4 artifacts for a bounded DAX mechanism test.

No mounts, devices, SDK calls or Guest creation. This synthetic input proves no
application workload or net memory saving. Original deployment images stay intact.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024**2), b''):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mkfs-ext4', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    output = Path(args.output).absolute()
    if (not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(output)) or '..' in output.parts
            or output.resolve() != output or output.exists()):
        raise ValueError('Output must be a new absolute directory without redirection')
    plan = {'revision': 'ext4-dax-probe-input-v1', 'output': str(output),
            'lowerBytes': 64 * 1024**2, 'upperBytes': 64 * 1024**2,
            'payloadBytes': 8 * 1024**2, 'SDK_called': False, 'Guest_created': False,
            'syntheticMechanismInputOnly': True, 'memorySavingAccepted': False,
            'status': 'PLAN_ONLY'}
    if not args.run:
        print(json.dumps(plan, indent=2))
        return 0
    if sys.platform != 'linux' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise RuntimeError('Ordinary Linux user only')
    caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if any(int(caps[key].strip(), 16) for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')):
        raise RuntimeError('Zero capabilities required')
    tool = Path(args.mkfs_ext4).resolve(strict=True)
    with tool.open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            raise ValueError('Explicit real mkfs.ext4 ELF required')
    os.umask(0o077)
    output.mkdir(mode=0o700)
    root = output / 'lower-files'
    root.mkdir(mode=0o700)
    (root / '.aenv-dax-probe').write_bytes(b'AgentENV immutable DAX base\n' * 160)
    with (root / 'common-data.bin').open('xb') as stream:
        block = hashlib.shake_256(b'AgentENV deterministic mechanism input v1').digest(1024**2)
        for unused in range(8):
            stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())
    before = {p.name: sha(p) for p in root.iterdir()}
    artifacts = {}
    for kind in ('lower', 'upper'):
        image = output / (kind + '.ext4')
        fd = os.open(image, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.ftruncate(fd, plan[kind + 'Bytes'])
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise RuntimeError('New image is not a regular file')
            os.fsync(fd)
        finally:
            os.close(fd)
        command = [str(tool), '-F', '-q', '-t', 'ext4', '-b', '4096', '-m', '0',
                   '-O', '^has_journal,^orphan_file,^inline_data',
                   '-E', 'lazy_itable_init=0,lazy_journal_init=0', '-L', 'aenv_' + kind]
        if kind == 'lower':
            command += ['-d', str(root)]
        command += [str(image)]
        with (output / (kind + '-mkfs.log')).open('xb') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=120)
        if result.returncode:
            raise RuntimeError('mkfs failed; new private artifacts preserved; inspect its own log')
        artifacts[kind] = {'path': str(image), 'sha256': sha(image), 'bytes': image.stat().st_size}
    if before != {p.name: sha(p) for p in root.iterdir()}:
        raise RuntimeError('Input files changed')
    plan.update(status='SYNTHETIC_EXT4_ARTIFACTS_READY_NOT_GUEST_PASS', artifacts=artifacts, sourceFiles=before)
    with (output / 'return.json').open('x') as stream:
        json.dump(plan, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(plan, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
