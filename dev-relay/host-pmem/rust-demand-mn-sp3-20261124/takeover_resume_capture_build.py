"""Resume the native capture executable build in a jwk-owned release cache."""

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path


SOURCE = Path('/home/jwk/agent/sp3-mn/src/AgentENV')
CAPTURE = Path('/home/jwk/agent/sp3-mn/relay-guest-assets-001/template-capture-001')
TOOLCHAIN = Path('/home/jwk/.local/rustup/bin')
HEAD = '207462625ee21d669ddfc34cbfd47932f5a757b7'
ENV = {'PATH': str(TOOLCHAIN) + ':/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/home/jwk',
       'LANG': 'C', 'LC_ALL': 'C', 'CARGO_NET_OFFLINE': 'true', 'CARGO_BUILD_JOBS': '4',
       'LIBCLANG_PATH': '/usr/lib64', 'RUSTC': str(TOOLCHAIN / 'rustc'), 'GIT_OPTIONAL_LOCKS': '0'}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-sha', required=True)
    args = parser.parse_args()
    need(os.geteuid() == 0 and os.uname().nodename.split('.')[0] == 'agent1', 'Use M unified root entry')
    os.umask(0o077)
    need(ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) == 0, 'Set no_new_privs failed')
    os.setgroups([])
    os.setgid(1205)
    os.setuid(1204)
    status = Path('/proc/self/status').read_text()
    need(all(re.search(r'^' + field + r':\s+0+$', status, re.M)
             for field in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), 'Build retained privileges')

    need(CAPTURE.resolve(strict=True) == CAPTURE and CAPTURE.stat().st_uid == 1204,
         'Original capture work area differs')
    source = SOURCE / 'src/bin/mn_titanic_capture.rs'
    need(source.resolve(strict=True) == source and hashlib.sha256(source.read_bytes()).hexdigest() == args.source_sha,
         'Staged native template source differs')
    for name in ('config.toml', 'rootfs-image.json'):
        path = CAPTURE / name
        need(path.resolve(strict=True) == path and path.is_file() and path.stat().st_uid == 1204,
             'Original capture input differs: ' + name)
    head = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=SOURCE, env=ENV,
                                   text=True, timeout=15).strip()
    need(head == HEAD, 'Original AgentENV checkout differs')
    previous = SOURCE / 'target/release'
    target = CAPTURE / 'target-private-001'
    need(previous.resolve(strict=True) == previous and previous.is_dir(), 'Release cache unavailable')
    used_kb = int(subprocess.check_output(['/usr/bin/du', '-sk', '--', str(previous)], env=ENV,
                                         text=True, timeout=120).split()[0])
    need(shutil.disk_usage(CAPTURE).free > used_kb * 1280 + (4 << 30), 'Insufficient space for private release cache')
    target.mkdir(mode=0o700)
    log_copy = CAPTURE / 'copy-release-cache-001.log'
    with log_copy.open('xb') as logs:
        subprocess.run(['/usr/bin/cp', '-RP', '--reflink=auto', '--preserve=mode,timestamps,links',
                        '--no-preserve=ownership', '--', str(previous), str(target / 'release')],
                       env=ENV, check=True, timeout=780, stdout=logs, stderr=subprocess.STDOUT)
    subprocess.run(['/usr/bin/chmod', '-R', 'u+rwX', '--', str(target)], env=ENV, check=True, timeout=120)
    env = dict(ENV, CARGO_TARGET_DIR=str(target))
    includes = sorted(Path('/usr/lib64/clang').glob('*/include/stdbool.h')) + sorted(
        Path('/usr/lib/clang').glob('*/include/stdbool.h'))
    if includes:
        env['BINDGEN_EXTRA_CLANG_ARGS'] = '-isystem ' + str(includes[0].parent)
    print(json.dumps({'event': 'native_capture_build_in_private_cache', 'copiedReleaseKiB': used_kb,
                      'cargoTarget': str(target)}), flush=True)
    log = CAPTURE / 'cargo-build-resume-001.log'
    with log.open('xb') as output:
        result = subprocess.run([str(TOOLCHAIN / 'cargo'), 'build', '--locked', '--offline', '--release',
                                 '--bin', 'mn_titanic_capture'], cwd=SOURCE, env=env, stdin=subprocess.DEVNULL,
                                stdout=output, stderr=subprocess.STDOUT, timeout=6600)
    if result.returncode:
        with log.open('rb') as stream:
            stream.seek(max(0, log.stat().st_size - 7500))
            print(stream.read(7500).decode('utf-8', 'replace'), flush=True)
        return result.returncode
    binary = target / 'release/mn_titanic_capture'
    print(json.dumps({'status': 'MN_TITANIC_CAPTURE_BINARY_READY', 'binary': str(binary),
                      'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                      'config': str(CAPTURE / 'config.toml'),
                      'rootfsImageConfig': str(CAPTURE / 'rootfs-image.json')}), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
