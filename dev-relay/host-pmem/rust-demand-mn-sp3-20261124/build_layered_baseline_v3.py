"""Build missing ARM64 AgentENV layered-demand artifacts from pinned clean sources."""

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import re
import signal
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


HOME = Path('/home/jwk')
WORK = HOME / 'agent/sp3-mn'
AGENT_COMMIT = 'bffdc74bf9b2a11467ee25159099d03a19110f98'
AGENT_TREE = '044b48e11c83c80d67b12caa5989a5729401294a'
KERNEL_COMMIT = 'bd8bc91e46e55418840e4cab751b19e5d08afc82'
KERNEL_TREE = '93f12be0b395a48bb11daab438405c8ac53169e8'
TARGET = 'aarch64-unknown-linux-gnu'
SYSTEM_PATH = '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
ENV = {'PATH': SYSTEM_PATH, 'HOME': str(HOME), 'USER': 'jwk', 'LOGNAME': 'jwk', 'LANG': 'C', 'LC_ALL': 'C',
       'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
       'CARGO_NET_GIT_FETCH_WITH_CLI': 'true', 'CARGO_NET_RETRY': '2', 'CARGO_HTTP_TIMEOUT': '60',
       'CARGO_BUILD_JOBS': '4', 'CMAKE_BUILD_PARALLEL_LEVEL': '4', 'CARGO_INCREMENTAL': '0',
       'LIBCLANG_PATH': '/usr/lib64'}


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def drop_root():
    if os.geteuid() != 0:
        return
    info = Path(__file__).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
         'untrusted root build worker')
    program = Path(__file__).read_bytes()
    need(0 < len(program) <= 128 * 1024, 'build worker exceeds size bound')
    proxy_names = ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY')
    proxy_values = {name: os.environ[name] for name in proxy_names if name in os.environ}
    env = {'PATH': SYSTEM_PATH, 'HOME': str(HOME), 'USER': 'jwk', 'LOGNAME': 'jwk',
           'LANG': 'C', 'LC_ALL': 'C', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
           'CARGO_NET_GIT_FETCH_WITH_CLI': 'true', 'CARGO_NET_RETRY': '2',
           'CARGO_HTTP_TIMEOUT': '60', 'CARGO_BUILD_JOBS': '4',
           'CMAKE_BUILD_PARALLEL_LEVEL': '4', 'CARGO_INCREMENTAL': '0',
           'LIBCLANG_PATH': '/usr/lib64', **proxy_values}
    setpriv = '/usr/bin/setpriv'
    need(Path(setpriv).is_file(), 'trusted setpriv is unavailable')
    os.execve(setpriv, [setpriv, '--reuid=1204', '--regid=1205', '--clear-groups',
                        '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                        '--no-new-privs', '/usr/bin/python3', '-I', '-B', '-c',
                        program.decode('utf-8'), *sys.argv[1:]], env)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def checked_dir(path):
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode)
         and info.st_uid == os.getuid() and not info.st_mode & 0o022,
         'Unexpected or writable build directory: ' + str(path))


def run(argv, cwd, env, timeout=900):
    result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    tail = result.stdout[-10000:].decode('utf-8', 'replace')
    print(json.dumps({'argv': argv, 'cwd': str(cwd), 'exit': result.returncode,
                      'tail': tail[-3000:]}, sort_keys=True), flush=True)
    need(result.returncode == 0, 'command failed: ' + argv[0])
    return tail


def identity(args):
    user = pwd.getpwnam('jwk')
    need(os.geteuid() == 1204 and os.getegid() == 1205 and not os.getgroups(),
         'build must run as zero-capability jwk with no supplementary groups')
    need((user.pw_uid, user.pw_gid, user.pw_dir) == (1204, 1205, str(HOME)), 'jwk identity differs')
    need(os.uname().machine == 'aarch64' and os.uname().release == args.kernel,
         'native target kernel differs')
    need(Path('/etc/machine-id').read_text().strip() == args.machine_id
         and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == args.boot_id,
         'node enrollment identity changed')


def toolchain(env):
    candidates = []
    candidates.extend(sorted((HOME / '.rustup/toolchains').glob('1.93.0-aarch64-*/bin')))
    candidates.extend((HOME / '.cargo/bin', HOME / '.local/rustup/bin'))
    for parent in (HOME, WORK, HOME / 'opt'):
        if parent.is_dir():
            candidates.extend(sorted(parent.glob('*rust*/bin')))
            candidates.extend(sorted(parent.glob('*rust*/*/bin')))
    for directory in dict.fromkeys(candidates):
        cargo, rustc = directory / 'cargo', directory / 'rustc'
        if not cargo.is_file() or not rustc.is_file():
            continue
        actual = dict(env, PATH=str(directory) + ':' + SYSTEM_PATH, RUSTC=str(rustc))
        result = subprocess.run([str(rustc), '-vV'], env=actual, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15, check=False)
        details = result.stdout.decode('utf-8', 'replace')
        if result.returncode == 0 and re.search(r'^release: 1\.93\.0$', details, re.M) and (
                'host: ' + TARGET in details):
            return str(cargo), actual, details
    raise RuntimeError('private Rust 1.93.0 ARM64 toolchain is unavailable')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', choices=('agent1', 'agent2'), required=True)
    parser.add_argument('--kernel', required=True)
    parser.add_argument('--machine-id', required=True)
    parser.add_argument('--boot-id', required=True)
    parser.add_argument('--proxy', required=True)
    args = parser.parse_args()
    need(re.fullmatch(r'6\.6\.0-145\.3\.34\.165\.oe2403sp3\.aarch64', args.kernel), 'kernel pin differs')
    need(re.fullmatch(r'http://(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}', args.proxy), 'proxy syntax differs')
    identity(args)
    checked_dir(HOME)
    from uuid import UUID

    known_volumes = {'agent1': '01a21fe3-9305-7e31-ac60-cb28b9532df5',
                     'agent2': '01a21fe1-048a-7740-94a6-62f9e6927ecd'}
    need((Path('/etc/aenv/ub/relay-dabd65d32a1c5c3e91a994bbcbbb9e6f/device-state/root.json').exists()
          or Path('/var/lib/aenv-ub-sdk/relay-dabd65d32a1c5c3e91a994bbcbbb9e6f/state/sdk.json').exists()),
         'audited prior-generation journals are unavailable')
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            name = Path(os.readlink(process / 'exe')).name
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        need(name not in ('server', 'firecracker', 'uvm-ublk-daemon')
             and not name.startswith('agentenv-ub-provider'),
             'a previous AENV or provider process is active')
    need(Path('/sys/module/obmm/srcversion').read_text().strip() == '29F10664C1EE59D7127F8C7',
         'loaded OBMM ABI differs from the volume query baseline')
    volume = UUID(known_volumes[args.node])
    volume_wire = bytearray(struct.Struct('<II16sIIII7Q').size)
    struct.pack_into('<II16s', volume_wire, 0, 1, 0, volume.bytes)
    obmm_fd = os.open('/dev/obmm_pmem', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        fcntl.ioctl(obmm_fd, 0xc060b801, volume_wire, True)
    finally:
        os.close(obmm_fd)
    volume_row = struct.Struct('<II16sIIII7Q').unpack(volume_wire)
    need(volume_row[7] == 2**32 and all(value == 0 for value in volume_row[8:14]),
         'prior generation volume is active or differs from the read-only audit')
    root = WORK / 'agentenv-layered-baseline-build'
    root.mkdir(mode=0o700, exist_ok=True)
    checked_dir(root)
    attempt = Path(tempfile.mkdtemp(prefix='attempt-', dir=root))
    (attempt / 'tmp').mkdir(mode=0o700)
    env = dict(ENV, TMPDIR=str(attempt / 'tmp'), http_proxy=args.proxy, https_proxy=args.proxy,
               HTTP_PROXY=args.proxy, HTTPS_PROXY=args.proxy)
    cargo, env, rust = toolchain(env)
    checkout_root = attempt / 'checkout'
    checkout_root.mkdir(mode=0o700)
    agent_source = checkout_root / 'AgentENV'
    kernel_source = checkout_root / 'kernel'
    for destination, repository, commit, expected_tree in (
            (agent_source, 'AgentENV', AGENT_COMMIT, AGENT_TREE),
            (kernel_source, 'kernel', KERNEL_COMMIT, KERNEL_TREE)):
        destination.mkdir(mode=0o700)
        run(['/usr/bin/git', 'init', '--quiet'], destination, env, 60)
        run(['/usr/bin/git', 'fetch', '--no-tags', '--depth=1',
             'https://gitcode.com/Igali/' + repository + '.git', commit], destination, env, 900)
        run(['/usr/bin/git', 'checkout', '--quiet', '--detach', 'FETCH_HEAD'], destination, env, 60)
        head = subprocess.run(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=destination, env=env,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True).stdout.strip()
        tree = subprocess.run(['/usr/bin/git', 'rev-parse', 'HEAD^{tree}'], cwd=destination, env=env,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True).stdout.strip()
        need((head, tree) == (commit, expected_tree), 'isolated checkout commit or tree differs')
    source = agent_source
    build = attempt / 'target'
    env['CARGO_TARGET_DIR'] = str(build)
    packages = ['-p', 'agentenv', '--bin', 'server', '-p', 'uvm-ublk-daemon', '--bin', 'uvm-ublk-daemon',
                '-p', 'agentenv-ub-provider', '--bin', 'agentenv-ub-provider']
    try:
        run([cargo, 'fetch', '--locked', '--target', TARGET, '--offline'], source, env, 180)
        offline = True
    except (RuntimeError, subprocess.TimeoutExpired):
        run([cargo, 'fetch', '--locked', '--target', TARGET], source, env, 1800)
        offline = False
    run([cargo, 'build', '--offline', '--locked', '--release', *packages], source, env, 7800)
    outputs = {}
    for name in ('server', 'uvm-ublk-daemon', 'agentenv-ub-provider'):
        path = build / 'release' / name
        need(path.is_file() and path.stat().st_size > 1024 * 1024, 'expected release artifact missing')
        outputs[name] = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}
    adapter = attempt / 'libaenv-ub.so'
    run(['/usr/bin/c++', '-std=c++17', '-O2', '-fPIC', '-shared', '-pthread', '-Wall', '-Wextra', '-Werror',
         '-I', '/usr/include', str(source / 'storage/ub-demand/sdk_adapter.cpp'), '-L', '/usr/lib64',
         '-lubsm_sdk', '-Wl,-z,relro,-z,now', '-o', str(adapter)], source, env, 300)
    outputs['libaenv-ub.so'] = {'path': str(adapter), 'bytes': adapter.stat().st_size, 'sha256': sha(adapter)}
    record = {'status': 'LAYERED_BASELINE_BUILT_NOT_INSTALLED', 'node': args.node,
              'agentenvCommit': AGENT_COMMIT, 'agentenvTree': AGENT_TREE,
              'obmmCommit': KERNEL_COMMIT, 'obmmTree': KERNEL_TREE,
              'rustc': rust, 'cargo': cargo, 'dependenciesFetchedOffline': offline,
              'attempt': str(attempt), 'artifacts': outputs, 'installed': False}
    receipt = attempt / 'build-receipt.json'
    with receipt.open('x') as stream:
        json.dump(record, stream, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(record, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        drop_root()
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(json.dumps({'status': 'LAYERED_BASELINE_BUILD_FAILED', 'reason': str(error)[:400]}), flush=True)
        raise SystemExit(1)
