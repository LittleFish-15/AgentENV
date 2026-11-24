"""Reuse the SP3 checkout and compile pinned AgentENV as the ordinary build user."""

import hashlib
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


HOME = Path('/home/jwk')
COMMIT = '207462625ee21d669ddfc34cbfd47932f5a757b7'
TREE = 'abbbafd81c41a8ca4a17efe41c88079ce2e67577'
TARGET = 'aarch64-unknown-linux-gnu'
SYSTEM_PATH = '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
UBM = Path('/run/ubm/socket/ubm_nuds/restconf.sock')


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def checked_jwk_dir(path):
    info = path.lstat()
    need(path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and not info.st_mode & 0o022, 'Unexpected ordinary working directory: ' + str(path))


def capture(argv, cwd, env, seconds=15):
    return subprocess.run(argv, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=seconds)


def platform_facts():
    try:
        socket = stat.S_ISSOCK(UBM.lstat().st_mode)
    except FileNotFoundError:
        socket = False
    result = {'ubmSocketPresent': socket, 'obmmLoaded': Path('/sys/module/obmm').is_dir(),
              'ublkControlPresent': Path('/dev/ublk-control').is_char_device()}
    try:
        topo = capture(['/usr/bin/ubsectl', 'display', 'topo', '-t', 'cpu'], '/',
                       {'PATH': SYSTEM_PATH, 'LC_ALL': 'C'}, seconds=10)
        result.update(topoExit=topo.returncode, topoOutputLines=len(topo.stdout.splitlines()),
                      topoReportsFailure=bool(re.search(r'(?i)failed|\berror\b', topo.stdout)))
    except (OSError, subprocess.TimeoutExpired) as error:
        result['topoError'] = type(error).__name__
    return result


def ordinary_environment(proxy):
    user = pwd.getpwnam('jwk')
    need((user.pw_uid, user.pw_gid, user.pw_dir) == (1204, 1205, str(HOME)), 'Ordinary account differs')
    os.setgroups([])
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)
    status = Path('/proc/self/status').read_text()
    need(all(re.search(r'^' + key + r':\s+0+$', status, re.M) for key in ('CapEff', 'CapPrm', 'CapAmb')),
         'Build process retained privileges')
    env = {name: proxy for name in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY')}
    env.update(PATH=SYSTEM_PATH, HOME=str(HOME), USER='jwk', LOGNAME='jwk', LANG='C', LC_ALL='C',
               GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0',
               CARGO_NET_GIT_FETCH_WITH_CLI='true', CARGO_HTTP_TIMEOUT='60', CARGO_NET_RETRY='2',
               CARGO_BUILD_JOBS='4', CMAKE_BUILD_PARALLEL_LEVEL='4', CARGO_INCREMENTAL='0',
               LIBCLANG_PATH='/usr/lib64')
    for name in ('SSL_CERT_FILE', 'SSL_CERT_DIR'):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def checkout_candidate_paths():
    excluded = {'.git', '.cargo', '.rustup', '.cache', 'target', 'vendor', 'tmp', 'logs', 'root'}
    for count, (root, dirs, _) in enumerate(os.walk(HOME)):
        if count >= 2048:
            return
        path = Path(root)
        dirs[:] = sorted(name for name in dirs if not name.startswith('.') and name not in excluded)
        if (path / '.git').exists() and (path / 'Cargo.lock').is_file():
            try:
                checked_jwk_dir(path)
            except (RuntimeError, OSError):
                pass
            else:
                yield path
            dirs[:] = []
        if len(path.relative_to(HOME).parts) >= 4:
            dirs[:] = []


def pinned_checkout(path, env):
    checked_jwk_dir(path)
    for revision, expected in [('HEAD', COMMIT), ('HEAD^{tree}', TREE)]:
        answer = capture(['git', 'rev-parse', '--verify', revision], path, env)
        if answer.returncode or answer.stdout.strip() != expected:
            return False
    answer = capture(['git', 'status', '--porcelain', '--untracked-files=no'], path, env)
    return answer.returncode == 0 and not answer.stdout.strip()


def toolchain(env):
    paths = list(sorted((HOME / '.rustup/toolchains').glob('1.93.0-aarch64-*/bin')))
    paths += [HOME / '.cargo/bin', HOME / 'bin']
    for parent in (HOME, HOME / 'agent', HOME / '.local', HOME / 'opt'):
        if parent.is_dir():
            paths.extend(sorted(parent.glob('*rust*/bin')))
            paths.extend(sorted(parent.glob('*rust*/*/bin')))
    for path in dict.fromkeys(paths):
        if not all(os.access(path / binary, os.X_OK) for binary in ('rustc', 'cargo')):
            continue
        candidate = dict(env, PATH=str(path) + ':' + SYSTEM_PATH, RUSTC=str(path / 'rustc'))
        answer = capture([str(path / 'rustc'), '-vV'], HOME, candidate)
        if answer.returncode == 0 and re.search(r'^release: 1\.93\.0$', answer.stdout, re.M) and (
                'host: ' + TARGET in answer.stdout):
            return str(path / 'cargo'), candidate
    raise RuntimeError('Private Rust 1.93.0 ARM64 toolchain not found in the inspected jwk paths')


def phase(label, argv, source, env, attempt, report, timeout):
    log = attempt / (label + '.log')
    print('MN_BUILD_PHASE=' + label, flush=True)
    with log.open('xb') as output:
        process = subprocess.Popen(argv, cwd=source, env=env, stdout=output, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            raise
    with log.open('rb') as stream:
        stream.seek(max(0, log.stat().st_size - 12 * 1024))
        tail = stream.read().decode(errors='replace')
    report['phases'][label] = {'exit': code, 'log': str(log)}
    if code:
        patterns = {'configParse': r'could not parse TOML|failed to parse (?:the )?TOML',
                    'resolution': r'Could not resolve|failed to resolve|name resolution',
                    'network': r'timed out|HTTP \d{3}|failed to fetch|failed to download|TLS|certificate',
                    'libublk': r'libublk', 'offlineMissing': r'offline|no matching package named',
                    'rustCompile': r'error\[E\d+\]|could not compile|custom build command'}
        report['phases'][label]['indicators'] = [key for key, pattern in patterns.items()
                                                 if re.search(pattern, tail, re.I)]
        errors = [line for line in tail.splitlines() if re.match(r'^error(?:\[E\d+\])?:', line)
                  and not re.search(r'(?i)token|password|credential|authorization|https?://', line)]
        report['phases'][label]['errors'] = [line[:260] for line in errors[-4:]]
    return code == 0


def native_build(proxy, report):
    env = ordinary_environment(proxy)
    checked_jwk_dir(HOME)
    # A build outside the relay can share Cargo caches or keep a checkout busy.
    for process in Path('/proc').iterdir():
        if process.name.isdigit():
            try:
                if process.stat().st_uid == os.getuid() and (process / 'comm').read_text().strip() in (
                        'cargo', 'rustc', 'rustup'):
                    raise RuntimeError('A jwk Rust build or dependency fetch is already active')
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
    root = HOME / 'agentenv-mn-build'
    root.mkdir(mode=0o700, exist_ok=True)
    checked_jwk_dir(root)
    attempt = Path(tempfile.mkdtemp(prefix='attempt-', dir=root))
    scratch = attempt / 'tmp'
    scratch.mkdir(mode=0o700)
    env['TMPDIR'] = str(scratch)
    cargo, env = toolchain(env)
    report['cargoPath'] = cargo
    source = next((path for path in checkout_candidate_paths() if pinned_checkout(path, env)), None)
    if source is None:
        source = root / 'source'
        source.mkdir(mode=0o700, exist_ok=True)
        checked_jwk_dir(source)
        need(not any(source.iterdir()), 'Private fallback checkout contains unverified files')
        for label, args in [('git-init', ['init', '--quiet']),
                            ('git-fetch', ['fetch', '--no-tags', '--depth=1',
                                           'https://gitcode.com/Igali/AgentENV.git', COMMIT]),
                            ('git-checkout', ['checkout', '--quiet', '--detach', COMMIT])]:
            need(phase(label, ['git', *args], source, env, attempt, report, 300), label + ' failed')
    need(pinned_checkout(source, env), 'Pinned clean checkout is unavailable')
    report['checkout'] = str(source)
    target = source / 'target'
    target.mkdir(mode=0o700, exist_ok=True)
    checked_jwk_dir(target)
    env['CARGO_TARGET_DIR'] = str(target)
    fetch = [cargo, 'fetch', '--locked', '--target', TARGET]
    if not phase('cargo-cache', fetch + ['--offline'], source, env, attempt, report, 120):
        if 'configParse' in report['phases']['cargo-cache']['indicators']:
            clean_cargo = root / 'cargo'
            clean_cargo.mkdir(mode=0o700, exist_ok=True)
            checked_jwk_dir(clean_cargo)
            env['CARGO_HOME'] = str(clean_cargo)
        need(phase('cargo-fetch', fetch, source, env, attempt, report, 1500), 'Locked dependency fetch failed')
    packages = ['-p', 'agentenv', '--bin', 'server', '-p', 'uvm-ublk-daemon', '--bin', 'uvm-ublk-daemon',
                '-p', 'agentenv-ub-provider', '--bin', 'agentenv-ub-provider']
    need(phase('cargo-release', [cargo, 'build', '--offline', '--locked', '--release', *packages],
               source, env, attempt, report, 7800), 'Native release build failed')
    need(pinned_checkout(source, env), 'Pinned checkout changed during the build')
    report['artifacts'] = {}
    for name in ('server', 'uvm-ublk-daemon', 'agentenv-ub-provider'):
        path = target / 'release' / name
        with path.open('rb') as stream:
            digest = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        report['artifacts'][name] = {'path': str(path), 'sha256': digest.hexdigest(), 'bytes': path.stat().st_size}
    report['status'] = 'SP3_NATIVE_RELEASE_BUILT_NOT_DEPLOYED'


def interrupted(*_):
    raise InterruptedError('Relay interrupted the build')


if __name__ == '__main__':
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    report = {'status': 'SP3_NATIVE_RELEASE_STOPPED', 'commit': COMMIT, 'tree': TREE, 'phases': {}}
    try:
        need(os.geteuid() == 0 and len(sys.argv) == 2
             and re.fullmatch(r'http://(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}', sys.argv[1]),
             'Use the unified M/N worker and the approved build proxy')
        report['platform'] = platform_facts()
        print('MN_UB_PLATFORM=' + json.dumps(report['platform'], sort_keys=True), flush=True)
        native_build(sys.argv[1], report)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        report['reason'] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    print(json.dumps(report, sort_keys=True), flush=True)
    raise SystemExit(0 if report['status'] == 'SP3_NATIVE_RELEASE_BUILT_NOT_DEPLOYED' else 1)
