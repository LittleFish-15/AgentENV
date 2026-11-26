"""Install the pinned native AENV CLI and connect it to the live M/N test unit."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import traceback
from pathlib import Path


UID, GID = 1204, 1205
WORK = Path('/home/jwk/agent/sp3-mn')
BUILD = WORK / 'cli-build-4fb630a'
RUST = Path('/home/jwk/.local/rustup/bin')
URL = 'https://gitcode.com/Igali/AgentENV.git'
REF = 'refs/heads/feat/ub-rootfs-demand-baseline'
COMMIT = '4fb630a28d56ab0b58a499a2c7b94d834f26bd56'
TREE = '6dbeb841c9e2f5bc66c258a310f48787a33286e8'
WRAPPER_PATH = Path('/usr/local/bin/aenv')
CLI = Path('/opt/aenv/cli-4fb630a/aenv')
PATH = '/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

WRAPPER = r'''#!/usr/bin/python3 -I
"""Run the AgentENV CLI against the Titanic service on this node."""
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import tomllib


CLI = '/opt/aenv/cli-4fb630a/aenv'
WORK = Path('/home/jwk/agent/sp3-mn')
SERVER = WORK / 'src/AgentENV/target/release/server'
UNIT = 'aenv-mn-titanic.service'
ENV = {'PATH': '/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/home/jwk',
       'USER': 'jwk', 'LOGNAME': 'jwk', 'LANG': 'C.UTF-8'}


def fail(message):
    raise RuntimeError(message)


def running_server():
    status = subprocess.check_output(['/usr/bin/systemctl', 'show', UNIT, '-p', 'ActiveState', '-p',
                                     'ControlGroup'], env=ENV, text=True, timeout=5)
    fields = dict(line.split('=', 1) for line in status.splitlines() if '=' in line)
    group = fields.get('ControlGroup')
    if fields.get('ActiveState') != 'active' or group != '/system.slice/' + UNIT:
        fail('AENV is not running. Check systemctl status ' + UNIT)
    pids = (Path('/sys/fs/cgroup' + group) / 'cgroup.procs').read_text().split()
    choices = []
    for pid in pids:
        if not pid.isdecimal():
            continue
        node = Path('/proc') / pid
        try:
            if Path(os.readlink(node / 'exe')) != SERVER:
                continue
            argv = (node / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
            if len(argv) != 3 or argv[1] != b'--config' or node.stat().st_uid != 1204:
                continue
            config = Path(os.fsdecode(argv[2]))
            relative = config.relative_to(WORK)
            if len(relative.parts) != 2 or not re.fullmatch(r'aenv-tit-d[0-9]{2}', relative.parts[0]):
                continue
            if relative.parts[1] == 'config.toml' and config.resolve(strict=True) == config:
                choices.append((node, config))
        except (OSError, ValueError):
            continue
    if len(choices) != 1:
        fail('Cannot identify the AENV Server in ' + UNIT)
    return choices[0]


def get_key(server, config):
    environment = (server / 'environ').read_bytes().split(b'\0')
    key = next((item.split(b'=', 1)[1] for item in environment if item.startswith(b'AENV_API_KEY=')), None)
    if key is None:
        with config.open('rb') as stream:
            home = Path(tomllib.load(stream)['home_path'])
        if home != config.parent / 'h' or home.resolve(strict=True) != home:
            fail('Unexpected AENV home')
        external = Path('/run/secrets/api-key')
        path = external if external.is_file() else home / 'secrets/api-key'
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, 1204) or info.st_mode & 0o022:
                fail('Unexpected API key file owner or mode')
            key = stream.read(260).strip()
    if not re.fullmatch(rb'[A-Za-z0-9_.~-]{32,256}', key):
        fail('Unexpected AENV API key format')
    return key


def main():
    if os.geteuid() != 0:
        fail('Run this local AENV entry from the node root terminal')
    server, config = running_server()
    fd = os.open(server / 'ns/net', os.O_RDONLY | os.O_CLOEXEC)
    try:
        if running_server() != (server, config):
            fail('AENV Server changed during connection setup')
        key = get_key(server, config)
        with tempfile.TemporaryDirectory(prefix='aenv-cli-', dir='/run') as temporary:
            base = Path(temporary)
            directory = base / 'aenv'
            directory.mkdir(mode=0o700)
            auth = directory / 'credentials'
            with auth.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(b'url = "http://127.0.0.1:19384"\napi_key = "' + key + b'"\n')
            for path in (auth, directory, base):
                os.chown(path, 1204, 1205)
            argv = ['/usr/bin/nsenter', '--net=/proc/self/fd/' + str(fd), '--', '/usr/bin/setpriv',
                    '--reuid=1204', '--regid=1205', '--init-groups', '--no-new-privs', '--', CLI,
                    *sys.argv[1:]]
            return subprocess.run(argv, pass_fds=(fd,), env={**ENV, 'XDG_CONFIG_HOME': str(base)}).returncode
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, KeyError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print('aenv: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
'''


def need(value, message):
    if not value:
        raise RuntimeError(message)


def run(argv, env, log, timeout, cwd=None):
    with log.open('xb') as output:
        result = subprocess.run(argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.STDOUT, timeout=timeout)
    return result.returncode


def show_failure(log):
    with log.open('rb') as stream:
        stream.seek(max(0, log.stat().st_size - 8192))
        lines = stream.read(8192).decode('utf-8', 'replace').splitlines()
    for line in lines[-15:]:
        if not re.search(r'(?i)password|authorization|private.key|token|api.key|e2b_', line):
            print(line, flush=True)


def build(proxy):
    os.initgroups('jwk', GID)
    os.setgid(GID)
    os.setuid(UID)
    status = Path('/proc/self/status').read_text()
    need(all(re.search(r'^' + key + r':\s+0+$', status, re.M)
             for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), 'Build retained capabilities')
    env = {name: proxy for name in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY')}
    env.update(PATH=str(RUST) + ':' + PATH, RUSTC=str(RUST / 'rustc'), HOME='/home/jwk', USER='jwk',
               LOGNAME='jwk', LANG='C', LC_ALL='C', GIT_TERMINAL_PROMPT='0', GIT_CONFIG_GLOBAL='/dev/null',
               GIT_CONFIG_NOSYSTEM='1', CARGO_NET_GIT_FETCH_WITH_CLI='true', CARGO_BUILD_JOBS='4',
               CMAKE_BUILD_PARALLEL_LEVEL='4', CARGO_INCREMENTAL='0', LIBCLANG_PATH='/usr/lib64',
               CARGO_TARGET_DIR=str(BUILD / 'target'))
    info = subprocess.check_output([str(RUST / 'rustc'), '-vV'], env=env, timeout=15, text=True)
    need('host: aarch64-unknown-linux-gnu' in info and 'release: 1.93.0' in info, 'Unexpected private Rust')
    BUILD.mkdir(mode=0o700)
    repo = BUILD / 'source'
    repo.mkdir(mode=0o700)
    cargo = str(RUST / 'cargo')
    print(json.dumps({'status': 'MN_AENV_CLI_NATIVE_BUILD_STARTED', 'commit': COMMIT}), flush=True)
    for name, command, timeout in (
        ('git-init', ['git', 'init', '--quiet'], 20),
        ('git-fetch', ['git', 'fetch', '--no-tags', '--depth=12', URL, REF], 420),
        ('checkout', ['git', 'checkout', '--detach', COMMIT], 40),
    ):
        log = BUILD / (name + '.log')
        if run(command, env, log, timeout, repo):
            show_failure(log)
            raise RuntimeError(name + ' failed')
    need(subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=repo, env=env, text=True,
                                 timeout=12).strip() == TREE, 'GitCode source tree differs')
    fetch = [cargo, 'fetch', '--locked', '--target', 'aarch64-unknown-linux-gnu']
    if run(fetch + ['--offline'], env, BUILD / 'cache.log', 90, repo):
        log = BUILD / 'fetch.log'
        if run(fetch, env, log, 1200, repo):
            show_failure(log)
            raise RuntimeError('Locked Cargo dependency fetch failed')
    log = BUILD / 'release.log'
    if run([cargo, 'build', '--locked', '--offline', '--release', '-p', 'aenv', '--bin', 'aenv'],
           env, log, 5400, repo):
        show_failure(log)
        raise RuntimeError('aenv CLI compilation failed')


def trusted_dir(path):
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode)
         and info.st_uid == 0 and not info.st_mode & 0o022, 'Untrusted directory: ' + str(path))


def install(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proxy', required=True)
    args = parser.parse_args()
    need(os.geteuid() == 0 and os.uname().nodename.split('.')[0] in ('agent1', 'agent2'), 'Use the M/N root entry')
    need(re.fullmatch(r'http://(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}', args.proxy), 'Invalid build proxy')
    need(not any(os.path.lexists(path) for path in (WRAPPER_PATH, CLI.parent, BUILD)),
         'An existing CLI or prior work area needs inspection')
    trusted_dir(Path('/usr/local/bin'))
    trusted_dir(Path('/opt/aenv'))
    os.umask(0o077)
    pid = os.fork()
    if pid == 0:
        try:
            build(args.proxy)
        except Exception:
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    need(status == 0, 'Native aenv CLI build failed')
    artifact = BUILD / 'target/release/aenv'
    fd = os.open(artifact, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == UID and 0 < info.st_size <= 128 * 1024 * 1024,
             'Invalid built aenv artifact')
        program = stream.read()
    need(program[:6] == b'\x7fELF\x02\x01' and int.from_bytes(program[18:20], 'little') == 183,
         'Native ARM64 ELF expected')
    CLI.parent.mkdir(mode=0o755)
    CLI.parent.chmod(0o755)
    managed = []
    try:
        for path, content in ((CLI, program), (WRAPPER_PATH, WRAPPER.encode())):
            install(path, content)
            managed.append((path, content))
        subprocess.run(['/usr/bin/bash', '-lc', 'test "$(command -v aenv)" = /usr/local/bin/aenv'],
                       env={'PATH': PATH, 'HOME': '/root', 'LANG': 'C'}, check=True, timeout=12)
        data = subprocess.check_output([str(WRAPPER_PATH), 'ls', '--output', 'json'],
                                       env={'PATH': PATH, 'HOME': '/root', 'LANG': 'C'}, timeout=40)
        sandboxes = json.loads(data)
        need(isinstance(sandboxes, list), 'Unexpected aenv ls response')
    except Exception:
        for path, content in reversed(managed):
            if path.is_file() and path.read_bytes() == content:
                path.unlink()
        if not any(CLI.parent.iterdir()):
            CLI.parent.rmdir()
        raise
    print(json.dumps({'status': 'MN_AENV_LS_READY', 'command': str(WRAPPER_PATH), 'sandboxCount': len(sandboxes),
                      'cliSha256': hashlib.sha256(program).hexdigest(), 'commit': COMMIT}), flush=True)


if __name__ == '__main__':
    main()
