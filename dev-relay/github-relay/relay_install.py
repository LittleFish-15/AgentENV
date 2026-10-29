"""Install the pinned ordinary-user relay entry; no system services or root changes."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

BASE = Path('/home/jwk/agent/github-relay')
RUNNER_COMMIT = 'defa56afc47446d57182d56e0fd99eddb8e42525'
RUNNER_SHA = '8a8200b0d1dfe8e4fac70431ba61db5274a145b7e0a875195df640af93890adf'
RUNNER_BYTES = 28097
RUNNER_NAME = 'runner-' + RUNNER_SHA[:12] + '.py'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def repo(value):
    need(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value), 'Invalid repository name')
    return value


def launcher(control, results):
    repo(control); repo(results)
    need(control != results, 'Control and results repositories must differ')
    runner = str(BASE / RUNNER_NAME)
    return ('#!/bin/bash\nset -eu\numask 077\n'
            'test "$(id -u)" -eq 1204 || { echo "Use ordinary jwk"; exit 1; }\n'
            '/usr/bin/python3 -I -B ' + runner + ' enroll --control-repo ' + control + ' --result-repo ' + results + '\n'
            'exec /usr/bin/python3 -I -B ' + runner + ' run\n').encode()


def write_exact(path, raw, mode):
    need(not path.is_symlink(), 'Existing entry is redirected')
    if path.exists():
        need(path.is_file() and path.read_bytes() == raw, 'Existing entry differs; preserved')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control-repo', required=True)
    parser.add_argument('--result-repo', required=True)
    parser.add_argument('--start', action='store_true')
    args = parser.parse_args()
    body = launcher(args.control_repo, args.result_repo)
    need(os.name == 'posix' and os.getuid() == os.geteuid() == 1204 and os.getgid() == 1205,
         'Run as ordinary jwk UID1204/GID1205')
    os.umask(0o077)
    need(BASE.resolve() == BASE and BASE.parent.is_dir(), 'Expected existing ordinary workspace')
    parent = BASE.parent.stat()
    need(parent.st_uid == 1204 and not stat.S_IMODE(parent.st_mode) & 0o022, 'Workspace owner/mode differs')
    BASE.mkdir(mode=0o700, exist_ok=True)
    info = BASE.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 1204 and not stat.S_IMODE(info.st_mode) & 0o077,
         'Relay directory must be private and owned by jwk')
    target = BASE / RUNNER_NAME
    if target.exists() or target.is_symlink():
        need(not target.is_symlink() and target.is_file(), 'Runner entry redirected')
        raw = target.read_bytes()
    else:
        curl = next((Path(folder) / 'curl' for folder in ('/usr/bin', '/bin', '/usr/local/bin')
                     if (Path(folder) / 'curl').is_file()), None)
        need(curl is not None, 'curl is required; no package is installed automatically')
        tool = curl.resolve().stat()
        need(tool.st_uid == 0 and not stat.S_IMODE(tool.st_mode) & 0o022, 'curl ownership differs')
        fd, temporary = tempfile.mkstemp(prefix='download-', dir=BASE)
        os.close(fd)
        url = 'https://api.github.com/repos/LittleFish-15/AgentENV/contents/dev-relay/github-relay/relay_runner.py?ref=' + RUNNER_COMMIT
        result = subprocess.run([str(curl), '-fL', '--connect-timeout', '10', '--max-time', '45',
                                 '--max-filesize', '65536', '-H', 'Accept: application/vnd.github.raw+json',
                                 url, '-o', temporary], stdin=subprocess.DEVNULL, timeout=50)
        need(result.returncode == 0, 'Download failed; temporary file preserved')
        raw = Path(temporary).read_bytes()
    need(len(raw) == RUNNER_BYTES and hashlib.sha256(raw).hexdigest() == RUNNER_SHA, 'Runner length or SHA differs')
    write_exact(target, raw, 0o600)
    start = BASE / 'start.sh'
    write_exact(start, body, 0o700)
    print('RELAY_FIXED_COMMAND_READY=bash ' + str(start), flush=True)
    if args.start:
        os.execv('/bin/bash', ['bash', str(start)])


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('RELAY_INSTALL_STOPPED: ' + type(error).__name__ + ': ' + str(error))
        raise SystemExit(1)
