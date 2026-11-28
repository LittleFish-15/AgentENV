"""Relocate the existing SP3 relay beneath /root after a home ownership change."""

import fcntl
import getpass
import hashlib
import json
import os
import re
import ssl
import urllib.request
import warnings
import stat
import sys
import tempfile
import types
from contextlib import ExitStack, contextmanager
from pathlib import Path


OLD_ROOT = Path('/home/jwk/root')
ROOT = Path('/root/agentenv-mn-sp3')
STATE_NAME = 'relay-sp3-20261124'
STATE = ROOT / STATE_NAME
SESSION = 'rust-demand-mn-sp3-20261124-01'
PIN = '588e88fed385f33f9bea60ac2ead82aa495a187dfdada6f4571726af24ddf22d'
LAUNCHER = (b'#!/bin/bash\nset -eu\numask 077\n'
            b'exec /usr/bin/python3 -I -B /root/agentenv-mn-sp3/recover_root_entry.py\n')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@contextmanager
def opened(path, flags, parent=None):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        yield fd
    finally:
        os.close(fd)


def check_dir(fd, uid=0, gid=None):
    entry = os.fstat(fd)
    require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == uid
            and (gid is None or entry.st_gid == gid) and not entry.st_mode & 0o022,
            'Unexpected directory ownership or writability')


def read_file(parent, name, limit):
    with opened(name, os.O_RDONLY | os.O_NONBLOCK, parent) as fd:
        entry = os.fstat(fd)
        require(stat.S_ISREG(entry.st_mode) and entry.st_uid == 0 and entry.st_nlink == 1
                and stat.S_IMODE(entry.st_mode) == 0o600 and entry.st_size <= limit,
                'Unexpected legacy state file type, ownership, mode or size')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(limit + 1)
        require(len(raw) == entry.st_size, 'State file changed during read')
        return raw


def copy_state(parent, target, budget, depth=0):
    require(depth <= 4, 'Legacy state nesting exceeded the limit')
    for name in os.listdir(parent):
        budget[0] -= 1
        require(budget[0] >= 0, 'Legacy state file count exceeded the limit')
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            with opened(name, os.O_RDONLY | os.O_DIRECTORY, parent) as child:
                check_dir(child)
                (target / name).mkdir(mode=0o700)
                copy_state(child, target / name, budget, depth + 1)
        else:
            data = read_file(parent, name, min(2 * 1024 * 1024, budget[1]))
            budget[1] -= len(data)
            (target / name).write_bytes(data)


def load_relay(state):
    with opened(state, os.O_RDONLY | os.O_DIRECTORY) as fd:
        check_dir(fd)
        raw = read_file(fd, 'entry.py', 256 * 1024)
    require(hashlib.sha256(raw).hexdigest() == PIN, 'Original SP3 relay digest differs')
    relay = types.ModuleType('original_sp3_relay')
    relay.__file__ = str(state / 'entry.py')
    exec(compile(raw, relay.__file__, 'exec'), relay.__dict__)
    relay.STATE = state
    relay.CREDENTIALS = state / 'credentials.json'
    return relay


def assert_binding(relay):
    with opened(relay.STATE, os.O_RDONLY | os.O_DIRECTORY) as fd:
        check_dir(fd)
        local = json.loads(read_file(fd, 'enrollment.json', 192 * 1024))
    current = relay.identity()
    node = local['node']
    require(local['schema'] == 1 and node in relay.ALIASES and local['sessionId'] == SESSION
            and local['entrySha256'] == PIN, 'Existing SP3 enrollment differs')
    require(all(current[key] == local['identity'][key]
                for key in ('machineId', 'hostname', 'kernel', 'architecture')),
            'Local machine, hostname, kernel or architecture differs')
    relay.local_address(local['expectedAddress'], local['peerAddress'])
    return local, current


def install():
    with ExitStack() as stack:
        parent = stack.enter_context(opened('/', os.O_RDONLY | os.O_DIRECTORY))
        check_dir(parent)
        for part, uid, gid in [('home', 0, None), ('jwk', 1204, 1205),
                               ('root', 0, None), (STATE_NAME, 0, None)]:
            parent = stack.enter_context(opened(part, os.O_RDONLY | os.O_DIRECTORY, parent))
            check_dir(parent, uid, gid)
        lock = stack.enter_context(opened('operation.lock', os.O_RDWR, parent))
        info = os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'Legacy operation lock differs')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix='.agentenv-mn-recover-', dir='/root') as temp:
            stage = Path(temp) / ROOT.name
            stage.mkdir(mode=0o700)
            staged_state = stage / STATE_NAME
            staged_state.mkdir(mode=0o700)
            copy_state(parent, staged_state, [512, 32 * 1024 * 1024])
            relay = load_relay(staged_state)
            assert_binding(relay)
            relay.credentials()
            (stage / 'recover_root_entry.py').write_bytes(Path(__file__).read_bytes())
            (stage / 'root-start.sh').write_bytes(LAUNCHER)
            require(not os.path.lexists(ROOT), 'Protected entry appeared during recovery')
            stage.rename(ROOT)


def run_queued_task():
    with opened(ROOT, os.O_RDONLY | os.O_DIRECTORY) as fd:
        check_dir(fd)
        require(read_file(fd, 'root-start.sh', 1024) == LAUNCHER, 'Protected launcher differs')
        require(read_file(fd, 'recover_root_entry.py', 32 * 1024) == Path(__file__).read_bytes(),
                'Protected recovery entry differs')
    relay = load_relay(STATE)
    local, current = assert_binding(relay)
    node = local['node']
    with opened(STATE, os.O_RDONLY | os.O_DIRECTORY) as directory:
        token = read_file(directory, 'single-token', 512).decode('ascii')
    control, results = verified_single_token(relay, token)
    profile = relay.fetch(control, f'root-entry-v1/{SESSION}/profiles/{node}.json')
    # Retain the v1 identity and queue contract. This field describes the original
    # enrollment only. No task or credential path is opened using the remote field.
    require(profile['schema'] == 1 and profile['node'] == node and profile['sessionId'] == SESSION
            and profile['mode'] == 'manual' and profile['entrySha256'] == PIN
            and profile['rootArtifactDirectory'] == str(OLD_ROOT)
            and profile['expectedAddress'] == local['expectedAddress']
            and all(profile['identity'][key] == current[key]
                    for key in ('machineId', 'hostname', 'kernel', 'architecture')),
            'Pinned control profile differs')
    fd = relay.advisory_lock()
    try:
        boot = {'node': node, 'identity': current, 'entrySha256': PIN}
        relay.save(STATE / 'current-boot.json', boot)
        relay.put(results, f'root-entry-v1/{SESSION}/{node}/boots/{current["bootId"]}/{PIN}.json',
                  relay.wire(boot))
        print('MN_ROOT_ENTRY_READY=bash /root/agentenv-mn-sp3/root-start.sh', flush=True)
        relay.run_task(control, results, node, current, PIN)
    finally:
        os.close(fd)


def verified_single_token(relay, token):
    require(re.fullmatch(r'github_pat_[A-Za-z0-9_]{16,501}', token), 'Expected a fine-grained token')
    require(relay.API.API == 'https://api.github.com', 'Unexpected GitHub API endpoint')
    control, results = (relay.API.GitHub(token) for _ in range(2))
    for client in (control, results):
        client.opener = urllib.request.build_opener(
            relay.API.NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    for client, repo, repo_id in ((control, relay.CONTROL, 1438089258),
                                  (results, relay.RESULTS, 1438089386)):
        try:
            client.private_repo(repo, repo_id)
        except Exception as error:
            status = re.search(r'HTTP (\d{3})', str(error))
            detail = 'HTTP ' + status.group(1) if status else type(error).__name__
            raise RuntimeError(repo + ' verification failed over trusted HTTPS: ' + detail) from None
    return control, results


def replace_private(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.mn-entry-', delete=False) as stream:
        temp = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)


def migrate():
    require(sys.stdin.isatty() and sys.stderr.isatty(), 'Use the root terminal for hidden token input')
    with opened(ROOT, os.O_RDONLY | os.O_DIRECTORY) as fd:
        check_dir(fd)
        require(read_file(fd, 'root-start.sh', 1024) == LAUNCHER, 'Installed launcher differs')
        installed = read_file(fd, 'recover_root_entry.py', 32 * 1024)
    replacement = Path(__file__).read_bytes()
    require(hashlib.sha256(installed).hexdigest() == '798de1896d332f544d0528251ce83c47693f169e716f0aec72538a9202bc1d9c' or installed == replacement,
            'Installed recovery wrapper differs')
    relay = load_relay(STATE)
    assert_binding(relay)
    lock = relay.advisory_lock()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            token = getpass.getpass('New GitHub token for both relay repositories (hidden): ')
        verified_single_token(relay, token)
        replace_private(STATE / 'single-token', token.encode('ascii'))
        replace_private(ROOT / 'recover_root_entry.py', replacement)
        print('MN_SINGLE_TOKEN_READY', flush=True)
    finally:
        os.close(lock)


def main():
    require(sys.platform == 'linux' and os.getuid() == os.geteuid() == 0,
            'Use the designated node root terminal')
    os.umask(0o077)
    with opened('/root', os.O_RDONLY | os.O_DIRECTORY) as fd:
        check_dir(fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if sys.argv[1:] == ['--migrate-single-token']:
            migrate()
            return
        if not os.path.lexists(ROOT):
            require(sys.argv[1:] == ['--install'], 'One-time installation is required')
            install()
    require(sys.argv[1:] in ([], ['--install']), 'Unexpected arguments')
    run_queued_task()


if __name__ == '__main__':
    try:
        main()
    except (KeyError, OSError, ValueError, RuntimeError) as error:
        print('MN_ROOT_ENTRY_STOPPED=' + (str(error) if isinstance(error, RuntimeError)
                                          else type(error).__name__), file=sys.stderr, flush=True)
        raise SystemExit(1)
