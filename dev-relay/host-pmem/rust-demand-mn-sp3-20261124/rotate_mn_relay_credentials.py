"""Replace rejected M/N relay credentials without changing enrollment or queue state."""

import getpass
import json
import os
import re
import ssl
import stat
import sys
import tempfile
import types
import urllib.request
import warnings
from pathlib import Path


ROOT = Path('/root/agentenv-mn-sp3')
STATE = ROOT / 'relay-sp3-20261124'
PIN = '588e88fed385f33f9bea60ac2ead82aa495a187dfdada6f4571726af24ddf22d'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify(relay, token, repo, repo_id, label):
    client = relay.API.GitHub(token)
    client.opener = urllib.request.build_opener(
        relay.API.NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        client.private_repo(repo, repo_id)
    except Exception as error:
        message = str(error)
        http = re.search(r'HTTP (\d{3})', message)
        outcome = 'HTTP ' + http.group(1) if http else type(error).__name__
        print(f'{label} verification failed: {outcome}', flush=True)
        require(outcome == 'HTTP 401', 'Cannot verify repository over trusted HTTPS: ' + outcome)
        return False
    print(f'{label} repository verified', flush=True)
    return True


def main():
    require(os.getuid() == os.geteuid() == 0 and sys.stdin.isatty() and sys.stderr.isatty(),
            'Use the designated root terminal with hidden input')
    os.umask(0o077)
    launcher = ROOT / 'recover_root_entry.py'
    info = launcher.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
            and ROOT.resolve(strict=True) == ROOT and STATE.resolve(strict=True) == STATE,
            'Installed root recovery files differ')
    recovery = types.ModuleType('mn_recovery')
    recovery.__file__ = str(launcher)
    exec(compile(launcher.read_bytes(), str(launcher), 'exec'), recovery.__dict__)
    require(recovery.PIN == PIN and recovery.STATE == STATE, 'Installed enrollment contract differs')
    relay = recovery.load_relay(STATE)
    recovery.assert_binding(relay)
    lock = relay.advisory_lock()
    temp = None
    try:
        current = relay.credentials()
        proposed = dict(current)
        for key, repo, repo_id, label in (
            ('controlToken', relay.CONTROL, 1438089258, 'control-read'),
            ('resultToken', relay.RESULTS, 1438089386, 'results-write'),
        ):
            if verify(relay, current[key], repo, repo_id, label):
                continue
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                token = getpass.getpass(f'New {label} GitHub token (hidden input): ')
            require(re.fullmatch(r'github_pat_[A-Za-z0-9_]{16,501}', token),
                    'Expected a fine-grained personal access token')
            require(verify(relay, token, repo, repo_id, label), 'New token could not be verified')
            proposed[key] = token
        require(proposed['controlToken'] != proposed['resultToken'], 'Use separate tokens')
        if proposed != current:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=STATE,
                                             prefix='.credentials-', delete=False) as stream:
                temp = Path(stream.name)
                os.fchmod(stream.fileno(), 0o600)
                json.dump(proposed, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, STATE / 'credentials.json')
            temp = None
            fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        print('MN_RELAY_CREDENTIALS_VERIFIED', flush=True)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('MN_RELAY_ROTATION_STOPPED=' + (str(error) if isinstance(error, RuntimeError)
                                             else type(error).__name__), flush=True)
        raise SystemExit(1)
