"""Install only a missing packaged OverlayBD default and resume guest preparation."""

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path


BASE = Path('/home/jwk/agent/sp3-mn')
WORK = BASE / 'relay-guest-assets-001'
RELEASE = WORK / 'deps/overlaybd'
DEFAULT = Path('/etc/overlaybd/overlaybd.json')
SERVER = BASE / 'src/AgentENV/target/release/server'
SERVER_SHA = '1d450f7cabbd10c41ef11bd6dc093e962b2439204a5a376e1bb2c748210ca917'
DEFAULT_SHA = '2c4f54339d2ff96ddccaedc6531060ce6478f39d7a13c5bfc3e1a72e453b069f'
UID, GID = 1204, 1205


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def verified_source():
    marker = RELEASE / 'tools-release.json'
    expected = {'tag_name': 'v1.0.18-aenv.1', 'asset_name':
                'overlaybd-tools-v1.0.18-aenv.1-linux-aarch64.tar.gz', 'digest': None}
    need(marker.resolve(strict=True) == marker and json.loads(marker.read_bytes()) == expected,
         'Original installed release metadata differs')
    source = RELEASE / 'etc/overlaybd/overlaybd.json'
    need(source.resolve(strict=True) == source and source.is_file() and
         0 < source.stat().st_size <= 128 * 1024, 'Unexpected release default config')
    data = source.read_bytes()
    need(isinstance(json.loads(data), dict) and hashlib.sha256(data).hexdigest() == DEFAULT_SHA,
         'Release default config differs from the reviewed source bytes')
    return data


def install_absent_default(data):
    parent = DEFAULT.parent
    if not os.path.lexists(parent):
        parent.mkdir(mode=0o750)
        os.chown(parent, 0, GID)
        parent.chmod(0o750)
    info = parent.lstat()
    need(parent.resolve(strict=True) == parent and stat.S_ISDIR(info.st_mode)
         and info.st_uid == 0 and not info.st_mode & 0o022, 'Existing /etc/overlaybd needs reconciliation')
    if os.path.lexists(DEFAULT):
        info = DEFAULT.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             'Existing system config needs reconciliation')
        return 'existing_file_preserved'
    fd, temporary = tempfile.mkstemp(prefix='.relay-default-', dir=parent)
    staging = Path(temporary)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            os.fchown(stream.fileno(), 0, GID)
            os.fchmod(stream.fileno(), 0o640)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(staging, DEFAULT, follow_symlinks=False)
        return 'packaged_default_installed'
    finally:
        staging.unlink()


def main():
    host = os.uname().nodename.split('.')[0]
    need(os.geteuid() == 0 and host in ('agent1', 'agent2'), 'Use existing M/N unified entry')
    need(WORK.resolve(strict=True) == WORK and WORK.stat().st_uid == UID and
         hashlib.sha256(SERVER.read_bytes()).hexdigest() == SERVER_SHA, 'Private setup or pinned server differs')
    cfg = WORK / 'config.toml'
    need(cfg.resolve(strict=True) == cfg and cfg.is_file() and cfg.stat().st_uid == UID,
         'Original private config differs')
    normal = ['/usr/bin/setpriv', '--no-new-privs', '--reuid=1204', '--regid=1205', '--init-groups', '--']
    data = verified_source()
    if os.path.lexists(DEFAULT.parent):
        subprocess.run(normal + ['/usr/bin/test', '-x', str(DEFAULT.parent)], check=True)
    setup = install_absent_default(data)
    subprocess.run(normal + ['/usr/bin/test', '-r', str(DEFAULT)], check=True)
    print(json.dumps({'status': setup, 'node': host, 'path': str(DEFAULT),
                      'sha256': hashlib.sha256(DEFAULT.read_bytes()).hexdigest()}), flush=True)
    env = {key: os.environ[key] for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy',
           'https_proxy', 'no_proxy', 'SSL_CERT_FILE', 'SSL_CERT_DIR') if key in os.environ}
    env.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME=str(WORK / 'home'), TMPDIR=str(WORK / 'tmp'),
               LANG='C', LC_ALL='C', NO_COLOR='1')
    code = subprocess.run(normal + [str(SERVER), '--setup-only', '--config', str(cfg)], cwd=WORK,
                          env=env, stdin=subprocess.DEVNULL, timeout=600).returncode
    print(json.dumps({'status': 'MN_RESUMED_GUEST_SETUP', 'node': host, 'code': code,
                      'config': str(cfg)}), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
