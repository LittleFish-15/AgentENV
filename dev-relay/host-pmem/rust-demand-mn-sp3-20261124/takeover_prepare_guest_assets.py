"""Prepare isolated AgentENV guest dependencies and fetch one pinned owner OCI input."""

import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
from pathlib import Path


HOME = Path('/home/jwk/agent/sp3-mn')
ARTIFACTS = HOME / 'artifacts/deps'
SERVER = HOME / 'src/AgentENV/target/release/server'
SERVER_HASH = '1d450f7cabbd10c41ef11bd6dc093e962b2439204a5a376e1bb2c748210ca917'
FC = ARTIFACTS / 'firecracker/firecracker'
KERNEL = ARTIFACTS / 'vmlinux-6.1.175-aarch64'
UID, GID = 1204, 1205
HOST_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
REQUIRED = ('curl', 'debugfs', 'ip', 'iptables-restore', 'iptables-save', 'jq', 'mkfs.ext4',
            'prlimit', 'resize2fs', 'sudo', 'umoci', 'zstd')


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def digest(path):
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def directory(path):
    path.mkdir(mode=0o700)
    os.chown(path, UID, GID)


def log_tail(path):
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - (6 << 10)))
        lines = stream.read(6 << 10).decode('utf-8', 'replace').splitlines()
    return [line for line in lines if not re.search(r'(?i)password|authorization|private.key|token', line)][-16:]


def run(name, command, env, work, seconds):
    print('MN_GUEST_INPUT_PHASE=' + name, flush=True)
    prefix = ['/usr/bin/setpriv', '--no-new-privs', '--reuid=1204', '--regid=1205', '--init-groups', '--']
    stdout, stderr = work / (name + '.out'), work / (name + '.err')
    try:
        with stdout.open('xb') as output, stderr.open('xb') as errors:
            process = subprocess.run(prefix + command, cwd=work, env=env, stdin=subprocess.DEVNULL,
                                     stdout=output, stderr=errors, timeout=seconds)
        code = process.returncode
    except subprocess.TimeoutExpired:
        code = 124
    if code:
        print(json.dumps({'phase': name, 'exitCode': code, 'stdout': log_tail(stdout),
                          'stderr': log_tail(stderr)}), flush=True)
    return code, stdout


def retain_overlaybd_release(deps):
    old = ARTIFACTS / 'overlaybd'
    marker = old / 'tools-release.json'
    expected = {'tag_name': 'v1.0.18-aenv.1', 'asset_name':
                'overlaybd-tools-v1.0.18-aenv.1-linux-aarch64.tar.gz', 'digest': None}
    files = ('tools-release.json', 'etc/overlaybd/overlaybd.json', 'bin/overlaybd-create',
             'bin/overlaybd-apply', 'bin/overlaybd-commit', 'bin/overlaybd-resize')
    if not marker.is_file() or marker.is_symlink() or json.loads(marker.read_bytes()) != expected:
        return False
    if not all((old / name).is_file() and (old / name).resolve() == old / name for name in files):
        return False
    destination = deps / 'overlaybd'
    for folder in ('.', 'bin', 'etc', 'etc/overlaybd'):
        directory(destination / folder)
    for name in files:
        target = destination / name
        shutil.copyfile(old / name, target)
        os.chown(target, UID, GID)
        target.chmod(0o700 if name.startswith('bin/') else 0o600)
    return True


def prepare(image):
    host = os.uname().nodename.split('.')[0]
    need(os.geteuid() == 0 and host in ('agent1', 'agent2') and os.uname().machine == 'aarch64',
         'Use the M/N root entry')
    need(bool(image) == (host == 'agent1'), 'Only the owner fetches the one benchmark image')
    if image:
        need(re.fullmatch(r'swr\.cn-north-4\.myhuaweicloud\.com/kunpeng-ai/'
                         r'dsbench-modeling-titanic@sha256:[a-f0-9]{64}', image), 'Unexpected benchmark OCI reference')
    account = pwd.getpwnam('jwk')
    need((account.pw_uid, account.pw_gid, account.pw_dir) == (UID, GID, '/home/jwk'), 'Runtime user differs')
    home = HOME.lstat()
    need(HOME.resolve(strict=True) == HOME and stat.S_ISDIR(home.st_mode)
         and home.st_uid in (0, UID) and not home.st_mode & 0o022, 'Runtime work parent differs')
    need(digest(SERVER) == SERVER_HASH and FC.is_file() and KERNEL.is_file(), 'Native server or known FC assets differ')
    missing = [name for name in REQUIRED if not shutil.which(name, path=HOST_PATH)]
    print(json.dumps({'knownFirecracker': str(FC), 'knownGuestKernel': str(KERNEL),
                      'missingRuntimeCommands': missing}), flush=True)
    need(shutil.disk_usage(HOME).free >= 2 << 30, 'Private preparation needs 2 GiB available')

    work = HOME / 'relay-guest-assets-001'
    directory(work)
    children = {name: work / name for name in ('home', 'deps', 'runtime', 'tmp')}
    for path in children.values():
        directory(path)
    reused = retain_overlaybd_release(children['deps'])
    cfg = work / 'config.toml'
    content = (f'home_path = "{children["home"]}"\nruntime_path = "{children["runtime"]}"\n'
               f'deps_path = "{children["deps"]}"\nvirtualization_mode = "kvm"\n'
               f'[firecracker]\nbinary_path = "{FC}"\n[kernel]\nimage_path = "{KERNEL}"\n')
    with cfg.open('x') as stream:
        stream.write(content)
    os.chown(cfg, UID, GID)
    cfg.chmod(0o600)
    env = {name: os.environ[name] for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
           'http_proxy', 'https_proxy', 'no_proxy', 'SSL_CERT_FILE', 'SSL_CERT_DIR') if name in os.environ}
    env.update(PATH=HOST_PATH, HOME=str(children['home']), TMPDIR=str(children['tmp']), LANG='C', LC_ALL='C')
    print(json.dumps({'privatePrep': str(work), 'reusedValidatedOverlaybdRelease': reused}), flush=True)
    if missing:
        setup_rc = 1
    else:
        setup_rc, _ = run('aenv-setup-only', [str(SERVER), '--setup-only', '--config', str(cfg)], env, work, 540)

    regctl = children['deps'] / 'regctl/v0.11.5/regctl'
    image_result = None
    if image and regctl.is_file():
        rc, output = run('benchmark-manifest', [str(regctl), 'manifest', 'get', '--format', 'raw-body', image],
                         env, work, 45)
        image_result = {'ref': image, 'metadataExit': rc}
        if rc == 0:
            raw = output.read_bytes().rstrip(b'\n')
            expected_hash = image.split('@sha256:')[1]
            need(hashlib.sha256(raw).hexdigest() == expected_hash, 'Registry manifest does not match pinned digest')
            layers = json.loads(raw)['layers']
            compressed = sum(layer['size'] for layer in layers)
            need(0 < compressed <= 512 << 20, 'Pinned benchmark layers exceed the bounded download')
            image_result.update(compressedBytes=compressed, layers=len(layers))
            layout = work / 'benchmark-oci'
            copy, _ = run('benchmark-oci-copy', [str(regctl), 'image', 'copy', '--platform', 'linux/arm64',
                          image, f'ocidir://{layout}:benchmark'], env, work, 560)
            image_result.update(copyExit=copy, ociLayout=str(layout) if copy == 0 else None)
    print(json.dumps({'status': 'MN_GUEST_ASSETS_ATTEMPTED', 'node': host, 'setupExit': setup_rc,
                      'privateConfig': str(cfg), 'deps': str(children['deps']),
                      'toolsFiles': [str(path) for path in children['deps'].glob('tools/**/*')
                                     if path.is_file() and path.name in ('tools.ext4', 'image.json')],
                      'benchmark': image_result}), flush=True)
    return 0 if setup_rc == 0 and (not image or image_result and image_result.get('copyExit') == 0) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-ref')
    raise SystemExit(prepare(parser.parse_args().image_ref))
