"""Start only the staged Provider generation and capture startup evidence."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import time
import uuid
from pathlib import Path


PROVIDER = Path('/opt/aenv/bin/agentenv-ub-provider-5ecfe105')
PROVIDER_SHA = '5ecfe105521b583e3e419bdf6da09258144a5a4e63834de6612b4bcf880647d8'
ROLE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def json_file(path):
    need(path.resolve(strict=True) == path and path.is_file() and path.stat().st_size <= 2 * 1024 * 1024,
         'Unexpected configuration or journal file: ' + str(path))
    return json.loads(path.read_bytes())


def start(label, argv, home, logs):
    output = logs / (label + '.log')
    with output.open('xb') as stream:
        child = subprocess.Popen(argv, env={**ROLE_ENV, 'HOME': home}, cwd='/', stdin=subprocess.DEVNULL,
                                 stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
                                 close_fds=True)
    print(json.dumps({'event': 'role_dispatched', 'role': label, 'launcherPid': child.pid,
                      'log': str(output)}), flush=True)
    return child


def print_tail(label, path):
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - 4096))
        raw = stream.read(4096).decode('utf-8', 'replace')
    lines = [line for line in raw.splitlines()
             if not re.search(r'(?i)password|authorization|private.key|token', line)]
    print(json.dumps({'event': 'current_role_log', 'role': label, 'tail': lines[-20:]}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=uuid.UUID)
    parser.add_argument('--manifest-sha', required=True)
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    need(os.geteuid() == 0 and host in ('agent1', 'agent2'), 'Use the M/N unified entry')
    os.umask(0o077)
    run = args.run.hex
    root_dir = Path('/etc/aenv/ub') / ('relay-' + run)
    sdk_dir = Path('/var/lib/aenv-ub-sdk') / ('relay-' + run)
    root_cfg, sdk_cfg = root_dir / 'device-root.json', sdk_dir / 'device-sdk.json'
    root, sdk = json_file(root_cfg), json_file(sdk_cfg)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    for cfg in (root, sdk):
        need(cfg['run'] == run and cfg['node'] == host and cfg['manifestSha256'] == args.manifest_sha
             and cfg['device']['bootId'] == boot and cfg['device']['kernelRelease'] == os.uname().release,
             'Staged generation differs from the running node')
    need(root['device'] == sdk['device'] and root['rootSocket'] == sdk['rootSocket']
         and root['sdkSocket'] == sdk['sdkSocket'] and root['sdk'] == sdk['sdk'],
         'Provider roles have conflicting staged configuration')
    need(root['rootSocket'] == str(root_dir / 'rootctl/root.sock') and
         root['sdkSocket'] == str(sdk_dir / 'sdk.sock') and
         root['device']['brokerSocket'] == str(root_dir / 'broker/broker.sock') and
         root['device']['index'] == str(root_dir / 'index/stable-index.json') and
         root['device']['stateDir'] == str(root_dir / 'device-state') and
         root['sdk']['stateDir'] == str(sdk_dir / 'state'), 'Unexpected generation paths')
    fresh_paths = (root['rootSocket'], root['sdkSocket'], root['device']['brokerSocket'],
                   root['device']['index'], root_dir / 'device-state/root.json', sdk_dir / 'state')
    need(not any(os.path.lexists(path) for path in fresh_paths), 'Prior generation activity requires reconciliation')
    need(PROVIDER.resolve(strict=True) == PROVIDER and PROVIDER.is_file()
         and hashlib.sha256(PROVIDER.read_bytes()).hexdigest() == PROVIDER_SHA,
         'Provider build differs')
    for process in Path('/proc').iterdir():
        if process.name.isdecimal():
            try:
                executable = Path(os.readlink(process / 'exe')).name
            except OSError:
                continue
            need(not executable.startswith('agentenv-ub-provider'), 'A Provider process is already active')

    logs = root_dir / 'launch-evidence'
    logs.mkdir(mode=0o700)
    sdk_role = start('sdk', ['/usr/sbin/runuser', '-u', 'jwk', '--', str(PROVIDER),
                             'sdk', str(sdk_cfg)], '/home/jwk', logs)
    root_role = None
    try:
        socket_deadline = time.monotonic() + 15
        while time.monotonic() < socket_deadline:
            need(sdk_role.poll() is None, 'SDK exited before its socket appeared')
            try:
                if stat.S_ISSOCK((sdk_dir / 'sdk.sock').lstat().st_mode):
                    break
            except FileNotFoundError:
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError('SDK socket did not appear')
        root_role = start('root', [str(PROVIDER), 'root', str(root_cfg)], '/root', logs)
        deadline = time.monotonic() + 155
        while time.monotonic() < deadline:
            need(sdk_role.poll() is None and root_role.poll() is None, 'A Provider role exited during startup')
            index_path = root_dir / 'index/stable-index.json'
            if index_path.is_file():
                index = json_file(index_path)
                journal = json_file(root_dir / 'device-state/root.json')
                if journal.get('phase') == 'serving':
                    need(index.get('state') == 'metadata_ready' and journal.get('run') == run
                         and index.get('replicas') and all(row.get('generation') == run for row in index['replicas']),
                         'Published index does not attest the expected generation')
                    print(json.dumps({'status': 'MN_PROVIDER_SERVING', 'node': host, 'run': run,
                                      'sdkLauncherPid': sdk_role.pid, 'rootPid': root_role.pid,
                                      'index': str(index_path), 'phase': journal['phase'],
                                      'replicas': len(index['replicas'])}), flush=True)
                    return
            time.sleep(0.5)
        raise RuntimeError('Provider ready index did not appear before the observation deadline')
    except (OSError, RuntimeError, ValueError):
        print_tail('sdk', logs / 'sdk.log')
        if root_role is not None:
            print_tail('root', logs / 'root.log')
        raise


if __name__ == '__main__':
    main()
