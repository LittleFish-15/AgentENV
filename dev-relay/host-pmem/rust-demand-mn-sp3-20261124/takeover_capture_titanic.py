"""Capture one Titanic template with an isolated network and a temporary ublk ACL."""

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
from pathlib import Path


BASE = Path('/home/jwk/agent/sp3-mn/relay-guest-assets-001/template-capture-001')
SOURCE = Path('/home/jwk/agent/sp3-mn/src/AgentENV')
BINARY = BASE / 'target-private-001/release/mn_titanic_capture'
CONFIG = BASE / 'config.toml'
LOWERS = BASE / 'rootfs-image.json'
CONTROL = Path('/dev/ublk-control')
FORWARD = Path('/proc/sys/net/ipv4/ip_forward')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/home/jwk', 'LANG': 'C', 'LC_ALL': 'C',
       'NO_COLOR': '1', 'AENV_UBLK_DAEMON_BINARY_PATH': str(SOURCE / 'target/release/uvm-ublk-daemon')}
ACL_BEFORE = ['user::rw-', 'group::---', 'other::---']
ACL_DURING = ['user::rw-', 'user:1204:rw-', 'group::---', 'mask::rw-', 'other::---']
ISOLATED = r'''
set -euo pipefail
test "$(readlink /proc/self/ns/net)" != "$1"
ip link set dev lo up
printf '1\n' > /proc/sys/net/ipv4/ip_forward
test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1
exec /usr/bin/setpriv --reuid=1204 --regid=1205 --init-groups --no-new-privs \
  --inh-caps=-all,+net_admin,+sys_admin --ambient-caps=-all,+net_admin,+sys_admin \
  --bounding-set=-all,+net_admin,+sys_admin -- "$2" "$3" "$4"
'''


def need(value, message):
    if not value:
        raise RuntimeError(message)


def pinned(path, expected):
    need(path.resolve(strict=True) == path and path.is_file() and
         hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'Input digest differs: ' + str(path))


def acl():
    report = subprocess.check_output(['/usr/bin/getfacl', '-cpn', '--', str(CONTROL)],
                                     env=ENV, text=True, timeout=8)
    return [line for line in report.splitlines() if line.strip()]


def identity():
    info = CONTROL.lstat()
    need(stat.S_ISCHR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0,
         'Expected root-owned ublk character device')
    return info.st_dev, info.st_ino, info.st_rdev


def interrupted(*_):
    raise InterruptedError('Template capture interrupted')


def capture():
    command = ['/usr/bin/unshare', '--net', '--', '/bin/bash', '-c', ISOLATED, 'mn-titanic-capture',
               os.readlink('/proc/self/ns/net'), str(BINARY), str(CONFIG), str(LOWERS)]
    path = BASE / 'template-capture.log'
    with path.open('xb') as logs:
        child = subprocess.Popen(command, cwd=BASE, env=ENV, stdin=subprocess.DEVNULL, stdout=logs,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            print(json.dumps({'event': 'MN_NATIVE_TEMPLATE_CAPTURE_STARTED', 'pid': child.pid,
                              'log': str(path)}), flush=True)
            return child.wait(timeout=1600)
        except (subprocess.TimeoutExpired, InterruptedError):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    print('MN_CAPTURE_PROCESS_STILL_PRESENT=' + str(child.pid), flush=True)
            raise
        finally:
            with path.open('rb') as source:
                source.seek(max(0, path.stat().st_size - 16384))
                lines = [line for line in source.read(16384).decode('utf-8', 'replace').splitlines()
                         if not re.search(r'(?i)password|authorization|private.key|token', line)]
                for line in lines[-60:]:
                    print(line, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('binary-sha', 'config-sha', 'lowers-sha'):
        parser.add_argument('--' + key, required=True)
    args = parser.parse_args()
    need(os.geteuid() == 0 and os.uname().nodename.split('.')[0] == 'agent1', 'Use the M root entry')
    os.umask(0o077)
    for path, wanted in ((BINARY, args.binary_sha), (CONFIG, args.config_sha), (LOWERS, args.lowers_sha)):
        pinned(path, wanted)
    need(Path(ENV['AENV_UBLK_DAEMON_BINARY_PATH']).is_file(), 'Existing daemon unavailable')
    need(not (BASE / 'template-capture.log').exists(), 'Prior capture needs reconciliation')
    for process in Path('/proc').iterdir():
        if process.name.isdecimal():
            try:
                executable = Path(os.readlink(process / 'exe')).name
            except OSError:
                continue
            need(executable not in ('server', 'uvm-ublk-daemon', 'mn_titanic_capture', 'firecracker'),
                 'Another runtime is already active: ' + executable)
    device = identity()
    need(acl() == ACL_BEFORE, 'Existing ublk ACL differs; retain it')
    host_forward = FORWARD.read_text().strip()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        subprocess.run(['/usr/bin/setfacl', '-m', 'u:1204:rw-,m::rw-', '--', str(CONTROL)],
                       env=ENV, check=True, timeout=8)
        need(identity() == device and acl() == ACL_DURING, 'Unexpected ACL after temporary grant')
        code = capture()
    finally:
        if identity() != device:
            raise RuntimeError('ublk device was replaced; do not alter its new ACL')
        current = acl()
        if current == ACL_DURING:
            subprocess.run(['/usr/bin/setfacl', '--set-file=-', '--', str(CONTROL)],
                           input='\n'.join(ACL_BEFORE) + '\n', env=ENV, text=True, check=True, timeout=8)
        need(acl() == ACL_BEFORE, 'Unexpected ublk ACL after the attempted restoration')
        need(FORWARD.read_text().strip() == host_forward, 'Host forwarding state differs')
        print(json.dumps({'event': 'runtime_scope_restored', 'deviceAclRestored': True,
                          'hostIpForward': host_forward}), flush=True)
    print(json.dumps({'status': 'MN_TITANIC_CAPTURE_RETURNED', 'exitCode': code}), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
