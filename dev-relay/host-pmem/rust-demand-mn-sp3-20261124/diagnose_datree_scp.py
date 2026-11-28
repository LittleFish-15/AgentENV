import argparse
import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path


WORK = Path('/opt/aenv-datree-import-001')
REMOTE = 'jwk@90.96.12.112:/opt/aenv-datree-relay-001/datree-peer.tar'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', required=True)
    parser.add_argument('--boot-id', required=True)
    parser.add_argument('--machine-id', required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or args.node != os.uname().nodename.split('.')[0]
            or args.boot_id != Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            or args.machine_id != Path('/etc/machine-id').read_text().strip()):
        raise RuntimeError('Node identity differs')
    user = pwd.getpwnam('jwk')
    home = Path(user.pw_dir)
    ssh = home / '.ssh'
    facts = {'node': args.node, 'uid': user.pw_uid, 'gid': user.pw_gid,
             'sshDir': {'exists': ssh.is_dir(), 'mode': oct(ssh.stat().st_mode & 0o777) if ssh.exists() else None},
             'knownHosts': {'exists': (ssh / 'known_hosts').is_file()},
             'targetWork': {'exists': os.path.lexists(WORK)}}
    if os.path.lexists(WORK):
        st = WORK.lstat()
        facts['targetWork'].update({'mode': oct(st.st_mode & 0o777), 'uid': st.st_uid, 'gid': st.st_gid,
                                    'entries': sorted(p.name for p in WORK.iterdir()) if WORK.is_dir() else []})
        incoming = WORK / 'incoming' / 'datree-peer.tar'
        if os.path.lexists(incoming):
            st = incoming.lstat()
            facts['targetWork']['partialBundle'] = {
                'regular': incoming.is_file(), 'bytes': st.st_size,
                'uid': st.st_uid, 'gid': st.st_gid}
    command = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ConnectTimeout=12', 'jwk@90.96.12.112',
               'test -r /opt/aenv-datree-relay-001/datree-peer.tar && stat -c "%s %a %u %g" /opt/aenv-datree-relay-001/datree-peer.tar']
    env = {'HOME': str(home), 'USER': 'jwk', 'LOGNAME': 'jwk', 'PATH': '/usr/bin:/bin'}
    result = subprocess.run(['/usr/sbin/runuser', '-u', 'jwk', '--'] + command,
                            capture_output=True, text=True, timeout=25, env=env)
    facts['noninteractiveSsh'] = {'exitCode': result.returncode,
                                  'stdout': result.stdout[-2000:], 'stderr': result.stderr[-2000:]}
    print(json.dumps(facts, sort_keys=True))


if __name__ == '__main__':
    main()
