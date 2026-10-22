"""User-scoped, dedicated A-to-B experiment transport; no sshd/config changes."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess

COMMENT = 'agentenv-native-four-transport-v1'
DIRECTORY = Path('/home/jwk/.ssh/agentenv-native-four')
KEY = DIRECTORY / 'id_ed25519'
KNOWN = DIRECTORY / 'known_hosts'
DESTINATION = 'jwk@agent1'


def need(value, message):
    if not value:
        raise RuntimeError(message)


def public_key(text):
    parts = text.strip().split()
    need(len(parts) in (2, 3) and parts[0] == 'ssh-ed25519', 'Expected one Ed25519 public key')
    raw = base64.b64decode(parts[1], validate=True)
    need(len(raw) == 51 and raw[:19] == b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20', 'Invalid Ed25519 key encoding')
    return parts[0] + ' ' + parts[1]


def fingerprint(key):
    raw = base64.b64decode(public_key(key).split()[1])
    return 'SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')


def authorized_line(key):
    return ('restrict ' + public_key(key) + ' ' + COMMENT + '\n').encode()


def revised_authorized_keys(previous, key, remove=False):
    need(len(previous) <= 1024**2 and b'\0' not in previous, 'Unexpected authorized_keys contents')
    desired = authorized_line(key)
    lines = previous.splitlines(keepends=True)
    matches = [line for line in lines if COMMENT.encode() in line]
    need(all(line == desired or line == desired.rstrip(b'\n') for line in matches),
         'Experiment key marker exists with different contents; preserved')
    if remove:
        return b''.join(line for line in lines if line not in matches)
    if matches:
        need(len(matches) == 1, 'Duplicate experiment authorization; preserved')
        return previous
    # Do not add a second, less restricted copy of an already authorized key.
    need(public_key(key).split()[1].encode() not in previous, 'Public key already exists without our exact marker')
    return previous + (b'\n' if previous and not previous.endswith(b'\n') else b'') + desired


def ordinary(host):
    need(os.name == 'posix' and os.getuid() == os.geteuid() == 1204
         and os.getgid() == os.getegid() == 1205 and socket.gethostname() == host,
         'Run as ordinary jwk on the intended node, not root or sudo')
    caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(caps[k].strip(), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')),
         'Capability-free user session required')
    os.umask(0o077)


def owned_directory(path):
    if not path.exists():
        path.mkdir(mode=0o700)
    meta = path.lstat()
    need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 1204 and path.resolve(strict=True) == path
         and not meta.st_mode & 0o022, 'Unsafe directory, preserved: ' + str(path))


def owned_file(path, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204 and meta.st_nlink == 1
             and meta.st_size <= 1024**2 and not meta.st_mode & (0o077 if private else 0o022),
             'Unsafe file, preserved: ' + str(path))
        return stream.read()


def create_exact(path, contents):
    if path.exists() or path.is_symlink():
        need(owned_file(path, True) == contents, 'Existing experiment file differs; preserved')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


def ssh_args(batch=True):
    return ['/usr/bin/ssh', '-F', '/dev/null', '-i', str(KEY),
            '-oIdentitiesOnly=yes', '-oIdentityAgent=none', '-oStrictHostKeyChecking=yes',
            '-oUserKnownHostsFile=' + str(KNOWN), '-oGlobalKnownHostsFile=/dev/null',
            '-oUpdateHostKeys=no', '-oHostKeyAlgorithms=ssh-ed25519',
            '-oForwardAgent=no', '-oClearAllForwardings=yes', '-oRequestTTY=no',
            '-oConnectTimeout=10', '-oServerAliveInterval=15', '-oServerAliveCountMax=4',
            '-oBatchMode=' + ('yes' if batch else 'no'), DESTINATION]


def remote_code(key, remove):
    # This literal runs as the authenticated remote jwk. No remote helper upload
    # or root action. Serialize data separately; never interpolate key as code.
    import inspect
    definitions = '\n\n'.join(inspect.getsource(fn) for fn in
        (need, public_key, authorized_line, revised_authorized_keys))
    return ('import base64,json,os,socket,stat,fcntl,tempfile\nfrom pathlib import Path\n'
            + 'COMMENT=' + repr(COMMENT) + '\n' + definitions + '\n'
            + 'KEY=' + repr(public_key(key)) + '\nREMOVE=' + repr(remove) + '\n' + REMOTE_EDIT)


REMOTE_EDIT = r'''
need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205 and socket.gethostname()=='agent1', 'Wrong remote user or host')
home=Path('/home/jwk');need(home.resolve(strict=True)==home and home.stat().st_uid==1204, 'Wrong home')
os.umask(0o077)
directory=home/'.ssh'
if not directory.exists(): directory.mkdir(mode=0o700)
m=directory.lstat();need(stat.S_ISDIR(m.st_mode) and m.st_uid==1204 and not m.st_mode&0o022 and directory.resolve()==directory,'Unsafe .ssh; preserved')
lock=os.open(directory/'.agentenv-native-four.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
lm=os.fstat(lock);need(stat.S_ISREG(lm.st_mode) and lm.st_uid==1204 and lm.st_nlink==1 and not lm.st_mode&0o077,'Unsafe lock')
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
path=directory/'authorized_keys'
def read_current():
 try: fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except FileNotFoundError: return None,b''
 with os.fdopen(fd,'rb') as f:
  m=os.fstat(f.fileno());need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_nlink==1 and m.st_size<=1048576 and not m.st_mode&0o022,'Unsafe authorized_keys; preserved')
  return (m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns,stat.S_IMODE(m.st_mode)),f.read()
before,old=read_current();new=revised_authorized_keys(old,KEY,REMOVE)
if new!=old:
 fd,name=tempfile.mkstemp(prefix='.agentenv-four-',dir=directory)
 try:
  with os.fdopen(fd,'wb') as f:
   os.fchmod(f.fileno(),before[-1] if before else 0o600);f.write(new);f.flush();os.fsync(f.fileno())
  now,current=read_current();need(now==before and current==old,'Concurrent authorized_keys change; preserved')
  os.replace(name,path)
 finally:
  if os.path.exists(name): os.unlink(name)
print('FOUR_SSH_AUTHORIZATION_REMOVED' if REMOVE else 'FOUR_SSH_AUTHORIZATION_INSTALLED')
'''


def check_connection():
    command = "import os,socket;assert os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205 and socket.gethostname()=='agent1';print('FOUR_SSH_JWK_READY')"
    result = subprocess.run(ssh_args() + [shlex.join(['/usr/bin/python3', '-I', '-B', '-c', command])],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    return result.returncode == 0 and result.stdout.strip() == 'FOUR_SSH_JWK_READY'


def setup():
    ordinary('server1')
    host = public_key(input('Paste B_HOST_PUBLIC_KEY from the B terminal: ').strip())
    print('Pinned B host fingerprint: ' + fingerprint(host), flush=True)
    owned_directory(Path('/home/jwk/.ssh'))
    owned_directory(DIRECTORY)
    create_exact(KNOWN, ('agent1 ' + host + '\n').encode())
    if not KEY.exists() and not KEY.is_symlink():
        need(not KEY.with_suffix('.pub').exists(), 'Orphan public key preserved')
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', COMMENT, '-f', str(KEY)], check=True)
    owned_file(KEY, True)  # Content deliberately never printed or transmitted.
    derived = subprocess.check_output(['/usr/bin/ssh-keygen', '-y', '-f', str(KEY)], text=True, timeout=15)
    key = public_key(derived)
    need(public_key(owned_file(KEY.with_suffix('.pub')).decode()) == key, 'Key pair mismatch')
    if not check_connection():
        print('Install restricted experiment public key. Enter B jwk password only at the SSH prompt.', flush=True)
        command = shlex.join(['/usr/bin/python3', '-I', '-B', '-c', remote_code(key, False)])
        subprocess.run(ssh_args(False) + [command], stdin=subprocess.DEVNULL, check=True, timeout=240)
    need(check_connection(), 'Batch authentication did not pass; preserve files for diagnosis')
    print(json.dumps({'status': 'FOUR_SSH_JWK_READY', 'user': 'jwk', 'destination': DESTINATION,
                      'keyFingerprint': fingerprint(key), 'hostFingerprint': fingerprint(host),
                      'privateKeyTransmitted': False, 'sshdChanged': False, 'rootUsed': False}))


def revoke():
    ordinary('server1')
    owned_file(KEY, True)
    key = public_key(owned_file(KEY.with_suffix('.pub')).decode())
    command = shlex.join(['/usr/bin/python3', '-I', '-B', '-c', remote_code(key, True)])
    subprocess.run(ssh_args() + [command], stdin=subprocess.DEVNULL, check=True, timeout=30)
    print('Experiment authorization removed on B. Dedicated local files retained; no other keys changed.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('host-key-b', 'setup-a', 'check-a', 'revoke-a'))
    args = parser.parse_args()
    if args.mode == 'host-key-b':
        ordinary('agent1')
        path = Path('/etc/ssh/ssh_host_ed25519_key.pub')
        meta = path.lstat()
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022 and meta.st_size < 4096,
             'Unexpected host public key')
        key = public_key(path.read_text())
        print('B_HOST_PUBLIC_KEY=' + key)
        print('B_HOST_FINGERPRINT=' + fingerprint(key))
    elif args.mode == 'setup-a':
        setup()
    elif args.mode == 'check-a':
        ordinary('server1')
        need(check_connection(), 'Dedicated connection not ready')
        print('FOUR_SSH_JWK_READY')
    else:
        revoke()


if __name__ == '__main__':
    main()
