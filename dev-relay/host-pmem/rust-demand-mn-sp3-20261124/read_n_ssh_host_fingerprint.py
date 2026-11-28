import argparse
import json
import os
import subprocess
from pathlib import Path


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
    public = Path('/etc/ssh/ssh_host_ed25519_key.pub')
    if not public.is_file():
        raise RuntimeError('N Ed25519 host public key is absent')
    result = subprocess.run(['/usr/bin/ssh-keygen', '-lf', str(public), '-E', 'sha256'],
                            capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError('ssh-keygen failed: ' + result.stderr[-1000:])
    fields = result.stdout.strip().split()
    if len(fields) < 3 or fields[1].split(':', 1)[0] != 'SHA256':
        raise RuntimeError('Unexpected host key fingerprint output')
    print(json.dumps({'node': args.node, 'algorithm': 'ssh-ed25519',
                      'fingerprint': fields[1], 'keyBits': fields[0],
                      'keyComment': ' '.join(fields[2:])}, sort_keys=True))


if __name__ == '__main__':
    main()
