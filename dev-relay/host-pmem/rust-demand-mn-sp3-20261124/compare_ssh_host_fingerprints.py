import argparse
import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path


PINNED = 'SHA256:OWbB11cJjmHBjk27nVf7+OP7/ksWj/AxB7g7iuh5bYzM'


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
    if args.node == 'agent1':
        result = subprocess.run(['/usr/bin/ssh-keyscan', '-T', '12', '-t', 'ed25519', '90.96.12.112'],
                                capture_output=True, text=True, timeout=20)
        found = set()
        for line in result.stdout.splitlines():
            if not line or line.startswith('#'):
                continue
            row = line.split()
            if len(row) >= 3 and row[0] == '90.96.12.112' and row[1] == 'ssh-ed25519':
                blob = base64.b64decode(row[2], validate=True)
                found.add('SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('='))
        report = {'node': args.node, 'probe': 'ssh-keyscan-ed25519', 'exitCode': result.returncode,
                  'fingerprints': sorted(found), 'matchesPinned': found == {PINNED},
                  'stderr': result.stderr[-1000:]}
    elif args.node == 'agent2':
        public = Path('/etc/ssh/ssh_host_ed25519_key.pub')
        result = subprocess.run(['/usr/bin/ssh-keygen', '-lf', str(public), '-E', 'sha256'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise RuntimeError('ssh-keygen failed: ' + result.stderr[-1000:])
        fields = result.stdout.strip().split()
        if len(fields) < 3:
            raise RuntimeError('Unexpected ssh-keygen output')
        report = {'node': args.node, 'probe': 'local-public-host-key', 'fingerprint': fields[1],
                  'matchesPinned': fields[1] == PINNED}
    else:
        raise RuntimeError('Unexpected node')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
