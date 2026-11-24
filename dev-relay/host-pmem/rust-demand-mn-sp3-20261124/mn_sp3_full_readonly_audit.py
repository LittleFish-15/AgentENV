"""Bounded, read-only M/N readiness audit for the SP3 demand deployment."""

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import re
import stat
import subprocess
import time
from pathlib import Path


MIB = 1024 * 1024
ROOT = Path('/home/jwk')
UBM_SOCKET = Path('/run/ubm/socket/ubm_nuds/restconf.sock')
UBSE_SOCKET = Path('/var/run/ubse/ubse_ubm.socket')
PINNED_UBSE_SHA = '22ce7d2f4309765d18e4df41a8a2941aacd023cac46d8f135aee0cd4a2e19d45'


def command(argv, cwd='/', timeout=8, limit=24 * 1024, env=None):
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
        stdout = result.stdout[:limit].decode('utf-8', 'replace')
        stderr = result.stderr[:limit].decode('utf-8', 'replace')
        return {'argv': argv, 'exit': result.returncode, 'stdout': stdout,
                'stderr': stderr, 'truncated': len(result.stdout) > limit or len(result.stderr) > limit}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'argv': argv, 'exit': None, 'stdout': '', 'stderr': type(error).__name__}


def digest(path, maximum=64 * MIB):
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            return {'path': str(path), 'bytes': info.st_size, 'mode': stat.S_IMODE(info.st_mode),
                    'uid': info.st_uid, 'gid': info.st_gid}
        hasher = hashlib.sha256()
        with resolved.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                hasher.update(block)
        return {'path': str(path), 'bytes': info.st_size, 'mode': f'{stat.S_IMODE(info.st_mode):04o}',
                'uid': info.st_uid, 'gid': info.st_gid, 'sha256': hasher.hexdigest()}
    except (OSError, ValueError) as error:
        return {'path': str(path), 'error': type(error).__name__}


def path_fact(path):
    try:
        info = path.lstat()
        value = {'path': str(path), 'type': stat.filemode(info.st_mode), 'uid': info.st_uid,
                 'gid': info.st_gid, 'mode': f'{stat.S_IMODE(info.st_mode):04o}'}
        if stat.S_ISSOCK(info.st_mode):
            value['socket'] = True
        if stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
            value.update(major=os.major(info.st_rdev), minor=os.minor(info.st_rdev))
        return value
    except OSError as error:
        return {'path': str(path), 'present': False, 'error': type(error).__name__}


def tail(path, limit=24 * 1024):
    try:
        with path.open('rb') as stream:
            stream.seek(max(0, path.stat().st_size - limit))
            data = stream.read(limit + 1).decode('utf-8', 'replace')
        lines = [line for line in data.splitlines() if not re.search(r'(?i)(token|password|secret|authorization|private.key)', line)]
        return '\n'.join(lines[-160:])
    except OSError as error:
        return f'[{type(error).__name__}]'


def run_as_jwk(argv, cwd='/home/jwk', timeout=12):
    return command(['runuser', '-u', 'jwk', '--', *argv], cwd=cwd, timeout=timeout)


def package_facts():
    names = ('kernel', 'kernel-devel', 'ubs-engine', 'ubs-engine-client-libs', 'ubs-mem-shmem',
             'ubs-comm-lib', 'obmm', 'obmm-devel', 'rust', 'cargo', 'openssl', 'openssl-libs')
    result = command(['rpm', '-q', '--qf', '%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\\n', *names])
    return {'packages': result['stdout'].splitlines(), 'query': result}


def module_facts():
    result = {}
    for name in ('ublk_drv', 'obmm', 'ubus', 'ummu_core', 'uburma'):
        result[name] = {
            'loaded': Path('/sys/module', name).is_dir(),
            'modinfo': command(['modinfo', '-F', 'filename', name]),
            'vermagic': command(['modinfo', '-F', 'vermagic', name]),
            'srcversion': command(['modinfo', '-F', 'srcversion', name]),
            'depends': command(['modinfo', '-F', 'depends', name]),
            'signer': command(['modinfo', '-F', 'signer', name]),
        }
    result['configFiles'] = [str(path) for path in Path('/boot').glob('config-*')][:4]
    return result


def tool_facts():
    tools = {}
    for name in ('git', 'gcc', 'g++', 'make', 'cmake', 'pkg-config', 'protoc', 'cargo', 'rustc',
                 'mke2fs', 'debugfs', 'ubsectl', 'firecracker', 'overlaybd-tcmu-runner'):
        tools[name] = command(['sh', '-lc', f'command -v {name} && {name} --version 2>&1 | head -n 2'], timeout=6)
    tools['jwk-rustc'] = run_as_jwk(['sh', '-lc', 'command -v rustc; rustc -vV'], timeout=10)
    tools['jwk-cargo'] = run_as_jwk(['sh', '-lc', 'command -v cargo; cargo -vV'], timeout=10)
    return tools


def network_facts(expected, peer):
    return {
        'addresses': command(['ip', '-brief', 'address'], limit=16 * 1024),
        'routes': command(['ip', 'route', 'get', str(peer)], limit=8 * 1024),
        'expected': str(expected), 'peer': str(peer),
        'tcp22': command(['timeout', '5', 'bash', '-c', f'cat < /dev/null > /dev/tcp/{peer}/22'], timeout=7),
    }


def service_facts():
    names = ('ubse.service', 'ubsmd.service', 'aenv.service', 'agentenv.service',
             'agentenv-ub-sdk.service', 'agentenv-ub-device.service')
    return {name: command(['systemctl', 'show', name, '--no-pager',
                           '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'FragmentPath'])
            for name in names}


def process_facts():
    result = command(['ps', '-eo', 'user=,pid=,ppid=,stat=,etime=,comm=,args=', '--sort=pid'], limit=80 * 1024)
    selected = []
    for line in result['stdout'].splitlines():
        if re.search(r'(?i)(agentenv|uvm-ublk|firecracker|overlaybd|ubse|cargo|rustc|rocksdb)', line):
            selected.append(line[:500])
    return {'selected': selected[-120:], 'count': len(selected)}


def known_files():
    candidates = [
        ROOT / 'agent' / 'sp3-mn' / 'src' / 'AgentENV',
        ROOT / 'agentenv-mn-build',
        ROOT / 'agent' / 'builds',
        ROOT / 'agent' / 'bin',
        ROOT / '.local' / 'rustup',
        ROOT / '.cargo',
        Path('/etc/aenv/ub/sdk.json'), Path('/etc/aenv/ub/device.json'),
        Path('/dev/kvm'), Path('/dev/ublk-control'), Path('/dev/obmm'), Path('/dev/obmm_pmem'),
        Path('/usr/bin/ubse'), Path('/usr/bin/firecracker'), Path('/usr/local/bin/firecracker'),
        Path('/usr/local/bin/overlaybd'), Path('/usr/bin/overlaybd'),
    ]
    result = {}
    for path in candidates:
        if path.is_file() and path.stat().st_size <= 64 * MIB:
            result[str(path)] = digest(path)
        else:
            result[str(path)] = path_fact(path)
    return result


def build_facts():
    result = {}
    base = ROOT / 'agentenv-mn-build'
    if base.is_dir():
        attempts = sorted((p for p in base.glob('attempt-*') if p.is_dir()), key=lambda p: p.name)[-4:]
        for attempt in attempts:
            logs = {}
            for path in sorted(attempt.glob('*.log')):
                logs[path.name] = {'bytes': path.stat().st_size, 'tail': tail(path)}
            result[attempt.name] = logs
    source = ROOT / 'agent' / 'sp3-mn' / 'src' / 'AgentENV'
    if source.is_dir():
        result['checkout'] = {'path': str(source),
                              'head': command(['git', 'rev-parse', 'HEAD'], cwd=str(source)),
                              'tree': command(['git', 'rev-parse', 'HEAD^{tree}'], cwd=str(source)),
                              'status': command(['git', 'status', '--porcelain'], cwd=str(source)),
                              'cargoLock': digest(source / 'Cargo.lock')}
    return result


def ub_facts():
    topo = command(['timeout', '12', 'ubsectl', 'display', 'topo', '-t', 'cpu'], timeout=15, limit=24 * 1024)
    memory = command(['timeout', '12', 'ubsectl', 'check', 'memory'], timeout=15, limit=24 * 1024)
    return {'ubmSocket': path_fact(UBM_SOCKET), 'ubseSocket': path_fact(UBSE_SOCKET),
            'topology': topo, 'memory': memory, 'socketParent': path_fact(UBM_SOCKET.parent)}


def audit(args):
    current = {'hostname': platform.node(), 'machineId': Path('/etc/machine-id').read_text().strip(),
               'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
               'kernel': platform.release(), 'architecture': platform.machine()}
    issues = []
    if current['architecture'] != 'aarch64':
        issues.append('architecture is not native ARM64')
    ub = ub_facts()
    if ub['ubmSocket'].get('type') != 's' or ub['topology']['exit'] != 0 or len(ub['topology']['stdout'].splitlines()) < 3:
        issues.append('UBM socket or usable CPU topology is unavailable')
    if not Path('/dev/ublk-control').exists():
        issues.append('ublk control device is missing')
    if not Path('/sys/module/obmm').is_dir():
        issues.append('demand OBMM module is not loaded')
    if not Path('/etc/aenv/ub/sdk.json').is_file() or not Path('/etc/aenv/ub/device.json').is_file():
        issues.append('demand role configuration files are missing')
    result = {'status': 'FULL_READ_ONLY_MN_AUDIT', 'node': args.node_label, 'identity': current,
              'network': network_facts(args.expected_address, args.peer_address),
              'kernel': {'release': current['kernel'], 'modules': module_facts()},
              'ub': ub, 'devices': {str(path): path_fact(path) for path in
                                    (Path('/dev/kvm'), Path('/dev/ublk-control'), Path('/dev/obmm'), Path('/dev/obmm_pmem'))},
              'packages': package_facts(), 'tools': tool_facts(), 'services': service_facts(),
              'processes': process_facts(), 'files': known_files(), 'builds': build_facts(),
              'issues': issues, 'readOnly': True, 'guestCreated': False, 'sdkCalled': False,
              'servicesChanged': False, 'kernelChanged': False, 'ubsePinnedSha256': PINNED_UBSE_SHA,
              'collectedUnix': time.time()}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node-label', choices=('node-m', 'node-n'), required=True)
    parser.add_argument('--expected-address', type=ipaddress.ip_address, required=True)
    parser.add_argument('--peer-address', type=ipaddress.ip_address, required=True)
    parser.add_argument('--machine-id', required=True)
    parser.add_argument('--boot-id', required=True)
    args = parser.parse_args()
    if os.getuid() != 0 or os.geteuid() != 0 or platform.system() != 'Linux':
        raise SystemExit(2)
    result = audit(args)
    result['identityMatchesBinding'] = result['identity']['machineId'] == args.machine_id and result['identity']['bootId'] == args.boot_id
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'status': 'FULL_READ_ONLY_AUDIT_FAILED', 'error': type(error).__name__}))
        raise SystemExit(1)
