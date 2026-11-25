"""Verify existing deployment inputs and build only the pinned private SDK adapter."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from pathlib import Path


COMMIT = '207462625ee21d669ddfc34cbfd47932f5a757b7'
TREE = 'abbbafd81c41a8ca4a17efe41c88079ce2e67577'
SOURCE = Path('/home/jwk/agent/sp3-mn/src/AgentENV')
ADAPTER_SHA = '44bb086095f3ed3f2cee2bef40b5ef03b982eb7cc70587ac06dfa4d4c7b1346d'
SDK_PINS = {'/usr/include/ubs_mem.h': '7815d1fbdb9c84a04170961b8b248c05ead361cb24fa0ccb22bd33008cb68ddc',
            '/usr/include/ubs_mem_def.h': '3ae4e258ce8356ce84e62550f0aa392d6333da115d78efdc19833b2175399a15',
            '/usr/lib64/libubsm_sdk.so': '88686bc4e869c6442eb7d88128a2d3efd82468696c489734fc80b4692ac60223'}
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/home/jwk', 'LANG': 'C', 'LC_ALL': 'C',
       'GIT_OPTIONAL_LOCKS': '0'}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def facts(path, hash_file=False):
    path = Path(path)
    try:
        info = path.stat()
        result = {'path': str(path), 'bytes': info.st_size, 'uid': info.st_uid,
                  'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode))}
        if hash_file and stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
            after = path.stat()
            need((info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) == (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Input changed during hashing')
            result['sha256'] = digest.hexdigest()
        return result
    except OSError as error:
        return {'path': str(path), 'error': type(error).__name__}


def run(argv, timeout=12, user=False, cwd='/', limit=12000):
    if user:
        argv = ['/usr/sbin/runuser', '-u', 'jwk', '--', *argv]
    try:
        result = subprocess.run(argv, cwd=cwd, env=ENV, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        def clean(raw):
            lines = raw.decode(errors='replace').splitlines()
            return '\n'.join(re.sub(r'https?://\S+', '[URL]', line) for line in lines
                             if not re.search(r'(?i)password|token|private.key|authorization', line))[-limit:]
        return {'exit': result.returncode, 'stdout': clean(result.stdout), 'stderr': clean(result.stderr)}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'exit': None, 'error': type(error).__name__}


def platform_report():
    processes = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / 'comm').read_text().strip()
            if re.search(r'(?i)ubm|lcne|ubse|sentry|cargo|rustc|server|firecracker|ublk|agentenv', comm):
                exe = entry / 'exe'
                processes.append({'pid': entry.name, 'comm': comm, 'exe': os.readlink(exe),
                                  'binary': facts(exe, hash_file=True)})
        except (OSError, RuntimeError):
            continue
    return {'processes': processes[:64],
            'unixSockets': run(['/usr/sbin/ss', '-xlpn']),
            'ubmPackages': run(['/usr/bin/rpm', '-qa', '--qf', '%{NAME} %{VERSION}-%{RELEASE}\n']),
            'sentryMonitor': run(['/usr/bin/sentryctl', 'status', 'sentry_msg_monitor']),
            'sentryServices': run(['/usr/bin/systemctl', 'show', 'sysSentry.service', 'syssentry.service',
                                   'sentry_msg_monitor.service', '-p', 'Id', '-p', 'ActiveState', '-p', 'MainPID']),
            'topology': run(['/usr/bin/ubsectl', 'display', 'topo', '-t', 'cpu']),
            'memoryHealth': run(['/usr/bin/ubsectl', 'check', 'memory']),
            'loadedObmmSrcversion': Path('/sys/module/obmm/srcversion').read_text().strip()
                if Path('/sys/module/obmm/srcversion').exists() else None,
            'obmmParameters': {p.name: p.read_text().strip() for p in
                Path('/sys/module/obmm/parameters').glob('*') if p.is_file()},
            'sdkAccount': run(['/usr/bin/id', 'ubsmd']),
            'jwkAccount': run(['/usr/bin/id', 'jwk'])}


def locate_inputs():
    result = {}
    names = {'firecracker', 'uvm-ublk-daemon', 'overlaybd-create', 'overlaybd-apply', 'overlaybd-commit',
             'libaenv-ub.so', 'ublk_drv.ko', 'obmm.ko', 'vmlinux', 'vmlinux.bin'}
    roots = [Path('/home/jwk/agent/sp3-mn'), Path('/home/jwk/.local'), Path('/opt'), Path('/usr/local')]
    excluded = {'.git', 'target', 'kernel.partial', 'kernel', 'src', 'registry', 'vendor', 'node_modules',
                'lib', 'lib64', 'share', 'include', '.cargo', 'toolchains'}
    for base in roots:
        count = 0
        for folder, dirs, files in os.walk(base):
            count += 1
            if count > 512:
                result[str(base)] = {'scanLimitReached': True}
                break
            directory = Path(folder)
            dirs[:] = sorted(d for d in dirs if d not in excluded and not d.startswith('.'))
            if len(directory.relative_to(base).parts) >= 5:
                dirs[:] = []
            for name in files:
                if name in names or re.match(r'^(vmlinux|firecracker)[-.].*(?:aarch64|patch|guest|v\d)', name):
                    path = directory / name
                    result[str(path)] = facts(path, hash_file=True)
    for base in (Path('/usr/include/ub'), Path('/usr/include/linux')):
        for path in sorted(base.glob('*obmm*.h'))[:12]:
            result[str(path)] = facts(path, hash_file=True)
            text = path.read_text(errors='replace')
            result[str(path)]['demandMacros'] = re.findall(r'^#define (OBMM_PMEM_[A-Z0-9_]+)', text, re.M)
    return result


def adapter_build(folder):
    source = SOURCE / 'storage/ub-demand/sdk_adapter.cpp'
    raw = source.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == ADAPTER_SHA, 'Pinned adapter source differs')
    private_source = folder / 'sdk_adapter.cpp'
    private_source.write_bytes(raw)
    headers = folder / 'include'
    headers.mkdir(mode=0o700)
    for name, expected in SDK_PINS.items():
        raw = Path(name).read_bytes()
        need(hashlib.sha256(raw).hexdigest() == expected, 'SDK input digest differs')
        if name.endswith('.h'):
            (headers / Path(name).name).write_bytes(raw)
        else:
            (folder / 'libubsm_sdk.so').write_bytes(raw)
    library = folder / 'libubsm_sdk.so'
    output = folder / 'libaenv-ub.so'
    answer = run(['/usr/bin/c++', '-std=c++17', '-O2', '-fPIC', '-shared', '-pthread',
                  '-Wall', '-Wextra', '-Werror', '-I', str(headers), str(private_source), str(library),
                  '-Wl,-z,relro,-z,now,-z,defs', '-o', str(output)], timeout=120)
    if answer['exit'] == 0:
        answer['artifact'] = facts(output, True)
        answer['dynamic'] = run(['/usr/bin/readelf', '-d', str(output)])
    return answer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--machine-id', required=True)
    parser.add_argument('--boot-id', required=True)
    args = parser.parse_args()
    need(os.getuid() == os.geteuid() == 0, 'Use the unified root entry')
    need(Path('/etc/machine-id').read_text().strip() == args.machine_id
         and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == args.boot_id, 'Task identity differs')
    os.umask(0o077)
    folder = Path(tempfile.mkdtemp(prefix='deploy-prepare-', dir='/root/agentenv-mn-sp3'))
    report = {'status': 'DEPLOY_PREPARATION_COLLECTED', 'privateOutput': str(folder),
              'sdkCalled': False, 'moduleChanged': False, 'guestCreated': False}
    for key, task in [('platform', platform_report), ('inputs', locate_inputs)]:
        try:
            report[key] = task()
        except (OSError, RuntimeError) as error:
            report[key] = {'error': type(error).__name__}
    packages = report.get('platform', {}).get('ubmPackages')
    if packages:
        packages['stdout'] = '\n'.join(line for line in packages.get('stdout', '').splitlines()
                                       if re.search(r'(?i)ubm|lcne|sentry|ubs-|obmm', line))
    report['checkout'] = {revision: run(['/usr/bin/git', 'rev-parse', revision], user=True, cwd=SOURCE)
                          for revision in ('HEAD', 'HEAD^{tree}')}
    report['binaries'] = {}
    for name in ('server', 'uvm-ublk-daemon', 'agentenv-ub-provider'):
        path = SOURCE / 'target/release' / name
        report['binaries'][name] = facts(path, True)
        report['binaries'][name]['elf'] = run(['/usr/bin/readelf', '-h', str(path)])
        report['binaries'][name]['help'] = run([str(path), '--help'], user=True)
    try:
        need(report['checkout']['HEAD']['stdout'] == COMMIT
             and report['checkout']['HEAD^{tree}']['stdout'] == TREE, 'Checkout differs')
        report['adapterBuild'] = adapter_build(folder)
    except (OSError, RuntimeError) as error:
        report['adapterBuild'] = {'error': str(error)}
    (folder / 'report.json').write_text(json.dumps(report, sort_keys=True))
    print(json.dumps(report, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
