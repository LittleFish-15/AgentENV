"""Node A only: check/build this independent source with existing offline inputs.
Never installs dependencies, starts a service, accesses SDK objects or changes devices.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path('/home/jwk/agent')
LOCK_SHA = '6cb5431f5fd58fc0fbfa3f8094e3a3c3801a11fc47a976ebb841b32deab325e4'


def path_under_root(value, exists=True):
    path = Path(value).absolute()
    if not path.is_relative_to(ROOT) or path.resolve(strict=exists) != path:
        raise ValueError('Build paths must stay under /home/jwk/agent without redirection')
    return path


def pointer(variable, filename):
    value = os.environ.get(variable)
    if not value:
        value = path_under_root(filename).read_text().strip()
    return path_under_root(value)


def main():
    if (sys.platform != 'linux' or socket.gethostname() != 'server1'
            or os.getuid() != 1204 or os.geteuid() != 1204 or os.getgid() != 1205):
        raise SystemExit('Use node-a/server1 ordinary jwk UID1204/GID1205')
    if os.uname().machine != 'aarch64':
        raise SystemExit('Expected original ARM64 server1')
    caps = [line.split(':')[1].strip() for line in Path('/proc/self/status').read_text().splitlines()
            if line.startswith(('CapInh:', 'CapPrm:', 'CapEff:', 'CapAmb:'))]
    if len(caps) != 4 or any(int(value, 16) for value in caps):
        raise SystemExit('Build directly as jwk with zero capabilities')
    os.umask(0o077)
    source = path_under_root(Path(__file__).absolute().parents[2])
    if hashlib.sha256((source / 'Cargo.lock').read_bytes()).hexdigest() != LOCK_SHA:
        raise SystemExit('Lockfile differs from the fixed offline baseline; no online resolution')
    rust = pointer('AENV_RUST_BIN_DIR', ROOT / 'toolchains/agentenv-rust-1.99.0-offline.path')
    vendor = pointer('AENV_VENDOR_DIR', ROOT / 'offline/agentenv-vendor-ae9c626.path')
    if not rust.is_relative_to(ROOT / 'toolchains') or (rust / 'rustup').exists():
        raise SystemExit('Use the existing standalone private compiler, never rustup proxies')
    manifest = json.loads((vendor / 'agentenv-vendor-manifest.json').read_text())
    if not vendor.is_relative_to(ROOT / 'offline') or manifest['lock_sha256'] != LOCK_SHA:
        raise SystemExit('Offline dependency bundle belongs to another source lockfile')
    for tool in ('gcc', 'g++', 'ar', 'make', 'cmake', 'clang', 'protoc', 'pkg-config', 'readelf'):
        if shutil.which(tool) is None:
            raise SystemExit('Missing existing build tool: ' + tool + '; no installation attempted')
    for tool in ('cargo', 'rustc', 'rustdoc'):
        if not (rust / tool).is_file():
            raise SystemExit('Missing private compiler component: ' + tool)
    if shutil.disk_usage(ROOT).free < 16 * 1024**3:
        raise SystemExit('Independent full build needs at least 16GiB free working space; no cleanup attempted')
    reports = path_under_root(ROOT / 'relay/reports')
    output = Path(tempfile.mkdtemp(prefix='node-a-ub-layers-build-', dir=reports))
    print('REPORT_DIRECTORY=' + str(output), flush=True)
    env = dict(os.environ)
    for variable in list(env):
        if variable.startswith('GIT_'):
            env.pop(variable)
    for variable in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET',
                     'LD_PRELOAD', 'LD_AUDIT'):
        env.pop(variable, None)
    for variable, directory in {'CARGO_HOME': 'cargo', 'RUSTUP_HOME': 'rustup-unused',
                                'TMPDIR': 'tmp', 'XDG_CACHE_HOME': 'cache', 'XDG_CONFIG_HOME': 'config',
                                'XDG_STATE_HOME': 'state', 'CARGO_TARGET_DIR': 'target',
                                'CCACHE_DIR': 'cache/ccache', 'SCCACHE_DIR': 'cache/sccache'}.items():
        path = output / directory
        path.mkdir(parents=True, exist_ok=True)
        env[variable] = str(path)
    env.update(PATH=str(rust) + os.pathsep + env['PATH'], RUSTC=str(rust / 'rustc'),
               RUSTDOC=str(rust / 'rustdoc'), CARGO_NET_OFFLINE='true', CARGO_BUILD_JOBS='2',
               CMAKE_BUILD_PARALLEL_LEVEL='2', GIT_TERMINAL_PROMPT='0',
               PROTOC=shutil.which('protoc'))
    env.update(CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0')
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONPYCACHEPREFIX=str(output / 'cache/pycache'))
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CEILING_DIRECTORIES=str(source.parent))
    if Path('/usr/lib64/libclang.so').is_file():
        env['LIBCLANG_PATH'] = '/usr/lib64'
    config = output / 'cargo-offline.toml'
    config.write_text('''[net]
offline = true
[source.crates-io]
replace-with = "agentenv-offline"
[source."git+https://github.com/ublk-org/libublk-rs.git?rev=c6a3e06"]
git = "https://github.com/ublk-org/libublk-rs.git"
rev = "c6a3e06"
replace-with = "agentenv-offline"
[source.agentenv-offline]
directory = ''' + json.dumps(str(vendor)) + '\n')
    cargo = [str(rust / 'cargo'), '--config', str(config)]
    report = {'status': 'NOT_COMPLETED', 'directory': str(output), 'source': str(source),
              'node': 'node-a', 'uid': 1204, 'phases': {}, 'service_started': False,
              'SDK_called': False, 'Guest_or_ublk_tests_executed': False}
    try:
        commit = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'],
                                         env=env, stderr=subprocess.DEVNULL, timeout=15).decode().strip()
        report['source_commit'] = commit if len(commit) == 40 and all(c in '0123456789abcdef' for c in commit) else None
    except (OSError, subprocess.SubprocessError):
        report['source_commit'] = None

    def run(name, command):
        print('PHASE=' + name, flush=True)
        with (output / (name + '.log')).open('wb') as log:
            process = subprocess.Popen(command, cwd=source, env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                started = last_progress = time.monotonic()
                while True:
                    try:
                        rc = process.wait(timeout=5)
                        break
                    except subprocess.TimeoutExpired:
                        free = shutil.disk_usage(ROOT).free
                        if free < 2 * 1024**3:
                            raise RuntimeError('Build free-space floor reached; stopping only this build process group')
                        now = time.monotonic()
                        if now - last_progress >= 30:
                            print('BUILD_PROGRESS phase=' + name + ' elapsed_s=' + str(int(now - started))
                                  + ' free_disk_mib=' + str(free // 1024**2), flush=True)
                            last_progress = now
            except BaseException:
                # Only this newly created build process group; never global process cleanup.
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                raise
        report['phases'][name] = rc
        if rc:
            print((output / (name + '.log')).read_text(errors='replace')[-16000:], flush=True)
            raise RuntimeError(name + ' failed; preserve logs and do not install/upgrade system components')

    try:
        run('rust-version', [str(rust / 'rustc'), '-Vv'])
        run('resolution', cargo + ['metadata', '--frozen', '--format-version', '1'])
        run('check-server-daemon', cargo + ['check', '--frozen', '-p', 'agentenv', '-p', 'uvm-ublk-daemon'])
        run('test-ub-wire-and-file', cargo + ['test', '--frozen', '-p', 'overlaybd', '--lib', 'backend::ub', '--', '--test-threads=2'])
        run('test-ub-and-legacy-config', cargo + ['test', '--frozen', '-p', 'overlaybd', '--lib', 'config::'])
        run('test-ub-ancestor-staging', cargo + ['test', '--frozen', '-p', 'agentenv', '--lib',
                                              'split_runtime_suffix_keeps_ub_ancestor_without_a_local_duplicate'])
        run('build-runtime', cargo + ['build', '--frozen', '--release', '-p', 'agentenv', '--bin', 'server'])
        run('build-cli', cargo + ['build', '--frozen', '--release', '-p', 'aenv', '--bin', 'aenv'])
        run('build-daemon', cargo + ['build', '--frozen', '--release', '-p', 'uvm-ublk-daemon', '--bin', 'uvm-ublk-daemon'])
        run('build-layer-probe', cargo + ['build', '--frozen', '--release', '-p', 'overlaybd', '--example', 'ub_layer_probe'])
        artifacts = output / 'artifacts'
        artifacts.mkdir()
        for name in ('server', 'aenv', 'uvm-ublk-daemon', 'examples/ub_layer_probe'):
            shutil.copy2(output / 'target/release' / name, artifacts / Path(name).name)
        report['artifacts'] = str(artifacts)
        report['sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts.iterdir()}
        report['status'] = 'UB_LAYERS_OFFLINE_BUILD_COMPLETED_NO_SERVICE_STARTED'
    except BaseException as error:
        report.update(status='STOPPED_UB_LAYERS_BUILD', error=type(error).__name__ + ': ' + str(error))
    (output / 'return.json').write_text(json.dumps(report, indent=2))
    print('BEGIN_RETURN_REPORT')
    print(json.dumps(report, indent=2))
    print('END_RETURN_REPORT')
    return 0 if report['status'].startswith('UB_LAYERS_OFFLINE_BUILD_COMPLETED') else 1


if __name__ == '__main__':
    try:
        code = main()
    except Exception as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'STOPPED_BUILD_PRECONDITION_NO_BUILD_STARTED', 'error': str(error)}, indent=2))
        print('END_RETURN_REPORT')
        code = 1
    raise SystemExit(code)
