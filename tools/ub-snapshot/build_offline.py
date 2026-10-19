"""Node A only: check/build independent source with an existing compiler.
Never installs/upgrades a toolchain/system package or changes a service/device.
Locked dependency downloads into a private cache require --allow-locked-network.
"""
import hashlib
import argparse
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
import re
import stat

ROOT = Path('/home/jwk/agent')
LOCK_SHA = '6cb5431f5fd58fc0fbfa3f8094e3a3c3801a11fc47a976ebb841b32deab325e4'


def path_under_root(value, exists=True):
    path = Path(value).absolute()
    if not path.is_relative_to(ROOT) or path.resolve(strict=exists) != path:
        raise ValueError('Build paths must stay under /home/jwk/agent without redirection')
    return path


def bounded_directories(roots, max_depth=5, limit=160):
    """Inspect known toolchain locations, never a whole-home recursive search."""
    skip = {'target', 'cache', 'tmp', 'unpack', 'downloads', 'registry', '.git', 'vendor',
            'cargo', 'cargo-offline', 'lib', 'share', 'etc'}
    queue, seen = [(Path(root), 0) for root in roots], set()
    while queue and len(seen) < limit:
        path, depth = queue.pop(0)
        try:
            path = path.resolve(strict=True)
            if path in seen or not path.is_dir():
                continue
            seen.add(path)
            yield path
            if depth < max_depth:
                queue.extend((child, depth + 1) for child in sorted(path.iterdir())
                             if child.name not in skip and not child.is_symlink() and child.is_dir())
        except OSError:
            continue


def pointer_value(path, warnings):
    try:
        path_under_root(path)
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
            raise ValueError('pointer is too large')
        return path.read_text().strip()
    except (OSError, ValueError) as error:
        warnings.append({'pointer': str(path), 'reason': str(error)})
        return None


def real_compiler_binary(path):
    """Reject rustup proxies before executing anything; queries cannot sync a channel."""
    path = Path(path).resolve(strict=True)
    if path.name == 'rustup' or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError('not an existing executable compiler binary')
    manager = path.parent / 'rustup'
    if manager.exists() and os.path.samefile(path, manager):
        raise ValueError('rustup proxy, not the real installed toolchain')
    with path.open('rb') as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:4] != b'\x7fELF' or int.from_bytes(header[18:20], 'little') != 183:
        raise ValueError('not an ARM64 ELF executable; wrapper/proxy not run')
    return path


def probe_rust(directory, runner=subprocess.run):
    rustc = real_compiler_binary(Path(directory) / 'rustc')
    cargo = real_compiler_binary(Path(directory) / 'cargo')
    # Stock sysroot proof is checked before running the binary. An unpacked rustc
    # component or cargo-bin rustup proxy is not an installed compiler+stdlib.
    standard = next((rustc.parent.parent / lib / 'rustlib/aarch64-unknown-linux-gnu/lib'
                     for lib in ('lib', 'lib64')
                     if (rustc.parent.parent / lib / 'rustlib/aarch64-unknown-linux-gnu/lib').is_dir()
                     and any((rustc.parent.parent / lib / 'rustlib/aarch64-unknown-linux-gnu/lib').glob('libstd-*.rlib'))), None)
    if standard is None:
        raise ValueError('installed ARM64 standard library not found beside compiler')
    env = dict(os.environ)
    for name in ('LD_PRELOAD', 'LD_AUDIT'):
        env.pop(name, None)
    result = runner([str(rustc), '-Vv'], capture_output=True, text=True, timeout=15, env=env)
    version = re.search(r'^release: (\d+)\.(\d+)\.(\d+)\s*$', result.stdout, re.M)
    if result.returncode or not version or 'host: aarch64-unknown-linux-gnu' not in result.stdout:
        raise ValueError('existing stable ARM64 compiler identity query failed')
    cargo_result = runner([str(cargo), '-V'], capture_output=True, text=True, timeout=15, env=env)
    if cargo_result.returncode or not cargo_result.stdout.startswith('cargo '):
        raise ValueError('existing cargo identity query failed')
    return {'bin': str(rustc.parent), 'rustc': str(rustc), 'cargo': str(cargo),
            'version': '.'.join(version.groups()), 'cargo_version': cargo_result.stdout.strip(),
            'standard_library': str(standard)}


def discover_rust(environment, which=shutil.which, runner=subprocess.run):
    warnings, candidates = [], []
    explicit = environment.get('AENV_RUST_BIN_DIR')
    if explicit:
        try:
            return probe_rust(explicit, runner), warnings
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            return None, [{'override': explicit, 'reason': str(error)}]
    pointer = pointer_value(ROOT / 'toolchains/agentenv-rust-1.99.0-offline.path', warnings)
    if pointer:
        candidates.append(Path(pointer))
    for name in ('rustc', 'cargo'):
        found = which(name)
        if found:
            candidates.append(Path(found).parent)
    roots = [ROOT / 'toolchains', ROOT / 'rustup/toolchains', ROOT / '.rustup/toolchains',
             Path.home() / '.rustup/toolchains']
    if environment.get('RUSTUP_HOME'):
        roots.append(Path(environment['RUSTUP_HOME']) / 'toolchains')
    for path in bounded_directories(roots):
        if (path / 'rustc').is_file():
            candidates.append(path)
        if (path / 'bin/rustc').is_file():
            candidates.append(path / 'bin')
    available, seen = [], set()
    for directory in candidates:
        try:
            directory = directory.resolve(strict=True)
            if directory in seen:
                continue
            seen.add(directory)
            available.append(probe_rust(directory, runner))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            warnings.append({'candidate': str(directory), 'reason': str(error)})
    if not available:
        return None, warnings
    return max(available, key=lambda item: tuple(map(int, item['version'].split('.')))), warnings


def discover_vendor(environment):
    warnings = []
    explicit = environment.get('AENV_VENDOR_DIR')
    candidates = [Path(explicit)] if explicit else []
    if not explicit:
        value = pointer_value(ROOT / 'offline/agentenv-vendor-ae9c626.path', warnings)
        if value:
            candidates.append(Path(value))
        if (ROOT / 'offline').is_dir():
            candidates.extend(sorted((ROOT / 'offline').glob('vendor-ae9c626-*'))[:32])
        locations = existing_inputs()
        candidates.extend(locations['vendors'])
    for candidate in candidates:
        try:
            candidate = path_under_root(candidate)
            marker = candidate / 'agentenv-vendor-manifest.json'
            path_under_root(marker)
            if marker.stat().st_size > 65536:
                raise ValueError('vendor marker is too large')
            manifest = json.loads(marker.read_text())
            if manifest.get('lock_sha256') != LOCK_SHA:
                raise ValueError('vendor belongs to another Cargo.lock')
            return candidate, warnings
        except (OSError, ValueError) as error:
            warnings.append({'candidate': str(candidate), 'reason': str(error)})
    return None, warnings


def existing_inputs():
    """Read-only bounded inventory of old experiment inputs; never reads credentials.

    Old build reports/configs may record a vendor outside the historical offline
    directory. Cargo homes are detected by registry/cache, without loading their
    config, credentials, Git checkout or build scripts.
    """
    queue = [(ROOT / name, 0) for name in
             ('toolchains', 'src', 'offline', 'builds', 'deps', 'vendor', 'cache',
              '.cargo', 'cargo', 'cargo-home', 'cargo-offline')]
    original_report = ROOT / 'relay/reports/node-a-build-20261015T063406Z-wAjyMg'
    vendors, cargo_homes, seen = [], [], set()
    for filename in ('cargo-offline.toml', 'build-environment.txt'):
        try:
            config = path_under_root(original_report / filename)
            if config.stat().st_size > 65536:
                continue
            for line in config.read_text().splitlines():
                match = re.fullmatch(r'\s*directory\s*=\s*(".*")\s*', line)
                value = json.loads(match.group(1)) if match else (
                    line.split('=', 1)[1] if line.startswith('vendor_directory=') else None)
                if value:
                    vendors.append(path_under_root(value))
        except (OSError, ValueError):
            continue
    skip = {'target', '.git', 'git', 'registry', 'tmp', 'unpack', 'downloads',
            'node_modules', 'rustup', 'lib', 'lib64', 'share', 'bin', 'include',
            'agentenv-ub-build-v2'}
    while queue and len(seen) < 700:
        path, depth = queue.pop(0)
        try:
            path = path_under_root(path)
            if path in seen or not path.is_dir():
                continue
            seen.add(path)
            if (path / 'agentenv-vendor-manifest.json').is_file():
                vendors.append(path)
                continue
            if (path / 'registry/cache').is_dir():
                path_under_root(path / 'registry/cache')
                cargo_homes.append(path)
            # These are package sources, never build-cache discovery roots.
            if (path / '.cargo-checksum.json').is_file():
                continue
            if depth < 5:
                queue.extend((child, depth + 1) for child in sorted(path.iterdir())
                             if child.name not in skip and not child.is_symlink() and child.is_dir())
        except (OSError, ValueError):
            continue
    return {'vendors': list(dict.fromkeys(vendors)),
            'cargo_homes': list(dict.fromkeys(cargo_homes)), 'directories_scanned': len(seen)}


def reuse_crate_archives(source, cache, locations):
    """Copy only lockfile-hashed .crate archives into existing private registry slots.

    Never shares mutable old Cargo homes/target directories, copies config or
    credentials, unpacks archives, or overwrites an existing destination.
    """
    expected = {}
    for block in (source / 'Cargo.lock').read_text().split('[[package]]')[1:]:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"\n]+)"$', block, re.M))
        if fields.get('source') == 'registry+https://github.com/rust-lang/crates.io-index':
            name = fields.get('name', '') + '-' + fields.get('version', '') + '.crate'
            if re.fullmatch(r'[A-Za-z0-9_.+\-]+\.crate', name) and re.fullmatch(r'[a-f0-9]{64}', fields.get('checksum', '')):
                expected[name] = fields['checksum']
    result = {'old_cargo_homes': [str(p) for p in locations['cargo_homes']],
              'archives_copied': 0, 'bytes_copied': 0, 'invalid_archives_skipped': 0,
              'existing_archives_preserved': 0, 'directories_scanned': locations['directories_scanned']}
    registry = path_under_root(cache / 'cargo/registry/cache', exists=False)
    # Cargo chooses its namespace. Do not invent a registry identity or import
    # an old cache's mirror configuration. A previous partial fetch creates it.
    destinations = ([path_under_root(p) for p in sorted(registry.iterdir())
                     if p.is_dir() and not p.is_symlink()] if registry.is_dir() else [])
    result['destination_slots'] = len(destinations)
    for home in locations['cargo_homes']:
        try:
            old_registry = path_under_root(home / 'registry/cache')
            slots = [path_under_root(p) for p in sorted(old_registry.iterdir())
                     if p.is_dir() and not p.is_symlink()][:32]
        except (OSError, ValueError):
            continue
        for slot in slots:
            for name, digest in expected.items():
                missing = []
                for dest in destinations:
                    target = dest / name
                    if target.exists() or target.is_symlink():
                        result['existing_archives_preserved'] += 1
                    else:
                        missing.append(target)
                if not missing:
                    continue
                try:
                    archive = path_under_root(slot / name)
                    size = archive.stat().st_size
                    if not archive.is_file() or size > 128 * 1024**2:
                        continue
                    # Stage the verified bytes in the new owned cache. This also
                    # avoids trusting an old file that changes during the copy.
                    with archive.open('rb') as src, tempfile.TemporaryFile(dir=cache) as staged:
                        checksum, count = hashlib.sha256(), 0
                        while chunk := src.read(1024**2):
                            count += len(chunk)
                            if count > 128 * 1024**2:
                                break
                            checksum.update(chunk)
                            staged.write(chunk)
                        if count != size or checksum.hexdigest() != digest:
                            result['invalid_archives_skipped'] += 1
                            continue
                        for target in missing:
                            staged.seek(0)
                            temporary = None
                            try:
                                with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as output:
                                    temporary = Path(output.name)
                                    shutil.copyfileobj(staged, output)
                                    output.flush()
                                    os.fsync(output.fileno())
                                # Publish complete data atomically, exclusively.
                                # Link only a new private file, never the old cache.
                                os.link(temporary, target)
                            except FileExistsError:
                                continue
                            finally:
                                if temporary is not None:
                                    temporary.unlink()
                            result['archives_copied'] += 1
                            result['bytes_copied'] += count
                except (OSError, ValueError):
                    continue
    return result


def owned_cache():
    cache = path_under_root(ROOT / 'builds/agentenv-ub-build-v2', exists=False)
    marker = cache / 'build-cache.json'
    if cache.exists():
        if cache.stat().st_uid != os.getuid() or not marker.is_file() or marker.is_symlink():
            raise ValueError('Unknown existing build cache; preserved')
        record = json.loads(marker.read_text())
        if record != {'revision': 'ub-build-cache-v2', 'uid': 1204, 'lock_sha256': LOCK_SHA}:
            raise ValueError('Build cache identity differs; preserved')
    else:
        cache.mkdir(parents=True, mode=0o700)
        with marker.open('x') as stream:
            json.dump({'revision': 'ub-build-cache-v2', 'uid': 1204, 'lock_sha256': LOCK_SHA}, stream)
    return cache


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-locked-network', action='store_true',
                        help='use locked Cargo downloads in a private cache if an offline vendor is unavailable')
    args = parser.parse_args()
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
    reports = path_under_root(ROOT / 'relay/reports')
    output = Path(tempfile.mkdtemp(prefix='node-a-ub-layers-build-', dir=reports))
    print('REPORT_DIRECTORY=' + str(output), flush=True)
    rust_info, rust_warnings = discover_rust(os.environ)
    vendor, vendor_warnings = discover_vendor(os.environ)
    missing = [name for name in ('git', 'gcc', 'g++', 'ar', 'make', 'cmake', 'clang', 'protoc', 'pkg-config', 'readelf')
               if shutil.which(name) is None]
    if rust_info is None:
        missing.append('existing_real_ARM64_Rust_and_Cargo_with_standard_library')
    if vendor is None and (not args.allow_locked_network or os.environ.get('AENV_VENDOR_DIR')):
        missing.append('matching_offline_vendor_or_explicit_allow_locked_network')
    if shutil.disk_usage(ROOT).free < 16 * 1024**3:
        missing.append('16GiB_free_build_space')
    discovery = {'rust': rust_info, 'rust_diagnostics': rust_warnings, 'vendor': str(vendor) if vendor else None,
                 'vendor_diagnostics': vendor_warnings, 'missing': missing,
                 'dependency_mode': 'vendor_frozen' if vendor else 'locked_network' if args.allow_locked_network else 'blocked'}
    if missing:
        report = {'status': 'STOPPED_BUILD_PRECONDITION_NO_BUILD_STARTED', 'directory': str(output),
                  'node': 'node-a', 'hostname': socket.gethostname(), 'uid': os.getuid(),
                  'discovery': discovery, 'service_started': False, 'SDK_called': False,
                  'next_action': 'Return this complete report. No installation, upgrade or service change was attempted.'}
        (output / 'return.json').write_text(json.dumps(report, indent=2))
        print('BEGIN_RETURN_REPORT')
        print(json.dumps(report, indent=2))
        print('END_RETURN_REPORT')
        return 1
    rust = Path(rust_info['bin'])
    cache = owned_cache()
    reuse = reuse_crate_archives(source, cache, existing_inputs()) if not vendor else {
        'mode': 'reuse_existing_vendor_readonly', 'vendor': str(vendor)}
    print('EXISTING_INPUT_REUSE=' + json.dumps(reuse), flush=True)
    print('RUST_SELECTED=' + rust_info['rustc'] + ' version=' + rust_info['version'], flush=True)
    print('DEPENDENCY_MODE=' + discovery['dependency_mode'], flush=True)
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
        path = path_under_root(cache / directory, exists=False)
        path.mkdir(parents=True, exist_ok=True)
        env[variable] = str(path)
    env.update(PATH=str(rust) + os.pathsep + env['PATH'], RUSTC=rust_info['rustc'],
               CARGO_NET_OFFLINE='true' if vendor else 'false', CARGO_BUILD_JOBS='2',
               CMAKE_BUILD_PARALLEL_LEVEL='2', GIT_TERMINAL_PROMPT='0',
               PROTOC=shutil.which('protoc'))
    env.update(CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0')
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONPYCACHEPREFIX=str(cache / 'cache/pycache'))
    if (rust / 'rustdoc').is_file():
        env['RUSTDOC'] = str(rust / 'rustdoc')
    else:
        env.pop('RUSTDOC', None)
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CEILING_DIRECTORIES=str(source.parent))
    if Path('/usr/lib64/libclang.so').is_file():
        env['LIBCLANG_PATH'] = '/usr/lib64'
    config = output / 'cargo-offline.toml'
    config.write_text(('''[net]
offline = true
[source.crates-io]
replace-with = "agentenv-offline"
[source."git+https://github.com/ublk-org/libublk-rs.git?rev=c6a3e06"]
git = "https://github.com/ublk-org/libublk-rs.git"
rev = "c6a3e06"
replace-with = "agentenv-offline"
[source.agentenv-offline]
directory = ''' + json.dumps(str(vendor)) + '\n') if vendor else '[net]\noffline = false\n')
    cargo = [rust_info['cargo'], '--config', str(config)]
    locked = '--frozen' if vendor else '--locked'
    report = {'status': 'NOT_COMPLETED', 'directory': str(output), 'source': str(source),
              'node': 'node-a', 'uid': 1204, 'phases': {}, 'service_started': False,
              'SDK_called': False, 'Guest_or_ublk_tests_executed': False,
              'discovery': discovery, 'build_cache': str(cache), 'existing_input_reuse': reuse}
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
        run('rust-version', [rust_info['rustc'], '-Vv'])
        run('resolution', cargo + ['metadata', locked, '--format-version', '1'])
        run('check-server-daemon', cargo + ['check', locked, '-p', 'agentenv', '-p', 'uvm-ublk-daemon'])
        run('test-ub-wire-and-file', cargo + ['test', locked, '-p', 'overlaybd', '--lib', 'backend::ub', '--', '--test-threads=2'])
        run('test-ub-and-legacy-config', cargo + ['test', locked, '-p', 'overlaybd', '--lib', 'config::'])
        run('test-ub-ancestor-staging', cargo + ['test', locked, '-p', 'agentenv', '--lib',
                                              'split_runtime_suffix_keeps_ub_ancestor_without_a_local_duplicate'])
        run('build-runtime', cargo + ['build', locked, '--release', '-p', 'agentenv', '--bin', 'server'])
        run('build-cli', cargo + ['build', locked, '--release', '-p', 'aenv', '--bin', 'aenv'])
        run('build-daemon', cargo + ['build', locked, '--release', '-p', 'uvm-ublk-daemon', '--bin', 'uvm-ublk-daemon'])
        run('build-layer-probe', cargo + ['build', locked, '--release', '-p', 'overlaybd', '--example', 'ub_layer_probe'])
        artifacts = output / 'artifacts'
        artifacts.mkdir()
        for name in ('server', 'aenv', 'uvm-ublk-daemon', 'examples/ub_layer_probe'):
            shutil.copy2(cache / 'target/release' / name, artifacts / Path(name).name)
        report['artifacts'] = str(artifacts)
        report['sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts.iterdir()}
        report['status'] = ('UB_LAYERS_OFFLINE_BUILD_COMPLETED_NO_SERVICE_STARTED' if vendor
                            else 'UB_LAYERS_LOCKED_BUILD_COMPLETED_NO_SERVICE_STARTED')
    except BaseException as error:
        report.update(status='STOPPED_UB_LAYERS_BUILD', error=type(error).__name__ + ': ' + str(error))
    (output / 'return.json').write_text(json.dumps(report, indent=2))
    print('BEGIN_RETURN_REPORT')
    print(json.dumps(report, indent=2))
    print('END_RETURN_REPORT')
    return 0 if report['status'] in ('UB_LAYERS_OFFLINE_BUILD_COMPLETED_NO_SERVICE_STARTED',
                                   'UB_LAYERS_LOCKED_BUILD_COMPLETED_NO_SERVICE_STARTED') else 1


if __name__ == '__main__':
    try:
        code = main()
    except Exception as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'STOPPED_BUILD_PRECONDITION_NO_BUILD_STARTED', 'error': str(error)}, indent=2))
        print('END_RETURN_REPORT')
        code = 1
    raise SystemExit(code)
