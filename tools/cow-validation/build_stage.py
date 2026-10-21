#!/usr/bin/env python3
"""Build in isolated directories and stage new artifacts; never activate services.

Requires an existing Linux build environment and matching complete FC checkout.
Default is plan only. This does not create Guests, call UB or modify deployment,
kernel, groups, permissions, networking, systemd, or system package installations.
"""
import argparse
import ctypes
import hashlib
import json
import os
import platform
import re
from pathlib import Path
import shutil
import subprocess
import sys


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(part)
    return digest.hexdigest()


def validate_policy(raw):
    value = json.loads(raw)
    if set(value) != {'vmm', 'api', 'vcpu'}:
        raise ValueError('Expected the original vmm/api/vcpu policy map')
    for name, policy in value.items():
        if policy.get('default_action') not in ('trap', 'kill_process', 'kill_thread') or policy.get('filter_action') != 'allow':
            raise ValueError('Policy must deny unknown syscalls: ' + name)
        rules = policy.get('filter')
        if not isinstance(rules, list) or not rules or any(not isinstance(row, dict) or not row.get('syscall') for row in rules):
            raise ValueError('Nonempty syscall rules required: ' + name)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--firecracker-source', required=True)
    parser.add_argument('--sdk-include')
    parser.add_argument('--sdk-lib')
    parser.add_argument('--output', required=True)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--only-firecracker', action='store_true')
    parser.add_argument('--rust-bin')
    parser.add_argument('--target', default='aarch64-unknown-linux-gnu',
        choices=['aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-gnu'])
    parser.add_argument('--seccomp-policy', required=True)
    parser.add_argument('--seccomp-policy-sha256', required=True)
    parser.add_argument('--seccomp-library')
    parser.add_argument('--fast-release', action='store_true', help='Disable LTO only; keep release optimization')
    args = parser.parse_args()
    source = Path(args.source).resolve(strict=True)
    fc_source = Path(args.firecracker_source).resolve(strict=True)
    patch_dir = source / 'components/firecracker-native-pmem'
    baseline = json.loads((patch_dir / 'baseline.json').read_text())
    for relative, expected in baseline['files'].items():
        path = fc_source / relative
        if hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest() != expected:
            raise ValueError('FC source mismatch: ' + relative)
    policy = Path(args.seccomp_policy).resolve(strict=True)
    if not re.fullmatch(r'[0-9a-f]{64}', args.seccomp_policy_sha256) or sha(policy) != args.seccomp_policy_sha256:
        raise ValueError('Explicit seccomp policy checksum differs')
    arch = args.target.split('-')[0]
    canonical_policy = fc_source / ('resources/seccomp/' + arch + '-unknown-linux-musl.json')
    if policy.read_bytes() != canonical_policy.read_bytes():
        raise ValueError('Policy must match the original same-architecture policy in the pinned FC source')
    validate_policy(policy.read_bytes())
    if not args.only_firecracker and (not args.sdk_include or not args.sdk_lib):
        raise ValueError('Full build requires explicit existing SDK include/library directories')
    output = Path(args.output).absolute()
    if output.resolve() != output or output.exists():
        raise ValueError('Output must be a new absolute path without redirected components')
    if output.is_relative_to(source) or output.is_relative_to(fc_source):
        raise ValueError('Build output must be outside both source trees')
    commands = [
        ['cargo', 'build', '--locked', '--release', '--manifest-path', str(source / 'Cargo.toml'),
         '-p', 'agentenv', '-p', 'aenv', '-p', 'uvm-ublk-daemon', '--bins'],
        ['cargo', 'build', '--locked', '--release', '--manifest-path', str(output / 'fc-source/Cargo.toml'), '-p', 'firecracker'],
        ['cargo', 'build', '--locked', '--release', '--manifest-path', str(source / 'components/native-fd-verifier/Cargo.toml')],
        ['c++', '-std=c++17', '-O2', '-fPIC', '-shared', '-pthread', '-Wall', '-Wextra', '-Werror',
         '-I', str(Path(args.sdk_include).resolve(strict=True)) if args.sdk_include else 'SDK_INCLUDE_NOT_USED',
         str(source / 'components/ub-memory-provider/sdk_adapter.cpp'),
         '-L', str(Path(args.sdk_lib).resolve(strict=True)) if args.sdk_lib else 'SDK_LIB_NOT_USED', '-lubsm_sdk',
         '-Wl,-z,relro,-z,now', '-o', str(output / 'artifacts/libaenv-ub.so')],
    ]
    for command in commands[:3]:
        command.extend(['--target', args.target, '--frozen'])
    if args.only_firecracker:
        selected = [1]
    else:
        selected = list(range(4))
    plan = {'version': 2, 'status': 'BUILD_PLAN_NO_DEPLOYMENT', 'commands': commands,
            'output': str(output), 'Guest_created': False, 'SDK_called': False,
            'selectedCommands': selected, 'seccompPolicySha256': sha(policy),
            'seccompPolicySource': str(canonical_policy), 'emptySeccompPermitted': False,
            'target': args.target, 'fastReleaseLtoDisabled': args.fast_release}
    if not args.run:
        print(json.dumps(plan, indent=2))
        return
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise RuntimeError('Build as an ordinary Linux user; no automatic elevation')
    if platform.machine() != arch:
        raise RuntimeError('This entry requires a native Linux build of the selected architecture')
    rust_bin = Path(args.rust_bin).resolve(strict=True) if args.rust_bin else None
    if rust_bin:
        for name in ('rustc', 'cargo'):
            binary = rust_bin / name
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise RuntimeError('Missing existing compiler executable: ' + name)
            if (rust_bin / 'rustup').exists() and os.path.samefile(binary, rust_bin / 'rustup'):
                raise RuntimeError('Rustup proxy refused; provide the real toolchain bin directory')
    output.mkdir(mode=0o700)
    artifacts = output / 'artifacts'
    artifacts.mkdir(mode=0o700)
    (output / 'plan.json').write_text(json.dumps(plan, indent=2))
    # New checkout copy only; preserve all existing sources and deployments.
    shutil.copytree(fc_source, output / 'fc-source', symlinks=False,
                    ignore=shutil.ignore_patterns('.git', 'target', '__pycache__'))
    env = dict(os.environ, CARGO_BUILD_JOBS='2', CARGO_PROFILE_RELEASE_DEBUG='0')
    if args.fast_release:
        env['CARGO_PROFILE_RELEASE_LTO'] = 'false'
    if rust_bin:
        env.update(PATH=str(rust_bin) + os.pathsep + env['PATH'], RUSTC=str(rust_bin / 'rustc'))
        if (rust_bin / 'rustdoc').is_file():
            env['RUSTDOC'] = str(rust_bin / 'rustdoc')
    # FC ships its own public C declarations: a missing system header/.pc is not
    # evidence of a missing runtime library. Inspect and link the exact existing
    # library through a new private linker name; never change system symlinks.
    seccomp_path = Path(args.seccomp_library or '/usr/lib64/libseccomp.so.2').resolve(strict=True)
    with seccomp_path.open('rb') as stream:
        elf = stream.read(20)
    expected_machine = 183 if arch == 'aarch64' else 62
    if elf[:4] != b'\x7fELF' or int.from_bytes(elf[18:20], 'little') != expected_machine:
        raise ValueError('libseccomp is not the selected native ELF architecture')
    class Version(ctypes.Structure):
        _fields_ = [('major', ctypes.c_uint), ('minor', ctypes.c_uint), ('micro', ctypes.c_uint)]
    library = ctypes.CDLL(str(seccomp_path))
    for name in ('seccomp_init', 'seccomp_release', 'seccomp_arch_add',
                 'seccomp_syscall_resolve_name', 'seccomp_rule_add', 'seccomp_rule_add_array', 'seccomp_export_bpf'):
        getattr(library, name)
    library.seccomp_version.restype = ctypes.POINTER(Version)
    version = library.seccomp_version().contents
    if (version.major, version.minor) < (2, 5):
        raise ValueError('Existing libseccomp must provide API version >= 2.5')
    private_lib = output / 'private-lib'
    private_lib.mkdir(mode=0o700)
    (private_lib / 'libseccomp.so').symlink_to(seccomp_path)
    env['LIBRARY_PATH'] = str(private_lib) + (os.pathsep + env['LIBRARY_PATH'] if env.get('LIBRARY_PATH') else '')
    env['LD_LIBRARY_PATH'] = str(private_lib) + (os.pathsep + env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else '')
    (output / 'libseccomp.json').write_text(json.dumps({'path': str(seccomp_path), 'sha256': sha(seccomp_path),
        'version': [version.major, version.minor, version.micro],
        'systemHeaderPresent': Path('/usr/include/seccomp.h').is_file(), 'privateLinkOnly': True}, indent=2))
    check = output / 'libseccomp-check.c'
    check.write_text('typedef void *scmp_filter_ctx; extern scmp_filter_ctx seccomp_init(unsigned int); extern void seccomp_release(scmp_filter_ctx); int main(void) { scmp_filter_ctx c = seccomp_init(0x80000000U); if (!c) return 1; seccomp_release(c); return 0; }\n')
    with (output / 'libseccomp-check.log').open('w') as log:
        result = subprocess.run(['cc', str(check), str(seccomp_path), '-o', str(output / 'libseccomp-check')],
            env=env, stdout=log, stderr=subprocess.STDOUT, timeout=60)
    if result.returncode:
        raise RuntimeError('Existing native libseccomp failed explicit library link check; nothing was installed')
    subprocess.run(['git', 'apply', '--check', str(patch_dir / 'native-pmem-fd-v2.patch')],
                   cwd=output / 'fc-source', env=env, check=True)
    subprocess.run(['git', 'apply', str(patch_dir / 'native-pmem-fd-v2.patch')],
                   cwd=output / 'fc-source', env=env, check=True)
    native = output / 'fc-source/src/vmm/src/devices/virtio/pmem/native_fd.rs'
    if hashlib.sha256(native.read_bytes().replace(b'\r\n', b'\n')).hexdigest() != baseline['native_module_sha256']:
        raise ValueError('Applied FC mapping source differs from the canonical verifier source')
    # GNU upstream has no default policy: explicitly install the original nonempty
    # same-architecture policy only in this new isolated source copy.
    selected_policy = output / 'fc-source/resources/seccomp' / (args.target + '.json')
    if selected_policy.exists() and selected_policy.read_bytes() != policy.read_bytes():
        raise ValueError('Copied target policy differs; do not overwrite it')
    selected_policy.write_bytes(policy.read_bytes())
    targets = [output / 'runtime-target', output / 'fc-target', output / 'verifier-target', None]
    for index, (command, target) in enumerate(zip(commands, targets)):
        if index not in selected:
            continue
        current = dict(env)
        if target is not None:
            current['CARGO_TARGET_DIR'] = str(target)
        with (output / f'build-{index}.log').open('w') as log:
            result = subprocess.run(command, cwd=output, env=current, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            (output / 'status.json').write_text(json.dumps({'status': 'BUILD_FAILED_NOT_ACTIVATED',
                'commandIndex': index, 'exitCode': result.returncode}))
            raise RuntimeError('Build failed; inspect its own build log. No service was changed.')
    fc_log = (output / 'build-1.log').read_text(errors='replace')
    if 'empty default seccomp policy' in fc_log or 'No default seccomp policy' in fc_log:
        raise RuntimeError('FC build unexpectedly selected an empty seccomp policy; artifacts refused')
    for name, parent in [('server', 'runtime-target'), ('aenv', 'runtime-target'),
                         ('uvm-ublk-daemon', 'runtime-target'), ('firecracker', 'fc-target'),
                         ('aenv-native-fd-verify', 'verifier-target')]:
        if args.only_firecracker and name != 'firecracker':
            continue
        shutil.copy2(output / parent / args.target / 'release' / name, artifacts / name)
    manifest = {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in artifacts.iterdir()}
    (output / 'artifacts.json').write_text(json.dumps(manifest, indent=2))
    (output / 'status.json').write_text(json.dumps({'status': 'FIRECRACKER_BUILT_AND_STAGED_NOT_DEPLOYED' if args.only_firecracker else 'BUILT_AND_STAGED_NOT_DEPLOYED', 'componentsBuilt': ['firecracker'] if args.only_firecracker else ['server', 'aenv', 'uvm-ublk-daemon', 'firecracker', 'aenv-native-fd-verify', 'libaenv-ub.so'],
        'Guest_created': False, 'SDK_called': False, 'services_changed': False,
        'guest_tools_image_built': False, 'erofs_images_built': False, 'seccompPolicySha256': sha(policy), 'emptySeccompPermitted': False}))
    print(str(output / 'artifacts.json'))


if __name__ == '__main__':
    main()
