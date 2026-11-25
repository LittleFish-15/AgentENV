"""Stage real local lower input, build the native template entry, and check runtime access."""

import argparse
import ctypes
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


SOURCE = Path('/home/jwk/agent/sp3-mn/src/AgentENV')
ASSETS = Path('/home/jwk/agent/sp3-mn/relay-guest-assets-001')
CAPTURE = ASSETS / 'template-capture-001'
TOOLCHAIN = Path('/home/jwk/.local/rustup/bin')
PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
ENV = {'PATH': str(TOOLCHAIN) + ':' + PATH, 'HOME': '/home/jwk', 'LANG': 'C', 'LC_ALL': 'C',
       'CARGO_NET_OFFLINE': 'true', 'CARGO_BUILD_JOBS': '4', 'LIBCLANG_PATH': '/usr/lib64',
       'RUSTC': str(TOOLCHAIN / 'rustc'), 'GIT_OPTIONAL_LOCKS': '0'}
BASE_HEAD = '207462625ee21d669ddfc34cbfd47932f5a757b7'
RUNTIME_USER = ['/usr/bin/setpriv', '--no-new-privs', '--reuid=1204', '--regid=1205', '--init-groups', '--']

CAPTURE_SOURCE = r'''
use std::path::Path;

use agentenv::cfg::ConfigManager;
use agentenv::sandbox::UblkDeviceManager;
use agentenv::snapshot::SnapshotManager;
use agentenv::template::{TemplateBuildSpec, TemplateBuilder};
use anyhow::{ensure, Context, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 2, "usage: mn_titanic_capture CONFIG LOCAL_OVERLAYBD_CONFIG");
    agentenv::logging::init();
    let config = ConfigManager::init_global_from_path(Path::new(&args[0]))?.config();
    agentenv::privileges::require_runtime_capabilities()?;
    agentenv::privileges::clear_ambient_capabilities()?;
    agentenv::setup::ensure_environment(config, None).await?;
    UblkDeviceManager::init_global_from_config(config).await?;
    let manager = SnapshotManager::new(None)?;
    let record = TemplateBuilder::new()
        .build_and_publish(
            &manager,
            TemplateBuildSpec::new()
                .from_overlaybd_config(Path::new(&args[1]))
                .alias("mn-titanic-verify-001")
                .resources(2, 1024)
                .run("test -d /task && python -c 'import sys; print(sys.version.split()[0])'"),
        )
        .await
        .context("capture and publish Titanic template from local committed lowers")?;
    let snapshot = record.committed.as_ref().context("template record has no committed snapshot")?;
    println!("{}", serde_json::json!({
        "status": "MN_TITANIC_TEMPLATE_COMMITTED",
        "templateId": record.id.to_string(),
        "rootfsLowers": snapshot.rootfs_layers,
        "memoryLowers": snapshot.memory_layers,
    }));
    Ok(())
}
'''.lstrip()


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def preflight(host):
    access = {}
    for path in ('/dev/kvm', '/dev/ublk-control'):
        device = Path(path)
        access[path] = {'present': device.is_char_device(), 'jwkReadWrite': all(
            subprocess.run(RUNTIME_USER + ['/usr/bin/test', mode, path], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5).returncode == 0
            for mode in ('-r', '-w'))}
    caps = Path('/proc/self/status').read_text()
    effective = int(re.search(r'^CapEff:\s+([a-f0-9]+)', caps, re.M)[1], 16)
    topo = {'node': host, 'jwkDeviceAccess': access,
            'ipForward': Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),
            'rootHasRuntimeCaps': effective & ((1 << 12) | (1 << 21)) == ((1 << 12) | (1 << 21))}
    print(json.dumps({'status': 'MN_GUEST_RUNTIME_PREFLIGHT', **topo}), flush=True)


def build_owner(expected_receipt):
    chain_dir = ASSETS / 'benchmark-native-lower-001'
    receipt = (chain_dir / 'committed-lowers.json').read_bytes()
    need(hashlib.sha256(receipt).hexdigest() == expected_receipt, 'Verified lower list differs')
    layers = json.loads(receipt)['rootfsLowers']
    need(len(layers) == 9, 'Expected the committed nine-layer Titanic input')
    lower_configs = []
    for i, layer in enumerate(layers):
        path = Path(layer['file'])
        need(path == chain_dir / f'layer-{i:02d}/overlaybd.commit' and path.resolve(strict=True) == path
             and path.is_file() and path.stat().st_size == layer['bytes'], 'Committed lower identity differs')
        lower_configs.append({'file': str(path), 'digest': layer['digest'], 'size': layer['bytes']})

    native = ctypes.CDLL(None, use_errno=True)
    need(native.prctl(38, 1, 0, 0, 0) == 0, 'Could not disable privilege gains during build')
    os.setgroups([])
    os.setgid(1205)
    os.setuid(1204)
    status = Path('/proc/self/status').read_text()
    need(all(re.search(r'^' + key + r':\s+0+$', status, re.M)
             for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), 'Build retained privileges')
    output = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=SOURCE, env=ENV,
                                     text=True, timeout=15).strip()
    need(output == BASE_HEAD, 'AgentENV checkout differs')
    need(os.access(SOURCE / 'src/bin', os.W_OK), 'Source bin directory is not writable by jwk')
    lock = SOURCE / 'target/release/.cargo-lock'
    reuse_target = os.access(SOURCE / 'target/release', os.W_OK) and (not lock.exists() or os.access(lock, os.W_OK))
    need((TOOLCHAIN / 'cargo').is_file() and (TOOLCHAIN / 'rustc').is_file(), 'Existing private Rust toolchain missing')

    CAPTURE.mkdir(mode=0o700)
    home, runtime = CAPTURE / 'home', CAPTURE / 'runtime'
    home.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    original_deps = ASSETS.parent / 'artifacts/deps'
    config = CAPTURE / 'config.toml'
    config.write_text(f'home_path = "{home}"\nruntime_path = "{runtime}"\n'
                      f'deps_path = "{ASSETS / "deps"}"\nvirtualization_mode = "kvm"\n'
                      f'[firecracker]\nbinary_path = "{original_deps / "firecracker/firecracker"}"\n'
                      f'cgroup_pool_size = 1\n[kernel]\nimage_path = "{original_deps / "vmlinux-6.1.175-aarch64"}"\n'
                      '[snapshot]\nrepository_backend = "posix_fs"\np2p_enabled = false\n',
                      encoding='utf-8')
    input_config = CAPTURE / 'rootfs-image.json'
    input_config.write_text(json.dumps({'lowers': lower_configs}), encoding='utf-8')
    path = SOURCE / 'src/bin/mn_titanic_capture.rs'
    with path.open('x', encoding='utf-8') as stream:
        stream.write(CAPTURE_SOURCE)
    env = dict(ENV)
    target = SOURCE / 'target' if reuse_target else CAPTURE / 'target'
    env['CARGO_TARGET_DIR'] = str(target)
    includes = sorted(Path('/usr/lib64/clang').glob('*/include/stdbool.h')) + sorted(
        Path('/usr/lib/clang').glob('*/include/stdbool.h'))
    if includes:
        env['BINDGEN_EXTRA_CLANG_ARGS'] = '-isystem ' + str(includes[0].parent)
    log = CAPTURE / 'cargo-build.log'
    print(json.dumps({'event': 'build_native_template_entry', 'reusedReleaseTarget': reuse_target,
                      'cargoTarget': str(target)}), flush=True)
    with log.open('xb') as stream:
        result = subprocess.run([str(TOOLCHAIN / 'cargo'), 'build', '--locked', '--offline', '--release',
                                 '--bin', 'mn_titanic_capture'], cwd=SOURCE, env=env, stdin=subprocess.DEVNULL,
                                stdout=stream, stderr=subprocess.STDOUT, timeout=3900)
    if result.returncode:
        with log.open('rb') as stream:
            stream.seek(max(0, log.stat().st_size - 5000))
            print(stream.read(5000).decode('utf-8', 'replace'), flush=True)
        return result.returncode
    binary = target / 'release/mn_titanic_capture'
    print(json.dumps({'status': 'MN_TITANIC_CAPTURE_BINARY_READY', 'binary': str(binary),
                      'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'config': str(config),
                      'rootfsImageConfig': str(input_config), 'resources': {'vcpus': 2, 'mib': 1024}}), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lower-list-sha')
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    need(os.geteuid() == 0 and host in ('agent1', 'agent2'), 'Use the M/N root entry')
    need(bool(args.lower_list_sha) == (host == 'agent1'), 'Only M prepares the native capture executable')
    os.umask(0o077)
    preflight(host)
    return build_owner(args.lower_list_sha) if args.lower_list_sha else 0


if __name__ == '__main__':
    raise SystemExit(main())
