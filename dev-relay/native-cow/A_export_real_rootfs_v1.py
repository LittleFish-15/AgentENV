"""A: offline native tests and immutable rootfs export; ordinary user only."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import time
import zlib

PAYLOAD = {'storage/overlaybd/src/lib.rs': {'sha256': 'f63aa4355e234096fec5908f1f4e770e29efb2851fda26c89f4a47b7b42845c2', 'bytes': 1384, 'data': 'eNqVVMFu3CAQvfsrUHppo0S59ISVWxSpUk5Jb1GEJni8i4oBAd7dJMq/F2xs0GZtbXyBGd48mOcHpn8lnW7IK/B/qJq6igHXnbHonNCqrkxCcK1asclxg8ohw4PR1hdZvVdSQ8M24DGn8eB/M+fBjxuIDjaYpnocJbyhTVPXBdxc22rbgScfFQlfTPYOCbeBn9IIpXREUHpZV5/Vj2febn62CL63SG7JRdtLefHrZeYbNmetkHiac1hPwwD7HrFDuxP8HO6ETPQzi2rwsNbtADhVtNJT0ik3MxUOsrMOPTTgYaE4YtIwQ494tigN2tWmR0iqizWBygrusktMMCEzEpSKVpizFlv0fJszFvZfjBfMZX1vWAdKtOhOrET2IqvAuK2efLX4c5f7mRiKjtxb0Y3XWhbhLqrPhF7QSFM6IY6k3YlwfJBrjo3FBeqI4H25srjplL4Xtetujwzl/fj4E4P7ML8ij0H8oPRTUucv2k4okPcgZGD6rM9lnm/HwP00RnUGzY6n9CE68w4dt8J4bc/YIv+70UesN8GbDBybVlh6kKqbm9DS9QgjfovD6wjcs70VHm2mDDvHc/deyFHYDKqr/74f2Ug='}, 'storage/overlaybd/src/raw_export.rs': {'sha256': '9ede4fd3b73ab869bd772907685a3dcc92c907aedad92ad2bc3da6ed8e681210', 'bytes': 4205, 'data': 'eNqtV99v2zYQfvdfcWmBQEo9xUmzLJGbFGixvuyhwDo0D0EgMNLJ5iKTKkk19Wr/7zuSkiw5itNuMQxDIu/nd98d6cPDPXgnK5FhBhq/VCgMZwXokimNICtTVgZyqYCBwlQKbVSVGhIu5IynJMkXbIbRqCJpbbI45jKOv2ss8jF8Qrzzvx+UXIzhSnGD6+lodHh4CH/NETJmGBR8wQ2kFIPRcLs0qOGeBA0KyEkNhBT/oJJwAn/wd1CSNx3BB16gXmqDC2eMFYVMmeFSABMZLNAwZztlAjKe56imYOZcA32FNJRM3hqAL5U0LBqV1S347OCTy/6jS/7N1SV8HwF9PBgxXI3daw1A4uKPoTo98evW8YPFWrizUufYWZmxsn5bj0Z8URZvrmKPGbxyKF4+EpiNPBcg8D7YxDgU33ZsIfxCNqlWtSH72XrdJD7urfWs97c2TgZVYpj011skttYdHp219cj/dnNmZYkiC/YXxFJPOus9hv3r6uzGpWf5+CfqqjBvgvCyk1mBBrj4ygqewQWsVk7yd6WkimNp5qiCF4rdA34rpTKOmHBbZTPSwm8pIjXMi3DaWuM57FnXUYEiCCOukwW55GWBicyDk8n5abiFqkJTKQHkMdjpOZ1X4k7DotIUBboGIL7zmbABdCJY9zIjVCgrC0nPaVQXob+YzjG9wyxhWRZskgCmHUn6svIukSrBQmNQoxe+nfZcp3OmKMYLV4ptRzYXD0d/h/rRUOIrm97KJRlxuxBGTCyD1e0KDm5h7wIm4ZaiGxxtsL29A7CO+sE1o8VjE9WvPQR8/OETmVLBLcaX3k6vHSyZGj/1/qYndrDAOwmGi0pT7rPdZsRD4gjYQa3Qs4N4QSManVMuZjQDlwQhcUfmwE3U2rBz3PGHC1ecXj22AqP8elUoiqYKF7YKW9L24xKlpoVXF161y6JpT3wNFtYBG+S1NWOrPSDSVDLj2jCRWqLx05M4NmqZ2AMjaAyE0YKVCRKyq2QFG3TfTgdtOjU/6iJN0zZoDq44fl8pRXgHjcvdNmzsFPpDifVol09bPEwszha8bQ/rAUp0mUceiY7T/t6G7PXTZv/jXRDUrdSfqA2T3Ukc7Fs7bo5SDTvF6LoebaKqbdTefsRGLfrQBhdGJlwIYl+rf7Wt7aGrlSmPl9dpPgvIqQlvRguZgX3UtZa7olQl0pQ9mG5WmksLFVlLNfVgvLy2mjfumYKZS7otJCxVUuvEN01yh1gmDVoyzzUaHYRbB4w9lyhIqkD36I5je1Z7h/75M6b+IQzHcFpPrjEc10+diUDWoubU+4rp3vVkCmdH58c3YVSJe8XKYJfwb1Nn78eEJz8jfP5clpnWqEyCX/bsbSbq87GDzuMqffqFgzDa4vjL5oULr0O3sPcy6GXfqV5HkUN+DFuV2KVjJaLo6Pj47KxVbKuyS9GpkObp67OTrssf0LQqUdQqnT9Uqi/kBHSBCiyV3SGTc0GjpRkxNM9nZj6m1kyLKrMHjZUxivHCvtgmiYbCcFH402AMv/ZrsR7sN4V/o/2X4XstySR1H93bE3uo0d+TYpm4afk87fa6bbenWu3oSdp6AvaUjtv+pEuhPY3CnyD7TxJ9t/ijHB9DP71dpbH/xXSiDS+KxN29EjZjnP4XtrPQ35Kfpza+LpP/N0sGirJRerooD1CePOLhUXydk0Vplq2bYWwrUV/smzOGKUzaXrjnZk5uaI+JGT7TWWOp6X+fgO366L8xeNJmvB79CwdFuUs='}, 'storage/overlaybd/src/bin/aenv-export-rootfs.rs': {'sha256': '27f8e26d60d7f713723d6f7439e9d81f6a437ac02c7acf1530faa720bc5b48d6', 'bytes': 14084, 'data': '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'}}
ROOT = Path('/home/jwk/agent')
BASE = ROOT / 'deployments/agentenv-native-fe63038'
WORK = ROOT / 'builds/rootfs-export-v1'
ARCHIVE = ROOT / 'builds/agentenv-native-fe63038-input/agentenv-native-core-fe63038-nolinks.tar.gz'
ARCHIVE_SHA = 'd4010d3384de95ec5fd3811da00623a01caf768cd34c828cfb3820510cb3b257'
LOCK_SHA = '6cb5431f5fd58fc0fbfa3f8094e3a3c3801a11fc47a976ebb841b32deab325e4'
RUST = ROOT / 'toolchains/agentenv-rust-1.99.0/rustup/toolchains/1.99.0-aarch64-unknown-linux-gnu/bin'
CARGO_HOME = ROOT / 'builds/agentenv-ub-build-v2/cargo'
TARGET = ROOT / 'builds/agentenv-native-fe63038/target'
PARENT_REPORT = ROOT / 'relay/reports/node-a-native-parent-g_w49uzp/return.json'
SNAPSHOT = '01a15e10-1a61-7601-b2f9-59748696a00a'
OCI_DIGEST = 'sha256:039f1b18eb5c1bf56c074234e718af2f6156cbb729d638f05d1d8cf95dffe409'
REPO = BASE / 'state/snapshot-store/repository'
CONFIGS = BASE / 'state/image-cache/configs'
CORE_COMMIT = '734ba2e45216b1c80e2f35236fdd6916c9fef396'
GIB = 1024 ** 3


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def safe(path):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT), 'Path outside experiment root')
    need(path.resolve(strict=True) == path, 'Redirected path refused')
    return path


def read(path, limit=2 * 1024 ** 2):
    path = safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, 'Unexpected file type or length')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'File changed while reading')
    need(len(data) == before.st_size, 'Short bounded read')
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    raw = json.dumps(value, indent=2).encode()
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def identity(layers):
    return 'sha256:' + sha(json.dumps([0, layers], separators=(',', ':')).encode())


def descriptor(layer):
    digest, size = layer.get('digest'), layer.get('size')
    need(isinstance(digest, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', digest), 'Invalid layer digest')
    need(type(size) is int and 0 < size <= 2 * GIB, 'Invalid layer byte count')
    return {'digest': digest, 'size': size}


def choose_source(parent, record, candidates):
    need(parent.get('status') == 'NATIVE_RUNTIME_PARENT_CAPTURED_GUEST_RELEASED_UB_DISABLED'
         and parent.get('parentDeleted') is True and parent.get('snapshotId') == SNAPSHOT,
         'Prior successful parent receipt differs')
    image = parent.get('imageVerification', {})
    need(image.get('manifest_digest') == OCI_DIGEST and image.get('layer_count') == 12,
         'Verified input image identity differs')
    need(record.get('id') == SNAPSHOT, 'Snapshot catalog identity differs')
    layers = record.get('committed', {}).get('rootfs_layers', [])
    need(len(layers) == 13 and all(set(x) == {'Managed'} for x in layers), 'Unexpected committed rootfs stack')
    committed = [descriptor(x['Managed']) for x in layers]
    inventory = parent.get('layerInventory', {}).get('rootfs', [])
    need(len(inventory) == len(committed), 'Prior inventory length differs')
    need(all(x.get('origin') == 'Managed' and x.get('digest') == y['digest']
             and x.get('stored_bytes_declared') == y['size'] for x, y in zip(inventory, committed)),
         'Catalog differs from captured parent inventory')
    matches = []
    for path, raw in candidates:
        cfg = json.loads(raw)
        upper = cfg.get('upper', {})
        if any(upper.get(k) for k in ('data', 'index', 'target', 'gzipIndex')):
            continue
        lowers = cfg.get('lowers', [])
        if len(lowers) != 12 or any(x.get('ub') or x.get('gzipIndex') or x.get('targetFile') for x in lowers):
            continue
        ids = [descriptor(x) for x in lowers]
        if ids == committed[:-1]:
            matches.append((path, raw, ids))
    need(len(matches) == 1, 'Expected exactly one original immutable source config matching the catalog prefix; found ' + str(len(matches)))
    return matches[0]


def inputs():
    parent = json.loads(read(PARENT_REPORT))
    record_path = REPO / 'catalog/records' / (SNAPSHOT + '.json')
    record_raw = read(record_path)
    directory = safe(CONFIGS)
    entries = list(directory.iterdir())
    need(len(entries) <= 256, 'Source config directory exceeds bounded scan')
    candidates = [(p, read(p)) for p in entries
                  if OCI_DIGEST.split(':')[1] in p.name and p.name.endswith('-image.json')]
    path, raw, ids = choose_source(parent, json.loads(record_raw), candidates)
    layers = []
    for item in ids:
        p = safe(REPO / 'managed-layers' / (item['digest'].replace(':', '_') + '.overlaybd.commit'))
        meta = p.stat()
        need(stat.S_ISREG(meta.st_mode) and meta.st_size == item['size'], 'Managed layer length/type differs')
        layers.append(dict(path=str(p), **item))
    need(sum(x['size'] for x in ids) <= 2 * GIB, 'Stored inputs exceed 2 GiB budget')
    request = {'version': 1, 'sourceImage': identity(ids), 'virtualBytes': 64 * GIB,
               'maxInputBytes': 2 * GIB, 'maxWrittenBytes': 4 * GIB, 'layers': layers}
    evidence = {'snapshot': SNAPSHOT, 'sourceConfig': str(path), 'sourceConfigSha256': sha(raw),
                'catalogSha256': sha(record_raw), 'layerCount': len(ids),
                'sourceImage': request['sourceImage'], 'storedInputBytes': sum(x['size'] for x in ids),
                'capturedUpperExcludedAfterPrefixVerification': True,
                'sourceView': 'Original immutable OCI rootfs, not the captured writable upper'}
    return request, evidence, (path, raw), (record_path, record_raw)


def unpack_source(raw, destination):
    need(sha(raw) == ARCHIVE_SHA, 'Existing offline archive changed')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        members = archive.getmembers()
        need(len(members) <= 2000 and sum(m.size for m in members) <= 32 * 1024 ** 2, 'Source archive exceeds limits')
        seen = set()
        for member in members:
            rel = PurePosixPath(member.name)
            need(not rel.is_absolute() and '..' not in rel.parts and rel.parts[0] == 'agentenv-native-core'
                 and member.name not in seen and (member.isdir() or member.isfile()), 'Invalid source archive entry')
            seen.add(member.name)
        destination.mkdir(mode=0o700)
        for member in members:
            out = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                out.mkdir(mode=0o700, exist_ok=True)
            else:
                out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.extractfile(member) as src, out.open('xb') as dst:
                    shutil.copyfileobj(src, dst)
                out.chmod(0o700 if member.mode & 0o111 else 0o600)
    return destination / 'agentenv-native-core'


def run(command, name, source, env, report, timeout=1800):
    print('PHASE=' + name, flush=True)
    logfile = WORK / (name + '.log')
    with logfile.open('xb') as stream:
        process = subprocess.Popen(command, cwd=source, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        started = last = time.monotonic()
        try:
            while True:
                try:
                    code = process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    need(time.monotonic() - started < timeout, 'Phase exceeded time budget: ' + name)
                    need(shutil.disk_usage(ROOT).free >= 4 * GIB, 'Free-space floor reached')
                    need(logfile.stat().st_size < 16 * 1024 ** 2, 'Phase log exceeded limit')
                    if time.monotonic() - last >= 20:
                        print('PROGRESS phase=' + name + ' elapsed_s=' + str(int(time.monotonic() - started)), flush=True)
                        last = time.monotonic()
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            raise
    report['phases'][name] = {'exitCode': code, 'seconds': round(time.monotonic() - started, 2)}
    if code:
        with logfile.open('rb') as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 12000))
            report['failureLogTail'] = stream.read().decode(errors='replace')
        raise RuntimeError('Phase failed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    report = {'revision': 'A-rootfs-export-v1', 'status': 'PLAN_ONLY', 'coreCommit': CORE_COMMIT,
              'workDirectory': str(WORK), 'SDK_called': False, 'Guest_created': False,
              'ublkDevicesCreated': 0, 'servicesChanged': False, 'sourceModified': False,
              'nativeBindingAccepted': False, 'memfileCrossNodeCowAccepted': False, 'phases': {},
              'scope': 'Offline build/tests and sparse immutable rootfs export; no UB allocation or memory benefit claim'}
    if not args.run:
        print(json.dumps(report, indent=2))
        return 0
    made = False
    try:
        need(sys.platform == 'linux' and platform.machine() == 'aarch64' and socket.gethostname() == 'server1', 'Use node A ARM64 Linux')
        need(os.getuid() == os.geteuid() == 1204 and os.getgid() == os.getegid() == 1205, 'Use ordinary jwk, without sudo')
        caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        need(all(int(caps[k].strip(), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), 'Zero process capabilities required')
        safe(ROOT)
        safe(WORK.parent)
        safe(TARGET)
        safe(CARGO_HOME)
        need(not WORK.exists() and not WORK.is_symlink(), 'Existing export attempt preserved; do not rerun')
        need(shutil.disk_usage(ROOT).free >= 16 * GIB, 'At least 16 GiB free disk required for build/export headroom')
        archive = read(ARCHIVE, 4 * 1024 ** 2)
        need(sha(archive) == ARCHIVE_SHA, 'Offline source archive differs')
        print('PHASE=verify_original_rootfs_identity_no_Guest_no_ublk', flush=True)
        request, evidence, original_config, catalog = inputs()
        os.umask(0o077)
        WORK.mkdir(mode=0o700)
        made = True
        report['input'] = evidence
        save(WORK / 'request.json', request)
        save(WORK / 'input-evidence.json', evidence)
        source = unpack_source(archive, WORK / 'source')
        need(sha(read(source / 'Cargo.lock')) == LOCK_SHA, 'Frozen dependency lock differs')
        for name, item in PAYLOAD.items():
            need(name in ('storage/overlaybd/src/lib.rs', 'storage/overlaybd/src/raw_export.rs',
                          'storage/overlaybd/src/bin/aenv-export-rootfs.rs'), 'Unexpected core overlay')
            data = zlib.decompress(base64.b64decode(item['data'], validate=True))
            need(len(data) == item['bytes'] and sha(data) == item['sha256'], 'Embedded core source differs')
            (source / name).write_bytes(data)
        env = {'HOME': str(Path.home()), 'USER': 'jwk', 'LOGNAME': 'jwk', 'LANG': 'C.UTF-8',
               'PATH': str(RUST) + ':/usr/local/bin:/usr/bin:/bin', 'CARGO_HOME': str(CARGO_HOME),
               'CARGO_TARGET_DIR': str(TARGET), 'CARGO_NET_OFFLINE': 'true', 'CARGO_BUILD_JOBS': '2',
               'CARGO_INCREMENTAL': '0', 'RUSTC': str(RUST / 'rustc'), 'RUSTDOC': str(RUST / 'rustdoc'),
               'CARGO_PROFILE_RELEASE_LTO': 'false', 'CARGO_PROFILE_RELEASE_DEBUG': '0',
               'LIBCLANG_PATH': '/usr/lib64', 'CMAKE_BUILD_PARALLEL_LEVEL': '2',
               'LD_LIBRARY_PATH': str(BASE / 'native/lib') + ':' + str(BASE / 'native/fallback/lib'),
               'TMPDIR': str(WORK / 'tmp'), 'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CEILING_DIRECTORIES': str(WORK)}
        (WORK / 'tmp').mkdir(mode=0o700)
        cargo = str(safe(RUST / 'cargo'))
        common = ['--release', '--offline', '--locked', '-p', 'overlaybd', '--no-default-features', '--bin', 'aenv-export-rootfs']
        run([str(RUST / 'rustc'), '--edition=2021', '--test', str(source / 'storage/overlaybd/src/raw_export.rs'),
             '-o', str(WORK / 'sparse-tests')], 'compile-sparse-tests', source, env, report, 120)
        run([str(WORK / 'sparse-tests')], 'run-sparse-tests', source, env, report, 60)
        # Compile the exact published binary test module in a minimal harness.
        # The crate's broad dev-dependencies otherwise build unrelated AWS and
        # container suites. Registry versions/checksums must stay in Cargo.lock.
        import tomllib
        harness = WORK / 'test-harness'
        harness.mkdir(mode=0o700)
        manifest = ('[package]\nname="aenv-rootfs-export-tests"\nversion="0.1.0"\nedition="2021"\n'
                    '[workspace]\n[[bin]]\nname="export-tests"\npath=' + json.dumps(str(source / 'storage/overlaybd/src/bin/aenv-export-rootfs.rs')) + '\n'
                    '[dependencies]\noverlaybd={path=' + json.dumps(str(source / 'storage/overlaybd')) + ',default-features=false}\n'
                    'anyhow="1.0"\nserde={version="1.0",features=["derive"]}\n'
                    'serde_json={version="1.0",features=["preserve_order"]}\n'
                    'sha2={version="0.10.9",features=["asm"]}\nlibc="0.2.174"\n'
                    'tokio={version="1.44.2",features=["full"]}\ntempfile="3"\n')
        (harness / 'Cargo.toml').write_text(manifest)
        frozen = read(source / 'Cargo.lock')
        (harness / 'Cargo.lock').write_bytes(frozen)
        run([cargo, 'metadata', '--offline', '--format-version', '1', '--manifest-path', str(harness / 'Cargo.toml')],
            'resolve-minimal-test-harness-offline', harness, env, report, 120)
        def registry_set(raw):
            return {(p['name'], p['version'], p.get('source'), p.get('checksum'))
                    for p in tomllib.loads(raw.decode()).get('package', []) if p.get('source')}
        need(registry_set(read(harness / 'Cargo.lock')) <= registry_set(frozen), 'Test harness dependency drift from frozen source')
        run([cargo, 'test', '--release', '--offline', '--locked', '--manifest-path', str(harness / 'Cargo.toml'),
             '--bin', 'export-tests'], 'native-layered-export-tests', harness, env, report)
        run([cargo, 'build'] + common, 'build-rootfs-exporter', source, env, report)
        if (RUST / 'cargo-clippy').is_file():
            # This feature profile has existing unused-code warnings in the library.
            # Fail clippy lints while leaving those unrelated rustc warnings visible.
            run([cargo, 'clippy'] + common + ['--', '-D', 'clippy::all'], 'clippy-rootfs-exporter', source, env, report)
        else:
            report['clippy'] = 'UNAVAILABLE_NATIVE_COMPONENT_NOT_INSTALLED'
        binary = TARGET / 'release/aenv-export-rootfs'
        binary_raw = read(binary, 128 * 1024 ** 2)
        need(binary_raw[:6] == b'\x7fELF\x02\x01' and int.from_bytes(binary_raw[18:20], 'little') == 183, 'Expected AArch64 ELF64')
        staged = WORK / 'aenv-export-rootfs'
        with staged.open('xb') as stream:
            stream.write(binary_raw)
        staged.chmod(0o700)
        report['exporterSha256'] = sha(binary_raw)
        need(read(original_config[0]) == original_config[1] and read(catalog[0]) == catalog[1], 'Source descriptors changed during build')
        run([str(staged), str(WORK / 'request.json'), str(WORK / 'raw')],
            'export-real-rootfs', source, env, report, 1800)
        result = json.loads(read(WORK / 'raw/export.json'))
        need(result.get('status') == 'RAW_ROOTFS_EXPORTED_NO_UB_OR_GUEST'
             and result.get('sourceImage') == request['sourceImage'], 'Exporter receipt differs')
        need(read(original_config[0]) == original_config[1] and read(catalog[0]) == catalog[1], 'Source descriptors changed during export')
        report['export'] = result
        report['status'] = 'NATIVE_TESTS_PASSED_REAL_ROOTFS_EXPORTED_NOT_PUBLISHED_TO_UB'
        report['next'] = 'Validate/compact this own ext4 copy before any UB publication; 64 GiB sparse logical size is not a small UB allocation'
    except BaseException as error:
        report.update(status='STOPPED_ROOTFS_EXPORT_PRESERVE_PARTIALS', errorType=type(error).__name__, reason=str(error)[:1500])
    finally:
        if made:
            save(WORK / 'return.json', report)
        print('BEGIN_A_ROOTFS_EXPORT_REPORT')
        print(json.dumps(report, indent=2))
        print('END_A_ROOTFS_EXPORT_REPORT')
    return 0 if report['status'] == 'NATIVE_TESTS_PASSED_REAL_ROOTFS_EXPORTED_NOT_PUBLISHED_TO_UB' else 1


if __name__ == '__main__':
    raise SystemExit(main())
