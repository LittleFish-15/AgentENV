"""Find the Datree template and inspect the pinned startup contract on M/N."""

import argparse
import hashlib
import json
import subprocess
import os
import re
import stat
from pathlib import Path


BASES = tuple(map(Path, ('/home/jwk/agent/sp3-mn', '/var/lib/aenv',
                        '/var/lib/agentenv', '/root/aenv-pmem', '/opt/aenv')))
PRUNE = {'target', '.cargo', '.rustup', '.git', 'kernel.partial', 'kernel', 'node_modules',
         'vendor', 'evidence', 'AgentENV', 'src', 'build', 'bin', 'deps',
         'node_modules', 'snapshots', 'layers', 'runtime', 'r', 'oci-blobs', 'logs'}
NAMES = {'server', 'uvm-ublk-daemon', 'firecracker', 'vmlinux', 'vmlinux.bin', 'tools.ext4',
         'overlaybd-create', 'overlaybd-apply', 'overlaybd-commit', 'regctl', 'envd', 'aenv'}
RUNTIME_PATTERN = re.compile(r'^(vmlinux[-.]|firecracker[-.]|tools[-.]).+')
DIGEST = re.compile(r'sha256:([a-f0-9]{64})')


def path_fact(path):
    try:
        meta = path.stat()
    except OSError:
        return None
    return {'path': str(path), 'bytes': meta.st_size, 'mode': oct(stat.S_IMODE(meta.st_mode)),
            'uid': meta.st_uid, 'gid': meta.st_gid} if stat.S_ISREG(meta.st_mode) else None


def discover():
    repos, dependencies, loose = set(), {}, {}
    visited, truncated = set(), False
    for base in BASES:
        for raw, directories, files in os.walk(base, followlinks=False):
            folder = Path(raw)
            if folder in visited:
                directories[:] = []
                continue
            visited.add(folder)
            if len(visited) > 3500:
                truncated = True
                break
            if 'catalog' in directories and (folder / 'catalog/records').is_dir():
                repos.add(folder)
            directories[:] = sorted(name for name in directories if name not in PRUNE
                                     and not name.startswith('.') and name not in ('catalog', 'managed-layers')
                                     and not name.startswith(('lower-pack-', 'relay-incoming-')))
            if len(folder.relative_to(base).parts) >= 8:
                directories[:] = []
            for name in files:
                path = folder / name
                if name in NAMES or RUNTIME_PATTERN.fullmatch(name):
                    fact = path_fact(path)
                    if fact and len(dependencies) < 80:
                        dependencies[str(path)] = fact
                if name == 'overlaybd.commit' or name.endswith('.overlaybd.commit'):
                    fact = path_fact(path)
                    if fact and len(loose) < 48:
                        loose[str(path)] = fact
        if truncated:
            break

    # These known native build outputs are beneath the pruned Cargo target.
    target = Path('/home/jwk/agent/sp3-mn/src/AgentENV/target/release')
    for path in [target / 'server', target / 'uvm-ublk-daemon', Path('/usr/local/bin/firecracker')]:
        fact = path_fact(path)
        if fact:
            dependencies[str(path)] = fact
    return repos, dependencies, loose, len(visited), truncated


def snapshot_facts(repos, loose):
    found, unreadable, truncated = [], 0, False
    for repository in sorted(repos):
        records = sorted((repository / 'catalog/records').glob('*.json'))
        if len(records) > 512:
            truncated = True
        for path in records[:512]:
            try:
                with path.open('rb') as stream:
                    raw = stream.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError('oversize record')
                value = json.loads(raw)
                committed = value.get('committed')
                if not isinstance(committed, dict) or not committed.get('rootfs_layers'):
                    continue
                ordered_digests = tuple(next(iter(item.values())).get('digest')
                                        for item in committed['rootfs_layers'])
                if (value.get('id') != TEMPLATE and 'datree' not in str(value.get('alias', '')).lower()
                        and ordered_digests != DATREE_DIGESTS):
                    continue
                layers = []
                need_count = len(committed['rootfs_layers'])
                if need_count > 64:
                    continue
                for layer in committed['rootfs_layers']:
                    kind, body = next(iter(layer.items()))
                    digest, size = body.get('digest'), body.get('size')
                    if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or type(size) is not int or size <= 0:
                        raise ValueError('invalid layer identity')
                    name = digest.replace(':', '_') + '.overlaybd.commit'
                    expected = repository / 'managed-layers' / name
                    local = path_fact(expected)
                    if local is None:
                        local = next((fact for fact in loose.values()
                                      if Path(fact['path']).name == name and fact['bytes'] == size), None)
                    layers.append({'kind': kind, 'digest': digest, 'bytes': size,
                                   'file': local['path'] if local and local['bytes'] == size else None})
                artifact_root = repository / 'snapshots' / path.stem
                memory = committed.get('memory_layers', [])
                memory_present = bool(memory) and all(
                    DIGEST.fullmatch(row['digest'])
                    and (path_fact(repository / 'managed-layers' /
                                   (row['digest'].replace(':', '_') + '.overlaybd.commit')) or {}).get('bytes') == row['size']
                    for row in memory)
                found.append({'recordSha256': hashlib.sha256(raw).hexdigest(),
                              'record': str(path), 'templateId': value.get('id'), 'alias': value.get('alias'),
                              'virtualization': committed.get('virtualization_mode'),
                              'runtimeVersions': committed.get('runtime_versions'),
                              'rootfs': layers,
                              'localRootfsComplete': all(layer['file'] is not None for layer in layers),
                              'rootfsBytes': sum(layer['bytes'] for layer in layers),
                              'memoryLayersPresent': memory_present,
                              'snapshotArtifactsPresent': all((artifact_root / name).is_file()
                                  for name in ('commit', 'vm_state.bin', 'firecracker-manifest.json'))})
            except (OSError, ValueError, TypeError, AttributeError, KeyError, StopIteration):
                unreadable += 1
    found.sort(key=lambda entry: (not entry['localRootfsComplete'], entry['rootfsBytes']))
    return found[:24], unreadable, truncated or len(found) > 24


EXPECTED = {
    'agent1': {
        'attempt': '/root/agentenv-sp3/layered-baseline-build/attempt-aflp3z9b',
        'volume': '01a21fe3-9305-7e31-ac60-cb28b9532df5',
        'artifacts': {
            'server': ('target/release/server', 'a64852ff4dc991a72a6d7bb064c560b3c2cd3f31a6dfb117aa737b6c993c3cca'),
            'uvm-ublk-daemon': ('target/release/uvm-ublk-daemon', '5cde4369450526b930eb8c6967dcac497d19ac6ce70536946d8236b8566c61b7'),
            'agentenv-ub-provider': ('target/release/agentenv-ub-provider', 'bd5a833a67e27ece65eafead7ef4547941d06d4f10ee957d321ffd05981ee8c9'),
            'libaenv-ub.so': ('libaenv-ub.so', 'b729412a67e56d0c8545f07228930b5e4a01463f7acd6c3aa3813343a42332e7'),
        },
    },
    'agent2': {
        'attempt': '/root/agentenv-sp3/layered-baseline-build/attempt-_gun1gos',
        'volume': '01a21fe1-048a-7740-94a6-62f9e6927ecd',
        'artifacts': {
            'server': ('target/release/server', 'd8962860eb35749569fb21cfc3e7d15cd48a09c95d9d4bb82992ac281697d9fb'),
            'uvm-ublk-daemon': ('target/release/uvm-ublk-daemon', '18a1902501737ae71e90f5193768cadb61bf0876beab2f4a817152992d39b31c'),
            'agentenv-ub-provider': ('target/release/agentenv-ub-provider', '44f800cf1a50299a656561fd9a21a0ae7693ecff3f4ce56cd5705d988e68992e'),
            'libaenv-ub.so': ('libaenv-ub.so', 'b729412a67e56d0c8545f07228930b5e4a01463f7acd6c3aa3813343a42332e7'),
        },
    },
}

TEMPLATE = '01a15c6e-7519-75d0-8cd0-0ad309956168'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', choices=tuple(EXPECTED), required=True)
    parser.add_argument('--boot-id', required=True)
    parser.add_argument('--machine-id', required=True)
    args = parser.parse_args()
    if not (os.geteuid() == 0 and os.uname().nodename.split('.')[0] == args.node
            and Path('/etc/machine-id').read_text().strip() == args.machine_id
            and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == args.boot_id):
        raise RuntimeError('Node identity differs')
    checkout = Path(EXPECTED[args.node]['attempt']) / 'checkout/AgentENV'
    sources = subprocess.run(['/usr/bin/git', 'rev-parse', 'HEAD', 'HEAD^{tree}'],
                             cwd=checkout, capture_output=True, text=True, check=True, timeout=10)
    if sources.stdout.splitlines() != ['bffdc74bf9b2a11467ee25159099d03a19110f98',
                                       '044b48e11c83c80d67b12caa5989a5729401294a']:
        raise RuntimeError('Pinned AgentENV checkout differs')
    def show(path):
        return subprocess.run(['/usr/bin/git', 'show', 'HEAD:' + path], cwd=checkout,
                              capture_output=True, text=True, check=True, timeout=10).stdout
    repos, _, loose, visited, truncated = discover()
    records, unreadable, records_truncated = snapshot_facts(repos, loose)
    for record in records:
        ordered = tuple(layer['digest'] for layer in record['rootfs'])
        record['sameOrderedRootfsAsN'] = ordered == DATREE_DIGESTS
        if record['sameOrderedRootfsAsN'] and record['localRootfsComplete']:
            passed = []
            for layer in record['rootfs']:
                digest = hashlib.sha256()
                with Path(layer['file']).open('rb') as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(block)
                passed.append('sha256:' + digest.hexdigest() == layer['digest'])
            record['sourceLayerHashesMatch'] = all(passed)
    marker = re.compile(r'rootfs_demand_index_root|struct .*Config|pub sources|pub lowers|pub index_root|'
                        r'adapter_sha256|image_id|manifest_sha256|metadata_ready|fn .*layered')
    paths = ('src/bin/server.rs', 'src/cfg.rs', 'storage/ub-demand/src/config.rs',
             'storage/ub-demand/src/runtime.rs')
    excerpts = {}
    for path in paths:
        lines = show(path).splitlines()
        selected = set()
        for i, line in enumerate(lines):
            if marker.search(line):
                selected.update(range(max(0, i-3), min(len(lines), i+5)))
        excerpts[path] = [[i+1, lines[i][:350]] for i in sorted(selected)[:420]]
    print(json.dumps({'status': 'MN_DATREE_SOURCE_LAYOUT_INVENTORY', 'node': args.node,
                      'repositories': sorted(map(str, repos)), 'snapshotRecords': records,
                      'catalogRecordsUnreadable': unreadable, 'directoriesInspected': visited,
                      'walkTruncated': truncated, 'catalogResultTruncated': records_truncated,
                      'layeredSourceExcerpts': excerpts}, sort_keys=True), flush=True)


DATREE_DIGESTS = ('sha256:a9aa9dd5b3f33e978a4d289b59f1b08a367e0247005aa18da5336ab26afc1187', 'sha256:f24ba1ad4d02e8ae08b6ba86d4ae66321c95e495ab7acbc8dbfe0ac2a689ae37', 'sha256:ac6c75b85ae40dfa6a1cfc1276f348944aedfcad36520aa6169c5575e5c2f0ea', 'sha256:977e2cd00fcf337e5a15eb35a2f0f312711aea8f1ea9d60744ec03dbf88b4dbe', 'sha256:b31884184b792e2316a4758d9a93027b79fcaa2dbe904e3c953220a2677a5ab4', 'sha256:fee8796bb532008aa4fdc0d093cb5ff3010431feeac6024a9741348a7ce8c752', 'sha256:9557eff6b8cc215acd2e7c544eb49c9938a2b622cf3ea3d62b9c6a863671ec8e', 'sha256:c767eb485d3227ea45728d33be9ef6de57437c40aabf9a737f600f67bcdfc658')


if __name__ == '__main__':
    main()
