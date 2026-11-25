"""Find local committed rootfs layers and the matching runtime dependencies."""

import json
import os
import re
import stat
from pathlib import Path


BASES = tuple(map(Path, ('/var/lib/aenv', '/var/lib/agentenv', '/opt/aenv', '/opt/agent-benchmark',
                        '/root/aenv-pmem', '/home/jwk/agent/sp3-mn')))
PRUNE = {'target', '.cargo', '.rustup', '.git', 'kernel.partial', 'kernel', 'node_modules',
         'vendor', 'evidence', 'AgentENV'}
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
            if len(visited) > 640:
                truncated = True
                break
            if 'catalog' in directories and (folder / 'catalog/records').is_dir():
                repos.add(folder)
            directories[:] = sorted(name for name in directories if name not in PRUNE
                                     and not name.startswith('.') and name not in ('catalog', 'managed-layers')
                                     and not name.startswith(('lower-pack-', 'relay-incoming-')))
            if len(folder.relative_to(base).parts) >= 5:
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
        if len(records) > 48:
            truncated = True
        for path in records[:48]:
            try:
                with path.open('rb') as stream:
                    raw = stream.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError('oversize record')
                value = json.loads(raw)
                committed = value.get('committed')
                if not isinstance(committed, dict) or not committed.get('rootfs_layers'):
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
                found.append({'record': str(path), 'templateId': value.get('id'), 'alias': value.get('alias'),
                              'virtualization': committed.get('virtualization_mode'),
                              'runtimeVersions': committed.get('runtime_versions'),
                              'rootfs': layers,
                              'localRootfsComplete': all(layer['file'] is not None for layer in layers),
                              'rootfsBytes': sum(layer['bytes'] for layer in layers),
                              'snapshotArtifactsPresent': artifact_root.is_dir()})
            except (OSError, ValueError, TypeError, AttributeError, KeyError, StopIteration):
                unreadable += 1
    found.sort(key=lambda entry: (not entry['localRootfsComplete'], entry['rootfsBytes']))
    return found[:24], unreadable, truncated or len(found) > 24


def main():
    repos, dependencies, loose, visited, truncated = discover()
    records, unreadable, records_truncated = snapshot_facts(repos, loose)
    print(json.dumps({'status': 'MN_GUEST_INPUTS_OBSERVED', 'node': os.uname().nodename,
                      'catalogRepositories': [str(repo) for repo in sorted(repos)],
                      'snapshotRecords': records, 'catalogRecordsUnreadable': unreadable,
                      'catalogResultTruncated': records_truncated, 'candidateCommittedFiles': list(loose.values()),
                      'dependencies': list(dependencies.values()), 'directoriesInspected': visited,
                      'walkTruncated': truncated, 'kvm': Path('/dev/kvm').is_char_device(),
                      'ublk': Path('/dev/ublk-control').is_char_device()}, ensure_ascii=True), flush=True)


if __name__ == '__main__':
    main()
