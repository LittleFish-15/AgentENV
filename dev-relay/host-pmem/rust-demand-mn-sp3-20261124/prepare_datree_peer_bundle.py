import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
from pathlib import Path

REPO = Path('/home/jwk/agent/sp3-mn/aenv-tit-d01/h/snapshot-store/repository')
TEMPLATE = '01a21c5a-b2bf-7400-94a3-f860187d7df7'
CATALOG_SHA = '9d1e1c460e67f8c9edd8a22680e88c1d2c0e7758205cdcd6fd61365f97b62974'
ALIAS = 'datree-mn-n'
STAGE = Path('/opt/aenv-datree-relay-001')
EXPECTED = [('sha256:a9aa9dd5b3f33e978a4d289b59f1b08a367e0247005aa18da5336ab26afc1187', 151735296), ('sha256:f24ba1ad4d02e8ae08b6ba86d4ae66321c95e495ab7acbc8dbfe0ac2a689ae37', 385143808), ('sha256:ac6c75b85ae40dfa6a1cfc1276f348944aedfcad36520aa6169c5575e5c2f0ea', 451728384), ('sha256:977e2cd00fcf337e5a15eb35a2f0f312711aea8f1ea9d60744ec03dbf88b4dbe', 46080), ('sha256:b31884184b792e2316a4758d9a93027b79fcaa2dbe904e3c953220a2677a5ab4', 68604928), ('sha256:fee8796bb532008aa4fdc0d093cb5ff3010431feeac6024a9741348a7ce8c752', 760665088), ('sha256:9557eff6b8cc215acd2e7c544eb49c9938a2b622cf3ea3d62b9c6a863671ec8e', 46080), ('sha256:c767eb485d3227ea45728d33be9ef6de57437c40aabf9a737f600f67bcdfc658', 28672)]


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def sha(path):
    state = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            state.update(block)
    return state.hexdigest()


def regular(path, size=None):
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
         and (size is None or info.st_size == size), 'Unexpected template file: ' + str(path))
    return info.st_size


def checked_layer(row):
    digest, size = row['digest'], row['size']
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', digest) and type(size) is int and size > 0,
         'Unexpected layer identity')
    path = REPO / 'managed-layers' / (digest.replace(':', '_') + '.overlaybd.commit')
    regular(path, size)
    need('sha256:' + sha(path) == digest, 'Stored layer digest mismatch: ' + path.name)
    return path


def main():
    parser = argparse.ArgumentParser(description='Stage Datree snapshot inputs for native SCP')
    for name in ('node','boot-id','machine-id'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    need(os.geteuid() == 0 and args.node == os.uname().nodename.split('.')[0] == 'agent2'
         and args.boot_id == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
         and args.machine_id == Path('/etc/machine-id').read_text().strip(), 'N identity differs')
    os.umask(0o077)
    record = REPO / 'catalog/records' / (TEMPLATE + '.json')
    regular(record)
    need(sha(record) == CATALOG_SHA, 'N Datree catalog differs')
    value = json.loads(record.read_bytes())
    need(value['id'] == TEMPLATE and value['alias'] == ALIAS, 'Datree identity differs')
    committed = value['committed']
    lowers = [x['Managed'] for x in committed['rootfs_layers']]
    need([(x['digest'], x['size']) for x in lowers] == EXPECTED
         and not committed.get('attached_drives') and not committed.get('volume_snapshots'),
         'Datree lower layout or attached drives differ')
    tree = REPO / 'snapshots' / TEMPLATE
    alias = REPO / 'catalog/aliases' / ALIAS
    marker = tree / 'commit'
    regular(alias)
    need(json.loads(alias.read_bytes()) == TEMPLATE and regular(marker, 9) == 9
         and marker.read_bytes() == b'committed', 'Datree commit or alias differs')
    files = [record, alias, marker, tree / 'vm_state.bin', tree / 'firecracker-manifest.json']
    for name in ('snapshot.json', 'memory-startup.pack'):
        optional = tree / name
        if os.path.lexists(optional):
            files.append(optional)
    need(not committed.get('memory_startup') or tree / 'memory-startup.pack' in files,
         'Committed memory startup pack is missing')
    mem = committed.get('memory_layers', [])
    need(bool(mem), 'Datree memory layer list is empty')
    files.append(checked_layer(lowers[-1]))
    files.extend(checked_layer(row) for row in mem)
    files = list(dict.fromkeys(files))
    contents = {str(f.relative_to(REPO)): {'bytes': regular(f), 'sha256': sha(f)} for f in files}
    parent = STAGE.parent
    info = parent.lstat()
    need(parent.resolve(strict=True) == parent and stat.S_ISDIR(info.st_mode)
         and info.st_uid == 0 and not info.st_mode & 0o022, 'Unexpected staging parent')
    need(shutil.disk_usage(parent).free > sum(x['bytes'] for x in contents.values()) + 2**20,
         'Insufficient space for Datree transfer bundle')
    STAGE.mkdir(mode=0o700)
    bundle = STAGE / 'datree-peer.tar'
    with tarfile.open(bundle, 'x') as stream:
        for f in files:
            stream.add(f, arcname=f.relative_to(REPO).as_posix(), recursive=False)
    digest = sha(bundle)
    os.chown(bundle, 0, 1205)
    bundle.chmod(0o440)
    os.chown(STAGE, 0, 1205)
    STAGE.chmod(0o750)
    print(json.dumps({'status': 'MN_DATREE_PEER_BUNDLE_READY', 'templateId': TEMPLATE,
                      'path': str(bundle), 'bytes': bundle.stat().st_size, 'sha256': digest,
                      'members': contents}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
