"""Verify the existing committed Titanic snapshot and create its real DAX backing."""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path


BASE = Path('/home/jwk/agent/sp3-mn/mn-tcap-004')
REPO = BASE / 'h/snapshot-store'
SERVER = Path('/home/jwk/agent/sp3-mn/src/AgentENV/target/release/server')
SERVER_SHA = '1d450f7cabbd10c41ef11bd6dc093e962b2439204a5a376e1bb2c748210ca917'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C', 'LC_ALL': 'C'}
CONTAINER_BYTES = 2 * 1024**3
FIEMAP = 'aW1wb3J0IGZjbnRsCmltcG9ydCBvcwppbXBvcnQgc3RydWN0CmltcG9ydCBzeXMKCnBhdGgsIGxlbmd0aCwgY2FwYWNpdHkgPSBzeXMuYXJndlsxXSwgaW50KHN5cy5hcmd2WzJdKSwgaW50KHN5cy5hcmd2WzNdKQpwYWdlID0gb3Muc3lzY29uZignU0NfUEFHRVNJWkUnKQpoZWFkZXIgPSBzdHJ1Y3QuU3RydWN0KCc8UVFJSUlJJykKZXh0ZW50ID0gc3RydWN0LlN0cnVjdCgnPFFRUVFRSUlJSScpCmxpbWl0ID0gMTI4CndpcmUgPSBieXRlYXJyYXkoaGVhZGVyLnNpemUgKyBsaW1pdCAqIGV4dGVudC5zaXplKQpoZWFkZXIucGFja19pbnRvKHdpcmUsIDAsIDAsIGxlbmd0aCwgMCwgMCwgbGltaXQsIDApCndpdGggb3BlbihwYXRoLCAncmInKSBhcyBsb3dlcjoKICAgIGZjbnRsLmlvY3RsKGxvd2VyLmZpbGVubygpLCAweGMwMjA2NjBiLCB3aXJlLCBUcnVlKQpzdGFydCwgc3BhbiwgZmxhZ3MsIG1hcHBlZCwgY291bnQsIHplcm8gPSBoZWFkZXIudW5wYWNrX2Zyb20od2lyZSkKaWYgKHN0YXJ0LCBzcGFuLCBmbGFncywgY291bnQsIHplcm8pICE9ICgwLCBsZW5ndGgsIDAsIGxpbWl0LCAwKSBvciBub3QgMSA8PSBtYXBwZWQgPD0gbGltaXQ6CiAgICBzeXMuZXhpdCgnSW5jb21wbGV0ZSBGSUVNQVAgcmVzdWx0JykKbmV4dF9vZmZzZXQsIHJhbmdlcyA9IDAsIFtdCmZvciBpbmRleCBpbiByYW5nZShtYXBwZWQpOgogICAgbG9naWNhbCwgcGh5c2ljYWwsIHNpemUsIHowLCB6MSwgZmxhZ3MsIHoyLCB6MywgejQgPSBleHRlbnQudW5wYWNrX2Zyb20oCiAgICAgICAgd2lyZSwgaGVhZGVyLnNpemUgKyBpbmRleCAqIGV4dGVudC5zaXplKQogICAgaWYgKGxvZ2ljYWwgIT0gbmV4dF9vZmZzZXQgb3Igbm90IGxvZ2ljYWwgPCBsZW5ndGggb3Igbm90IHNpemUgb3IKICAgICAgICAgICAgKGxvZ2ljYWwgfCBwaHlzaWNhbCB8IHNpemUpICUgcGFnZSBvciBwaHlzaWNhbCArIHNpemUgPiBjYXBhY2l0eSBvcgogICAgICAgICAgICBhbnkoKHowLCB6MSwgejIsIHozLCB6NCkpIG9yIGZsYWdzICYgfjB4MTAwMSBvcgogICAgICAgICAgICBib29sKGZsYWdzICYgMSkgIT0gKGluZGV4ID09IG1hcHBlZCAtIDEpKToKICAgICAgICBzeXMuZXhpdCgnTG93ZXIgaGFzIGEgZ2FwLCB1bndyaXR0ZW4vdW5hbGlnbmVkIGV4dGVudCBvciB1bnN1cHBvcnRlZCBGSUVNQVAgZmxhZycpCiAgICBuZXh0X29mZnNldCArPSBzaXplCiAgICByYW5nZXMuYXBwZW5kKChwaHlzaWNhbCwgcGh5c2ljYWwgKyBzaXplKSkKcmFuZ2VzLnNvcnQoKQppZiBuZXh0X29mZnNldCA8IGxlbmd0aCBvciBhbnkoYVsxXSA+IGJbMF0gZm9yIGEsIGIgaW4gemlwKHJhbmdlcywgcmFuZ2VzWzE6XSkpOgogICAgc3lzLmV4aXQoJ0ZJRU1BUCBkb2VzIG5vdCBjb3ZlciB0aGUgbG93ZXIgb3IgcGh5c2ljYWwgZXh0ZW50cyBvdmVybGFwJykKcHJpbnQoZidGSUVNQVAgcHJlZmxpZ2h0IE9LOiB7bWFwcGVkfSBleHRlbnRzLCB7bGVuZ3RofSBsb3dlciBieXRlcycpCg=='
PACK = r'''
set -euo pipefail
outer=$1 view=$2 layout=$3 checker=$4
mount -t ext4 -o loop,nosuid,nodev,noexec -- "$outer" "$view"
trap 'umount -- "$view"' EXIT
while IFS=$'\t' read -r source name expected bytes; do
  target=$view/$name
  ( set -o noclobber; : > "$target" )
  dd if="$source" of="$target" bs=4M conv=fsync status=none
  test "$(stat -c %s -- "$target")" -eq "$bytes"
  printf '%s  %s\n' "$expected" "$target" | sha256sum -c -
  /usr/bin/python3 -I -B "$checker" "$target" "$bytes" "$(stat -c %s -- "$outer")"
done < "$layout"
umount -- "$view"
trap - EXIT
'''


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def sha(path):
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def regular(path, size=None):
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
         and info.st_uid == 1204 and (size is None or info.st_size == size),
         'Unexpected committed artifact: ' + str(path))
    return info.st_size


def row_for(layer):
    digest = layer['digest']
    size = layer['size']
    need(re.fullmatch(r'sha256:[a-f0-9]{64}', digest) and type(size) is int and size > 0,
         'Invalid stored layer metadata')
    name = digest.replace(':', '_') + '.overlaybd.commit'
    path = REPO / 'managed-layers' / name
    regular(path, size)
    return {'name': name, 'digest': digest, 'bytes': size}, path


def file_record(file):
    return {'path': str(file), 'bytes': file.stat().st_size, 'sha256': sha(file)}


def prepare(snapshot, list_sha):
    need(os.geteuid() == 0 and os.uname().nodename.split('.')[0] == 'agent1', 'Use M unified root entry')
    need(os.sysconf('SC_PAGESIZE') == 4096, 'Expected 4 KiB pages for this ext4 layout')
    os.umask(0o077)
    record_path = REPO / 'catalog/records' / (snapshot + '.json')
    regular(record_path)
    record = json.loads(record_path.read_bytes())
    need(record['id'] == snapshot, 'Persisted catalog record ID differs')
    details = record['committed']
    tree = REPO / 'snapshots' / snapshot
    marker = tree / 'commit'
    regular(marker, len(b'committed'))
    need(marker.read_bytes() == b'committed' and not details['attached_drives']
         and not details.get('volume_snapshots'), 'Expected a committed rootfs-only template')
    root, memory = details['rootfs_layers'], details['memory_layers']
    identity = json.dumps({'rootfsLowers': root, 'memoryLowers': memory}, separators=(',', ':'),
                          sort_keys=True).encode()
    need(hashlib.sha256(identity).hexdigest() == list_sha and len(root) == 10 and len(memory) == 1,
         'Persisted layer list differs from the capture receipt')
    roots = [row_for(layer['Managed']) for layer in root]
    mems = [row_for(layer) for layer in memory]
    need(sum(row['bytes'] for row, _ in roots) == 1831881728, 'Unexpected rootfs stored byte count')
    alias = REPO / 'catalog/aliases' / 'mn-titanic-verify-001'
    regular(alias)
    need(json.loads(alias.read_bytes()) == snapshot, 'Persisted template alias differs')
    transfers = [record_path, alias, marker, tree / 'vm_state.bin', tree / 'firecracker-manifest.json']
    for name in ('snapshot.json', 'memory-startup.pack'):
        optional = tree / name
        if os.path.lexists(optional):
            transfers.append(optional)
    if details.get('memory_startup'):
        need(tree / 'memory-startup.pack' in transfers, 'Committed memory startup pack is missing')
    for file in transfers:
        regular(file)
    for row, file in mems:
        need('sha256:' + sha(file) == row['digest'], 'Stored memory layer digest differs')
        transfers.append(file)
    print(json.dumps({'status': 'MN_EXISTING_TEMPLATE_VERIFIED', 'templateId': snapshot,
                      'catalog': str(record_path), 'scopeResidueNames': sorted(
                          p.name for p in (BASE / 'r/netns').glob('agentenv-ns-*'))[:32]}), flush=True)

    parent = Path('/root/aenv-pmem')
    need(parent.resolve(strict=True) == parent and sha(SERVER) == SERVER_SHA,
         'Prepared server or root staging area differs')
    need(shutil.disk_usage(parent).free >= 3 * 1024**3, 'Need 3 GiB free in private staging area')
    work = Path(tempfile.mkdtemp(prefix='mn-titanic-share-001-', dir=parent))
    view, outer = work / 'view', work / 'lowers.ext4'
    view.mkdir(mode=0o700)
    with outer.open('xb') as stream:
        stream.truncate(CONTAINER_BYTES)
    layout = work / 'layers.tsv'
    layout.write_text(''.join(f'{path}\t{row["name"]}\t{row["digest"][7:]}\t{row["bytes"]}\n'
                              for row, path in roots), encoding='utf-8')
    checker = work / 'fiemap.py'
    checker.write_bytes(base64.b64decode(FIEMAP, validate=True))
    subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096', '-m', '0',
                    '-O', '^has_journal,^inline_data', '-E', 'lazy_itable_init=0,lazy_journal_init=0',
                    str(outer)], env=ENV, check=True)
    subprocess.run(['unshare', '--mount', '--propagation', 'private', '/bin/bash', '-s', '--',
                    str(outer), str(view), str(layout), str(checker)], input=PACK.encode(), env=ENV, check=True)
    subprocess.run(['e2fsck', '-fn', str(outer)], env=ENV, check=True)
    container_sha = sha(outer)
    manifest_path = work / 'manifest.json'
    subprocess.run([str(SERVER), '--prepare-host-pmem-image', str(outer), '--host-pmem-image-sha256',
                    container_sha, '--host-pmem-manifest', str(manifest_path)], env=ENV, check=True)
    manifest = json.loads(manifest_path.read_bytes())
    need(manifest['document']['fileBytes'] == CONTAINER_BYTES and
         manifest['document']['layerDigest'] == 'sha256:' + container_sha, 'Native prepared manifest differs')
    bundle = work / 'snapshot-for-n.tar'
    with tarfile.open(bundle, 'x') as archive:
        for source in transfers:
            regular(source)
            archive.add(source, arcname='snapshot-store/' + source.relative_to(REPO).as_posix(), recursive=False)
        archive.add(manifest_path, arcname='manifest.json', recursive=False)
    result = {'status': 'MN_REAL_TITANIC_PROVIDER_INPUT_PREPARED', 'templateId': snapshot,
              'ownerSourceImage': {'path': str(outer), 'bytes': CONTAINER_BYTES, 'sha256': container_sha},
              'manifest': file_record(manifest_path),
              'manifestDigest': manifest['sha256'], 'rootfsLowers': [row for row, _ in roots],
              'peerBundle': file_record(bundle), 'peerFiles': [str(p.relative_to(REPO)) for p in transfers]}
    (work / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=uuid.UUID, required=True)
    parser.add_argument('--layer-list-sha', required=True)
    args = parser.parse_args()
    prepare(str(args.template), args.layer_list_sha)
