"""Collect the owner evidence left by the two completed Titanic sandbox runs."""

import argparse
import json
import os
import re
from pathlib import Path


PROVIDER = Path('/opt/aenv/bin/agentenv-ub-provider-5ecfe105')
LOAD_BYTES = 256 * 1024
POOL_BYTES = 128 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def document(path):
    require(path.resolve(strict=True) == path and path.is_file() and path.stat().st_size <= 12 * 1024 * 1024,
            'Unexpected evidence path: ' + str(path))
    return json.loads(path.read_bytes())


def read_receipt(run, manifest_sha, pid):
    root = Path('/etc/aenv/ub') / ('relay-' + run)
    config_path = root / 'device-root.json'
    proc = Path('/proc') / str(pid)
    require((proc / 'exe').resolve(strict=True) == PROVIDER
            and (proc / 'cmdline').read_bytes().split(b'\0')[1:3] == [b'root', os.fsencode(config_path)],
            'Owner Provider process differs')
    config = document(config_path)
    require((config['run'], config['manifestSha256'], config['node'], config['ownerNode'])
            == (run, manifest_sha, 'agent1', 'agent1')
            and config['device']['bootId'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'Owner Provider config or boot differs')
    index = document(root / 'index/stable-index.json')
    require(index['state'] == 'metadata_ready' and index['mode'] == 'host-dax-stable-demand'
            and len(index['replicas']) == 10 and all(
                item['generation'] == run and item['manifestSha256'] == 'sha256:' + manifest_sha
                for item in index['replicas']), 'Owner ready index differs')
    journal = document(root / 'device-state/root.json')
    require((journal['run'], journal['node'], journal['manifest']) == (run, 'agent1', manifest_sha)
            and journal['phase'] in ('serving', 'unit_bound', 'slot_verified'), 'Owner root journal unexpectedly changed')
    path = Path('/var/lib/aenv-ub-sdk') / ('relay-' + run) / ('directory-' + run + '.json')
    directory = document(path)
    require((directory['run'], directory['manifest']) == (run, manifest_sha)
            and set(directory['ready']) == {'agent1', 'agent2'} and not (
                directory['closed'] or directory['faulted'] or directory['released'] or directory['drained']),
            'Coordinator directory is closed, faulted, released or incomplete')
    manifest = document(root / 'manifest.json')
    payload = manifest['document']
    require(manifest['sha256'] == manifest_sha and payload['fileBytes'] == 2**31
            and payload['chunkBytes'] == LOAD_BYTES and len(payload['chunks']) == 2**31 // LOAD_BYTES,
            'Unexpected owner image layout')

    slots, seen, importer_units = set(), set(), set()
    imported_pools = set(directory['node_pools']['agent2'])
    for key, item in directory['units'].items():
        unit = item['unit']
        number = unit['index']
        require(type(number) is int and 0 <= number < len(payload['chunks'])
                and str(number) == key and item['ready'] is True, 'Published unit is invalid or incomplete')
        chunk = payload['chunks'][number]
        pool = unit['pool']
        slot = unit['slotOffset']
        identity = (pool['poolUuid'], slot)
        require(chunk['offset'] == number * LOAD_BYTES and chunk['length'] == LOAD_BYTES
                and unit['sha256'] == chunk['sha256'] and unit['origin']
                and pool['ownerNode'] == 'agent1' and pool['run'] == run and pool['bytes'] == POOL_BYTES
                and 0 <= slot < POOL_BYTES and slot % LOAD_BYTES == 0 and identity not in slots,
                'Published slot, owner or manifest hash differs')
        slots.add(identity)
        seen.add(number)
        if pool['poolUuid'] in imported_pools:
            importer_units.add(number)
    bound = set(journal['bindings'])
    require(seen == set(journal['written']) and bound <= seen and len(seen) > 10,
            'Owner fill receipt and published units differ')
    print(json.dumps({'status': 'MN_TITANIC_OWNER_DIRECTORY_VERIFIED', 'run': run, 'node': 'agent1',
                      'manifestSha256': manifest_sha, 'providerPid': pid, 'phase': journal['phase'],
                      'bound': sorted(bound), 'writtenAndPublished': sorted(seen),
                      'unitsInPoolsIssuedToN': sorted(importer_units), 'poolCount': len(directory['pools']),
                      'loadBytes': LOAD_BYTES}, sort_keys=True), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--manifest-sha', required=True)
    parser.add_argument('--provider-pid', type=int, required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0 and os.uname().nodename.split('.')[0] == 'agent1'
            and re.fullmatch('[0-9a-f]{32}', args.run) and re.fullmatch('[0-9a-f]{64}', args.manifest_sha),
            'Use the M root entry for the pinned run')
    read_receipt(args.run, args.manifest_sha, args.provider_pid)
