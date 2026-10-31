"""Coordinator-authorized read-only reattachment after publisher boot loss.

This is a new local import, not publisher resurrection or a release receipt
for the old owner. The unchanged publication and its surviving peer remain
retained. Only the old publisher's machine may use this bounded recovery path.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import contract


def read_permit(config):
    path = Path(config['rejoinPermit'])
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('Rejoin permit path is redirected')
    # The coordinator owns the authorization and the path below its root home.
    # An ordinary SDK worker must not grant itself another reader identity.
    root = Path('/home/jwk/root')
    if root not in path.parents:
        raise ValueError('Rejoin permit must be in the coordinator root directory')
    for parent in (root, *reversed(list(path.parents)[:list(path.parents).index(root)])):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Rejoin permit has an untrusted parent')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_mode & 0o022 or not 0 < before.st_size <= 32768):
            raise ValueError('Rejoin permit owner/type/size differs')
        raw = stream.read(32769)
        after = os.fstat(stream.fileno())
    signature = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    if (signature(before) != signature(after) or signature(after) != signature(path.stat())
            or 'sha256:' + hashlib.sha256(raw).hexdigest() != config['rejoinPermitSha256']):
        raise ValueError('Rejoin permit bytes changed')
    return json.loads(raw)


def local_identity():
    return (Path('/etc/machine-id').read_text().strip(),
            Path('/proc/sys/kernel/random/boot_id').read_text().strip())


def validate_permit(config, manifest):
    if config.get('role') != 'rejoin' or config.get('mode') != 'pmem':
        raise ValueError('Rejoin permit applies only to read-only native imports')
    permit = read_permit(config)
    machine, boot = local_identity()
    fields = {'version', 'scope', 'machineId', 'previousPublisherBootId', 'currentBootId',
              'readerId', 'ownerId', 'manifestSha256', 'logicalBytes',
              'retainedPeer', 'releaseAuthority'}
    if (set(permit) != fields or type(permit['version']) is not int or permit['version'] != 1
            or permit['scope'] != 'readonly-native-publication-rejoin'
            or permit['releaseAuthority'] != 'local-mappings-only'
            or permit['machineId'] != machine or permit['currentBootId'] != boot
            or permit['previousPublisherBootId'] == permit['currentBootId']
            or any(not isinstance(permit[k], str) or re.fullmatch('[0-9a-f-]{36}', permit[k]) is None
                   for k in ('previousPublisherBootId', 'currentBootId'))
            or permit['readerId'] != config['readerId'] or permit['readerId'] in manifest['readers']
            or permit['ownerId'] != manifest['ownerId']
            or permit['manifestSha256'] != 'sha256:' + hashlib.sha256(contract.canonical(manifest)).hexdigest()
            or type(permit['logicalBytes']) is not int or permit['logicalBytes'] <= 0
            or permit['logicalBytes'] != sum(r['mappingBytes'] for r in manifest['replicas'])
            or permit['logicalBytes'] > config['logicalBudgetBytes']):
        raise ValueError('Rejoin generation, machine, boot or authority differs')
    peer = permit['retainedPeer']
    if (not isinstance(peer, dict) or set(peer) != {'machineId', 'bootId', 'readerId', 'pid', 'startTicks'}
            or peer['machineId'] == permit['machineId'] or peer['readerId'] not in manifest['readers']
            or not isinstance(peer['machineId'], str) or re.fullmatch('[0-9a-f]{32}', peer['machineId']) is None
            or not isinstance(peer['bootId'], str) or re.fullmatch('[0-9a-f-]{36}', peer['bootId']) is None
            or type(peer['pid']) is not int or peer['pid'] <= 0
            or not isinstance(peer['startTicks'], str) or not peer['startTicks'].isdecimal()):
        raise ValueError('Rejoin requires the exact retained peer identity')
    # Peer identity is a coordinator retention obligation, not a fresh remote
    # liveness proof. The SDK MAP and content verification must still succeed.
    return permit
