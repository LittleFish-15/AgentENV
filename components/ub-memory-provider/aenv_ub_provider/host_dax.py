"""Host FS-DAX stored lowers -> existing OverlayBD read protocol.

Consumes an EXISTING immutable readonly FS-DAX publication. Does not create a
pmem device, turn an OBMM FD into DAX, or attest shared UB physical provenance.
No Guest DAX/KVM mapping and no repository fallback. The platform publication
owner must retain the underlying range until all nodes' consumers have exited.
"""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import signal
import threading

from . import contract, fsdax, stored
from .io import atomic_json


class StoredDaxMapping:
    """Read an immutable stored file via DAX; retain only a wire header in RAM.

    mappingBytes is the legacy broker protocol's logical padded length, NOT
    the DAX extent size, physical allocation, or a measured UB footprint.
    """
    def __init__(self, path, replica):
        replica.validate()
        if replica.allowRepositoryFallback:
            raise ValueError('Host DAX requires repository fallback disabled')
        source = Path(path)
        if not source.is_absolute() or source.resolve(strict=True) != source:
            raise ValueError('Host DAX path must be absolute without redirection')
        self.fd = None
        self.mapping = None
        self.replica = replica
        self.header = replica.header()
        try:
            self.fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
            # Reject ordinary cached files BEFORE mmap, hashing or data reads.
            self.observed = fsdax.validate_fd(self.fd, replica.fileBytes)
            self.mapping = mmap.mmap(self.fd, replica.fileBytes, access=mmap.ACCESS_READ)
            stored.verify_mapping(replica, self)
            fsdax.validate_fd(self.fd, replica.fileBytes)
        except BaseException:
            self.close()
            raise

    def read(self, offset, count):
        if (type(offset) is not int or type(count) is not int or offset < 0
                or count < 0 or count > stored.CHUNK
                or offset > self.replica.mappingBytes
                or count > self.replica.mappingBytes - offset):
            raise ValueError('Read outside bounded stored DAX mapping')
        if self.mapping is None:
            raise RuntimeError('Stored DAX mapping is closed')
        if not count:
            return b''
        end = offset + count
        # Normal broker reads take this branch; no retained payload cache.
        data_end = stored.HEADER_BYTES + self.replica.fileBytes
        if offset >= stored.HEADER_BYTES and end <= data_end:
            return self.mapping[offset - stored.HEADER_BYTES:end - stored.HEADER_BYTES]
        result = bytearray(count)
        header_end = min(end, len(self.header))
        if offset < header_end:
            result[:header_end - offset] = self.header[offset:header_end]
        start, stop = max(offset, stored.HEADER_BYTES), min(end, data_end)
        if start < stop:
            result[start - offset:stop - offset] = self.mapping[
                start - stored.HEADER_BYTES:stop - stored.HEADER_BYTES]
        return bytes(result)

    def close(self):
        if self.mapping is not None:
            self.mapping.close()
            self.mapping = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def open_publication(catalog):
    if (not isinstance(catalog, dict) or set(catalog) != {'version', 'files'}
            or type(catalog['version']) is not int or catalog['version'] != 1
            or not isinstance(catalog['files'], list) or not 1 <= len(catalog['files']) <= 64):
        raise ValueError('Expected Host DAX stored publication version1/files')
    replicas, paths = [], []
    for item in catalog['files']:
        if not isinstance(item, dict) or set(item) != {'path', 'replica'} or not isinstance(item['path'], str):
            raise ValueError('Each stored DAX file requires path and replica')
        replica = stored.Replica(**item['replica']).validate()
        if replica.allowRepositoryFallback:
            raise ValueError('Host DAX publication cannot enable cached fallback')
        replicas.append(replica)
        paths.append(item['path'])
    if (len({r.brokerSocket for r in replicas}) != 1
            or len({r.objectName for r in replicas}) != len(replicas)
            or len({r.layerDigest for r in replicas}) != len(replicas)
            or len(set(paths)) != len(paths)):
        raise ValueError('Publication requires one socket and unique objects/digests/paths')
    mappings = []
    try:
        for path, replica in zip(paths, replicas):
            mappings.append(StoredDaxMapping(path, replica))
        return replicas, mappings
    except BaseException:
        for mapping in mappings:
            mapping.close()
        raise


def close_publication(broker, mappings):
    # stop() refuses active leases and joins workers. Never unmap on that error.
    result = broker.stop()
    for mapping in mappings:
        mapping.close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', required=True)
    parser.add_argument('--runtime-index', required=True)
    args = parser.parse_args()
    contract.linux_only()
    output = Path(args.runtime_index)
    if output.exists() or output.is_symlink():
        raise ValueError('Runtime index exists; preserve prior publication')
    with open(args.catalog, 'rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('Host DAX catalog exceeds 1MiB')
    replicas, mappings = open_publication(json.loads(raw))
    broker = stored.Broker(replicas, mappings)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    try:
        broker.start(replicas[0].brokerSocket)
        atomic_json(output, stored.index_for(replicas))
        print(json.dumps({'state': 'serving', 'source': 'host-fsdax-stored-lowers',
            'files': [m.observed for m in mappings], 'payloadCache': False,
            'repositoryFallback': False, 'GuestDax': False,
            'crossNodePhysicalIdentityAccepted': False,
            'catalogSha256': hashlib.sha256(raw).hexdigest(),
            'externalPublicationMustRemainImmutableAndRetained': True}), flush=True)
        while True:
            stop.wait()
            try:
                result = close_publication(broker, mappings)
                print(json.dumps({'state': 'local-readers-stopped', **result,
                    'sharedBackingReleased': False}), flush=True)
                return
            except RuntimeError as error:
                print(json.dumps({'state': 'busy-preserve-publication', 'reason': str(error)}), flush=True)
                stop.clear()
    finally:
        # On other failures stop first; active clients block unmapping.
        close_publication(broker, mappings)


if __name__ == '__main__':
    main()
