"""Bounded immutable source reads for demand publication; Linux O_DIRECT only.

Preparing a manifest scans the source but never allocates UB. Filling a chunk
uses its exact range and verifies its digest; no ordinary buffered fallback.
"""
import hashlib
import mmap
import os
from pathlib import Path
import stat

from .host_dax_demand import MIB, canonical, require


class DirectSource:
    def __init__(self, path, expected_bytes):
        if not hasattr(os, 'O_DIRECT') or not hasattr(os, 'preadv'):
            raise RuntimeError('Native Linux O_DIRECT/preadv required; no buffered fallback')
        source = Path(path)
        require(source.is_absolute() and source.resolve(strict=True) == source, 'Unredirected absolute source required')
        self.fd = os.open(source, os.O_RDONLY | os.O_DIRECT | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_size == expected_bytes and expected_bytes > 0,
                    'Immutable source size/type differs')
            self.identity = self._identity(info)
            self.size = expected_bytes
            self.alignment = max(4096, os.sysconf('SC_PAGE_SIZE'))
            self.direct_bytes = 0
        except BaseException:
            os.close(self.fd); self.fd = None
            raise

    @staticmethod
    def _identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def read(self, offset, count):
        require(self.fd is not None and type(offset) is int and type(count) is int
                and 0 <= offset <= self.size and 0 <= count <= min(MIB, self.size-offset),
                'Invalid bounded direct-source read')
        require(self._identity(os.fstat(self.fd)) == self.identity, 'Source changed before read')
        if not count:
            return b''
        start = offset // self.alignment * self.alignment
        length = ((offset+count-start+self.alignment-1)//self.alignment)*self.alignment
        with mmap.mmap(-1, length) as buffer:
            read = os.preadv(self.fd, [buffer], start)
            require(read == min(length, self.size-start), 'Short direct read; no retry/fallback')
            self.direct_bytes += read
            result = bytes(buffer[offset-start:offset-start+count])
        require(self._identity(os.fstat(self.fd)) == self.identity, 'Source changed during read')
        return result

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None


def build_manifest(source, chunk_bytes=120*MIB, expected_layer_digest=None):
    require(type(chunk_bytes) is int and 4096 <= chunk_bytes <= 120*MIB and chunk_bytes % 4096 == 0,
            'Invalid chunk size')
    require(0 < source.size <= chunk_bytes*65536, 'Source exceeds bounded manifest capacity')
    chunks, whole = [], hashlib.sha256()
    for index, offset in enumerate(range(0, source.size, chunk_bytes)):
        length = min(chunk_bytes, source.size-offset)
        digest = hashlib.sha256()
        for cursor in range(0, length, MIB):
            data = source.read(offset+cursor, min(MIB, length-cursor))
            require(len(data) == min(MIB, length-cursor), 'Short manifest source read')
            digest.update(data); whole.update(data)
        chunks.append({'index': index, 'offset': offset, 'length': length, 'sha256': digest.hexdigest()})
    layer_digest = 'sha256:'+whole.hexdigest()
    require(expected_layer_digest is None or expected_layer_digest == layer_digest, 'Snapshot lower digest differs')
    document = {'version': 1, 'layerDigest': layer_digest, 'fileBytes': source.size,
                'chunkBytes': chunk_bytes, 'chunks': chunks}
    return document, hashlib.sha256(canonical(document)).hexdigest()


def copy_verified_chunk(source, chunk, destination):
    """Copy only a requested chunk to a new producer staging stream.

    Caller owns creation/immutability of destination and must not publish it
    until this succeeds. Staging cache/cost must be measured separately.
    """
    require(destination.tell() == 0, 'Chunk destination must be new and empty')
    require(destination.seek(0, os.SEEK_END) == 0, 'Existing destination content is preserved')
    destination.seek(0)
    digest = hashlib.sha256()
    for cursor in range(0, chunk.length, MIB):
        count = min(MIB, chunk.length-cursor)
        data = source.read(chunk.offset+cursor, count)
        require(len(data) == count, 'Short chunk source read')
        written = destination.write(data)
        require(written == len(data), 'Short chunk staging write')
        digest.update(data)
    require(digest.hexdigest() == chunk.sha256, 'Requested chunk differs from trusted manifest')
    return {'payloadBytes': chunk.length, 'chunkSha256': digest.hexdigest(),
            'UBAllocated': False, 'DaxPublished': False}


def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--bytes', type=int, required=True)
    parser.add_argument('--layer-digest', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--chunk-bytes', type=int, default=120*MIB)
    args = parser.parse_args()
    target = Path(args.output)
    require(target.is_absolute() and target.parent.resolve(strict=True) == target.parent
            and not target.exists() and not target.is_symlink(), 'New manifest output required; never overwrite')
    reader = DirectSource(args.source, args.bytes)
    try:
        document, pin = build_manifest(reader, args.chunk_bytes, args.layer_digest)
    finally:
        reader.close()
    with target.open('x', encoding='utf-8') as stream:
        json.dump(document, stream, sort_keys=True, separators=(',', ':'))
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps({'status': 'DEMAND_MANIFEST_PREPARED_NO_UB', 'manifestSha256': pin,
                      'chunks': len(document['chunks']), 'fileBytes': args.bytes,
                      'SDKCalled': False, 'moduleChanged': False, 'DaxPublished': False}))


if __name__ == '__main__':
    main()
