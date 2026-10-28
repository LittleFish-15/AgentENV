"""Linux producer-side immutable chunk-image builder; never allocates UB.

Only newly created private staging files are formatted. Source data is read
through DirectSource; staging costs and file-cache residency are not claimed
to be zero. A completed image is still not a published DAX object.
"""
import hashlib
import os
from pathlib import Path
import stat
import struct
import subprocess

from .demand_source import DirectSource, copy_verified_chunk
from .host_dax_demand import MIB, require


def direct_digest(path, length):
    source = DirectSource(path, length)
    try:
        digest = hashlib.sha256()
        for offset in range(0, length, MIB):
            digest.update(source.read(offset, min(MIB, length-offset)))
        return digest.hexdigest()
    finally:
        source.close()


def build_chunk_image(source, chunk, directory, mke2fs, image_bytes=128*MIB):
    require(hasattr(os, 'posix_fadvise'), 'Native Linux preparation required')
    require(type(image_bytes) is int and image_bytes % (4*MIB) == 0
            and chunk.length+8*MIB <= image_bytes <= 1024*MIB,
            'Image must include explicit metadata room and bounded alignment')
    root = Path(directory)
    require(root.is_absolute() and root.parent.resolve(strict=True) == root.parent
            and not root.exists() and not root.is_symlink(), 'New unredirected private staging directory required')
    parent = root.parent.stat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
            and not parent.st_mode & 0o022, 'Owned non-writable-by-others staging parent required')
    tool = Path(mke2fs).resolve(strict=True)
    info = tool.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'Expected trusted installed mke2fs; never install tools automatically')
    root.mkdir(mode=0o700)
    seed = root/'seed'; seed.mkdir(mode=0o700)
    payload = seed/'payload.bin'
    with payload.open('xb') as stream:
        result = copy_verified_chunk(source, chunk, stream)
        stream.flush(); os.fsync(stream.fileno())
    image = root/'chunk.ext4'
    with image.open('xb') as stream:
        stream.truncate(image_bytes); stream.flush(); os.fsync(stream.fileno())
    args = [str(tool), '-q', '-t', 'ext4', '-F', '-b', '4096', '-m', '0',
            '-O', '^has_journal,^inline_data', '-E', 'lazy_itable_init=0,lazy_journal_init=0',
            '-d', str(seed), str(image)]
    completed = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=300)
    (root/'mke2fs.log').write_bytes(completed.stdout+completed.stderr)
    require(completed.returncode == 0, 'Chunk filesystem preparation failed; preserve staging')
    with image.open('rb') as stream:
        stream.seek(1024); superblock = stream.read(1024)
    require(len(superblock) == 1024 and struct.unpack_from('<H', superblock, 56)[0] == 0xEF53,
            'Invalid prepared ext4 superblock')
    require(struct.unpack_from('<I', superblock, 24)[0] == 2
            and struct.unpack_from('<I', superblock, 4)[0]*4096 == image_bytes
            and struct.unpack_from('<H', superblock, 58)[0] == 1,
            'Prepared ext4 size/block-size/clean-state differs')
    compat = struct.unpack_from('<I', superblock, 92)[0]
    incompat = struct.unpack_from('<I', superblock, 96)[0]
    require(not compat & 0x4 and not incompat & 0x8000, 'Journal/inline-data forbidden for chunk publication')
    for path in (payload, image):
        fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
        try:
            os.fsync(fd)
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
    digest = direct_digest(image, image_bytes)
    return {'path': str(image), 'sha256': digest, 'bytes': image_bytes,
            'payload': result, 'stagingCacheAdviceRequested': True,
            'stagingCacheResidencyBytes': None, 'UBAllocated': False, 'DaxPublished': False}
