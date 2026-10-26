"""Immutable stored lowers read directly from UB; no pmem/DAX device.

Direct source preflight precedes SDK allocation. No buffered source fallback,
process payload cache, automatic remote release or claim of hardware sealing.
"""
import hashlib
import mmap
import os
from pathlib import Path
import stat
import threading

from . import stored, raw


class NativeBackend(raw.NativeRawBackend):
    """Record the public lookup's segment-to-local-device binding, not raw PAs."""
    def __init__(self, library, inspection_limit):
        super().__init__(library, inspection_limit)
        self.mapping_evidence = []

    def map(self, replica, writable=False):
        mapping = super().map(replica, writable)
        if not writable:
            segments = self.open_segments(mapping, replica.mappingBytes)
            rows, offset = [], 0
            try:
                for fd, length in segments:
                    target = os.readlink('/proc/self/fd/' + str(fd))
                    meta = os.fstat(fd)
                    if not stat.S_ISCHR(meta.st_mode) or not target.startswith('/dev/obmm_shmdev'):
                        raise ValueError('SDK segment is not an OBMM device')
                    rows.append({'logicalOffset': offset, 'bytes': length, 'device': target,
                                 'major': os.major(meta.st_rdev), 'minor': os.minor(meta.st_rdev)})
                    offset += length
            finally:
                for fd, _ in segments:
                    os.close(fd)
            self.mapping_evidence.append({'objectName': replica.objectName,
                'mappingBytes': replica.mappingBytes, 'segments': rows,
                'protection': 'PROT_READ_MAP_SHARED', 'kernelSealed': False})
        return mapping


def file_identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


class DirectFile:
    """Pinned Linux O_DIRECT FD, sequential bounded reads including EOF tail."""
    def __init__(self, path, size):
        path = Path(path)
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('Direct source must have a canonical absolute path')
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECT | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            meta = os.fstat(self.fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_size != size or size <= 0:
                raise ValueError('Direct source type/size differs')
            self.identity = file_identity(meta)
            self.page = os.sysconf('SC_PAGESIZE')
            if self.page not in (4096, 16384, 65536):
                raise ValueError('Unsupported source buffer alignment')
            self.size, self.offset = size, 0
        except BaseException:
            os.close(self.fd)
            raise

    def fileno(self):
        return self.fd

    def check(self):
        if self.fd is None or file_identity(os.fstat(self.fd)) != self.identity:
            raise ValueError('Direct source changed/closed; no fallback')

    def read(self, count):
        self.check()
        if type(count) is not int or not 0 < count <= stored.CHUNK:
            raise ValueError('Direct reads must be explicitly bounded')
        count = min(count, self.size - self.offset)
        if not count:
            return b''
        if self.offset % self.page or (count % self.page and self.offset + count != self.size):
            raise ValueError('Unaligned non-tail direct source read')
        aligned = (count + self.page - 1) // self.page * self.page
        with mmap.mmap(-1, aligned) as buffer:
            got = os.preadv(self.fd, [buffer], self.offset)
            self.check()
            if got != count:
                raise ValueError('Short direct source read; no buffered retry')
            result = buffer[:count]
        self.offset += count
        return result

    def __enter__(self):
        self.check()
        self.offset = 0
        return self

    def __exit__(self, *args):
        # SourceSet owns the FD through preflight and publication.
        return False

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class SourceSet:
    def __init__(self, sources):
        self.files = {}
        try:
            for digest, (path, size) in sources.items():
                if path is None or str(path) in self.files:
                    raise ValueError('Direct publication needs distinct pinned source paths')
                stream = DirectFile(path, size)
                self.files[str(path)] = stream
                observed = hashlib.sha256()
                with stream:
                    while part := stream.read(stored.CHUNK):
                        observed.update(part)
                if 'sha256:' + observed.hexdigest() != digest:
                    raise ValueError('Direct source digest differs before SDK allocation')
        except BaseException:
            self.close()
            raise

    def open(self, path):
        return self.files[str(path)]

    def close(self):
        for stream in self.files.values():
            stream.close()


class Publisher(stored.Publisher):
    def publish(self, sources, socket_path, logical_budget, reuse=(), allow_fallback=False):
        if reuse or allow_fallback:
            raise ValueError('Direct publication requires a fresh generation without fallback')
        self.state['sourceReadMode'] = 'O_DIRECT'
        self.state['kernelSealed'] = False
        selected = SourceSet(sources)  # Every source validated before any SDK call.
        try:
            return super().publish(sources, socket_path, logical_budget,
                                   source_open=selected.open)
        finally:
            selected.close()


class Broker(stored.Broker):
    """At most two live payload responses, including blocked socket sends.

    Limits request payload concurrency, not all allocator/socket/kernel memory.
    Idle VM leases do not consume response admission slots.
    """
    def __init__(self, replicas, mappings, uid=None):
        super().__init__(replicas, mappings, uid)
        self.payload_slots = threading.BoundedSemaphore(2)
        self.payload_active = self.payload_peak = self.payload_failures = 0

    def send_payload(self, stream, mapping, offset, count):
        if not 0 < count <= stored.CHUNK:
            raise ValueError('Direct response exceeds bounded request size')
        if not self.payload_slots.acquire(timeout=30):
            raise TimeoutError('Direct payload admission timeout; no fallback')
        with self.condition:
            self.payload_active += 1
            self.payload_peak = max(self.payload_peak, self.payload_active)
        try:
            data = mapping.read(stored.HEADER_BYTES + offset, count)
            if len(data) != count:
                raise ValueError('Short direct UB read')
            stream.settimeout(30)
            # Separate sends avoid allocating header+payload as another bytes.
            stream.sendall(stored.RESPONSE.pack(stored.MAGIC, 0, count))
            stream.sendall(data)
        except BaseException:
            with self.condition:
                self.payload_failures += 1
            raise
        finally:
            # Do not release admission while this frame still owns the payload.
            data = None
            with self.condition:
                self.payload_active -= 1
            self.payload_slots.release()

    def status(self):
        with self.condition:
            return {'source': 'ub-direct-stored', 'activeLeases': self.active,
                    'reads': self.reads, 'bytes': self.bytes,
                    'activePayloadResponses': self.payload_active,
                    'peakPayloadResponses': self.payload_peak,
                    'payloadFailures': self.payload_failures,
                    'maxPayloadResponses': 2, 'maxReadBytes': stored.CHUNK,
                    'kernelSealed': False, 'physicalSharingAccepted': False}
