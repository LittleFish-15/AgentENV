"""Bounded UB chunk cache for the stored-layer read path, never a DAX image.

One owner serializes metadata. Readers copy a verified chunk while holding an
explicit pin. A lost response/disconnect never releases a pin. No page-fault
interception or physical-memory saving is inferred from this implementation.
"""
from dataclasses import dataclass
import hashlib
import mmap
import os
from pathlib import Path
import re
import socket
import threading
import time
import uuid

from . import contract, stored

CHUNK = 64 * 1024
MAX_CATALOG = 16 * 1024 * 1024


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def sha(value):
    return isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None


def catalog(value, paths=False):
    if (not isinstance(value, dict) or set(value) != {'version', 'chunkBytes', 'layers'}
            or type(value['version']) is not int or value['version'] != 1
            or type(value['chunkBytes']) is not int or value['chunkBytes'] != CHUNK
            or not isinstance(value['layers'], list) or not 1 <= len(value['layers']) <= 64):
        raise ValueError('Invalid lazy chunk catalog')
    selected, blocks = {}, 0
    for layer in value['layers']:
        fields = {'digest', 'fileBytes', 'chunks'} | ({'path'} if paths else set())
        if (not isinstance(layer, dict) or set(layer) != fields or not sha(layer['digest'])
                or type(layer['fileBytes']) is not int or not 0 < layer['fileBytes'] < 2**63
                or not isinstance(layer['chunks'], list)
                or len(layer['chunks']) != (layer['fileBytes'] + CHUNK - 1) // CHUNK
                or any(not sha(h) for h in layer['chunks']) or layer['digest'] in selected):
            raise ValueError('Invalid or duplicate lazy layer/chunk identity')
        if paths and (not isinstance(layer['path'], str) or not Path(layer['path']).is_absolute()):
            raise ValueError('Lazy source must have an absolute path')
        blocks += len(layer['chunks'])
        if blocks > 200000:
            raise ValueError('Lazy catalog chunk count exceeds bounded metadata limit')
        selected[layer['digest']] = layer
    return selected


def prepare(sources):
    """Explicit offline preprocessing. This reads all inputs; serving does not."""
    layers = []
    for expected, (source, size) in sources.items():
        total, chunks = hashlib.sha256(), []
        with Path(source).open('rb') as stream:
            before = os.fstat(stream.fileno())
            for offset in range(0, size, CHUNK):
                data = stream.read(min(CHUNK, size - offset))
                if len(data) != min(CHUNK, size - offset):
                    raise ValueError('Short source while preparing chunk catalog')
                total.update(data)
                chunks.append(digest(data))
            after = os.fstat(stream.fileno())
            if stream.read(1) or file_identity(before) != file_identity(after):
                raise ValueError('Source changed while preparing chunk catalog')
        if 'sha256:' + total.hexdigest() != expected:
            raise ValueError('Source differs from committed stored layer digest')
        layers.append({'digest': expected, 'fileBytes': size, 'chunks': chunks,
                       'path': str(Path(source).resolve(strict=True))})
    value = {'version': 1, 'chunkBytes': CHUNK, 'layers': layers}
    catalog(value, paths=True)
    if len(contract.canonical(value)) > MAX_CATALOG:
        raise ValueError('Lazy catalog exceeds bounded serialized size')
    return value


def file_identity(meta):
    return meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns


class DirectSources:
    """Linux O_DIRECT range reads avoid populating the source file pagecache.

    The catalog is trusted/pinned before serving. Every requested chunk is
    checked against it. There is no buffered-read fallback.
    """
    def __init__(self, value, root):
        self.layers = catalog(value, paths=True)
        self.files = {}
        root = Path(root).resolve(strict=True)
        try:
            for key, layer in self.layers.items():
                path = Path(layer['path'])
                if path.resolve(strict=True) != path or not path.is_relative_to(root):
                    raise ValueError('Lazy source must be canonical and inside sourceRoot')
                fd = os.open(path, os.O_RDONLY | os.O_DIRECT | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    import stat
                    meta = os.fstat(fd)
                    if not stat.S_ISREG(meta.st_mode) or meta.st_size != layer['fileBytes']:
                        raise ValueError('Lazy source is not the declared regular file')
                    self.files[key] = fd, file_identity(meta)
                except BaseException:
                    os.close(fd)
                    raise
        except BaseException:
            self.close()
            raise

    def read(self, key, block):
        layer = self.layers[key]
        fd, expected = self.files[key]
        offset = block * CHUNK
        count = min(CHUNK, layer['fileBytes'] - offset)
        if not 0 < count <= CHUNK or file_identity(os.fstat(fd)) != expected:
            raise ValueError('Lazy source identity changed or range is invalid')
        # Anonymous mmap supplies a page-aligned temporary I/O buffer, not a
        # mapping of the source file. Last-file reads may return a short tail.
        aligned = (count + 4095) // 4096 * 4096
        with mmap.mmap(-1, aligned) as buffer:
            got = os.preadv(fd, [buffer], offset)
            if got != count or file_identity(os.fstat(fd)) != expected:
                raise ValueError('Short/changed direct source read')
            return buffer[:count]

    def close(self):
        while self.files:
            _, (fd, _) = self.files.popitem()
            os.close(fd)


@dataclass
class Entry:
    slot: int
    state: str = 'loading'
    pins: int = 0
    used: int = 0
    error: str = ''


class Cache:
    def __init__(self, value, mapping, slots, source, cache_id, tokens, journal):
        self.layers = catalog(value)
        if type(slots) is not int or not 4 <= slots <= 65536:
            raise ValueError('UB cache requires 4..65536 bounded chunk slots')
        self.mapping, self.slots, self.source = mapping, slots, source
        self.cache_id, self.tokens, self.journal = cache_id, dict(tokens), journal
        self.condition = threading.Condition()
        self.entries, self.leases, self.released, self.opened = {}, {}, set(), set()
        self.observation = None
        self.clock = self.loading = 0
        self.frozen = self.poisoned = False
        self.stats = {'hits': 0, 'misses': 0, 'waits': 0, 'evictions': 0,
                      'backendBytes': 0, 'fillErrors': 0}

    def save(self):
        try:
            self.journal({'cacheId': self.cache_id, 'pins': dict(self.leases),
                          'releasedReaders': sorted(self.released), 'openedReaders': sorted(self.opened),
                          'frozen': self.frozen,
                          'statistics': dict(self.stats)})
        except BaseException:
            self.poisoned = True
            self.condition.notify_all()
            raise

    def authorized(self, request):
        import hmac
        reader, token = request.get('reader'), request.get('token')
        if (request.get('cacheId') != self.cache_id or not isinstance(reader, str)
                or not isinstance(token, str) or reader not in self.tokens
                or not hmac.compare_digest(token, self.tokens[reader])):
            raise ValueError('Unknown cache generation or reader credential')
        return reader

    def request(self, request):
        reader = self.authorized(request)
        base = {'operation', 'reader', 'token', 'cacheId'}
        operation = request['operation']
        expected = base | ({'digest', 'block'} if operation == 'acquire' else
                           {'lease'} if operation == 'release' else
                           {'snapshot', 'offset'} if operation == 'residency-page' else
                           {'snapshot'} if operation == 'residency-close' else set())
        if set(request) != expected:
            raise ValueError('Unexpected lazy metadata fields')
        if operation == 'acquire':
            return self.acquire(reader, request['digest'], request['block'])
        with self.condition:
            if self.poisoned:
                raise RuntimeError('Cache journal failed; generation must be reconciled')
            if operation == 'open-reader':
                if self.frozen or reader in self.opened or reader in self.released:
                    raise RuntimeError('Reader already admitted or generation is closed; do not start a duplicate importer')
                self.opened.add(reader)
                self.save()
                return {'state': 'reader-opened'}
            if operation == 'release':
                lease = request['lease']
                if not isinstance(lease, str) or lease not in self.leases or self.leases[lease]['reader'] != reader:
                    raise ValueError('Unknown lease or wrong reader')
                record = self.leases.pop(lease)
                self.entries[(record['digest'], record['block'])].pins -= 1
                # Explicit release follows the reader's completed mapping read.
                # The durable journal may conservatively retain this old pin
                # until the next grant, reader release, or freeze checkpoints
                # the complete live set. Every new grant is still persisted
                # before it is sent. Crash recovery must not infer expiry from
                # this stale superset, nor resume this exclusive generation.
                self.condition.notify_all()
                return {'state': 'released'}
            if operation == 'reader-release':
                if reader not in self.opened:
                    raise RuntimeError('Reader was never admitted')
                if any(p['reader'] == reader for p in self.leases.values()):
                    raise RuntimeError('Reader has outstanding or uncertain chunk pins')
                self.released.add(reader)
                self.save()
                return {'state': 'reader-released'}
            if operation == 'residency-open':
                # One bounded diagnostic image, independent of reader leases.
                # Taking or expiring it never pins, evicts or loads payload.
                rows = tuple((key[0], key[1] * CHUNK, self.length(key), entry.slot)
                             for key, entry in sorted(self.entries.items()) if entry.state == 'ready')
                snapshot = uuid.uuid4().hex
                captured = time.monotonic_ns()
                self.observation = (snapshot, reader, captured, rows)
                return {'state': 'residency-snapshot', 'snapshot': snapshot, 'cacheId': self.cache_id,
                        'ownerMonotonicNs': captured, 'ownerUnixNs': time.time_ns(),
                        'entries': len(rows), 'readyBytes': sum(row[2] for row in rows),
                        'poolBytes': self.slots * CHUNK, 'chunkBytes': CHUNK,
                        'scope': 'logical-ready-content-not-physical-increment'}
            if operation in ('residency-page', 'residency-close'):
                observation = self.observation
                if (observation is None or observation[:2] != (request['snapshot'], reader)
                        or time.monotonic_ns() - observation[2] > 60 * 10**9):
                    raise ValueError('Diagnostic snapshot absent, superseded or expired; no payload state changed')
                if operation == 'residency-close':
                    self.observation = None
                    return {'state': 'residency-closed'}
                offset = request['offset']
                rows = observation[3]
                if type(offset) is not int or not 0 <= offset <= len(rows):
                    raise ValueError('Invalid diagnostic page offset')
                end = min(offset + 16, len(rows))
                return {'state': 'residency-page', 'snapshot': observation[0],
                        'offset': offset, 'next': end, 'entries': rows[offset:end], 'done': end == len(rows)}
            if operation == 'status':
                return {'state': 'frozen' if self.frozen else 'serving', **self.stats,
                        'pins': len(self.leases), 'loading': self.loading,
                        'readyBytes': sum(self.length(k) for k, e in self.entries.items() if e.state == 'ready'),
                        'poolBytes': self.slots * CHUNK,
                        'releasedReaders': len(self.released), 'openedReaders': len(self.opened)}
            raise ValueError('Unknown lazy metadata operation')

    def length(self, key):
        return min(CHUNK, self.layers[key[0]]['fileBytes'] - key[1] * CHUNK)

    def acquire(self, reader, layer, block):
        if (not isinstance(layer, str) or layer not in self.layers or type(block) is not int
                or not 0 <= block < len(self.layers[layer]['chunks'])):
            raise ValueError('Unknown layer or out-of-bounds chunk')
        key, deadline = (layer, block), time.monotonic() + 30
        with self.condition:
            while True:
                if self.poisoned or self.frozen or reader in self.released or reader not in self.opened:
                    raise RuntimeError('Cache/reader admission is closed')
                if len(self.leases) + self.loading >= 4096:
                    raise RuntimeError('Outstanding chunk pin limit reached')
                entry = self.entries.get(key)
                if entry is None:
                    used = {e.slot for e in self.entries.values()}
                    free = next((s for s in range(self.slots) if s not in used), None)
                    if free is None:
                        candidates = [(e.used, k) for k, e in self.entries.items()
                                      if e.state != 'loading' and not e.pins]
                        if not candidates:
                            raise RuntimeError('Cache full with pinned/loading chunks; no fallback')
                        _, victim = min(candidates)
                        free = self.entries.pop(victim).slot
                        self.stats['evictions'] += 1
                    entry = self.entries[key] = Entry(free)
                    self.loading += 1
                    self.stats['misses'] += 1
                    break
                if entry.state == 'failed':
                    raise RuntimeError('Chunk fill failed: ' + entry.error)
                if entry.state == 'ready':
                    self.stats['hits'] += 1
                    return self.pin(reader, key, entry)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Waiting for a concurrent chunk fill timed out')
                self.stats['waits'] += 1
                self.condition.wait(remaining)
        try:
            data = self.source(layer, block)
            with self.condition:
                self.stats['backendBytes'] += len(data)
            expected = self.layers[layer]['chunks'][block]
            if len(data) != self.length(key) or digest(data) != expected:
                raise ValueError('Backend chunk differs from pinned chunk catalog')
            self.mapping.write(entry.slot * CHUNK, data)
            if digest(self.mapping.read(entry.slot * CHUNK, len(data))) != expected:
                raise ValueError('UB fill readback differs; chunk never becomes ready')
            with self.condition:
                self.loading -= 1
                entry.state = 'ready'
                result = self.pin(reader, key, entry)
                self.condition.notify_all()
                return result
        except BaseException as error:
            with self.condition:
                if entry.state == 'loading':
                    self.loading -= 1
                    entry.state, entry.error = 'failed', type(error).__name__
                    self.stats['fillErrors'] += 1
                self.condition.notify_all()
            raise

    def pin(self, reader, key, entry):
        if self.frozen or self.poisoned or reader in self.released or reader not in self.opened:
            raise RuntimeError('Cache/reader admission is closed')
        if len(self.leases) >= 4096:
            raise RuntimeError('Outstanding chunk pin limit reached')
        lease = uuid.uuid4().hex + uuid.uuid4().hex
        self.clock += 1
        entry.pins += 1
        entry.used = self.clock
        record = {'reader': reader, 'digest': key[0], 'block': key[1], 'slot': entry.slot}
        self.leases[lease] = record
        self.save()  # Durable pin before the descriptor can reach any reader.
        return {'state': 'ready', 'cacheId': self.cache_id, 'digest': key[0], 'block': key[1],
                'slot': entry.slot, 'bytes': self.length(key),
                'sha256': self.layers[key[0]]['chunks'][key[1]], 'lease': lease}

    def freeze(self):
        with self.condition:
            if self.poisoned or self.leases or self.loading or set(self.tokens) != self.released:
                raise RuntimeError('All readers must explicitly release before pool retirement')
            self.frozen = True
            self.save()


def collect_residency(request):
    """Read one immutable logical-ready snapshot using bounded metadata pages.

    Owner monotonic time belongs to the owner node, not the importing node.
    This is cache content occupancy, not device physical allocation accounting.
    """
    header = request({'operation': 'residency-open'})
    if (not isinstance(header, dict) or header.get('state') != 'residency-snapshot'
            or not isinstance(header.get('snapshot'), str)
            or re.fullmatch(r'[0-9a-f]{32}', header['snapshot']) is None
            or type(header.get('entries')) is not int or not 0 <= header['entries'] <= 65536
            or type(header.get('poolBytes')) is not int or header['poolBytes'] % CHUNK
            or not 4 * CHUNK <= header['poolBytes'] <= 65536 * CHUNK
            or header.get('chunkBytes') != CHUNK
            or type(header.get('readyBytes')) is not int or not 0 <= header['readyBytes'] <= header['poolBytes']
            or type(header.get('ownerMonotonicNs')) is not int or header['ownerMonotonicNs'] <= 0
            or type(header.get('ownerUnixNs')) is not int or header['ownerUnixNs'] <= 0
            or not isinstance(header.get('cacheId'), str)
            or re.fullmatch(r'[0-9a-f]{32}', header['cacheId']) is None
            or header.get('scope') != 'logical-ready-content-not-physical-increment'):
        raise ValueError('Invalid diagnostic residency header')
    rows, seen, slots = [], set(), set()
    try:
        while len(rows) < header['entries']:
            offset = len(rows)
            page = request({'operation': 'residency-page', 'snapshot': header['snapshot'], 'offset': offset})
            end = min(offset + 16, header['entries'])
            if (not isinstance(page, dict) or page.get('state') != 'residency-page'
                    or page.get('snapshot') != header['snapshot'] or type(page.get('offset')) is not int
                    or page['offset'] != offset or type(page.get('next')) is not int or page['next'] != end
                    or page.get('done') is not (end == header['entries'])
                    or not isinstance(page.get('entries'), (list, tuple)) or len(page['entries']) != end - offset):
                raise ValueError('Incomplete or mismatched residency page')
            for row in page['entries']:
                if (not isinstance(row, (list, tuple)) or len(row) != 4 or not sha(row[0])
                        or type(row[1]) is not int or row[1] < 0 or row[1] % CHUNK
                        or type(row[2]) is not int or not 0 < row[2] <= CHUNK
                        or type(row[3]) is not int or not 0 <= row[3] < header['poolBytes'] // CHUNK
                        or (row[0], row[1]) in seen or row[3] in slots):
                    raise ValueError('Invalid, duplicated or aliased ready content range')
                seen.add((row[0], row[1]));slots.add(row[3]);rows.append(list(row))
        if sum(row[2] for row in rows) != header['readyBytes']:
            raise ValueError('Residency content byte accounting differs')
        return dict(header, ranges=rows)
    finally:
        # Only a diagnostic copy is discarded; this never releases read pins.
        request({'operation': 'residency-close', 'snapshot': header['snapshot']})


class Reader:
    def __init__(self, value, mapping, slots, cache_id, reader, token, request, max_concurrent_reads=1):
        self.layers = catalog(value)
        self.mapping, self.slots, self.cache_id = mapping, slots, cache_id
        self.reader, self.token, self.request = reader, token, request
        if type(max_concurrent_reads) is not int or not 1 <= max_concurrent_reads <= 8:
            raise ValueError('Reader concurrency must be an explicit integer in 1..8')
        self.failed = self.closing = self.closed = self.retirement_attempted = False
        self.max_concurrent_reads = max_concurrent_reads
        self.active_reads = self.queued_waits = self.peak_active_reads = 0
        self.lock = threading.Condition()

    def poison(self):
        with self.lock:
            self.failed = True
            self.lock.notify_all()

    def status(self):
        with self.lock:
            return {'maxConcurrentReads': self.max_concurrent_reads, 'activeReads': self.active_reads,
                    'queuedReadWaits': self.queued_waits, 'peakActiveReads': self.peak_active_reads,
                    'readerClosing': self.closing,
                    'readerFailed': self.failed}

    def admit(self):
        with self.lock:
            if self.active_reads >= self.max_concurrent_reads:
                self.queued_waits += 1
            if not self.lock.wait_for(lambda: self.failed or self.closing
                                      or self.active_reads < self.max_concurrent_reads, timeout=30):
                raise RuntimeError('Reader concurrency admission exceeded 30 seconds; no grant requested')
            if self.failed or self.closing:
                raise RuntimeError('Reader admission closed or uncertain; no new grants')
            self.active_reads += 1
            self.peak_active_reads = max(self.peak_active_reads, self.active_reads)

    def depart(self):
        with self.lock:
            self.active_reads -= 1
            self.lock.notify()  # One freed admission slot; failures/closing wake all.

    def rpc(self, operation, **fields):
        with self.lock:
            if self.failed:
                raise RuntimeError('Reader has an uncertain operation; no implicit reconnect/retry')
        try:
            return self.request(dict(operation=operation, reader=self.reader, token=self.token,
                                     cacheId=self.cache_id, **fields))
        except BaseException:
            self.poison()
            raise

    def observe(self, operation, **fields):
        if operation not in ('residency-open', 'residency-page', 'residency-close'):
            raise ValueError('Not a diagnostic operation')
        return self.request(dict(operation=operation, reader=self.reader, token=self.token,
                                 cacheId=self.cache_id, **fields))

    def read(self, key, offset, count):
        if (key not in self.layers or type(offset) is not int or type(count) is not int
                or offset < 0 or not 0 < count <= stored.CHUNK
                or offset + count > self.layers[key]['fileBytes']):
            raise ValueError('Invalid bounded layer read')
        self.admit()
        try:
            result = bytearray()
            while len(result) < count:
                at = offset + len(result)
                block, within = divmod(at, CHUNK)
                grant = self.rpc('acquire', digest=key, block=block)
                size = min(CHUNK, self.layers[key]['fileBytes'] - block * CHUNK)
                expected = {'state', 'cacheId', 'digest', 'block', 'slot', 'bytes', 'sha256', 'lease'}
                if (not isinstance(grant, dict) or set(grant) != expected or grant['state'] != 'ready'
                        or (grant['cacheId'], grant['digest'], grant['block'], grant['bytes'], grant['sha256'])
                        != (self.cache_id, key, block, size, self.layers[key]['chunks'][block])
                        or type(grant['slot']) is not int or not 0 <= grant['slot'] < self.slots
                        or not isinstance(grant['lease'], str) or re.fullmatch(r'[0-9a-f]{64}', grant['lease']) is None):
                    self.poison()
                    raise ValueError('Invalid/stale chunk grant; possible pin preserved')
                try:
                    data = self.mapping.read(grant['slot'] * CHUNK, size)
                    if len(data) != size or digest(data) != grant['sha256']:
                        raise ValueError('Imported UB chunk failed integrity check')
                    take = min(count - len(result), size - within)
                    result.extend(data[within:within + take])
                finally:
                    # Synchronous mapping.read has finished even if it failed.
                    reply = self.rpc('release', lease=grant['lease'])
                    if reply != {'state': 'released'}:
                        self.poison()
                        raise ValueError('Unconfirmed chunk release')
            return bytes(result)
        finally:
            self.depart()

    def quiesce(self):
        """Close read admission before an SDK mapping may be unmapped."""
        with self.lock:
            if self.active_reads:
                raise RuntimeError('Active mapping reads remain; reader retirement refused')
            self.closing = True
            self.lock.notify_all()

    def release(self):
        self.quiesce()
        with self.lock:
            if self.retirement_attempted:
                raise RuntimeError('Reader retirement already begun; no implicit retry')
            self.retirement_attempted = True
        if self.rpc('reader-release') != {'state': 'reader-released'}:
            self.poison()
            raise ValueError('Unconfirmed reader release')
        with self.lock:
            self.closed = True


class LayerView:
    """Adapt the existing broker to verified chunk reads; no payload cache here."""
    def __init__(self, reader, replica):
        self.reader, self.replica = reader, replica

    def read(self, offset, count):
        if offset < stored.HEADER_BYTES:
            raise ValueError('Lazy virtual layer does not expose a stored object header')
        return self.reader.read(self.replica.layerDigest, offset - stored.HEADER_BYTES, count)


def connect(path, request):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(60)
        stream.connect(str(path))
        contract.same_uid(stream)
        contract.send_json(stream, request)
        reply = contract.receive_json(stream)
        if not isinstance(reply, dict) or reply.get('state') == 'error':
            raise RuntimeError('Lazy coordinator refused metadata request')
        return reply


class MetadataServer:
    """Local, same-UID UNIX endpoint; cross-node transport is operator supplied."""
    def __init__(self, callback):
        self.callback, self.stop_event = callback, threading.Event()
        self.workers, self.lock = set(), threading.Lock()
        self.semaphore = threading.BoundedSemaphore(128)

    def start(self, path):
        self.path = Path(path)
        if self.path.exists() or self.path.is_symlink():
            raise ValueError('Coordinator socket already exists')
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(path))
        os.chmod(path, 0o600)
        self.inode = self.path.stat().st_ino
        self.listener.listen(32)
        self.listener.settimeout(0.5)
        def accept():
            while not self.stop_event.is_set():
                try:
                    stream, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not self.semaphore.acquire(False):
                    stream.close()
                    continue
                def serve(client):
                    try:
                        with client:
                            client.settimeout(60)
                            contract.same_uid(client)
                            try:
                                reply = self.callback(contract.receive_json(client))
                            except Exception:
                                reply = {'state': 'error'}
                            # Sending a pin may fail: never undo the durable pin.
                            contract.send_json(client, reply)
                    except (OSError, EOFError):
                        pass
                    finally:
                        with self.lock:
                            self.workers.discard(threading.current_thread())
                        self.semaphore.release()
                worker = threading.Thread(target=serve, args=(stream,), daemon=True)
                with self.lock:
                    self.workers.add(worker)
                worker.start()
        self.thread = threading.Thread(target=accept, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.listener.close()
        self.thread.join(2)
        with self.lock:
            if self.workers:
                raise RuntimeError('Metadata workers still active; do not unmap pool')
        if self.path.exists() and self.path.stat().st_ino == self.inode:
            self.path.unlink()
