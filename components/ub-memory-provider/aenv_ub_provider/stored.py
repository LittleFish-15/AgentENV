"""Stored-layer sharing; broker reads copy data into node-local consumers."""
from dataclasses import dataclass, asdict, replace
import hashlib
import os
from pathlib import Path
import re
import socket
import struct
import threading
import uuid
from .io import atomic_json, read_json

MAGIC = b'AENVUB1\0'
CHUNK = 1024 * 1024
ALIGN = 4 * CHUNK
HEADER_BYTES = 4096
HEADER = struct.Struct('>8s16sQQ32s')
RESPONSE = struct.Struct('>8sII')

@dataclass(frozen=True)
class Replica:
    brokerSocket: str
    objectName: str
    generation: str
    layerDigest: str
    fileBytes: int
    mappingBytes: int
    allowRepositoryFallback: bool = False

    def validate(self):
        if type(self.allowRepositoryFallback) is not bool:
            raise ValueError('Fallback selection must be explicit boolean')
        if re.fullmatch(r'aenv_[0-9a-f]{32}', self.objectName) is None:
            raise ValueError('Invalid UB object namespace')
        if re.fullmatch(r'[0-9a-f]{32}', self.generation) is None:
            raise ValueError('Invalid generation')
        if re.fullmatch(r'sha256:[0-9a-f]{64}', self.layerDigest) is None:
            raise ValueError('Invalid stored layer identity')
        if (type(self.fileBytes) is not int or type(self.mappingBytes) is not int
                or self.fileBytes <= 0 or self.mappingBytes <= 0 or self.mappingBytes >= 2**64
                or self.mappingBytes % ALIGN or self.fileBytes + HEADER_BYTES > self.mappingBytes):
            raise ValueError('Invalid stored/mapping lengths')
        if not Path(self.brokerSocket).is_absolute() or len(os.fsencode(self.brokerSocket)) >= 108:
            raise ValueError('Broker needs an absolute short UNIX socket path')
        return self

    def header(self):
        self.validate()
        return HEADER.pack(MAGIC, bytes.fromhex(self.generation), self.fileBytes,
                           self.mappingBytes, bytes.fromhex(self.layerDigest[7:]))



def load_replicas(path, socket_path=None):
    data = read_json(path)
    if set(data) != {'version', 'state', 'replicas'} or data['version'] != 1 or data['state'] != 'ready':
        raise ValueError('Only a complete ready/version1 replica index is accepted')
    replicas = [Replica(**value).validate() for value in data['replicas']]
    if not replicas or len(replicas) > 64:
        raise ValueError('Replica count must be 1..64')
    if len({r.objectName for r in replicas}) != len(replicas) or len({r.layerDigest for r in replicas}) != len(replicas):
        raise ValueError('Duplicate object or stored layer identity')
    return [replace(r, brokerSocket=str(socket_path)).validate() if socket_path else r for r in replicas]



def index_for(replicas, state='ready'):
    return {'version': 1, 'state': state, 'replicas': [asdict(r) for r in replicas]}



def verify_mapping(replica, mapping):
    if mapping.read(0, HEADER.size) != replica.header():
        raise ValueError('UB object generation, length or stored identity changed')
    digest = hashlib.sha256()
    for offset in range(0, replica.fileBytes, CHUNK):
        part = mapping.read(HEADER_BYTES + offset, min(CHUNK, replica.fileBytes - offset))
        if len(part) != min(CHUNK, replica.fileBytes - offset):
            raise ValueError('Short native mapping read')
        digest.update(part)
    if 'sha256:' + digest.hexdigest() != replica.layerDigest:
        raise ValueError('UB layer content differs from durable stored bytes')



def recv_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise EOFError('Peer disconnected')
        result.extend(part)
    return bytes(result)



class Broker:
    def __init__(self, replicas, mappings, uid=None):
        if len(replicas) != len(mappings) or len({r.objectName for r in replicas}) != len(replicas):
            raise ValueError('One verified mapping is required per unique replica')
        self.entries = {r.objectName: (r, m) for r, m in zip(replicas, mappings)}
        self.uid = os.getuid() if uid is None and hasattr(os, 'getuid') else uid
        self.condition = threading.Condition()
        self.active = 0
        self.retiring = False
        self.reads = self.bytes = 0
        self.connections = set()
        self.semaphore = threading.BoundedSemaphore(128)
        self.listener = None
        self.path_identity = None

    def handle(self, stream):
        acquired = False
        try:
            stream.settimeout(5)
            if hasattr(socket, 'SO_PEERCRED') and self.uid is not None:
                _, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != self.uid:
                    raise ValueError('Unexpected local peer UID')
            if recv_exact(stream, 8) != MAGIC:
                raise ValueError('Invalid protocol magic')
            name_bytes = struct.unpack('>H', recv_exact(stream, 2))[0]
            if name_bytes != 37:
                raise ValueError('Invalid object name length')
            name = recv_exact(stream, name_bytes).decode('ascii')
            generation = recv_exact(stream, 16).hex()
            size, mapping_size = struct.unpack('>QQ', recv_exact(stream, 16))
            digest = 'sha256:' + recv_exact(stream, 32).hex()
            replica, mapping = self.entries[name]
            if (generation, size, mapping_size, digest) != (replica.generation, replica.fileBytes,
                                                           replica.mappingBytes, replica.layerDigest):
                raise ValueError('Replica identity mismatch')
            with self.condition:
                if self.retiring:
                    raise ValueError('Replica is retiring')
                self.active += 1
                acquired = True
            stream.sendall(RESPONSE.pack(MAGIC, 0, 0))
            while True:
                # Idle live VM leases remain valid; only each response has a deadline.
                stream.settimeout(None)
                offset, count = struct.unpack('>QI', recv_exact(stream, 12))
                if not 0 < count <= CHUNK or offset > size or count > size - offset:
                    raise ValueError('Invalid bounded read range')
                self.send_payload(stream, mapping, offset, count)
                with self.condition:
                    self.reads += 1
                    self.bytes += count
        except EOFError:
            pass
        except Exception:
            try:
                stream.settimeout(1)
                stream.sendall(RESPONSE.pack(MAGIC, 1, 0))
            except OSError:
                pass
        finally:
            stream.close()
            with self.condition:
                if acquired:
                    self.active -= 1
                self.connections.discard(stream)
                self.condition.notify_all()

    def send_payload(self, stream, mapping, offset, count):
        data = mapping.read(HEADER_BYTES + offset, count)
        if len(data) != count:
            raise ValueError('Short mapping read')
        stream.settimeout(30)
        stream.sendall(RESPONSE.pack(MAGIC, 0, count) + data)
        # Returning drops payload references before waiting for the next read.

    def start(self, path):
        self.path = Path(path)
        if self.path.exists() or self.path.is_symlink():
            raise ValueError('Socket path exists; do not unlink an unknown/live broker socket')
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        os.chmod(path, 0o600)
        self.path_identity = self.path.stat().st_ino
        self.listener.listen(32)
        self.listener.settimeout(0.5)

        def accept():
            while not self.retiring:
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not self.semaphore.acquire(blocking=False):
                    connection.close()
                    continue
                with self.condition:
                    self.connections.add(connection)

                def serve(client):
                    try:
                        self.handle(client)
                    finally:
                        self.semaphore.release()
                threading.Thread(target=serve, args=(connection,), daemon=True).start()
        self.thread = threading.Thread(target=accept, daemon=True)
        self.thread.start()

    def stop(self):
        with self.condition:
            if self.active:
                raise RuntimeError(f'{self.active} local reader leases still active; leave broker running')
            self.retiring = True
            connections = list(self.connections)
        if self.listener:
            self.listener.close()
            self.thread.join(2)
            if self.thread.is_alive():
                raise RuntimeError('Broker accept thread has not exited; do not unmap')
        for stream in connections:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        with self.condition:
            if not self.condition.wait_for(lambda: not self.connections, timeout=6):
                raise RuntimeError('Handshake/read workers have not exited; do not unmap')
        if self.path_identity is not None and self.path.exists() and self.path.stat().st_ino == self.path_identity:
            self.path.unlink()
        return {'read_requests': self.reads, 'read_bytes': self.bytes, 'active_leases': self.active}



def source_layers(image_paths, reuse=(), source_root=None):
    selected = {}
    previous = {r.layerDigest: r.validate() for r in reuse}
    for image in image_paths:
        image = Path(image).resolve(strict=True)
        config = read_json(image)
        for layer in config.get('lowers', []):
            if layer.get('targetFile') or layer.get('gzipIndex'):
                raise ValueError('Warp/target lower layers are outside the original Rust format support')
            digest, declared_size = layer.get('digest', ''), layer.get('size')
            if digest in previous:
                if declared_size != previous[digest].fileBytes:
                    raise ValueError('Ancestor replica differs from committed stored length')
                selected[digest] = None, declared_size
                continue
            raw = layer.get('file')
            if not raw and layer.get('dir'):
                directory = Path(layer['dir'])
                if not directory.is_absolute():
                    directory = image.parent / directory
                raw = str(directory / 'overlaybd.commit')
                if not Path(raw).exists():
                    raw = str(directory / 'overlaybd.sealed')
            if not raw:
                raise ValueError('Layer needs an existing offline stored file; no automatic registry download')
            source = Path(raw)
            if not source.is_absolute():
                source = image.parent / source
            source = source.resolve(strict=True)
            if not source.is_file() or (source_root is not None and not source.is_relative_to(Path(source_root).resolve(strict=True))):
                raise ValueError('Stored layer must be a regular file under the configured source root')
            size = source.stat().st_size
            digest = layer.get('digest', '')
            if re.fullmatch(r'sha256:[0-9a-f]{64}', digest) is None or size != layer.get('size') or not size:
                raise ValueError('Stored layer identity/length must match the committed layer')
            if digest in selected and selected[digest][1] != size:
                raise ValueError('One durable identity has different lengths')
            selected[digest] = source, size
    if not 1 <= len(selected) <= 64:
        raise ValueError('Publish needs 1..64 unique stored layers')
    return selected



class Publisher:
    def __init__(self, backend, journal):
        self.backend, self.journal = backend, Path(journal)
        self.state = {'version': 1, 'uid': os.getuid() if hasattr(os, 'getuid') else None,
                      'state': 'creating', 'objects': [], 'borrowed': []}
        self.published = False

    def save(self):
        atomic_json(self.journal, self.state)

    def publish(self, sources, socket_path, logical_budget, reuse=(), allow_fallback=False,
                source_open=None):
        if self.journal.exists():
            previous_state = read_json(self.journal)
            previous_objects = previous_state.get('objects', [])
            if (previous_state.get('version') != 1 or previous_state.get('uid') != self.state['uid']
                    or previous_state.get('state') != 'freed' or not previous_state.get('finalize_acknowledged')
                    or any(e.get('allocation_attempted') and not (e.get('creation_confirmed') and e.get('delete_acknowledged'))
                           for e in previous_objects)):
                raise ValueError('Previous publication unresolved; preserve its names and reconcile before new objects')
            atomic_json(self.journal.with_name('owner-history-' + uuid.uuid4().hex + '.json'), previous_state)
        total = sum(((size + HEADER_BYTES + ALIGN - 1) // ALIGN) * ALIGN for _, size in sources.values())
        if total > logical_budget or logical_budget <= 0:
            raise ValueError(f'Rounded logical request {total} exceeds explicit budget {logical_budget}; no allocation')
        previous = {r.layerDigest: r.validate() for r in reuse}
        for digest, (_, size) in sources.items():
            if digest in previous and previous[digest].fileBytes != size:
                raise ValueError('Reused ancestor layer differs from committed length')
        self.state['mapping_bytes_total'] = total
        self.state['new_allocation_bytes'] = sum(((size + HEADER_BYTES + ALIGN - 1) // ALIGN) * ALIGN
                                                 for digest, (_, size) in sources.items() if digest not in previous)
        self.backend.initialize()
        replicas, mappings = [], []
        for digest, (source, size) in sources.items():
            if digest in previous:
                replica = replace(previous[digest], brokerSocket=str(socket_path),
                                  allowRepositoryFallback=allow_fallback).validate()
                readonly = self.backend.map(replica)
                verify_mapping(replica, readonly)
                self.state['borrowed'].append(asdict(replica))
                self.save()
                replicas.append(replica)
                mappings.append(readonly)
                continue
            replica = Replica(str(socket_path), 'aenv_' + uuid.uuid4().hex, uuid.uuid4().hex,
                              digest, size, ((size + HEADER_BYTES + ALIGN - 1) // ALIGN) * ALIGN,
                              allow_fallback).validate()
            entry = {'replica': asdict(replica), 'allocation_attempted': False,
                     'creation_confirmed': False, 'delete_acknowledged': False}
            self.state['objects'].append(entry)
            self.save()
            entry['allocation_attempted'] = True
            self.save()
            self.backend.allocate(replica)
            entry['creation_confirmed'] = True
            self.save()
            writable = self.backend.map(replica, writable=True)
            digest_now = hashlib.sha256()
            with (source_open(source) if source_open else Path(source).open('rb')) as stream:
                before = os.fstat(stream.fileno())
                for offset in range(0, size, CHUNK):
                    part = stream.read(min(CHUNK, size - offset))
                    if len(part) != min(CHUNK, size - offset):
                        raise ValueError('Stored source changed/truncated while publishing')
                    digest_now.update(part)
                    writable.write(HEADER_BYTES + offset, part)
                after = os.fstat(stream.fileno())
                if stream.read(1) or (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                    raise ValueError('Stored source changed while publishing')
            if 'sha256:' + digest_now.hexdigest() != digest:
                raise ValueError('Stored file does not match the committed layer identity')
            # Initialize all exposed object bytes, including the alignment tail.
            for offset in range(HEADER_BYTES + size, replica.mappingBytes, CHUNK):
                writable.write(offset, bytes(min(CHUNK, replica.mappingBytes - offset)))
            writable.write(0, replica.header().ljust(HEADER_BYTES, b'\0'))
            writable.close()
            readonly = self.backend.map(replica)
            verify_mapping(replica, readonly)
            entry['backing_coverage_bytes'] = getattr(readonly, 'backing_coverage', None)
            replicas.append(replica)
            mappings.append(readonly)
            entry['ready'] = True
            self.save()
        self.state['state'] = 'ready'
        self.save()
        self.published = True
        return replicas, mappings

    def cleanup(self):
        self.backend.close_maps()
        for entry in self.state['objects']:
            if entry['creation_confirmed'] and not entry['delete_acknowledged']:
                self.backend.deallocate(Replica(**entry['replica']).validate())
                entry['delete_acknowledged'] = True
                self.save()
        uncertain = any(e['allocation_attempted'] and not e['creation_confirmed'] for e in self.state['objects'])
        self.backend.finalize()
        self.state['finalize_acknowledged'] = True
        self.state['state'] = 'unresolved_create' if uncertain else 'freed'
        self.save()
        if uncertain:
            raise RuntimeError('Creation result uncertain; names retained, no absence claim or new-name retry')
