"""Read-only UB layer broker. Real SDK calls require the separately built bridge.

The catalog stores durable layer identities. This tool manages only disposable
UB replicas; it never opens a VM, changes a service, or downloads dependencies.
"""
import argparse
import ctypes
from dataclasses import dataclass, asdict, replace
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import uuid

MAGIC = b'AENVUB1\0'
CHUNK = 1024 * 1024
ALIGN = 4 * CHUNK
HEADER_BYTES = 4096
HEADER = struct.Struct('>8s16sQQ32s')
RESPONSE = struct.Struct('>8sII')
ROOT = Path('/home/jwk/agent')


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if sys.platform == 'linux':
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_json(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(CHUNK + 1)
    if len(raw) > CHUNK:
        raise ValueError('JSON input exceeds 1MiB')
    return json.loads(raw)


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
        if re.fullmatch(r'jwk_aenv_[0-9a-f]{32}', self.objectName) is None:
            raise ValueError('Invalid experiment object namespace')
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


class SdkError(RuntimeError):
    def __init__(self, operation, rc):
        super().__init__(f'SDK {operation} failed: rc={rc}')
        self.operation, self.rc = operation, rc


class NativeBackend:
    def __init__(self, library, inspection_limit=256 * CHUNK):
        self.lib = ctypes.CDLL(str(library))
        self.mappings = []
        self.inspection_limit = inspection_limit
        self.allocation_calls = 0
        i, q, p = ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p
        declarations = {
            'allocate': [ctypes.c_char_p, q],
            'map': [ctypes.c_char_p, q, i, ctypes.POINTER(i), ctypes.POINTER(q)],
            'read': [i, q, p, q], 'write': [i, q, p, q],
            'unmap': [i], 'deallocate': [ctypes.c_char_p], 'finalize': [],
            'initialize': [],
        }
        for name, args in declarations.items():
            fn = getattr(self.lib, 'aenv_ub_' + name)
            fn.argtypes, fn.restype = args, i

    def call(self, operation, *args):
        rc = getattr(self.lib, 'aenv_ub_' + operation)(*args)
        if operation not in ('read', 'write'):
            print(f'SDK_PHASE={operation} rc={rc}', flush=True)
        if rc:
            raise SdkError(operation, rc)

    def allocate(self, replica):
        self.allocation_calls += 1
        self.call('allocate', replica.objectName.encode(), replica.mappingBytes)

    def initialize(self):
        self.call('initialize')

    def map(self, replica, writable=False):
        handle, coverage = ctypes.c_int(), ctypes.c_uint64()
        rc = self.lib.aenv_ub_map(replica.objectName.encode(), replica.mappingBytes,
                                int(writable), ctypes.byref(handle), ctypes.byref(coverage))
        print(f'SDK_PHASE=map rc={rc} backing_coverage_bytes={coverage.value}', flush=True)
        mapped = None
        if handle.value:
            mapped = NativeMapping(self, handle.value)
            self.mappings.append(mapped)
        if rc:
            raise SdkError('map', rc)
        if mapped is None or not replica.mappingBytes <= coverage.value <= self.inspection_limit:
            raise ValueError('Invalid/post-creation backing coverage exceeds experiment inspection limit')
        mapped.backing_coverage = coverage.value
        return mapped

    def deallocate(self, replica):
        self.call('deallocate', replica.objectName.encode())

    def close_maps(self):
        failures = []
        for mapped in self.mappings:
            try:
                mapped.close()
            except Exception as error:
                failures.append(str(error))
        if failures:
            raise RuntimeError('; '.join(failures))

    def finalize(self):
        self.call('finalize')


class NativeMapping:
    def __init__(self, backend, handle):
        self.backend, self.handle, self.closed = backend, handle, False

    def read(self, offset, count):
        if self.closed or not 0 < count <= CHUNK:
            raise ValueError('Invalid/closed bounded read')
        out = ctypes.create_string_buffer(count)
        self.backend.call('read', self.handle, offset, out, count)
        return out.raw

    def write(self, offset, data):
        if self.closed or not 0 < len(data) <= CHUNK:
            raise ValueError('Invalid/closed bounded write')
        self.backend.call('write', self.handle, offset, ctypes.create_string_buffer(data), len(data))

    def close(self):
        if not self.closed:
            self.backend.call('unmap', self.handle)
            self.closed = True


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
            if name_bytes != 41:
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
                data = mapping.read(HEADER_BYTES + offset, count)
                if len(data) != count:
                    raise ValueError('Short mapping read')
                stream.settimeout(30)
                stream.sendall(RESPONSE.pack(MAGIC, 0, count) + data)
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


def source_layers(image_paths, reuse=()):
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
            if not source.is_file() or not source.is_relative_to(ROOT):
                raise ValueError('Stored layer must be a regular file under the experiment workspace')
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

    def publish(self, sources, socket_path, logical_budget, reuse=(), allow_fallback=False):
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
            replica = Replica(str(socket_path), 'jwk_aenv_' + uuid.uuid4().hex, uuid.uuid4().hex,
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
            with Path(source).open('rb') as stream:
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


def check_local_path(path, exists=False):
    path = Path(path).absolute()
    if not path.is_relative_to(ROOT) or path.resolve(strict=exists) != path:
        raise ValueError('Experiment paths must stay under /home/jwk/agent without redirection')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['build', 'plan', 'publish', 'import', 'cleanup'])
    parser.add_argument('--work-dir', required=True)
    parser.add_argument('--bridge')
    parser.add_argument('--memory-image')
    parser.add_argument('--rootfs-image')
    parser.add_argument('--replicas')
    parser.add_argument('--reuse-index')
    parser.add_argument('--allow-repository-fallback', action='store_true')
    parser.add_argument('--logical-budget-mib', type=int, default=4)
    parser.add_argument('--max-backing-coverage-mib', type=int, default=256)
    parser.add_argument('--peer-stopped', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.getuid() != 1204 or os.geteuid() != 1204 or os.getgid() != 1205:
        raise SystemExit('Run only as original ordinary jwk UID1204/GID1205')
    import fcntl
    caps = [line.split(':')[1].strip() for line in Path('/proc/self/status').read_text().splitlines()
            if line.startswith(('CapInh:', 'CapPrm:', 'CapEff:', 'CapAmb:'))]
    if len(caps) != 4 or any(int(value, 16) for value in caps):
        raise SystemExit('Standalone broker requires zero capabilities')
    os.umask(0o077)
    work = check_local_path(args.work_dir)
    work.mkdir(parents=True, exist_ok=True)
    lock = os.open(work / 'broker.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    metadata = os.fstat(lock)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 1204 or metadata.st_nlink != 1:
        raise SystemExit('Unexpected broker lock identity')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    library = check_local_path(args.bridge, exists=True) if args.bridge else work / 'libaenv_ub_bridge.so'
    if args.action == 'build':
        environment = dict(os.environ, TMPDIR=str(work))
        for key in ('LD_PRELOAD', 'LD_AUDIT', 'CPATH', 'CPLUS_INCLUDE_PATH', 'C_INCLUDE_PATH'):
            environment.pop(key, None)
        subprocess.run(['/usr/bin/g++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-shared', '-fPIC', '-pthread', str(Path(__file__).with_name('bridge.cpp')),
                        '/usr/lib64/libubsm_sdk.so', '-Wl,-rpath,/usr/lib64', '-o', str(library)],
                       check=True, cwd=work, env=environment, timeout=180)
        print('BRIDGE_BUILT_NO_SDK_RUNTIME_CALLS', flush=True)
        return
    if args.action == 'plan':
        images = [check_local_path(p, exists=True) for p in (args.memory_image, args.rootfs_image) if p]
        reuse = load_replicas(check_local_path(args.reuse_index, exists=True)) if args.reuse_index else []
        sources = source_layers(images, reuse)
        previous = {r.layerDigest for r in reuse}
        rows = [{'digest': digest, 'stored_bytes': size,
                 'mapping_bytes': ((size + HEADER_BYTES + ALIGN - 1) // ALIGN) * ALIGN,
                 'borrow_existing_object': digest in previous}
                for digest, (_, size) in sources.items()]
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'UB_LAYER_PLAN_NO_SDK_CALLS', 'layers': rows,
                          'total_mapping_bytes': sum(r['mapping_bytes'] for r in rows),
                          'new_allocation_bytes': sum(r['mapping_bytes'] for r in rows if not r['borrow_existing_object']),
                          'physical_backing_before_creation': 'unknown; logical rounding is not a platform hard quota'}, indent=2))
        print('END_RETURN_REPORT')
        return
    if args.logical_budget_mib <= 0 or args.max_backing_coverage_mib <= 0:
        raise SystemExit('Budgets must be positive; this does not establish a platform quota')
    if args.action in ('publish', 'import'):
        with Path('/sys/bus/ub/ub_feature').open() as stream:
            first_line = stream.readline(513).strip()
        if not int(first_line, 0) & 4:
            raise SystemExit('Current NC shared-memory capability is not advertised; no SDK calls')
    backend = NativeBackend(library, args.max_backing_coverage_mib * CHUNK)
    publisher, broker, replicas = None, None, None
    journal = work / 'owner-receipt.json'
    reader_journal, reader_state = work / 'reader-receipt.json', None
    try:
        if args.action == 'cleanup':
            if not args.peer_stopped:
                raise ValueError('Cleanup requires all reader/VMM processes stopped and --peer-stopped')
            state = read_json(journal)
            if state.get('version') != 1 or state.get('uid') != 1204 or not state.get('objects'):
                raise ValueError('Invalid original owned receipt')
            publisher = Publisher(backend, journal)
            publisher.state = state
            for entry in state['objects']:
                if entry['creation_confirmed'] and not entry['delete_acknowledged']:
                    replica = Replica(**entry['replica']).validate()
                    mapped = backend.map(replica)
                    verify_mapping(replica, mapped)
                    mapped.close()
            publisher.cleanup()
            print('OWNED_REPLICA_CLEANUP_ACKNOWLEDGED')
            return
        if args.action == 'publish':
            images = [check_local_path(p, exists=True) for p in (args.memory_image, args.rootfs_image) if p]
            reuse = load_replicas(check_local_path(args.reuse_index, exists=True)) if args.reuse_index else []
            sources = source_layers(images, reuse)
            publisher = Publisher(backend, journal)
            replicas, mappings = publisher.publish(sources, work / 'broker.sock', args.logical_budget_mib * CHUNK,
                                                    reuse, args.allow_repository_fallback)
        else:
            replicas = load_replicas(check_local_path(args.replicas, exists=True), work / 'broker.sock')
            if sum(r.mappingBytes for r in replicas) > args.logical_budget_mib * CHUNK:
                raise ValueError('Import mapping total exceeds explicit budget')
            if reader_journal.exists():
                previous = read_json(reader_journal)
                if previous.get('uid') != 1204 or previous.get('state') != 'released':
                    raise ValueError('Previous reader release unresolved; preserve its receipt before a second import')
                atomic_json(work / ('reader-history-' + uuid.uuid4().hex + '.json'), previous)
            reader_state = {'version': 1, 'uid': 1204, 'state': 'intent_before_sdk',
                            'replicas': [asdict(r) for r in replicas], 'verified_mappings': 0}
            atomic_json(reader_journal, reader_state)
            backend.initialize()
            mappings = []
            for replica in replicas:
                mapped = backend.map(replica)
                mappings.append(mapped)
                verify_mapping(replica, mapped)
                reader_state['verified_mappings'] += 1
                reader_state['state'] = 'holding_imports'
                atomic_json(reader_journal, reader_state)
        broker = Broker(replicas, mappings)
        broker.start(work / 'broker.sock')
        atomic_json(work / 'replicas.json', index_for(replicas))
        print('UB_LAYER_BROKER_READY', flush=True)
        print('REPLICA_INDEX=' + str(work / 'replicas.json'), flush=True)
        print('Keep this process open. Stop local VMs/readers first; owner must also wait for all remote brokers to exit.', flush=True)
        while True:
            line = input('Type retire only after all required readers have stopped: ').strip()
            if line != 'retire':
                continue
            try:
                statistics = broker.stop()
            except RuntimeError as error:
                print(str(error), flush=True)
                continue
            break
        atomic_json(work / 'replicas.json', index_for(replicas, 'retiring'))
        backend.close_maps()
        if publisher:
            publisher.cleanup()
        else:
            backend.finalize()
            reader_state.update(state='released', finalize_acknowledged=True, mappings_released=True)
            atomic_json(reader_journal, reader_state)
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'UB_LAYER_BROKER_CLEAN_EXIT', 'role': args.action,
                          'statistics': statistics, 'allocation_calls': backend.allocation_calls,
                          'objects': [asdict(r) for r in replicas],
                          'owned_deletions_acknowledged': sum(e['delete_acknowledged'] for e in publisher.state['objects']) if publisher else 0,
                          'independent_global_absence_query': False}, indent=2))
        print('END_RETURN_REPORT')
    except BaseException as error:
        # Never delete published replicas after an interrupt: a remote reader may
        # still use them. Pending evidence is deliberately kept for reconciliation.
        can_release = broker is None
        if broker is not None:
            try:
                broker.stop()
                can_release = True
            except Exception as stop_error:
                print('BROKER_READERS_UNRESOLVED=' + str(stop_error), flush=True)
        if publisher and not publisher.published:
            try:
                publisher.cleanup()
            except Exception as cleanup_error:
                print('CLEANUP_PENDING=' + str(cleanup_error), flush=True)
        elif can_release:
            try:
                backend.close_maps()
                backend.finalize()
                if reader_state is not None:
                    reader_state.update(state='released', finalize_acknowledged=True, mappings_released=True,
                                        test_failed=True)
                    atomic_json(reader_journal, reader_state)
            except Exception as release_error:
                print('IMPORT_RELEASE_PENDING=' + str(release_error), flush=True)
        if reader_state is not None and reader_state.get('state') != 'released':
            reader_state['state'] = 'release_unresolved'
            atomic_json(reader_journal, reader_state)
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'STOPPED_UB_LAYER_BROKER', 'error': str(error),
                          'owner_receipt': str(journal) if publisher else None,
                          'reader_receipt': str(reader_journal) if reader_state is not None else None,
                          'remote_validation_passed': False}, indent=2))
        print('END_RETURN_REPORT')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
