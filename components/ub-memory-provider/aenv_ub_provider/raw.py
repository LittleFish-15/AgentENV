"""Offset-zero NC pmem images. Does not claim writable Guest RAM CoW."""
import array
import ctypes
import hashlib
import os
from pathlib import Path
import socket
import threading
import types
import uuid
from . import contract as n
from . import sdk as b

ALIGN = 4 * 1024 * 1024
CHUNK = 1024 * 1024

def shape(spec, name):
    return {'objectName': name, 'mappingBytes': (spec['bytes'] + ALIGN - 1) // ALIGN * ALIGN,
            'identity': {k: spec[k] for k in ('objectId', 'generation', 'sha256', 'bytes')}}



def validate_replica(replica, spec):
    if (set(replica) != {'objectName', 'mappingBytes', 'identity'}
            or not isinstance(replica['objectName'], str)
            or len(replica['objectName']) != 37 or not replica['objectName'].startswith('aenv_')
            or any(c not in '0123456789abcdef' for c in replica['objectName'][5:])
            or replica != shape(spec, replica['objectName'])):
        raise ValueError('Native raw replica identity/layout mismatch')
    return types.SimpleNamespace(**replica)



class NativeRawBackend(b.NativeBackend):
    def __init__(self, library, limit):
        super().__init__(library, limit)
        self.lib.aenv_ub_open_readonly_fds.argtypes = [ctypes.c_int, ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        self.lib.aenv_ub_open_readonly_fds.restype = ctypes.c_int

    def open_segments(self, mapping, size):
        fds = (ctypes.c_int * 32)(*([-1] * 32))
        lengths = (ctypes.c_uint64 * 32)()
        count = ctypes.c_uint32()
        self.call('open_readonly_fds', mapping.handle, size, fds, lengths, 32, ctypes.byref(count))
        try:
            if (not 1 <= count.value <= 32 or any(fds[i] < 0 for i in range(count.value))
                    or any(not lengths[i] or lengths[i] % n.ALIGN for i in range(count.value))
                    or sum(lengths[:count.value]) != size):
                raise ValueError('Native bridge returned incomplete or invalid device segments')
            return [(fds[i], lengths[i]) for i in range(count.value)]
        except BaseException:
            for fd in fds:
                if fd >= 0:
                    os.close(fd)
            raise



def verify_mapping(mapping, spec):
    digest = hashlib.sha256()
    for offset in range(0, spec['bytes'], CHUNK):
        count = min(CHUNK, spec['bytes'] - offset)
        data = mapping.read(offset, count)
        if len(data) != count:
            raise ValueError('Short raw SDK image read')
        digest.update(data)
    if 'sha256:' + digest.hexdigest() != spec['sha256']:
        raise ValueError('Raw UB image SHA256 differs')



class RawImages:
    def __init__(self, backend, journal, total_limit):
        self.backend, self.journal, self.total_limit = backend, journal, total_limit
        self.state = {'format': 'native-raw-v1', 'state': 'prepared', 'objects': [],
                      'physical_increment_measured': False, 'physical_hard_quota': False}
        self.entries = []
        self.readonly_mappings = []
        self.published = False

    def save(self):
        self.journal(self.state)

    def publish(self, entries, logical_budget):
        requested = sum(shape(e['backing'], 'aenv_' + '0' * 32)['mappingBytes'] for e in entries)
        if not entries or len(entries) > 8 or requested > logical_budget:
            raise ValueError('Native raw aligned requests exceed explicit budget')
        n.validate_catalog({'version': 1, 'objects': entries}, entries[0]['backing']['socket'], logical_budget)
        for entry in entries:
            if entry['backing']['bytes'] % n.ALIGN or n.digest_file(entry['path']) != (entry['backing']['sha256'], entry['backing']['bytes']):
                raise ValueError('Native source identity/alignment differs before SDK creation')
        self.backend.initialize()
        coverage = 0
        for entry in entries:
            spec = entry['backing']
            replica = shape(spec, 'aenv_' + uuid.uuid4().hex)
            api = validate_replica(replica, spec)
            if coverage + api.mappingBytes > self.total_limit:
                raise ValueError('Remaining coverage cannot hold even the next logical request')
            record = {'replica': replica, 'allocation_attempted': True,
                      'creation_confirmed': False, 'delete_acknowledged': False}
            self.state['objects'].append(record)
            self.state['state'] = 'intent_before_allocate'
            self.save() # Own object name and intent precede every create.
            self.backend.allocate(api)
            record['creation_confirmed'] = True
            self.save()
            mapped = self.backend.map(api, True)
            coverage += mapped.backing_coverage
            record['backing_coverage_bytes'] = mapped.backing_coverage
            if coverage > self.total_limit:
                raise ValueError('Post-map coverage exceeds inspection budget, not a physical quota')
            digest, offset = hashlib.sha256(), 0
            with Path(entry['path']).open('rb') as source:
                while offset < spec['bytes']:
                    part = source.read(min(CHUNK, spec['bytes'] - offset))
                    if not part:
                        raise ValueError('Native source truncated')
                    mapped.write(offset, part)
                    digest.update(part)
                    offset += len(part)
                if source.read(1):
                    raise ValueError('Native source grew')
            if 'sha256:' + digest.hexdigest() != spec['sha256']:
                raise ValueError('Native source changed before publication')
            verify_mapping(mapped, spec)
            mapped.close()
            readonly = self.backend.map(api, False)
            verify_mapping(readonly, spec)
            self.readonly_mappings.append((spec, readonly))
            fd = self.backend.open_segments(readonly, spec['bytes'])
            self.entries.append((spec, fd))
        self.state['state'] = 'ready'
        self.save()
        self.published = True
        return [item['replica'] for item in self.state['objects']]

    def imports(self, entries, index):
        if not entries:
            raise ValueError('No native import images')
        n.validate_catalog({'version': 1, 'objects': entries}, entries[0]['backing']['socket'],
                           sum(e['backing']['bytes'] for e in entries))
        if any(e['backing']['bytes'] % n.ALIGN for e in entries):
            raise ValueError('Native import image alignment differs')
        if (set(index) != {'format', 'state', 'replicas'} or index['format'] != 'native-raw-v1'
                or index['state'] != 'ready' or len(index['replicas']) != len(entries)):
            raise ValueError('Expected a Ready native raw index, never a stored-layer broker index')
        seen, coverage = set(), 0
        self.backend.initialize()
        self.state['imports'] = []
        for entry, replica in zip(entries, index['replicas']):
            spec = entry['backing']
            api = validate_replica(replica, spec)
            if api.objectName in seen:
                raise ValueError('Repeated native imported object')
            seen.add(api.objectName)
            record = {'replica': replica, 'mapping_attempted': True, 'mapped': False}
            self.state['imports'].append(record)
            self.state['state'] = 'intent_before_import'
            self.save()
            mapped = self.backend.map(api, False) # Import never calls allocate.
            record['mapped'] = True
            record['backing_coverage_bytes'] = mapped.backing_coverage
            self.save()
            coverage += mapped.backing_coverage
            if coverage > self.total_limit:
                raise ValueError('Imported post-map coverage exceeds inspection budget')
            verify_mapping(mapped, spec)
            self.readonly_mappings.append((spec, mapped))
            self.entries.append((spec, self.backend.open_segments(mapped, spec['bytes'])))
        self.state.update(state='ready_import')
        self.save()
        self.published = True

    def cleanup(self, readers_released=False):
        if self.published and not readers_released:
            raise RuntimeError('Published native object requires all local and remote readers stopped')
        post_errors = []
        if self.published:
            for spec, mapped in self.readonly_mappings:
                try:
                    verify_mapping(mapped, spec)
                except Exception as error:
                    post_errors.append(type(error).__name__ + ': ' + str(error))
        while self.entries:
            _, segments = self.entries.pop()
            for fd, _ in segments:
                os.close(fd)
        self.backend.close_maps()
        for record in self.state['objects']:
            if record['creation_confirmed'] and not record['delete_acknowledged']:
                self.backend.deallocate(types.SimpleNamespace(**record['replica']))
                record['delete_acknowledged'] = True
                self.save()
        self.backend.finalize()
        uncertain = any(not r['creation_confirmed'] for r in self.state['objects'])
        self.state['state'] = 'unresolved_create' if uncertain else 'released'
        self.state['finalize_acknowledged'] = True
        self.state['base_post_sha256_verified'] = not post_errors if self.published else None
        self.state['post_verification_errors'] = post_errors
        self.save()
        if uncertain:
            raise RuntimeError('Unknown create preserved; no deletion or new-name retry')
        if post_errors:
            raise ValueError('Native base integrity failed; stopped readers and owned resources were released')



class RawProvider:
    def __init__(self, entries):
        self.objects = {spec['objectId']: (spec, segments) for spec, segments in entries}
        if len(self.objects) != len(entries):
            raise ValueError('Duplicate native object identity')
        self.condition = threading.Condition()
        self.active = 0
        self.connections = set()
        self.retiring = False
        self.listener = None
        self.semaphore = threading.BoundedSemaphore(64)

    def prepare_handoff(self, request):
        if (not isinstance(request, dict)
                or set(request) != {'version', 'operation', 'objectId', 'generation', 'sha256', 'bytes', 'privateCow'}
                or type(request['version']) is not int or request['version'] != 2
                or request['operation'] != 'acquire' or request['privateCow'] is not False):
            raise ValueError('Native pmem provider refuses RAM CoW requests')
        spec, segments = self.objects[request['objectId']]
        if (not 1 <= len(segments) <= 32 or sum(length for _, length in segments) != spec['bytes']
                or any(length <= 0 or length % n.ALIGN for _, length in segments)):
            raise ValueError('Native provider segment coverage differs')
        if any(request[k] != spec[k] for k in ('objectId', 'generation', 'sha256', 'bytes')):
            raise ValueError('Native backing generation/content mismatch')
        return segments, {'version': 2, 'state': 'ready', 'backing': spec,
                          'privateCow': False, 'source': 'ub', 'cacheMode': 'nc',
                          'segmentLengths': [length for _, length in segments]}

    def handle(self, stream):
        acquired = False
        try:
            stream.settimeout(10)
            n.same_uid(stream)
            request = n.receive_json(stream)
            segments, response = self.prepare_handoff(request)
            with self.condition:
                if self.retiring:
                    raise ValueError('Native provider is retiring')
                self.active += 1
                acquired = True
            n.send_json(stream, response)
            if stream.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                      array.array('i', [fd for fd, _ in segments]))]) != 1:
                raise OSError('Short native FD handoff')
            stream.settimeout(None)
            while stream.recv(1):
                pass
        except (Exception, EOFError):
            pass # Closing a rejected handshake never advertises a successful source.
        finally:
            stream.close()
            with self.condition:
                if acquired:
                    self.active -= 1
                self.connections.discard(stream)
                self.condition.notify_all()

    def start(self, path):
        self.path = Path(path)
        metadata = self.path.parent.stat()
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError('Native socket parent must be private and owned')
        if self.path.exists() or self.path.is_symlink():
            raise FileExistsError('Existing native socket preserved')
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self.identity = (self.path.stat().st_dev, self.path.stat().st_ino)
        self.listener.listen(16)
        self.listener.settimeout(0.5)

        def accept():
            while not self.retiring:
                try:
                    stream, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not self.semaphore.acquire(blocking=False):
                    stream.close()
                    continue
                with self.condition:
                    self.connections.add(stream)
                def serve(client):
                    try:
                        self.handle(client)
                    finally:
                        self.semaphore.release()
                threading.Thread(target=serve, args=(stream,), daemon=True).start()
        self.thread = threading.Thread(target=accept, daemon=True)
        self.thread.start()

    def stop(self):
        with self.condition:
            if self.active:
                raise RuntimeError('Native consumer or inherited child leases are still active')
            self.retiring = True
            connections = list(self.connections)
        self.listener.close()
        self.thread.join(2)
        for stream in connections:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        with self.condition:
            if not self.condition.wait_for(lambda: not self.connections, 12):
                raise RuntimeError('Native handshake workers have not stopped')
        now = self.path.stat()
        if (now.st_dev, now.st_ino) == self.identity:
            self.path.unlink()
