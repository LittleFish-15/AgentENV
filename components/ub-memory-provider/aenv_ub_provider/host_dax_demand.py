"""Immutable chunk demand cache for the Host OBMM/FS-DAX read path.

No native backend is silently selected. The backend must publish sealed UB
chunk images, return authenticated DAX view FDs, and confirm both-node view
retirement before deleting a global object. This module never falls back to
ordinary files, resets a live generation, or equates capacity with physical
allocation. See docs/host-pmem-demand.md for the deployment contract.
"""
from dataclasses import dataclass
import copy
import hashlib
import json
import os
import re
import threading
import time
from typing import Protocol
import uuid

from . import fsdax, stored

MIB = 1024**2


def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


@dataclass(frozen=True)
class Chunk:
    index: int
    offset: int
    length: int
    sha256: str


class Manifest:
    def __init__(self, document, expected_sha256):
        require(hashlib.sha256(canonical(document)).hexdigest() == expected_sha256,
                'Trusted chunk manifest digest differs')
        require(set(document) == {'version', 'layerDigest', 'fileBytes', 'chunkBytes', 'chunks'}
                and type(document['version']) is int and document['version'] == 1,
                'Unsupported demand manifest')
        require(re.fullmatch(r'sha256:[0-9a-f]{64}', document['layerDigest']) is not None,
                'Invalid immutable layer digest')
        size, chunk_bytes = document['fileBytes'], document['chunkBytes']
        require(type(size) is int and 0 < size < 2**63 and type(chunk_bytes) is int
                and 4096 <= chunk_bytes <= 120*MIB and chunk_bytes % 4096 == 0,
                'Invalid bounded demand chunk size')
        require(isinstance(document['chunks'], list) and 0 < len(document['chunks']) <= 65536,
                'Invalid manifest chunk count')
        chunks, cursor = [], 0
        for i, value in enumerate(document['chunks']):
            require(set(value) == {'index', 'offset', 'length', 'sha256'}, 'Invalid chunk fields')
            require(type(value['index']) is int and value['index'] == i
                    and type(value['offset']) is int and value['offset'] == cursor
                    and type(value['length']) is int and value['length'] == min(chunk_bytes, size-cursor)
                    and value['length'] > 0 and re.fullmatch('[0-9a-f]{64}', value['sha256']) is not None,
                    'Chunk hole, overlap, length or digest mismatch')
            chunks.append(Chunk(**value)); cursor += value['length']
        require(cursor == size, 'Manifest does not cover the immutable layer')
        self.sha256 = expected_sha256
        self.layer_digest, self.file_bytes, self.chunk_bytes = document['layerDigest'], size, chunk_bytes
        self.chunks = tuple(chunks)

    def split(self, offset, length):
        require(type(offset) is int and type(length) is int and offset >= 0 and 0 <= length <= stored.CHUNK
                and offset <= self.file_bytes and length <= self.file_bytes-offset,
                'Read outside bounded immutable file')
        while length:
            chunk = self.chunks[offset // self.chunk_bytes]
            relative = offset - chunk.offset
            count = min(length, chunk.length-relative)
            yield chunk, relative, count
            offset += count; length -= count


@dataclass(frozen=True)
class Ticket:
    manifest: str
    chunk: int
    generation: str
    lease: str
    node: str


class PublicationBackend(Protocol):
    def publish(self, manifest: Manifest, chunk: Chunk, generation: str, object_name: str) -> dict:
        """One attempt. Verify the chunk image and end its writable mapping.

        Required result: objectName, generation, chunkSha256, payloadBytes,
        chargedCoverageBytes, immutable=True, source='obmm-host-fsdax'.
        chargedCoverageBytes is a conservative reservation charge, NOT newly
        allocated physical RAM. READY is a backing publication, not a local
        DAX view: view_factory must obtain the OBMM readonly seal before any
        file access. No unverified object may become READY.
        """

    def retire(self, publication: dict, attached_nodes: tuple[str, ...]) -> dict:
        """Return exact generation/object, releasedNodes, globalDeleteAcknowledged.

        Each node must close all file FDs and retire its mount/OBMM volume and
        SDK import first. The caller never substitutes timeout/death for this.
        """


class CacheFull(RuntimeError):
    pass


class DemandCache:
    """Single publisher; thread-safe same-chunk miss coalescing and durable pins.

    save(snapshot) must atomically persist and fsync before returning. A new
    instance does not adopt old records: explicit recovery is an external gate.
    Budget exhaustion fails closed; eviction is a separate explicit operation.
    """
    def __init__(self, backend: PublicationBackend, save, *, nodes, budget_bytes,
                 reservation_bytes=128*MIB, max_entries=64, prior_state=None):
        require(prior_state is None, 'Existing journal requires explicit cross-node recovery')
        require(nodes and all(isinstance(n,str) and 0<len(n)<=64 for n in nodes)
                and len(set(nodes)) == len(nodes), 'Explicit unique node identities required')
        require(type(reservation_bytes) is int and reservation_bytes > 0
                and type(budget_bytes) is int and budget_bytes >= reservation_bytes
                and type(max_entries) is int and max_entries > 0, 'Invalid demand capacity budget')
        self.backend, self.save = backend, save
        self.nodes = frozenset(nodes)
        self.budget, self.reservation, self.max_entries = budget_bytes, reservation_bytes, max_entries
        self.records = {}
        self.condition = threading.Condition()
        self.poisoned = False
        self.stats = {'misses': 0, 'hits': 0, 'coalescedWaits': 0, 'loadedPayloadBytes': 0,
                      'retirements': 0, 'physicalIncrementBytes': None}

    def _snapshot(self):
        return {'version': 1, 'capacityBudgetBytes': self.budget,
                'chargedBytes': sum(r['charge'] for r in self.records.values()),
                'chargeIsPhysicalIncrement': False, 'physicalHardQuota': False,
                'entries': copy.deepcopy(list(self.records.values())), 'stats': dict(self.stats)}

    def _persist(self):
        try:
            self.save(self._snapshot())
        except BaseException:
            self.poisoned = True
            self.condition.notify_all()
            raise

    def acquire(self, manifest, chunk, node, timeout=30):
        require(node in self.nodes and chunk in manifest.chunks, 'Unknown node or manifest chunk')
        key = (manifest.sha256, chunk.index)
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                if self.poisoned:
                    raise RuntimeError('Journal durability failed; preserve all resources')
                record = self.records.get(key)
                if record is None:
                    charge = sum(r['charge'] for r in self.records.values())
                    if len(self.records) >= self.max_entries or charge+self.reservation > self.budget:
                        raise CacheFull('No capacity; explicitly retire an idle acknowledged chunk first')
                    generation = uuid.uuid4().hex
                    record = {'manifest': manifest.sha256, 'chunk': chunk.index, 'generation': generation,
                              'objectName': 'aenv_'+uuid.uuid4().hex, 'phase': 'FILLING',
                              'charge': self.reservation, 'pins': {}, 'attachedNodes': [],
                              'lastUseNs': time.monotonic_ns()}
                    self.records[key] = record; self.stats['misses'] += 1
                    self._persist()  # Durable unique identity BEFORE an external create.
                    break
                if record['phase'] == 'READY':
                    self.stats['hits'] += 1
                    return self._pin(record, node)
                if record['phase'] != 'FILLING':
                    raise RuntimeError('Chunk outcome/retirement is unresolved; no implicit refill')
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Fill still pending; it is not cancelled or reallocated')
                self.stats['coalescedWaits'] += 1
                self.condition.wait(remaining)
        try:
            published = self.backend.publish(manifest, chunk, record['generation'], record['objectName'])
            required = {'objectName', 'generation', 'chunkSha256', 'payloadBytes',
                        'chargedCoverageBytes', 'immutable', 'source'}
            require(isinstance(published, dict) and required <= set(published), 'Incomplete publication evidence')
            charge = published['chargedCoverageBytes']
            require(type(charge) is int and charge > 0, 'Invalid observed coverage charge')
            with self.condition:
                # Keep even an excessive observed charge; do not hide overshoot.
                record['charge'] = max(record['charge'], charge)
                record['publication'] = copy.deepcopy(published)
            require(published['objectName'] == record['objectName']
                    and published['generation'] == record['generation']
                    and published['chunkSha256'] == chunk.sha256
                    and published['payloadBytes'] == chunk.length
                    and published['immutable'] is True and published['source'] == 'obmm-host-fsdax'
                    and charge <= self.reservation, 'Publication identity, provenance or coverage differs')
        except BaseException as error:
            with self.condition:
                record['phase'] = 'UNCERTAIN'; record['error'] = str(error)
                self._persist(); self.condition.notify_all()
            raise
        with self.condition:
            record['phase'] = 'READY'; self.stats['loadedPayloadBytes'] += chunk.length
            ticket = self._pin(record, node)
            self.condition.notify_all()
            return ticket

    def _pin(self, record, node):
        lease = uuid.uuid4().hex
        record['pins'][lease] = node
        if node not in record['attachedNodes']:
            record['attachedNodes'].append(node)
        record['lastUseNs'] = time.monotonic_ns()
        self._persist()  # Register a possible local view before returning authority.
        return Ticket(record['manifest'], record['chunk'], record['generation'], lease, node)

    def publication(self, ticket):
        with self.condition:
            record = self.records[(ticket.manifest, ticket.chunk)]
            require(record['generation'] == ticket.generation and record['pins'].get(ticket.lease) == ticket.node,
                    'Stale or foreign read ticket')
            return copy.deepcopy(record['publication'])

    def release(self, ticket):
        with self.condition:
            if self.poisoned:
                raise RuntimeError('Journal is uncertain; do not drop the pin')
            record = self.records[(ticket.manifest, ticket.chunk)]
            require(record['generation'] == ticket.generation and record['pins'].get(ticket.lease) == ticket.node,
                    'Unknown/duplicate read release; preserve generation')
            del record['pins'][ticket.lease]
            self._persist()

    def retire_idle(self):
        with self.condition:
            if self.poisoned:
                raise RuntimeError('Journal uncertain; no eviction')
            candidates = [(key, r) for key, r in self.records.items() if r['phase']=='READY' and not r['pins']]
            if not candidates:
                raise CacheFull('All chunks pinned, filling or uncertain; no forced eviction')
            key, record = min(candidates, key=lambda item:item[1]['lastUseNs'])
            record['phase'] = 'RETIRING'; self._persist()
            nodes = tuple(sorted(record['attachedNodes']))
            publication = copy.deepcopy(record['publication'])
        try:
            receipt = self.backend.retire(publication, nodes)
            require(receipt.get('objectName') == record['objectName']
                    and receipt.get('generation') == record['generation']
                    and receipt.get('releasedNodes') == list(nodes)
                    and receipt.get('globalDeleteAcknowledged') is True,
                    'Missing exact all-node view/import/global deletion receipt')
        except BaseException as error:
            with self.condition:
                record['phase'] = 'UNCERTAIN'; record['error'] = str(error)
                self._persist(); self.condition.notify_all()
            raise
        with self.condition:
            del self.records[key]; self.stats['retirements'] += 1
            self._persist(); self.condition.notify_all()
        return receipt

    def snapshot(self):
        with self.condition:
            return self._snapshot()


class DemandDaxMapping:
    """Existing stored-layer wire interface backed by demand-acquired DAX FDs.

    view_factory(publication, node) returns a retained view with fd, device and
    close(). It must verify the OBMM volume/shared-source binding, not just a
    matching hash. close() closes the file and obtains local retirement proof.
    Idle views are retained in this object until explicit drop_view/close;
    coordinator retirement must call every attached node before global delete.
    """
    def __init__(self, replica, manifest, cache, node, view_factory):
        replica.validate()
        require(not replica.allowRepositoryFallback and replica.layerDigest == manifest.layer_digest
                and replica.fileBytes == manifest.file_bytes, 'Demand replica/manifest mismatch or fallback enabled')
        self.replica, self.manifest, self.cache, self.node = replica, manifest, cache, node
        self.view_factory = view_factory
        self.header = replica.header()
        self.lock = threading.RLock()
        self.views = {}
        self.failed_tickets = {}
        self.closed = False
        # Deliberately no verify_mapping(): it would read the entire lower.

    def _view(self, ticket, chunk):
        with self.lock:
            require(not self.closed, 'Demand mapping closed')
            key = (ticket.chunk, ticket.generation)
            if key not in self.views:
                publication = self.cache.publication(ticket)
                view = self.view_factory(publication, self.node)
                try:
                    observed = fsdax.validate_fd(view.fd, chunk.length)
                    require(observed['device'] == view.device, 'DAX file does not belong to the bound OBMM view')
                    digest = hashlib.sha256()
                    for offset in range(0, chunk.length, stored.CHUNK):
                        size = min(stored.CHUNK, chunk.length-offset)
                        data = os.pread(view.fd, size, offset)
                        require(len(data) == size, 'Short DAX chunk verification')
                        digest.update(data)
                    require(digest.hexdigest() == chunk.sha256, 'DAX chunk content differs')
                except BaseException:
                    # Unknown close leaves the caller's durable ticket pinned.
                    view.close()
                    raise
                self.views[key] = {'view': view, 'users': 0}
            item = self.views[key]; item['users'] += 1
            return key, item['view']

    def read_payload(self, offset, length):
        result = bytearray()
        for chunk, relative, count in self.manifest.split(offset, length):
            ticket = self.cache.acquire(self.manifest, chunk, self.node)
            key = None
            try:
                key, view = self._view(ticket, chunk)
                fsdax.validate_fd(view.fd, chunk.length)
                data = os.pread(view.fd, count, relative)
                require(len(data) == count, 'Short DAX demand read; no local-file fallback')
                result.extend(data)
            except BaseException:
                # Retain the global ticket on any unresolved local read/close.
                with self.lock:
                    self.failed_tickets[ticket.lease] = ticket
                raise
            finally:
                if key is not None:
                    with self.lock:
                        self.views[key]['users'] -= 1
            # Local read references are gone BEFORE a global pin is released.
            # A racing eviction can now request a local view close safely.
            try:
                self.cache.release(ticket)
            except BaseException:
                with self.lock:
                    self.failed_tickets[ticket.lease] = ticket
                raise
        return bytes(result)

    def read(self, offset, length):
        require(type(offset) is int and type(length) is int and offset >= 0 and 0 <= length <= stored.CHUNK
                and offset <= self.replica.mappingBytes and length <= self.replica.mappingBytes-offset,
                'Invalid stored demand range')
        require(not self.closed, 'Demand mapping closed')
        end = offset+length
        result = bytearray(length)
        header_end = min(end, len(self.header))
        if offset < header_end:
            result[:header_end-offset] = self.header[offset:header_end]
        start, stop = max(offset, stored.HEADER_BYTES), min(end, stored.HEADER_BYTES+self.manifest.file_bytes)
        if start < stop:
            result[start-offset:stop-offset] = self.read_payload(start-stored.HEADER_BYTES, stop-start)
        return bytes(result)

    def drop_view(self, chunk_index, generation):
        with self.lock:
            key = (chunk_index, generation)
            item = self.views.get(key)
            if item is None:
                return
            require(item['users'] == 0, 'Local DAX read is active; no forced close')
            item['view'].close()
            del self.views[key]

    def close(self):
        with self.lock:
            require(all(not v['users'] for v in self.views.values()), 'Local readers still active')
            require(not self.failed_tickets, 'Failed read tickets require explicit reconciliation')
            for key in list(self.views):
                self.drop_view(*key)
            self.closed = True
