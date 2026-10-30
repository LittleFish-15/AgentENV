"""Ordinary-user SDK owner for immutable demand chunk images.

The supplied image_factory must use demand_image/DirectSource and the supplied
view_controller must implement authenticated per-node OBMM/DAX retirement.
No root SDK loading, network transport, module changes or guessed peer exits.
"""
import hashlib
import os
from pathlib import Path
import threading
import types

from . import raw, contract
from .demand_source import DirectSource
from .host_dax_demand import MIB, require


class ReclaimingNativeBackend(raw.NativeRawBackend):
    def deallocate(self, replica):
        # Only an acknowledged deletion restores this object's coverage budget.
        super().deallocate(replica)
        self.coverage_by_object.pop(replica.objectName, None)
        self.mappings = [mapping for mapping in self.mappings if not mapping.closed]


class NativeChunkPublisher:
    """Concrete publish/retire operations, intended behind one coordinator.

    image_factory(manifest, chunk, generation) returns a verified newly built
    image descriptor. view_controller.retire(publication, nodes) returns the
    exact object/generation and releasedNodes after all node views/imports are
    gone. Cache read pins must be zero before retire is invoked.
    """
    def __init__(self, adapter, adapter_sha256, region, root, save, image_factory,
                 view_controller, inspection_limit):
        self.adapter = Path(adapter)
        self.adapter_sha256 = adapter_sha256
        self.region, self.root, self.save = region, Path(root), save
        self.image_factory, self.view_controller = image_factory, view_controller
        self.inspection_limit = inspection_limit
        self.backend = None
        self.records = {}
        self.live = {}
        self.initialize_attempted = False
        self.finalize_attempted = False
        self.finalize_acknowledged = False
        self.lock = threading.RLock()

    def _record(self, name, **values):
        self.records[name].update(values)
        self.save({'version': 1, 'initializeAttempted': self.initialize_attempted,
                   'objects': list(self.records.values()), 'physicalIncrementBytes': None})

    def _initialize(self):
        require(not self.finalize_attempted and not self.finalize_acknowledged,'Owner finalization prevents new publications')
        if self.backend is not None:
            return
        require(not self.initialize_attempted, 'Unconfirmed SDK initialization cannot be retried')
        contract.linux_only()
        require(os.getuid() == os.geteuid() and os.geteuid() != 0, 'SDK owner must be an ordinary user')
        require(self.root.is_absolute() and self.root.resolve(strict=True) == self.root
                and self.root.stat().st_uid == os.geteuid() and not self.root.stat().st_mode & 0o077,
                'Private owned publication root required')
        digest = hashlib.sha256()
        with self.adapter.open('rb') as stream:
            for data in iter(lambda:stream.read(MIB), b''):digest.update(data)
        require(digest.hexdigest() == self.adapter_sha256, 'Pinned SDK adapter differs')
        self.initialize_attempted = True
        self.save({'version': 1, 'initializeAttempted': True, 'objects': list(self.records.values())})
        backend = ReclaimingNativeBackend(self.adapter, self.inspection_limit)
        backend.configure_region(self.region); backend.initialize()
        self.backend = backend

    def publish(self, manifest, chunk, generation, object_name):
        # SDK ownership transitions are serialized; DAX cache hits do not take
        # this lock. In particular two misses cannot race SDK initialization.
        with self.lock:
            return self._publish(manifest, chunk, generation, object_name)

    def _publish(self, manifest, chunk, generation, object_name):
        require(not self.finalize_attempted and not self.finalize_acknowledged,'Owner finalization prevents new publications')
        require(callable(self.image_factory) and callable(getattr(self.view_controller, 'retire', None)),
                'Native image builder and all-node view controller must be configured before allocation')
        require(object_name not in self.records, 'Existing object intent preserved')
        self.records[object_name] = {'objectName': object_name, 'generation': generation,
            'chunkSha256': chunk.sha256, 'phase': 'prepare_image', 'creationConfirmed': False}
        self._record(object_name)
        image = self.image_factory(manifest, chunk, generation)
        require(image['payload']['payloadBytes'] == chunk.length
                and image['payload']['chunkSha256'] == chunk.sha256, 'Chunk image payload identity differs')
        size = image['bytes']
        require(type(size) is int and size > 0 and size % raw.ALIGN == 0
                and size <= self.inspection_limit, 'Chunk image outside SDK budget')
        self._initialize()
        directory = self.root/generation; directory.mkdir(mode=0o700, exist_ok=False)
        source = {'objectId': 'chunk-'+manifest.sha256+'-'+str(chunk.index),
                  'generation': generation, 'sha256': 'sha256:'+image['sha256'],
                  'bytes': size, 'socket': str(directory/'data.sock')}
        contract.validate_spec(source)
        replica = types.SimpleNamespace(**raw.shape(source, object_name))
        self._record(object_name, phase='allocate_intent', image=source)
        self.backend.allocate(replica)
        self._record(object_name, phase='allocated', creationConfirmed=True)
        writable = self.backend.map(replica, True)
        self._record(object_name, phase='fill_intent', coverageBytes=writable.backing_coverage)
        reader = DirectSource(image['path'], size)
        digest = hashlib.sha256()
        try:
            for offset in range(0, size, MIB):
                data = reader.read(offset, min(MIB, size-offset))
                writable.write(offset, data); digest.update(data)
        finally:
            reader.close()
        require(digest.hexdigest() == image['sha256'], 'Chunk image changed during UB fill')
        raw.verify_mapping(writable, source)
        writable.close()
        readonly = self.backend.map(replica, False)
        raw.verify_mapping(readonly, source)
        segments = self.backend.open_segments(readonly, size)
        provider = raw.RawProvider([(source, segments)])
        # Preserve handles even if socket startup fails; never finalize siblings.
        self.live[object_name] = (readonly, segments, provider, replica)
        provider.start(source['socket'])
        self._record(object_name, phase='ready', coverageBytes=readonly.backing_coverage)
        return {'objectName': object_name, 'generation': generation,
                'chunkSha256': chunk.sha256, 'payloadBytes': chunk.length,
                'chargedCoverageBytes': readonly.backing_coverage, 'immutable': True,
                'source': 'obmm-host-fsdax', 'image': source, 'imageReplica': vars(replica),
                'requiresLocalReadonlyObmmSealBeforeFileAccess': True}

    def retire(self, publication, attached_nodes):
        with self.lock:
            return self._retire(publication, attached_nodes)

    def _retire(self, publication, attached_nodes):
        name = publication['objectName']; record = self.records[name]
        require(record['phase'] == 'ready' and record['generation'] == publication['generation'],
                'Publication is not confirmed ready for retirement')
        self._record(name, phase='retire_views_intent')
        receipt = self.view_controller.retire(publication, attached_nodes)
        require(receipt.get('objectName') == name and receipt.get('generation') == record['generation']
                and receipt.get('releasedNodes') == list(attached_nodes),
                'Incomplete per-node view/import retirement')
        readonly, segments, provider, replica = self.live[name]
        provider.stop()  # Refuses live FD leases, even after a bad peer receipt.
        for fd, _ in segments:os.close(fd)
        readonly.close()
        self._record(name, phase='delete_intent')
        self.backend.deallocate(replica)
        self._record(name, phase='deleted', deleteAcknowledged=True)
        del self.live[name]
        return {'objectName': name, 'generation': record['generation'],
                'releasedNodes': list(attached_nodes), 'globalDeleteAcknowledged': True}

    def finalize(self):
        with self.lock:
            self._finalize()

    def _finalize(self):
        if self.finalize_acknowledged:
            return
        require(not self.live and all(r.get('deleteAcknowledged') is True for r in self.records.values()),
                'Live or uncertain chunks prevent SDK finalization')
        if self.backend is not None:
            require(not self.finalize_attempted, 'SDK finalization outcome uncertain; no implicit retry')
            self.finalize_attempted = True
            self.save({'version':1,'initializeAttempted':self.initialize_attempted,
                       'finalizeAttempted':True,'finalizeAcknowledged':False,
                       'objects':list(self.records.values())})
            self.backend.finalize()
            self.finalize_acknowledged = True
            self.save({'version':1,'initializeAttempted':self.initialize_attempted,
                       'finalizeAttempted':True,'finalizeAcknowledged':True,
                       'objects':list(self.records.values())})
            self.backend = None
        else:
            self.finalize_acknowledged = True
            self.save({'version':1,'initializeAttempted':self.initialize_attempted,
                       'finalizeAttempted':False,'finalizeAcknowledged':True,
                       'objects':list(self.records.values())})
