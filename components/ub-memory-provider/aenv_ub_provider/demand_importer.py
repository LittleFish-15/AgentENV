"""One ordinary SDK importer session per B node; never allocates objects."""
import hashlib
import os
from pathlib import Path
import threading

from . import contract, raw
from .demand_native import ReclaimingNativeBackend
from .host_dax_demand import MIB, require


class Importer:
    def __init__(self,adapter,adapter_sha256,region,root,save,inspection_limit):
        self.adapter,self.adapter_sha256=Path(adapter),adapter_sha256
        self.region,self.root,self.save=region,Path(root),save
        self.inspection_limit=inspection_limit
        self.backend=None;self.initialized_attempt=False;self.records={};self.live={}
        self.lock=threading.RLock()
        self.finalize_attempt=False;self.finalize_ack=False

    def persist(self):
        self.save({'version':1,'initializeAttempted':self.initialized_attempt,
                   'finalizeAttempted':self.finalize_attempt,'finalizeAcknowledged':self.finalize_ack,
                   'objects':list(self.records.values()),'allocationCalls':0})

    def initialize(self):
        if self.backend is not None:return
        require(not self.initialized_attempt,'Unconfirmed importer initialization; no retry')
        contract.linux_only()
        require(os.getuid()==os.geteuid()!=0,'Ordinary SDK importer required')
        digest=hashlib.sha256()
        with self.adapter.open('rb') as f:
            for data in iter(lambda:f.read(MIB),b''):digest.update(data)
        require(digest.hexdigest()==self.adapter_sha256,'Pinned importer adapter differs')
        self.initialized_attempt=True;self.persist()
        backend=ReclaimingNativeBackend(self.adapter,self.inspection_limit)
        backend.configure_region(self.region);backend.initialize();self.backend=backend

    def attach(self,publication):
        with self.lock:
            name=publication['objectName'];generation=publication['generation']
            if name in self.records:
                record=self.records[name]
                require(record['generation']==generation and record['phase']=='READY','Old/unknown import preserved')
                return dict(record['source'])
            source=dict(publication['image'])
            replica=raw.validate_replica(publication['imageReplica'],source)
            self.records[name]={'objectName':name,'generation':generation,'phase':'INITIALIZING'};self.persist()
            self.initialize()
            directory=self.root/generation;directory.mkdir(mode=0o700,exist_ok=False)
            source['socket']=str(directory/'data.sock');contract.validate_spec(source)
            record=self.records[name];record.update(phase='IMPORT_INTENT',source=source);self.persist()
            mapping=self.backend.map(replica,False)
            record.update(phase='MAPPED',coverageBytes=mapping.backing_coverage);self.persist()
            raw.verify_mapping(mapping,source)
            segments=self.backend.open_segments(mapping,source['bytes'])
            provider=raw.RawProvider([(source,segments)])
            self.live[name]=(mapping,segments,provider)
            provider.start(source['socket'])
            record['phase']='READY';self.persist()
            return source

    def retire(self,publication):
        with self.lock:
            name=publication['objectName'];record=self.records[name]
            require(record['generation']==publication['generation'],'Import generation differs')
            if record['phase']=='RELEASED':return {'importDisposition':'unmap_acknowledged'}
            require(record['phase']=='READY','Import outcome uncertain; no unmap retry')
            mapping,segments,provider=self.live[name]
            provider.stop()  # Kernel/FD consumers must have retired first.
            record['phase']='UNMAP_INTENT';self.persist()
            for fd,_ in segments:os.close(fd)
            mapping.close()
            self.backend.coverage_by_object.pop(name,None)
            self.backend.mappings=[m for m in self.backend.mappings if not m.closed]
            record['phase']='RELEASED';del self.live[name];self.persist()
            return {'importDisposition':'unmap_acknowledged'}

    def finalize(self):
        with self.lock:
            require(not self.live and all(r['phase']=='RELEASED' for r in self.records.values()),
                    'Importer still has live or unconfirmed objects')
            if self.finalize_ack:return
            require(not self.finalize_attempt,'Unknown finalize cannot be retried')
            if self.backend is not None:
                self.finalize_attempt=True;self.persist();self.backend.finalize()
            self.finalize_ack=True;self.persist()


class OwnerSources:
    """A reuses the publisher's existing readonly FD provider, without re-import."""
    def attach(self,publication):return dict(publication['image'])
    def retire(self,publication):return {'importDisposition':'owner_anchor_retained'}
    def finalize(self):return None
