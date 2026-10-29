"""Production node-agent assembly: actual aenv reads drive demand acquisition.

Global node grants persist for the lifetime of local chunk views. Hot reads
use only local references and the existing ordinary DAX chunk broker.
"""
from contextlib import contextmanager
from dataclasses import asdict
import copy
import json
import os
from pathlib import Path
import threading
import time
import uuid

from . import stored
from .demand_views import ChunkBrokerView
from .demand_wire import Broker
from .host_dax_demand import require
from .io import atomic_json


class ConcreteChunkViewFactory:
    def __init__(self,node,uid,root,source_manager,supervisor):
        self.node,self.uid,self.root=node,uid,Path(root)
        self.sources,self.supervisor=source_manager,supervisor
        self.root.mkdir(mode=0o700,exist_ok=False)

    def open(self,grant):
        pub=grant['publication'];source=self.sources.attach(pub)
        directory=self.root/pub['generation']
        if not directory.exists():directory.mkdir(mode=0o700)
        params={'publication':pub,'source':source,'brokerSocket':str(directory/'b.sock')}
        status=self.supervisor.call('status',{'generation':pub['generation']})
        if status.get('phase')=='READY':ready=status['ready']
        elif status.get('phase')=='NONE':ready=self.supervisor.call('prepare',params)
        else:raise RuntimeError('Existing root view is not confirmed ready; no replacement mount')
        require(ready['run']==pub['run'] and ready['node']==self.node
                and ready['objectName']==pub['objectName'] and ready['generation']==pub['generation'],
                'Root view reply identity differs')
        return ChunkBrokerView(ready,self.uid)

    def retire(self,grant,view):
        publication=grant['publication']
        view.close()  # Close our lease before asking the child broker to stop.
        root=self.supervisor.call('retire',{'publication':publication})
        disposition=self.sources.retire(publication)
        return {'root':root,**disposition}


class LocalViewRegistry:
    def __init__(self,node,coordinator,factory,root):
        self.node,self.coordinator,self.factory=node,coordinator,factory
        self.root=Path(root);self.root.mkdir(mode=0o700,exist_ok=False)
        self.entries={};self.condition=threading.Condition();self.closed=False

    def _save(self):
        rows=[]
        for key,entry in self.entries.items():
            rows.append({'manifest':key[0],'chunk':key[1],**{k:v for k,v in entry.items() if k!='view'}})
        atomic_json(self.root/'views.json',{'node':self.node,'closed':self.closed,'entries':rows})

    @contextmanager
    def read(self,manifest,chunk,timeout):
        key=(manifest.sha256,chunk.index);deadline=time.monotonic()+timeout
        creator=False
        with self.condition:
            while True:
                require(not self.closed,'Node demand admission closed')
                entry=self.entries.get(key)
                if entry is None:
                    entry={'phase':'ATTACH_INTENT','operation':uuid.uuid4().hex,'users':0}
                    self.entries[key]=entry;self._save();creator=True;break
                if entry['phase']=='READY':entry['users']+=1;break
                require(entry['phase']=='ATTACH_INTENT','Local view unresolved; explicit reconciliation required')
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('Local view acquisition pending; no new operation created')
                self.condition.wait(remaining)
        if creator:
            try:
                grant=self.coordinator.acquire(entry['operation'],manifest.sha256,chunk.index,deadline)
                ticket=grant['ticket'];pub=grant['publication']
                require(ticket['node']==self.node and ticket['manifest']==manifest.sha256
                        and ticket['chunk']==chunk.index and ticket['generation']==pub['generation']
                        and pub['chunkSha256']==chunk.sha256 and pub['payloadBytes']==chunk.length,
                        'Coordinator grant differs from requested immutable block')
                with self.condition:entry['grant']=grant;self._save()
                view=self.factory.open(grant)
                with self.condition:
                    entry.update(phase='READY',view=view,users=1);self._save();self.condition.notify_all()
            except BaseException as error:
                with self.condition:
                    entry.update(phase='UNCERTAIN',reason=str(error));self._save();self.condition.notify_all()
                raise
        try:yield entry['view']
        finally:
            with self.condition:
                entry['users']-=1;self.condition.notify_all()
                # Hot refs need no remote call/fsync: the durable nodeGrant
                # remains pinned until the entire local view retires.

    def drain(self):
        with self.condition:
            self.closed=True;self._save()
            require(all(e['phase'] in ('READY','RELEASED') and not e['users'] for e in self.entries.values()),
                    'Active/unknown local readers prevent drain')
        for entry in self.entries.values():
            if entry['phase']=='RELEASED':continue
            require(entry['phase']=='READY','Unknown retirement cannot be repeated')
            with self.condition:entry['phase']='RETIRE_INTENT';self._save()
            receipt=self.factory.retire(entry['grant'],entry['view'])
            with self.condition:entry.update(phase='LOCAL_RELEASED',receipt=receipt);self._save()
            operation=uuid.uuid4().hex
            with self.condition:entry['releaseOperation']=operation;self._save()
            result=self.coordinator.call('release-node',operation,{'ticket':entry['grant']['ticket'],'receipt':receipt})
            require(result.get('state')=='RELEASED','Global node release acknowledgment missing')
            with self.condition:entry['phase']='RELEASED';self._save()
        self.factory.sources.finalize()
        return {'state':'RELEASED','node':self.node,'views':len(self.entries)}

    def status(self):
        with self.condition:
            return {'closed':self.closed,'views':[{k:v for k,v in e.items() if k!='view'} for e in self.entries.values()]}

    def reconcile_releases(self):
        """Explicit lost-ACK continuation. Never repeats root/SDK retirement."""
        for entry in self.entries.values():
            if entry['phase']!='LOCAL_RELEASED':continue
            operation=entry.get('releaseOperation')
            require(operation,'No durable release operation identity')
            # This metadata call is idempotent at the coordinator. It cannot
            # allocate/map/unmap or deallocate a data object.
            result=self.coordinator.call('release-node',operation,{
                'ticket':entry['grant']['ticket'],'receipt':entry['receipt']})
            require(result.get('state')=='RELEASED','Node release still unconfirmed')
            with self.condition:entry['phase']='RELEASED';self._save()
        return self.status()


class LogicalDemandMapping:
    def __init__(self,layer,manifest,registry):
        layer.validate()
        require(layer.layerDigest==manifest.layer_digest and layer.fileBytes==manifest.file_bytes
                and layer.manifestSha256=='sha256:'+manifest.sha256,'Logical demand layer/manifest differs')
        self.layer,self.manifest,self.registry=layer,manifest,registry
        # Metadata-only construction. No full-file content verification.

    def read_payload(self,offset,count):
        result=bytearray()
        for chunk,relative,size in self.manifest.split(offset,count):
            with self.registry.read(self.manifest,chunk,self.layer.requestTimeoutMs/1000) as view:
                data=view.read(relative,size)
                require(len(data)==size,'Short required demand block read')
                result.extend(data)
        return bytes(result)


class NodeAgent:
    def __init__(self,layers,manifests,registry,index_path,uid,max_payload_responses=4,event=None):
        self.registry,self.index_path=registry,Path(index_path)
        self.layers=layers
        self.event=event
        mappings=[LogicalDemandMapping(l,manifests[l.manifestSha256[7:]],registry) for l in layers]
        require(len({l.brokerSocket for l in layers})==1,'One local demand socket required')
        self.broker=Broker(layers,mappings,uid,max_payload_responses,event)

    def start(self):
        require(not self.index_path.exists() and not self.index_path.is_symlink(),'Existing demand index preserved')
        self.broker.start(self.layers[0].brokerSocket)
        atomic_json(self.index_path,{'version':2,'state':'metadata_ready','mode':'host-dax-demand',
                                    'replicas':[asdict(l) for l in self.layers]})
        return {'state':'metadata_ready','dataObjectsCreated':0,'layers':len(self.layers)}

    def stop(self):
        self.broker.stop()  # Refuses actual still-live aenv layer sessions.
        atomic_json(self.index_path,{'version':2,'state':'retiring','mode':'host-dax-demand',
                                    'replicas':[asdict(l) for l in self.layers]})
        result=self.registry.drain()
        if callable(getattr(self.event,'close',None)):self.event.close()
        atomic_json(self.index_path,{'version':2,'state':'retired','mode':'host-dax-demand',
                                    'replicas':[asdict(l) for l in self.layers]})
        return result

    def status(self):
        # The local framed protocol is bounded to 4096 bytes. Do not send full
        # publication credentials/receipts for every view in a status response.
        with self.registry.condition:
            views=[{'manifest':key[0],'chunk':key[1],'phase':entry['phase'],'users':entry['users']}
                   for key,entry in list(self.registry.entries.items())[:16]]
            result={'closed':self.registry.closed,'totalViews':len(self.registry.entries),'views':views}
        with self.broker.condition:
            result['broker']={'active':self.broker.active,'reads':self.broker.reads,'bytes':self.broker.bytes,
                              'failedReads':self.broker.failed_reads,'activePayloads':self.broker.active_payloads,
                              'peakPayloads':self.broker.peak_payloads}
        if callable(getattr(self.event,'status',None)):result['trace']=self.event.status()
        return result
