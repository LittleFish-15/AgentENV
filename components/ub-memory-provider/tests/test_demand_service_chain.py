"""Real logical mapping/registry/coordinator, mocked SDK and DAX boundaries.

This is L1 service integration, not Guest/UB hardware acceptance.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from aenv_ub_provider.demand_control import Coordinator, proof_mac
from aenv_ub_provider.demand_service import LocalViewRegistry, LogicalDemandMapping
from aenv_ub_provider.demand_wire import Layer
from aenv_ub_provider.host_dax_demand import Manifest, canonical, MIB


class Publisher:
    def __init__(self):self.fills=[];self.deleted=[];self.finalized=False
    def publish(self,manifest,chunk,generation,name):
        self.fills.append(chunk.index)
        return dict(objectName=name,generation=generation,chunkSha256=chunk.sha256,
                    payloadBytes=chunk.length,chargedCoverageBytes=128*MIB,
                    source='obmm-host-fsdax',immutable=True)
    def retire(self,publication,nodes):
        self.view_controller.retire(publication,nodes)
        self.deleted.append(publication['objectName'])
        return dict(objectName=publication['objectName'],generation=publication['generation'],
                    releasedNodes=list(nodes),globalDeleteAcknowledged=True)
    def finalize(self):self.finalized=True


class Client:
    def __init__(self,coordinator,node):self.coordinator=coordinator;self.node=node
    def call(self,method,operation,params=None):
        return self.coordinator.dispatch(self.node,dict(run='a'*32,method=method,operation=operation,params=params or {}))
    def acquire(self,operation,manifest,index,deadline):
        result=self.call('acquire',operation,dict(manifest=manifest,chunk=index))
        if result['state']!='READY':raise RuntimeError(result)
        return result['result']


class View:
    def __init__(self,data):self.data=data
    def read(self,offset,count):return self.data[offset:offset+count]


class Factory:
    def __init__(self,node,data):self.node=node;self.data=data;self.opens=0;self.sources=self
    def open(self,grant):
        self.opens+=1;index=grant['ticket']['chunk']
        return View(self.data[index*4096:(index+1)*4096])
    def retire(self,grant,view):
        pub=grant['publication']
        body=dict(run='a'*32,node=self.node,objectName=pub['objectName'],generation=pub['generation'],
                  localVolumeAbsent=True,workerExited=True)
        return dict(root=dict(body=body,mac=proof_mac(b'k'*32,body)),
                    importDisposition='owner_anchor_retained' if self.node=='a' else 'unmap_acknowledged')
    def finalize(self):pass


class ServiceChainTests(unittest.TestCase):
    def test_overlap_repeat_untouched_and_ordered_release(self):
        data=b'x'*4096+b'y'*4096+b'z'*4096
        digest=hashlib.sha256(data).hexdigest()
        document=dict(version=1,layerDigest='sha256:'+digest,fileBytes=len(data),chunkBytes=4096,
            chunks=[dict(index=i,offset=i*4096,length=4096,sha256=hashlib.sha256(data[i*4096:(i+1)*4096]).hexdigest()) for i in range(3)])
        manifest=Manifest(document,hashlib.sha256(canonical(document)).hexdigest())
        # In-memory journal boundary: this test checks service ownership/order,
        # not filesystem durability or Windows ACL behavior.
        with mock.patch.object(Path,'mkdir'), \
             mock.patch('aenv_ub_provider.demand_control.atomic_json'), \
             mock.patch('aenv_ub_provider.demand_service.atomic_json'):
            root=Path(tempfile.gettempdir())/'unused-demand-chain';publisher=Publisher()
            coordinator=Coordinator('a'*32,{manifest.sha256:manifest},publisher,root/'owner',['a','b'],
                {'a':b'k'*32,'b':b'k'*32},budget_bytes=256*MIB,image_key=b'i'*32,owner_node='a')
            mappings=[];registries=[];factories=[]
            for node in ('a','b'):
                factory=Factory(node,data);factories.append(factory)
                registry=LocalViewRegistry(node,Client(coordinator,node),factory,root/node);registries.append(registry)
                # This is metadata construction only, no SDK or view opening.
                socket_path='C:/d.sock' if os.name=='nt' else '/run/d.sock'
                layer=Layer(socket_path,'aenv_'+'b'*32,'c'*32,'sha256:'+digest,len(data),4*MIB,'sha256:'+manifest.sha256)
                mappings.append(LogicalDemandMapping(layer,manifest,registry))
            self.assertEqual(publisher.fills,[])
            with ThreadPoolExecutor(max_workers=8) as pool:
                values=list(pool.map(lambda index:mappings[index%2].read_payload(0,4096),range(16)))
            self.assertEqual(values,[b'x'*4096]*16)
            self.assertEqual(publisher.fills,[0])
            self.assertEqual([f.opens for f in factories],[1,1])
            self.assertEqual(mappings[1].read_payload(4096,4096),b'y'*4096)
            self.assertEqual(sorted(publisher.fills),[0,1]) # z remains unloaded
            client=Client(coordinator,'a');client.call('close-admission','d'*32)
            with self.assertRaises(ValueError):client.call('finish','e'*32)
            registries[1].drain()
            self.assertEqual(mappings[0].read_payload(0,4096),b'x'*4096)
            self.assertEqual(publisher.deleted,[])
            registries[0].drain();client.call('finish','f'*32)
            self.assertEqual(len(publisher.deleted),2)
            self.assertTrue(publisher.finalized)


if __name__=='__main__':unittest.main()
