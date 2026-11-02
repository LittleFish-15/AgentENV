"""Actual Python broker wire tests; data backend is a declared test double."""
import os
import json
import socket
import struct
import threading
import unittest

from aenv_ub_provider import demand_wire as wire, stored


class Mapping:
    def __init__(self):self.calls=[];self.fail=False
    def read_payload(self,offset,count):
        self.calls.append((offset,count))
        if self.fail:raise EOFError('Data source disappeared')
        return b'x'*count


class WireTests(unittest.TestCase):
    def setUp(self):
        path='C:/d.sock' if os.name=='nt' else '/run/d.sock'
        self.layer=wire.Layer(path,'aenv_'+'a'*32,'b'*32,'sha256:'+'c'*64,4096,4*1024**2,'sha256:'+'d'*64)
        self.mapping=Mapping();self.broker=wire.Broker([self.layer],[self.mapping])
        self.client,server=socket.socketpair();self.client.settimeout(2)
        self.worker=threading.Thread(target=self.broker.handle,args=(server,));self.worker.start()
        self.client.sendall(wire.MAGIC+struct.pack('>H',37)+self.layer.objectName.encode()+bytes.fromhex(self.layer.generation)
                            +struct.pack('>QQ',4096,4*1024**2)+bytes.fromhex('c'*64)+bytes.fromhex('d'*64))
        self.assertEqual(wire.RESPONSE.unpack(stored.recv_exact(self.client,24)),(wire.MAGIC,0,0,0))

    def tearDown(self):
        self.client.close();self.worker.join(3);self.assertFalse(self.worker.is_alive())

    def test_open_no_reads_and_live_session_blocks_retirement(self):
        self.assertEqual(self.mapping.calls,[])
        self.assertEqual(self.broker.active,1)
        with self.assertRaises(RuntimeError):self.broker.stop()

    def test_read_exact_and_wrong_request_id_is_rejected(self):
        self.client.sendall(wire.READ.pack(1,7,3))
        self.assertEqual(wire.RESPONSE.unpack(stored.recv_exact(self.client,24)),(wire.MAGIC,0,3,1))
        self.assertEqual(stored.recv_exact(self.client,3),b'xxx')
        self.client.sendall(wire.READ.pack(1,7,3))
        self.assertEqual(wire.RESPONSE.unpack(stored.recv_exact(self.client,24)),(wire.MAGIC,1,0,1))
        self.assertEqual(self.mapping.calls,[(7,3)])

    def test_data_eof_is_a_failure_not_normal_peer_disconnect(self):
        self.mapping.fail=True;self.client.sendall(wire.READ.pack(1,0,8))
        self.assertEqual(self.client.recv(1),b'')
        self.worker.join(2)
        self.assertEqual(self.broker.failed_reads,1)
        self.assertEqual(self.broker.payload_failures,1)
        self.assertEqual(self.broker.active_payloads,0)


class StableWireTests(unittest.TestCase):
    def exchange(self, *, bad_layout=False, bad_device=False, legacy_mapping=False):
        layout={'imageSha256':'sha256:'+'e'*64,'logicalBytes':wire.DEVICE_BYTES,
                'imageBytes':wire.LOAD_BYTES*2,'loadBytes':wire.LOAD_BYTES,
                'extents':[{'fileOffset':0,'deviceOffset':wire.LOAD_BYTES-2048,'bytes':4096}]}
        path='C:/d.sock' if os.name=='nt' else '/run/d.sock'
        layer=wire.Layer(path,'aenv_'+'a'*32,'b'*32,'sha256:'+'c'*64,
                         4096,4*1024**2,'sha256:'+'d'*64,stablePmem=layout)
        calls=[]
        class StableMapping:
            def read_stable_payload(self,offset,count,device):
                calls.append((offset,count,device));return b'x'*count
        mapping=Mapping() if legacy_mapping else StableMapping()
        broker=wire.Broker([layer],[mapping])
        client,server=socket.socketpair();client.settimeout(2)
        worker=threading.Thread(target=broker.handle,args=(server,));worker.start()
        try:
            offered=json.loads(json.dumps(layout))
            if bad_layout:offered['extents'][0]['deviceOffset']+=4096
            data=json.dumps(offered).encode()
            client.sendall(wire.STABLE_MAGIC+struct.pack('>H',37)+layer.objectName.encode()
                          +bytes.fromhex(layer.generation)+struct.pack('>QQ',layer.fileBytes,layer.logicalWireBytes)
                          +bytes.fromhex('c'*64)+bytes.fromhex('d'*64)+struct.pack('>I',len(data))+data)
            ack=wire.RESPONSE.unpack(stored.recv_exact(client,24))
            if bad_layout or legacy_mapping:
                self.assertEqual(ack,(wire.STABLE_MAGIC,1,0,0));self.assertEqual(calls,[]);return
            self.assertEqual(ack,(wire.STABLE_MAGIC,0,0,0));self.assertEqual(calls,[])
            device=wire.LOAD_BYTES+(1 if bad_device else 0)
            client.sendall(wire.READ.pack(1,2048,4)+struct.pack('>Q',device))
            ack=wire.RESPONSE.unpack(stored.recv_exact(client,24))
            self.assertEqual(ack,(wire.STABLE_MAGIC,int(bad_device),0 if bad_device else 4,1))
            if bad_device:self.assertEqual(calls,[])
            else:
                self.assertEqual(stored.recv_exact(client,4),b'xxxx')
                self.assertEqual(calls,[(2048,4,wire.LOAD_BYTES)])
        finally:
            client.close();worker.join(3);self.assertFalse(worker.is_alive())

    def test_metadata_open_then_real_mapping_dispatch(self):self.exchange()
    def test_client_cannot_substitute_trusted_image_layout(self):self.exchange(bad_layout=True)
    def test_client_cannot_read_a_different_device_offset(self):self.exchange(bad_device=True)
    def test_stable_protocol_cannot_use_old_chunk_mapping(self):self.exchange(legacy_mapping=True)


if __name__=='__main__':unittest.main()
