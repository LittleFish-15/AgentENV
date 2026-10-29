"""Actual Python broker wire tests; data backend is a declared test double."""
import os
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


if __name__=='__main__':unittest.main()
