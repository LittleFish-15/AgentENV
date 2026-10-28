"""Actual local aenv demand protocol. Open validates metadata without filling.

Mappings implement read_payload(offset, length). Production maps are supplied
by demand_service; no ordinary-file fallback is selected here.
"""
from dataclasses import dataclass
import socket
import struct
import threading
import time

from . import stored
from .host_dax_demand import require

MAGIC = b'AENVDM1\0'
RESPONSE = struct.Struct('>8sIIQ')
READ = struct.Struct('>QQI')


@dataclass(frozen=True)
class Layer:
    brokerSocket: str
    objectName: str
    generation: str
    layerDigest: str
    fileBytes: int
    logicalWireBytes: int
    manifestSha256: str
    requestTimeoutMs: int = 30000

    def validate(self):
        stored.Replica(self.brokerSocket, self.objectName, self.generation,
                       self.layerDigest, self.fileBytes, self.logicalWireBytes).validate()
        require(isinstance(self.manifestSha256, str) and self.manifestSha256.startswith('sha256:')
                and len(self.manifestSha256) == 71, 'Expected manifest sha256 identity')
        int(self.manifestSha256[7:], 16)
        require(type(self.requestTimeoutMs) is int and 1 <= self.requestTimeoutMs <= 300000,
                'Invalid bounded demand timeout')
        return self


class Broker(stored.Broker):
    def __init__(self, layers, mappings, uid=None, max_payload_responses=4, event=None):
        for layer in layers:layer.validate()
        replicas = [stored.Replica(l.brokerSocket, l.objectName, l.generation,
                                  l.layerDigest, l.fileBytes, l.logicalWireBytes) for l in layers]
        super().__init__(replicas, mappings, uid, max_payload_responses=max_payload_responses)
        self.layers = {l.objectName: l for l in layers}
        self.event = event
        self.failed_reads = 0

    def handle(self, stream):
        acquired = False
        request_id = 0
        try:
            stream.settimeout(5)
            if hasattr(socket, 'SO_PEERCRED') and self.uid is not None:
                pid, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                require(uid == self.uid, 'Unexpected demand peer UID')
            else:pid = None
            require(stored.recv_exact(stream, 8) == MAGIC, 'Demand protocol required')
            length = struct.unpack('>H', stored.recv_exact(stream, 2))[0]
            require(length == 37, 'Invalid demand object length')
            name = stored.recv_exact(stream, length).decode('ascii')
            generation = stored.recv_exact(stream, 16).hex()
            size, logical = struct.unpack('>QQ', stored.recv_exact(stream, 16))
            digest = 'sha256:'+stored.recv_exact(stream, 32).hex()
            manifest = 'sha256:'+stored.recv_exact(stream, 32).hex()
            layer = self.layers[name]
            require((generation,size,logical,digest,manifest) ==
                    (layer.generation,layer.fileBytes,layer.logicalWireBytes,layer.layerDigest,layer.manifestSha256),
                    'Demand metadata identity differs')
            with self.condition:
                require(not self.retiring, 'Demand broker draining')
                self.active += 1; acquired = True
            # No mapping read, SDK call or chunk acquisition at open.
            stream.sendall(RESPONSE.pack(MAGIC, 0, 0, 0))
            expected_id = 1
            mapping = self.entries[name][1]
            while True:
                stream.settimeout(None)
                request_id, offset, count = READ.unpack(stored.recv_exact(stream, READ.size))
                require(request_id == expected_id and 0 < count <= stored.CHUNK
                        and offset <= size and count <= size-offset, 'Invalid demand range/request ID')
                expected_id += 1
                start = time.monotonic_ns()
                ok = False
                require(self.payload_slots.acquire(timeout=layer.requestTimeoutMs/1000), 'Demand response slots busy')
                with self.condition:
                    self.active_payloads += 1
                    self.peak_payloads = max(self.peak_payloads, self.active_payloads)
                data = None
                try:
                    try:
                        data = mapping.read_payload(offset, count)
                        require(len(data) == count, 'Short demand read; no source fallback')
                        stream.settimeout(layer.requestTimeoutMs/1000)
                        stream.sendall(RESPONSE.pack(MAGIC, 0, len(data), request_id)+data)
                        ok = True
                        with self.condition:self.reads += 1;self.bytes += count
                    finally:
                        if self.event:
                            self.event({'kind':'demand_read','peerPid':pid,'requestId':request_id,
                                        'layerDigest':digest,'offset':offset,'requestedBytes':count,
                                        'completedBytes':count if ok else 0,'ok':ok,
                                        'startNs':start,'endNs':time.monotonic_ns()})
                finally:
                    del data
                    with self.condition:self.active_payloads -= 1
                    self.payload_slots.release()
        except EOFError:
            pass
        except Exception:
            with self.condition:self.failed_reads += 1
            try:stream.settimeout(1);stream.sendall(RESPONSE.pack(MAGIC, 1, 0, request_id))
            except OSError:pass
        finally:
            stream.close()
            with self.condition:
                if acquired:self.active -= 1
                self.connections.discard(stream)
                self.condition.notify_all()
