"""Actual local aenv demand protocol. Open validates metadata without filling.

Mappings implement read_payload(offset, length). Production maps are supplied
by demand_service; no ordinary-file fallback is selected here.
"""
from dataclasses import dataclass
import json
import socket
import struct
import threading
import time

from . import stored
from .host_dax_demand import require

MAGIC = b'AENVDM1\0'
STABLE_MAGIC = b'AENVDM2\0'
LOAD_BYTES = 256 * 1024
DEVICE_BYTES = 4 * 1024 ** 3
RESPONSE = struct.Struct('>8sIIQ')
READ = struct.Struct('>QQI')


def validate_stable_layout(layout, file_bytes):
    require(isinstance(layout, dict) and set(layout) == {
        'imageSha256', 'logicalBytes', 'imageBytes', 'loadBytes', 'extents'}, 'Invalid stable image layout')
    require(all(type(layout[k]) is int for k in ('logicalBytes', 'imageBytes', 'loadBytes'))
            and layout['logicalBytes'] == DEVICE_BYTES and layout['loadBytes'] == LOAD_BYTES
            and 0 < layout['imageBytes'] <= DEVICE_BYTES, 'Invalid stable device geometry')
    digest = layout['imageSha256']
    require(isinstance(digest, str) and digest.startswith('sha256:') and len(digest) == 71
            and all(c in '0123456789abcdefABCDEF' for c in digest[7:]), 'Invalid stable image digest')
    extents = layout['extents']
    require(isinstance(extents, list) and 0 < len(extents) <= 16384, 'Invalid stable extent count')
    end = 0; ranges = []
    for e in extents:
        require(isinstance(e, dict) and set(e) == {'fileOffset', 'deviceOffset', 'bytes'}
                and all(type(v) is int for v in e.values()), 'Invalid stable extent')
        require(e['fileOffset'] == end and e['bytes'] > 0 and e['deviceOffset'] >= 0
                and e['deviceOffset'] + e['bytes'] <= layout['imageBytes'], 'Stable extent outside image')
        end += e['bytes']; ranges.append((e['deviceOffset'], e['deviceOffset'] + e['bytes']))
    require(end == file_bytes, 'Stable extents do not cover lower')
    ranges.sort()
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), 'Overlapping device extents')


def stable_device_offset(layout, offset, count):
    # The layout is server-owned trusted metadata. Client offsets confer no authority.
    for e in layout['extents']:
        if e['fileOffset'] <= offset < e['fileOffset'] + e['bytes']:
            require(count <= e['fileOffset'] + e['bytes'] - offset, 'Read crosses file extent')
            device = e['deviceOffset'] + offset - e['fileOffset']
            require(count <= LOAD_BYTES - device % LOAD_BYTES, 'Read crosses device load unit')
            return device
    raise ValueError('Unmapped lower file range')


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
    stablePmem: dict | None = None

    def validate(self):
        if self.stablePmem is not None:
            validate_stable_layout(self.stablePmem, self.fileBytes)
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
        self.stable_layouts = {l.objectName: json.loads(json.dumps(l.stablePmem))
                               for l in layers if l.stablePmem is not None}
        self.event = event
        self.failed_reads = 0

    def handle(self, stream):
        acquired = False
        request_id = 0
        in_read = False
        magic = MAGIC
        try:
            stream.settimeout(5)
            if hasattr(socket, 'SO_PEERCRED') and self.uid is not None:
                pid, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                require(uid == self.uid, 'Unexpected demand peer UID')
            else:pid = None
            magic = stored.recv_exact(stream, 8)
            require(magic in (MAGIC, STABLE_MAGIC), 'Demand protocol required')
            length = struct.unpack('>H', stored.recv_exact(stream, 2))[0]
            require(length == 37, 'Invalid demand object length')
            name = stored.recv_exact(stream, length).decode('ascii')
            generation = stored.recv_exact(stream, 16).hex()
            size, logical = struct.unpack('>QQ', stored.recv_exact(stream, 16))
            digest = 'sha256:'+stored.recv_exact(stream, 32).hex()
            manifest = 'sha256:'+stored.recv_exact(stream, 32).hex()
            layer = self.layers[name]
            stable = name in self.stable_layouts
            require(stable == (magic == STABLE_MAGIC), 'Stable and chunk device protocols cannot be mixed')
            require((generation,size,logical,digest,manifest) ==
                    (layer.generation,layer.fileBytes,layer.logicalWireBytes,layer.layerDigest,layer.manifestSha256),
                    'Demand metadata identity differs')
            if stable:
                layout_size = struct.unpack('>I', stored.recv_exact(stream, 4))[0]
                require(0 < layout_size <= 1024 * 1024, 'Stable handshake layout too large')
                offered = json.loads(stored.recv_exact(stream, layout_size))
                validate_stable_layout(offered, size)
                require(offered == self.stable_layouts[name], 'Stable layout differs from trusted server binding')
                require(callable(getattr(self.entries[name][1], 'read_stable_payload', None)),
                        'Stable device mapping is not assembled; no legacy fallback')
            with self.condition:
                require(not self.retiring, 'Demand broker draining')
                self.active += 1; acquired = True
            # No mapping read, SDK call or chunk acquisition at open.
            stream.sendall(RESPONSE.pack(magic, 0, 0, 0))
            expected_id = 1
            mapping = self.entries[name][1]
            while True:
                stream.settimeout(None)
                request_id, offset, count = READ.unpack(stored.recv_exact(stream, READ.size))
                if stable:
                    stream.settimeout(layer.requestTimeoutMs/1000)
                    device = struct.unpack('>Q', stored.recv_exact(stream, 8))[0]
                    require(device == stable_device_offset(self.stable_layouts[name], offset, count),
                            'Client device offset differs from trusted file layout')
                require(request_id == expected_id and 0 < count <= stored.CHUNK
                        and offset <= size and count <= size-offset, 'Invalid demand range/request ID')
                expected_id += 1
                in_read = True
                start = time.monotonic_ns()
                ok = False
                require(self.payload_slots.acquire(timeout=layer.requestTimeoutMs/1000), 'Demand response slots busy')
                with self.condition:
                    self.active_payloads += 1
                    self.peak_payloads = max(self.peak_payloads, self.active_payloads)
                data = None
                try:
                    try:
                        data = (mapping.read_stable_payload(offset, count, device) if stable
                                else mapping.read_payload(offset, count))
                        require(len(data) == count, 'Short demand read; no source fallback')
                        stream.settimeout(layer.requestTimeoutMs/1000)
                        stream.sendall(RESPONSE.pack(magic, 0, len(data), request_id)+data)
                        ok = True
                        in_read = False
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
            # Idle peer EOF is normal; EOF raised by the data path is a failed
            # read and must not disappear from acceptance/accounting counters.
            if in_read:
                with self.condition:self.failed_reads += 1;self.payload_failures += 1
        except Exception:
            with self.condition:self.failed_reads += 1
            try:stream.settimeout(1);stream.sendall(RESPONSE.pack(magic, 1, 0, request_id))
            except OSError:pass
        finally:
            stream.close()
            with self.condition:
                if acquired:self.active -= 1
                self.connections.discard(stream)
                self.condition.notify_all()
