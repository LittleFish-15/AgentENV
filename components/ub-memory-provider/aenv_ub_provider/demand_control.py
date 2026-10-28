"""Authenticated control-only transport for one immutable demand run.

No payload data crosses this channel. A client sends create authority once,
then queries the same operation ID after a lost response. Never expires a pin.
"""
from dataclasses import asdict
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
from pathlib import Path
import ssl
import threading
import time
from urllib.parse import urlsplit

from .host_dax_demand import DemandCache, Ticket, canonical, require
from .io import atomic_json

MAX_MESSAGE = 1024 * 1024


def proof_mac(key, value):
    return hmac.new(key, canonical(value), hashlib.sha256).hexdigest()


class RetirementEvidence:
    def __init__(self, run, keys, owner_node='node-a'):
        self.run, self.keys, self.receipts = run, keys, {}
        self.owner_node=owner_node
        self.lock = threading.Lock()

    def accept(self, node, publication, receipt):
        root = receipt['root']; body = root['body']
        require(node in self.keys and hmac.compare_digest(root['mac'], proof_mac(self.keys[node], body)),
                'Root retirement receipt MAC differs')
        require(body['run'] == self.run and body['node'] == node
                and body['objectName'] == publication['objectName']
                and body['generation'] == publication['generation']
                and body.get('localVolumeAbsent') is True and body.get('workerExited') is True,
                'Incomplete local root retirement')
        require(receipt.get('importDisposition') ==
                ('owner_anchor_retained' if node==self.owner_node else 'unmap_acknowledged'),
                'No SDK import disposition')
        with self.lock:
            self.receipts[(publication['objectName'],publication['generation'],node)] = receipt

    def retire(self, publication, nodes):
        with self.lock:
            require(all((publication['objectName'],publication['generation'],n) in self.receipts for n in nodes),
                    'Missing authenticated node retirement evidence')
        return {'objectName':publication['objectName'],'generation':publication['generation'],
                'releasedNodes':list(nodes)}


class Coordinator:
    def __init__(self, run, manifests, publisher, root, nodes, receipt_keys,
                 budget_bytes=2*1024**3, reservation_bytes=128*1024**2, image_key=None, owner_node='node-a'):
        self.run, self.manifests, self.publisher = run, manifests, publisher
        require(isinstance(image_key,bytes) and len(image_key)>=32,'Owner image-signing key required')
        self.image_key,self.owner_node=image_key,owner_node
        self.root = Path(root)
        self.root.mkdir(mode=0o700, exist_ok=False)
        self.evidence = RetirementEvidence(run, receipt_keys, owner_node)
        publisher.view_controller = self.evidence
        self.cache = DemandCache(publisher, lambda s:atomic_json(self.root/'cache.json',s),
                                 nodes=nodes,budget_bytes=budget_bytes,reservation_bytes=reservation_bytes)
        self.operations = {}; self.lock = threading.RLock(); self.closed = False
        self.grants = {}

    def _save(self):
        atomic_json(self.root/'operations.json',{'run':self.run,'closed':self.closed,
                    'operations':list(self.operations.values())})

    def acquire(self, node, operation, manifest_id, index):
        require(isinstance(operation,str) and len(operation)==32 and all(c in '0123456789abcdef' for c in operation),
                'Stable operation ID required')
        manifest = self.manifests[manifest_id]
        require(type(index) is int and 0 <= index < len(manifest.chunks),'Invalid chunk selection')
        key = (node,operation)
        with self.lock:
            if key in self.operations:
                entry=self.operations[key]
                require((entry['manifest'],entry['chunk'])==(manifest_id,index),'Operation ID reused for another chunk')
                return dict(entry)
            require(not self.closed,'Run admission closed')
            entry={'node':node,'operation':operation,'manifest':manifest_id,'chunk':index,'state':'PENDING'}
            self.operations[key]=entry;self._save()
        try:
            ticket=self.cache.acquire(manifest,manifest.chunks[index],node)
            publication=self.cache.publication(ticket)
            publication.update(run=self.run,manifestSha256=manifest_id,chunkIndex=index,ownerNode=self.owner_node)
            publication['ownerSignature']=proof_mac(self.image_key,publication)
            result={'ticket':asdict(ticket),'publication':publication}
            with self.lock:
                self.grants[ticket.lease]=ticket
                entry.update(state='READY',result=result);self._save()
        except Exception as error:
            with self.lock:
                entry.update(state='UNCERTAIN',reason=str(error));self._save()
        return dict(entry)

    def dispatch(self,node,request):
        require(request.get('run')==self.run,'Wrong demand run')
        method=request['method'];params=request.get('params',{})
        if method=='acquire':
            return self.acquire(node,request['operation'],params['manifest'],params['chunk'])
        if method=='query':
            with self.lock:return dict(self.operations[(node,request['operation'])])
        if method=='release-node':
            ticket=Ticket(**params['ticket'])
            require(ticket.node==node,'Foreign node ticket')
            with self.lock:
                known=self.grants.get(ticket.lease)
                if known is None:
                    # Idempotence only for a recorded acknowledged release.
                    require(any(e.get('releasedLease')==ticket.lease for e in self.operations.values()),
                            'Unknown release lease')
                    return {'state':'RELEASED'}
                require(known==ticket,'Wrong generation/lease')
            publication=self.cache.publication(ticket)
            self.evidence.accept(node,publication,params['receipt'])
            self.cache.release(ticket)
            with self.lock:
                del self.grants[ticket.lease]
                self.operations[(node,request['operation'])]={'node':node,'operation':request['operation'],
                    'state':'RELEASED','releasedLease':ticket.lease};self._save()
            return {'state':'RELEASED'}
        if method=='status':
            return {'state':'CLOSED' if self.closed else 'SERVING','cache':self.cache.snapshot()}
        if method=='close-admission':
            with self.lock:self.closed=True;self._save()
            return {'state':'CLOSED'}
        if method=='finish':
            with self.lock:require(self.closed and not self.grants,'Close admission and retire all node views first')
            snapshot=self.cache.snapshot()
            require(all(e['phase']=='READY' and not e['pins'] for e in snapshot['entries']),
                    'Unknown/filling/pinned objects prevent run finalization')
            for _ in snapshot['entries']:self.cache.retire_idle()
            self.publisher.finalize()
            return {'state':'RELEASED','cache':self.cache.snapshot()}
        raise ValueError('Unsupported coordinator method')


class Client:
    def __init__(self,url,run,ca,certificate,key,server_fingerprint,timeout=30):
        parsed=urlsplit(url)
        require(parsed.scheme=='https' and parsed.hostname and parsed.path in ('','/'),
                'Explicit HTTPS coordinator origin required')
        self.host,self.port=parsed.hostname,parsed.port or 443
        self.run,self.fingerprint,self.timeout=run,server_fingerprint,timeout
        self.context=ssl.create_default_context(cafile=ca)
        self.context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(certificate,key)

    def call(self,method,operation,params=None):
        body=json.dumps({'run':self.run,'method':method,'operation':operation,'params':params or {}},separators=(',',':')).encode()
        require(len(body)<=MAX_MESSAGE,'Control message too large')
        connection=http.client.HTTPSConnection(self.host,self.port,context=self.context,timeout=self.timeout)
        try:
            connection.connect()
            cert=connection.sock.getpeercert(binary_form=True)
            require(hashlib.sha256(cert).hexdigest()==self.fingerprint,'Coordinator certificate fingerprint differs')
            connection.request('POST','/v1/control',body,{'Content-Type':'application/json'})
            reply=connection.getresponse();raw=reply.read(MAX_MESSAGE+1)
            require(len(raw)<=MAX_MESSAGE and reply.status==200,'Control response failed; query same operation')
            result=json.loads(raw)
            require(result.get('ok') is True,result.get('reason','Control request rejected'))
            return result['result']
        finally:connection.close()

    def acquire(self,operation,manifest,index,deadline):
        try:result=self.call('acquire',operation,{'manifest':manifest,'chunk':index})
        except (OSError,http.client.HTTPException):result={'state':'PENDING'}
        while result['state']=='PENDING' and time.monotonic()<deadline:
            time.sleep(min(0.1,max(0,deadline-time.monotonic())))
            # Status query, never a new create request or new identity.
            result=self.call('query',operation)
        require(result['state']=='READY','Demand operation unresolved: '+str(result))
        return result['result']


def server(address,coordinator,ca,certificate,key,node_fingerprints):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                require(self.path=='/v1/control','Unknown endpoint')
                fingerprint=hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
                node=node_fingerprints[fingerprint]
                count=int(self.headers.get('Content-Length','0'))
                require(0<count<=MAX_MESSAGE,'Invalid control length')
                result=coordinator.dispatch(node,json.loads(self.rfile.read(count)))
                reply={'ok':True,'result':result}
            except Exception as error:reply={'ok':False,'reason':str(error)}
            data=json.dumps(reply,separators=(',',':')).encode()
            self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers()
            try:self.wfile.write(data)
            except (OSError,ssl.SSLError):pass  # The operation remains durable/queryable.
        def log_message(self,*args):pass
    httpd=ThreadingHTTPServer(address,Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate,key);context.load_verify_locations(cafile=ca);context.verify_mode=ssl.CERT_REQUIRED
    httpd.socket=context.wrap_socket(httpd.socket,server_side=True)
    return httpd
