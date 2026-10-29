"""Executable native demand roles. No emulated data backend or implicit recovery.

Configuration is local/private. Control credentials are file references, never
command-line secret values. Existing state is preserved and requires explicit
reconciliation, rather than restarting an SDK transaction.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import stat
import threading
import time
import uuid

from .host_dax_demand import Manifest, require
from .io import atomic_json


class ReadJournal:
    """Bounded request metadata, no payloads. Dropped events invalidate tracing.

    No per-read fsync is used; exit fsync and collector costs are explicit.
    This stream is diagnostic, never authority to release UB ownership.
    """
    def __init__(self,path,limit=32*1024**2):
        self.stream=Path(path).open('xb');self.limit=limit;self.bytes=0;self.dropped=0
        self.events=0;self.lock=threading.Lock();self.closed=False

    def __call__(self,event):
        data=(json.dumps(dict(event,wallNs=time.time_ns()),separators=(',',':'))+'\n').encode()
        with self.lock:
            if self.closed or self.bytes+len(data)>self.limit:
                self.dropped+=1;return
            self.stream.write(data);self.bytes+=len(data);self.events+=1

    def status(self):
        with self.lock:return dict(events=self.events,bytes=self.bytes,dropped=self.dropped,
                                   traceComplete=self.dropped==0,closed=self.closed)

    def close(self):
        with self.lock:
            if not self.closed:
                self.stream.flush();os.fsync(self.stream.fileno());self.stream.close();self.closed=True


def private_json(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'Unredirected absolute config required')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and not info.st_mode & 0o077 and info.st_size <= 1024**2,
            'Private owned bounded config required')
    return json.loads(path.read_text())


def key_file(path):
    path = Path(path)
    info = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid() and not info.st_mode & 0o077
            and 32 <= info.st_size <= 4096, 'Private owned key file required')
    return path.read_bytes()


def validate(config):
    require(config.get('version') == 1 and config.get('role') in ('owner', 'node', 'root'),
            'Unsupported demand runtime config')
    require(isinstance(config.get('run'), str) and len(config['run']) == 32
            and all(c in '0123456789abcdef' for c in config['run']), 'Run epoch must be 32 lowercase hex')
    require(len(config.get('nodes', [])) == 2 and len(set(config['nodes'])) == 2
            and config.get('ownerNode') in config['nodes'], 'Explicit two-node owner contract required')
    require(config.get('node') in config['nodes'], 'Unknown local node')
    if config['role'] == 'owner':
        require(config['node'] == config['ownerNode'], 'Only the owner may publish UB')
        require(type(config.get('budgetBytes')) is int and 128*1024**2 <= config['budgetBytes'] <= 2*1024**3,
                'Explicit logical coverage budget must be 128 MiB..2 GiB; not a physical quota')
    rows = config.get('manifests')
    require(isinstance(rows, list) and 0 < len(rows) <= 64, 'Bounded trusted manifests required')
    manifests = {}
    for row in rows:
        manifest = Manifest(row['document'], row['sha256'])
        require(manifest.sha256 not in manifests, 'Duplicate manifest')
        manifests[manifest.sha256] = manifest
    require(isinstance(config.get('stateRoot'), str) and Path(config['stateRoot']).is_absolute(),
            'Explicit isolated state root required')
    common = {'owner': ('adapter','adapterSha256','region','mke2fs','receiptKeys','imageKey','tls',
                        'listenHost','listenPort','nodeFingerprints'),
              'node': ('rootSocket','adminSocket','indexPath','layers','tls','budgetBytes'),
              'root': ('rootConfig','imageKey','receiptKey','rootSocket')}
    require(all(key in config for key in common[config['role']]), 'Missing required role configuration')
    if config['role'] == 'node' and config['node'] != config['ownerNode']:
        require(all(key in config for key in ('adapter','adapterSha256','region')), 'Missing importer configuration')
    if config['role'] == 'node':
        from .demand_wire import Layer
        require(isinstance(config['layers'], list) and len(config['layers']) == len(manifests),
                'One explicit layer per manifest required')
        for row in config['layers']:
            layer = Layer(**row).validate()
            manifest = manifests[layer.manifestSha256[7:]]
            require(layer.layerDigest == manifest.layer_digest and layer.fileBytes == manifest.file_bytes,
                    'Layer/manifest identity mismatch')
    if config['role'] == 'owner':
        require(set(config['receiptKeys']) == set(config['nodes'])
                and set(config['nodeFingerprints'].values()) == set(config['nodes']), 'Both node trust bindings required')
        require(all(isinstance(row.get('sourcePath'), str) and Path(row['sourcePath']).is_absolute()
                    for row in rows), 'Explicit immutable owner source paths required')
    return manifests


def client(config):
    from .demand_control import Client
    tls = config['tls']
    return Client(tls['url'], config['run'], tls['ca'], tls['certificate'], tls['key'],
                  tls['serverFingerprint'], config.get('controlTimeoutSeconds', 30))


def assemble_owner(config, manifests):
    from .demand_control import Coordinator, server
    from .demand_native import NativeChunkPublisher
    from .demand_source import DirectSource
    from .demand_image import build_chunk_image
    root = Path(config['stateRoot'])
    root.mkdir(mode=0o700, exist_ok=False)
    publisher_root = root/'publisher'; publisher_root.mkdir(mode=0o700)
    staging = root/'staging'; staging.mkdir(mode=0o700)
    sources = {row['sha256']: row['sourcePath'] for row in config['manifests']}

    def image_factory(manifest, chunk, generation):
        # Open only on a real first miss. No source scan, image or SDK at startup.
        source = DirectSource(sources[manifest.sha256], manifest.file_bytes)
        try:
            return build_chunk_image(source, chunk, staging/generation, config['mke2fs'])
        finally:
            source.close()

    publisher = NativeChunkPublisher(config['adapter'], config['adapterSha256'], config['region'],
        publisher_root, lambda value: atomic_json(root/'publisher.json', value), image_factory,
        None, config['budgetBytes'])
    coordinator = Coordinator(config['run'], manifests, publisher, root/'coordinator', config['nodes'],
        {node: key_file(path) for node, path in config['receiptKeys'].items()},
        budget_bytes=config['budgetBytes'], image_key=key_file(config['imageKey']),
        owner_node=config['ownerNode'])
    tls = config['tls']
    return server((config['listenHost'], config['listenPort']), coordinator, tls['ca'],
                  tls['certificate'], tls['key'], config['nodeFingerprints'])


def assemble_node(config, manifests):
    from .demand_importer import Importer, OwnerSources
    from .demand_service import ConcreteChunkViewFactory, LocalViewRegistry, NodeAgent
    from .demand_views import RootClient
    from .demand_wire import Layer
    root = Path(config['stateRoot']); root.mkdir(mode=0o700, exist_ok=False)
    if config['node'] == config['ownerNode']:
        sources = OwnerSources()
    else:
        sdk_root = root/'sdk'; sdk_root.mkdir(mode=0o700)
        sources = Importer(config['adapter'], config['adapterSha256'], config['region'], sdk_root,
                           lambda value: atomic_json(root/'importer.json', value), config['budgetBytes'])
    supervisor = RootClient(config['rootSocket'], config['run'])
    factory = ConcreteChunkViewFactory(config['node'], os.geteuid(), root/'chunks', sources, supervisor)
    registry = LocalViewRegistry(config['node'], client(config), factory, root/'registry')
    layers = [Layer(**row).validate() for row in config['layers']]
    journal=ReadJournal(root/'demand-reads.jsonl')
    return NodeAgent(layers, manifests, registry, config['indexPath'], os.geteuid(),event=journal)


def node_admin(agent, config):
    """Same-UID/run local admin only. Drain refuses live aenv broker sessions."""
    from . import contract
    path = Path(config['adminSocket'])
    require(path.parent.resolve(strict=True) == path.parent and not path.exists()
            and not path.is_symlink(), 'Existing admin socket preserved')
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(path)); os.chmod(path, 0o600); listener.listen(4)
    while True:
        stream, _ = listener.accept()
        with stream:
            stream.settimeout(330)
            try:
                import struct
                _, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                require(uid == os.geteuid(), 'Foreign admin UID')
                request = contract.receive_json(stream)
                require(request.get('run') == config['run'], 'Wrong admin run')
                if request['method'] == 'status':
                    result = agent.status()
                elif request['method'] == 'drain':
                    result = agent.stop()
                else:
                    raise ValueError('Unsupported node admin method')
                contract.send_json(stream, {'ok': True, 'result': result})
            except Exception as error:
                contract.send_json(stream, {'ok': False, 'reason': str(error)})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('validate', 'serve', 'status', 'drain', 'close-admission', 'finish'))
    parser.add_argument('--config', required=True)
    args = parser.parse_args(argv)
    config = private_json(args.config); manifests = validate(config)
    if args.action == 'validate':
        print(json.dumps({'state': 'CONFIG_VALIDATED_NO_SDK', 'role': config['role'],
                          'manifests': len(manifests), 'SDK_called': False}))
        return
    require(os.name == 'posix' and hasattr(socket, 'SO_PEERCRED'), 'Native Linux required')
    require((os.geteuid() == 0) == (config['role'] == 'root'), 'Wrong role privilege')
    if args.action != 'serve':
        if config['role'] == 'owner':
            result = client(config).call(args.action, uuid.uuid4().hex)
        else:
            require(config['role'] == 'node' and args.action in ('status', 'drain'), 'Wrong admin action')
            from . import contract
            with socket.socket(socket.AF_UNIX) as stream:
                stream.settimeout(330); stream.connect(config['adminSocket'])
                contract.send_json(stream, {'run': config['run'], 'method': args.action})
                result = contract.receive_json(stream)
        print(json.dumps(result)); return
    require(os.environ.get('AENV_DEMAND_APPROVAL') == 'UB_DEMAND_' + config['run'],
            'Explicit run-scoped deployment approval is required before serving')
    if config['role'] == 'owner':
        assemble_owner(config, manifests).serve_forever()
    elif config['role'] == 'root':
        from .demand_views import RootSupervisor
        root_config = dict(config['rootConfig'], run=config['run'], nodes=config['nodes'],
                           ownerNode=config['ownerNode'], root=config['stateRoot'])
        RootSupervisor(root_config, manifests, key_file(config['imageKey']),
                       key_file(config['receiptKey'])).serve(config['rootSocket'])
    else:
        agent = assemble_node(config, manifests)
        print(json.dumps(agent.start()), flush=True)
        node_admin(agent, config)


if __name__ == '__main__':
    main()
