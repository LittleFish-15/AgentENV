"""Opt-in stored-layer UB demand cache. Does not deploy services or enable DAX."""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import signal
import socket
import threading
import types
import uuid

from . import contract, lazy, sdk, service, stored
from .io import atomic_json


def read_json(path, pin=None):
    with Path(path).open('rb') as stream:
        data = stream.read(lazy.MAX_CATALOG + 1)
    if len(data) > lazy.MAX_CATALOG:
        raise ValueError('Lazy input exceeds bounded metadata size')
    if pin is not None and lazy.digest(data) != pin:
        raise ValueError('Offline chunk catalog differs from configured SHA256')
    return json.loads(data)


def descriptors(manifest, socket_path):
    return [stored.Replica(brokerSocket=str(socket_path), **r).validate()
            for r in manifest['virtualLayers']]


def validate_manifest(value):
    if (not isinstance(value, dict) or set(value) != {'format', 'cacheId', 'pool', 'catalog', 'virtualLayers', 'readers'}
            or value['format'] != 'aenv-ub-lazy-v2'
            or not isinstance(value['cacheId'], str) or re.fullmatch(r'[0-9a-f]{32}', value['cacheId']) is None):
        raise ValueError('Expected a lazy stored cache manifest, never a native pmem binding')
    service.names(value['readers'])
    if not value['readers'] or value['readers'][0] != 'owner':
        raise ValueError('Lazy cache owner identity missing')
    layers = lazy.catalog(value['catalog'])
    pool = value['pool']
    if (not isinstance(pool, dict) or set(pool) != {'objectName', 'mappingBytes'}
            or not isinstance(pool['objectName'], str) or re.fullmatch(r'aenv_[0-9a-f]{32}', pool['objectName']) is None
            or type(pool['mappingBytes']) is not int or not stored.ALIGN <= pool['mappingBytes'] <= 4 * 1024**3
            or pool['mappingBytes'] % stored.ALIGN):
        raise ValueError('Invalid bounded UB cache pool')
    if not isinstance(value['virtualLayers'], list) or len(value['virtualLayers']) != len(layers):
        raise ValueError('One virtual broker descriptor required per immutable layer')
    refs = descriptors(value, '/validated/data.sock')
    if (len({r.objectName for r in refs}) != len(refs)
            or {r.layerDigest for r in refs} != set(layers)
            or any(r.objectName == pool['objectName'] or r.generation != value['cacheId']
                   or r.fileBytes != layers[r.layerDigest]['fileBytes'] or r.allowRepositoryFallback for r in refs)):
        raise ValueError('Lazy virtual descriptors differ from pinned catalog/generation')
    return value


def new_manifest(value, pool_bytes, readers):
    service.names(readers)
    if 'owner' in readers:
        raise ValueError('owner is reserved for the publisher')
    cache_id = uuid.uuid4().hex
    portable = {'version': 1, 'chunkBytes': lazy.CHUNK,
                'layers': [{k: v for k, v in layer.items() if k != 'path'} for layer in value['layers']]}
    refs = [stored.Replica('/validated/data.sock', 'aenv_' + uuid.uuid4().hex, cache_id,
                          layer['digest'], layer['fileBytes'],
                          (layer['fileBytes'] + stored.HEADER_BYTES + stored.ALIGN - 1) // stored.ALIGN * stored.ALIGN)
            for layer in portable['layers']]
    return validate_manifest({'format': 'aenv-ub-lazy-v2', 'cacheId': cache_id,
        'pool': {'objectName': 'aenv_' + uuid.uuid4().hex, 'mappingBytes': pool_bytes},
        'catalog': portable, 'virtualLayers': [{k: v for k, v in asdict(r).items() if k != 'brokerSocket'} for r in refs],
        'readers': ['owner', *readers]})


def load_config(path):
    config = read_json(path)
    common = {'version', 'role', 'workDir', 'adapter', 'adapterSha256', 'region', 'maxCoverageBytes'}
    extra = {'catalog', 'catalogSha256', 'sourceRoot', 'poolBytes', 'readers'} if config.get('role') == 'publish' else {
        'manifest', 'credential', 'coordinationSocket'}
    if (set(config) - {'maxConcurrentReads'} != common | extra
            or type(config.get('maxConcurrentReads', 1)) is not int or not 1 <= config.get('maxConcurrentReads', 1) <= 8
            or type(config['version']) is not int or config['version'] != 1
            or config['role'] not in ('publish', 'import') or not lazy.sha(config['adapterSha256'])
            or type(config['maxCoverageBytes']) is not int or not 0 < config['maxCoverageBytes'] < 2**63
            or not isinstance(config['region'], str) or not config['region'] or '\0' in config['region']
            or len(config['region'].encode()) >= 128):
        raise ValueError('Invalid lazy provider configuration')
    for name in ('workDir', 'adapter'):
        path = Path(config[name])
        if not path.is_absolute() or path.resolve() != path:
            raise ValueError('Lazy provider paths must be canonical and absolute')
    if len(os.fsencode(Path(config['workDir']) / 'coordinator.sock')) >= 108:
        raise ValueError('Lazy provider socket path is too long')
    if config['role'] == 'publish':
        if not lazy.sha(config['catalogSha256']):
            raise ValueError('Offline chunk catalog differs from configured SHA256')
        value = read_json(config['catalog'], config['catalogSha256'])
        lazy.catalog(value, paths=True)
        root = Path(config['sourceRoot']).resolve(strict=True)
        if not root.is_dir():
            raise ValueError('sourceRoot must be an existing directory')
        for layer in value['layers']:
            source = Path(layer['path'])
            if source.resolve(strict=True) != source or not source.is_relative_to(root) or source.stat().st_size != layer['fileBytes']:
                raise ValueError('Lazy source path/size differs from pinned catalog')
        manifest = new_manifest(value, config['poolBytes'], config['readers'])
        credential = None
    else:
        value = None
        manifest = validate_manifest(read_json(config['manifest']))
        credential = read_json(config['credential'])
        if (not isinstance(credential, dict) or set(credential) != {'cacheId', 'reader', 'token', 'manifestSha256'}
                or credential['cacheId'] != manifest['cacheId']
                or credential['reader'] not in manifest['readers'][1:]
                or not isinstance(credential['token'], str) or re.fullmatch(r'[0-9a-f]{64}', credential['token']) is None
                or credential['manifestSha256'] != service.identity(manifest)):
            raise ValueError('Reader credential is not bound to this exact cache manifest')
        endpoint = Path(config['coordinationSocket'])
        if not endpoint.is_absolute() or len(os.fsencode(endpoint)) >= 108:
            raise ValueError('Expected a short local UNIX endpoint for the approved metadata transport')
    if manifest['pool']['mappingBytes'] > config['maxCoverageBytes']:
        raise ValueError('Cache pool exceeds post-map inspection budget')
    return config, value, manifest, credential


def reader_status(reader, broker):
    """Keep local failure evidence available without retrying a failed reader."""
    status = {'state': 'unresolved_preserved', 'coordinatorStatusAvailable': False,
              'pins': None, 'loading': None, 'readyBytes': None}
    if not reader.status().get('readerFailed', False):
        try:
            remote = reader.rpc('status')
            if not isinstance(remote, dict) or remote.get('state') not in ('serving', 'frozen'):
                reader.poison()
                raise ValueError('Invalid coordinator status')
            status = dict(remote, coordinatorStatusAvailable=True)
        except Exception as error:
            status['coordinatorErrorType'] = type(error).__name__
    status.update(reader.status())
    status.update(broker.read_status())
    if status.get('readerFailed'):
        status['state'] = 'unresolved_preserved'
    return status


def serve(config, value, manifest, credential):
    import fcntl
    service.ordinary_linux()
    os.umask(0o077)
    work = Path(config['workDir'])
    work.mkdir(mode=0o700, exist_ok=False)
    lock = os.open(work / 'generation.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    state = {'state': 'intent_before_sdk', 'mode': 'stored-lazy', 'role': config['role'],
             'cacheId': manifest['cacheId'], 'pool': manifest['pool'],
             'physicalIncrementMeasured': False, 'daxDemandPagingAccepted': False,
             'maxConcurrentReads': config.get('maxConcurrentReads', 1)}
    journal_lock = threading.RLock()
    def journal(update):
        with journal_lock:
            state.update(update)
            if state.get('readerFailed'):
                state['state'] = 'unresolved_preserved'
            atomic_json(work / 'owner.json', state)
    backend = sources = metadata = control = None
    journal({})
    try:
        if service.identity_bytes(config['adapter']) != config['adapterSha256']:
            raise ValueError('SDK adapter changed before startup')
        backend = sdk.NativeBackend(config['adapter'], config['maxCoverageBytes'])
        backend.configure_region(config['region'])
        pool = types.SimpleNamespace(**manifest['pool'])
        slots = pool.mappingBytes // lazy.CHUNK
        coordinator = None
        if config['role'] == 'publish':
            sources = lazy.DirectSources(value, config['sourceRoot'])
            tokens = {reader: uuid.uuid4().hex + uuid.uuid4().hex for reader in manifest['readers']}
            for reader, token in tokens.items():
                atomic_json(work / ('reader-' + reader + '.json'), {'cacheId': manifest['cacheId'],
                    'reader': reader, 'token': token, 'manifestSha256': service.identity(manifest)})
            backend.initialize()
            journal({'state': 'intent_before_allocate', 'allocationAttempted': True})
            backend.allocate(pool)
            journal({'creationConfirmed': True})
            mapping = backend.map(pool, writable=True)
            journal({'backingCoverageBytes': mapping.backing_coverage})
            coordinator = lazy.Cache(manifest['catalog'], mapping, slots, sources.read,
                                     manifest['cacheId'], tokens, journal)
            reader = lazy.Reader(manifest['catalog'], mapping, slots, manifest['cacheId'],
                                 'owner', tokens['owner'], coordinator.request, config.get('maxConcurrentReads', 1),
                                 failure_journal=journal)
            if reader.rpc('open-reader') != {'state': 'reader-opened'}:
                raise ValueError('Owner reader admission was not confirmed')
            metadata = lazy.MetadataServer(coordinator.request)
            metadata.start(work / 'coordinator.sock')
        else:
            reader = lazy.Reader(manifest['catalog'], None, slots, manifest['cacheId'],
                                 credential['reader'], credential['token'],
                                 lambda request: lazy.connect(config['coordinationSocket'], request), config.get('maxConcurrentReads', 1),
                                 failure_journal=journal)
            if reader.rpc('open-reader') != {'state': 'reader-opened'}:
                raise ValueError('Importer admission was not confirmed')
            backend.initialize()
            journal({'state': 'intent_before_import'})
            mapping = backend.map(pool)  # Import never allocates, writes or deletes.
            reader.mapping = mapping
            journal({'backingCoverageBytes': mapping.backing_coverage})
        refs = descriptors(manifest, work / 'data.sock')
        broker = stored.Broker(refs, [lazy.LayerView(reader, replica) for replica in refs])
        atomic_json(work / 'manifest.json', manifest)
        # Compatibility descriptors name broker views, not allocated full-layer
        # SDK objects. Only manifest.pool is allocated/mapped by this service.
        atomic_json(work / 'runtime-index.json', stored.index_for(refs))
        broker.start(work / 'data.sock')
        control = socket.socket(socket.AF_UNIX)
        control.bind(str(work / 'control.sock'))
        os.chmod(work / 'control.sock', 0o600)
        control.listen(4)
        journal({'state': 'serving', 'startupPayloadBytes': 0, 'poolBytes': pool.mappingBytes})
        if reader.status().get('readerFailed', False):
            raise RuntimeError('Reader failed during startup; generation preserved')
        print(json.dumps({'state': 'serving', 'mode': 'stored-lazy', 'workDir': str(work),
                          'poolBytes': pool.mappingBytes, 'startupPayloadBytes': 0,
                          'daxDemandPagingAccepted': False, 'physicalIncrementMeasured': False}), flush=True)
        while True:
            stream, _ = control.accept()
            with stream:
                stream.settimeout(10)
                try:
                    contract.same_uid(stream)
                    request = contract.receive_json(stream)
                    if isinstance(request, dict) and request.get('operation') in ('residency-open', 'residency-page', 'residency-close'):
                        fields = dict(request)
                        operation = fields.pop('operation')
                        service.control_reply(stream, reader.observe(operation, **fields))
                        continue
                    if request == {'operation': 'status'}:
                        service.control_reply(stream, reader_status(reader, broker))
                        continue
                    if request != {'operation': 'retire'}:
                        raise ValueError('Expected explicit status or retire')
                    if reader.status().get('readerFailed', False):
                        raise RuntimeError('Reader failed; preserve SDK mappings and reconcile the generation')
                    if coordinator is not None:
                        with coordinator.condition:
                            if (coordinator.poisoned or coordinator.loading or coordinator.leases
                                    or set(manifest['readers'][1:]) - coordinator.released):
                                raise RuntimeError('Remote readers/pins still active or uncertain')
                    service.freeze_admission(broker)
                except Exception as error:
                    service.control_reply(stream, {'state': 'refused', 'reason': str(error)[:500]})
                    continue
                broker.stop()
                reader.quiesce()  # No active read may overlap either node unmapping.
                if coordinator is not None:
                    reader.release()
                    coordinator.freeze()
                    metadata.stop()  # Refuse unmap while a metadata worker is active.
                    sources.close()
                    backend.close_maps()
                    backend.deallocate(pool)
                    journal({'deleteAcknowledged': True})
                    backend.finalize()
                else:
                    backend.close_maps()
                    backend.finalize()
                    # Only acknowledge remote release after all local views and
                    # SDK mappings are gone. A lost ack cannot authorize reuse.
                    reader.release()
                journal({'state': 'released', 'finalizeAcknowledged': True})
                service.control_reply(stream, {'state': 'released'})
                return
    except BaseException as error:
        journal({'state': 'unresolved_preserved', 'errorType': type(error).__name__})
        # No crash/timeout/disconnect substitutes for explicit reader release.
        # Keep names, credentials and pin journal; never auto-restart/reallocate.
        raise
    finally:
        if control is not None:
            control.close()
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prepare = sub.add_parser('prepare')
    prepare.add_argument('--source-root', required=True)
    prepare.add_argument('--image', action='append', required=True)
    prepare.add_argument('--output', required=True)
    run = sub.add_parser('serve')
    run.add_argument('config')
    run.add_argument('--run', action='store_true')
    for operation in ('status', 'retire', 'residency'):
        command = sub.add_parser(operation)
        command.add_argument('work_dir')
    args = parser.parse_args()
    if args.command == 'prepare':
        output = Path(args.output)
        if output.exists() or output.is_symlink():
            raise ValueError('Offline catalog output already exists')
        sources = stored.source_layers(args.image, source_root=args.source_root)
        value = lazy.prepare_direct(sources, args.source_root)
        atomic_json(output, value)
        print(json.dumps({'state': 'offline_catalog_prepared_no_sdk', 'layers': len(value['layers']),
                          'catalogSha256': service.identity_bytes(output),
                          'sourceReadMode': 'O_DIRECT_no_buffered_fallback',
                          'catalogScansFullSources': True, 'poolPayloadFilledBytes': 0}))
        return 0
    if args.command in ('status', 'retire', 'residency'):
        service.ordinary_linux()
        work = Path(args.work_dir)
        meta = work.stat()
        if not work.is_absolute() or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
            raise ValueError('Control requires an owned private generation directory')
        if args.command == 'residency':
            reply = lazy.collect_residency(lambda request: lazy.connect(work / 'control.sock', request))
        else:
            reply = lazy.connect(work / 'control.sock', {'operation': args.command})
        print(json.dumps(reply))
        return 1 if reply.get('state') in ('refused', 'unresolved_preserved') else 0
    config, value, manifest, credential = load_config(args.config)
    if not args.run:
        print(json.dumps({'state': 'lazy_inputs_validated_no_sdk', 'poolBytes': manifest['pool']['mappingBytes'],
                          'startupPayloadBytes': 0, 'daxDemandPagingAccepted': False}))
        return 0
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt('Lazy provider interrupted; preserve the pool and pin journal')
    signal.signal(signal.SIGTERM, interrupted)
    serve(config, value, manifest, credential)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
