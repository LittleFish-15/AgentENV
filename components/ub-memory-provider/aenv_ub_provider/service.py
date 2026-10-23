"""Explicit lifecycle for one immutable UB generation, without service management.

The publisher owns allocations. Importers only map them. A trusted coordinator
must deliver release receipts from every configured reader before deletion.
Process death never constitutes a remote release receipt.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import sys
import uuid

from . import contract, raw, sdk, stored
from . import bindings
from .io import atomic_json, read_json


def identity(value):
    return 'sha256:' + hashlib.sha256(contract.canonical(value)).hexdigest()


def names(values):
    if (not isinstance(values, list) or len(values) > 64 or len(set(values)) != len(values)
            or any(not isinstance(v, str) or re.fullmatch(r'[a-zA-Z0-9._-]{1,64}', v) is None for v in values)):
        raise ValueError('Reader identities must be unique, portable names')
    return values


def load_config(path):
    return validate_config(read_json(path))


def validate_config(config):
    common = {'version', 'mode', 'role', 'workDir', 'adapter', 'adapterSha256', 'region',
              'logicalBudgetBytes', 'maxCoverageBytes'}
    role = config.get('role')
    mode = config.get('mode')
    if role == 'publish':
        extra = {'readers', 'sourceRoot', 'images'} if mode == 'stored' else {'readers', 'catalog'}
    elif role == 'import':
        extra = {'readerId', 'manifest'}
    else:
        raise ValueError('Provider role must be publish or import')
    if (set(config) != common | extra or type(config['version']) is not int or config['version'] != 1
            or mode not in ('stored', 'pmem')):
        raise ValueError('Unsupported provider configuration')
    for key in ('logicalBudgetBytes', 'maxCoverageBytes'):
        if type(config[key]) is not int or not 0 < config[key] < 2**63:
            raise ValueError('Positive explicit logical and post-map coverage budgets required')
    for key in ('workDir', 'adapter'):
        value = Path(config[key])
        if not value.is_absolute() or value.resolve() != value:
            raise ValueError('Provider paths must be absolute without symlink components')
    if re.fullmatch(r'sha256:[0-9a-f]{64}', config['adapterSha256']) is None:
        raise ValueError('Explicit built SDK adapter SHA256 required')
    if not isinstance(config['region'], str) or not config['region'] or len(config['region'].encode()) >= 128 or '\0' in config['region']:
        raise ValueError('Invalid existing SDK region')
    work = Path(config['workDir'])
    if len(os.fsencode(work / 'control.sock')) >= 108:
        raise ValueError('Work directory is too long for local UNIX sockets')
    if role == 'publish':
        names(config['readers'])
    else:
        names([config['readerId']])
    return config


def manifest_inputs(config):
    value = read_json(config['manifest'])
    if (set(value) != {'version', 'ownerId', 'mode', 'readers', 'replicas'}
            or type(value['version']) is not int or value['version'] != 1
            or value['mode'] != config['mode']
            or re.fullmatch(r'[0-9a-f]{32}', value['ownerId']) is None
            or config['readerId'] not in names(value['readers'])):
        raise ValueError('Importer is not a reader of this exact generation')
    return value


def inputs(config):
    data_socket = str(Path(config['workDir']) / 'data.sock')
    if config['role'] == 'import':
        manifest = manifest_inputs(config)
        if config['mode'] == 'pmem':
            entries = [{'backing': dict(r['identity'], socket=data_socket)} for r in manifest['replicas']]
            contract.validate_catalog({'version': 1, 'objects': entries}, data_socket, config['logicalBudgetBytes'])
            for entry, replica in zip(entries, manifest['replicas']):
                raw.validate_replica(replica, entry['backing'])
            if sum(replica['mappingBytes'] for replica in manifest['replicas']) > config['logicalBudgetBytes']:
                raise ValueError('Imported aligned images exceed logical budget')
            return entries, manifest
        replicas = [stored.Replica(brokerSocket=data_socket, **r).validate() for r in manifest['replicas']]
        if not 1 <= len(replicas) <= 64 or len({r.objectName for r in replicas}) != len(replicas):
            raise ValueError('Invalid stored import generation')
        if sum(r.mappingBytes for r in replicas) > config['logicalBudgetBytes']:
            raise ValueError('Imported generation exceeds logical budget')
        return replicas, manifest
    if config['mode'] == 'pmem':
        catalog = read_json(config['catalog'])
        entries = contract.validate_catalog(catalog, data_socket, config['logicalBudgetBytes'])
        for entry in entries:
            if entry['backing']['bytes'] % contract.ALIGN:
                raise ValueError('Pmem image must be 2MiB aligned')
        if sum(raw.shape(e['backing'], 'aenv_' + '0' * 32)['mappingBytes'] for e in entries) > config['logicalBudgetBytes']:
            raise ValueError('Aligned images exceed logical budget')
        return entries, None
    root = Path(config['sourceRoot']).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Stored source root must be a directory')
    selected = stored.source_layers(config['images'], source_root=root)
    requested = sum((size + stored.HEADER_BYTES + stored.ALIGN - 1) // stored.ALIGN * stored.ALIGN for _, size in selected.values())
    if requested > config['logicalBudgetBytes']:
        raise ValueError('Stored images exceed aligned logical budget')
    return selected, None


def release_receipts(request, manifest):
    if set(request) != {'operation', 'peerReceipts'} or request['operation'] != 'retire':
        raise ValueError('Expected explicit retire request')
    expected = set(manifest['readers'])
    if not isinstance(request['peerReceipts'], list) or len(request['peerReceipts']) != len(expected):
        raise ValueError('Every configured remote reader must supply a release receipt')
    seen = set()
    for path in request['peerReceipts']:
        receipt = read_json(path)
        if (set(receipt) != {'version', 'ownerId', 'readerId', 'manifestSha256', 'state'}
                or type(receipt['version']) is not int or receipt['version'] != 1
                or receipt['ownerId'] != manifest['ownerId']
                or receipt['manifestSha256'] != identity(manifest)
                or receipt['state'] != 'released' or receipt['readerId'] not in expected
                or receipt['readerId'] in seen):
            raise ValueError('Missing, duplicate, stale or incomplete remote release receipt')
        seen.add(receipt['readerId'])
    if seen != expected:
        raise ValueError('Remote release set differs')


def ordinary_linux():
    contract.linux_only()
    caps = [line.split()[1] for line in Path('/proc/self/status').read_text().splitlines()
            if line.startswith(('CapInh:', 'CapPrm:', 'CapEff:', 'CapAmb:'))]
    if os.getuid() != os.geteuid() or len(caps) != 4 or any(int(c, 16) for c in caps):
        raise ValueError('Provider requires an ordinary UID and zero capabilities')


def freeze_admission(provider):
    # Share the exact lock used by acquire. Merely checking active here and
    # setting retiring later in stop() leaves a new-reader race: stop then
    # raises outside the recoverable control-request path and exits the owner.
    with provider.condition:
        if provider.active:
            raise RuntimeError('Local Guest or inherited child leases still active')
        provider.retiring = True


def control_reply(stream, reply):
    # A client disconnect cannot change resource ownership. In particular, a
    # lost refusal must not terminate the serving owner, and a lost completion
    # reply must not overwrite an already durable release with "unresolved".
    try:
        contract.send_json(stream, reply)
    except OSError:
        pass


def serve(config, selected, manifest):
    import fcntl
    ordinary_linux()
    os.umask(0o077)
    work = Path(config['workDir'])
    work.mkdir(mode=0o700, exist_ok=False)  # An old journal is never silently reused.
    lock = os.open(work / 'generation.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    state = {'version': 1, 'state': 'intent_before_sdk', 'role': config['role'], 'mode': config['mode']}
    def journal(update):
        state.update(update)
        atomic_json(work / 'owner.json', state)
    journal({})
    backend = images = provider = control = None
    published = False
    try:
        adapter = Path(config['adapter'])
        if not stat.S_ISREG(adapter.stat().st_mode) or identity_bytes(adapter) != config['adapterSha256']:
            raise ValueError('SDK adapter differs from configured pin')
        backend_type = raw.NativeRawBackend if config['mode'] == 'pmem' else sdk.NativeBackend
        backend = backend_type(adapter, config['maxCoverageBytes'])
        backend.configure_region(config['region'])
        socket_path = str(work / 'data.sock')
        if config['mode'] == 'pmem':
            images = raw.RawImages(backend, journal, config['maxCoverageBytes'])
            if config['role'] == 'publish':
                replicas = images.publish(selected, config['logicalBudgetBytes'])
            else:
                images.imports(selected, {'format': 'native-raw-v1', 'state': 'ready', 'replicas': manifest['replicas']})
                replicas = manifest['replicas']
            provider = raw.RawProvider(images.entries)
        elif config['role'] == 'publish':
            images = stored.Publisher(backend, work / 'stored-owner.json')
            local, mappings = images.publish(selected, socket_path, config['logicalBudgetBytes'])
            replicas = [{k: v for k, v in asdict(r).items() if k != 'brokerSocket'} for r in local]
            provider = stored.Broker(local, mappings)
        else:
            mappings = []
            backend.initialize()
            for replica in selected:
                journal({'state': 'intent_before_import', 'importObject': replica.objectName})
                mapping = backend.map(replica)
                stored.verify_mapping(replica, mapping)
                mappings.append(mapping)
            replicas = manifest['replicas']
            provider = stored.Broker(selected, mappings)
            local = selected
        published = True
        if manifest is None:
            manifest = {'version': 1, 'ownerId': uuid.uuid4().hex, 'mode': config['mode'],
                        'readers': config['readers'], 'replicas': replicas}
        atomic_json(work / 'replicas.json', manifest)
        if config['mode'] == 'stored':
            atomic_json(work / 'runtime-index.json', stored.index_for(local))
        provider.start(socket_path)
        control = socket.socket(socket.AF_UNIX)
        control.bind(str(work / 'control.sock'))
        os.chmod(work / 'control.sock', 0o600)
        control.listen(4)
        journal({'state': 'serving', 'ownerId': manifest['ownerId'], 'manifestSha256': identity(manifest)})
        print(json.dumps({'state': 'serving', 'workDir': str(work), 'mode': config['mode'],
                          'physicalSharingAccepted': False}), flush=True)
        while True:
            stream, _ = control.accept()
            with stream:
                stream.settimeout(10)
                try:
                    contract.same_uid(stream)
                    request = contract.receive_json(stream)
                    if config['role'] == 'publish':
                        release_receipts(request, manifest)
                    elif request != {'operation': 'retire', 'peerReceipts': []}:
                        raise ValueError('Importer retirement only releases its own mappings')
                    freeze_admission(provider)
                except Exception as error:
                    control_reply(stream, {'state': 'refused', 'reason': str(error)[:1000]})
                    continue
                # No timeout, process death or local disconnect substitutes for remote receipts.
                provider.stop()
                journal({'state': 'retiring_readers_released'})
                if config['mode'] == 'pmem':
                    images.cleanup(readers_released=True)
                else:
                    for replica, mapping in provider.entries.values():
                        stored.verify_mapping(replica, mapping)
                    if images is not None:
                        images.cleanup()
                    else:
                        backend.close_maps()
                        backend.finalize()
                journal({'state': 'released'})
                if config['role'] == 'import':
                    atomic_json(work / 'release.json', {'version': 1, 'ownerId': manifest['ownerId'],
                        'readerId': config['readerId'], 'manifestSha256': identity(manifest), 'state': 'released'})
                control_reply(stream, {'state': 'released'})
                return
    except BaseException as error:
        journal({'state': 'unresolved_preserved', 'errorType': type(error).__name__, 'reason': str(error)[:1000]})
        # Only fully unpublished local resources may be cleaned without reader receipts.
        if not published and images is not None and not images.published:
            try:
                images.cleanup()
            except Exception as cleanup_error:
                journal({'cleanupError': str(cleanup_error)[:1000]})
        raise
    finally:
        if control is not None:
            control.close()
        os.close(lock)


def identity_bytes(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(part)
    return 'sha256:' + digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('serve')
    run.add_argument('config')
    run.add_argument('--run', action='store_true', help='Actually call the configured SDK; otherwise validate inputs only')
    retire = commands.add_parser('retire')
    retire.add_argument('work_dir')
    retire.add_argument('--peer-receipt', action='append', default=[])
    ram = commands.add_parser('bind-fsdax-memory')
    ram.add_argument('--source', required=True)
    ram.add_argument('--image', required=True)
    ram.add_argument('--virtual-bytes', required=True, type=int)
    ram.add_argument('--socket', required=True)
    ram.add_argument('--device-runtime', required=True)
    ram.add_argument('--output', required=True)
    bind = commands.add_parser('bind-rootfs')
    bind.add_argument('--source', required=True)
    bind.add_argument('--image', action='append', required=True)
    bind.add_argument('--socket', required=True)
    bind.add_argument('--max-bytes', type=int, required=True)
    bind.add_argument('--device-runtime', required=True)
    bind.add_argument('--lower-filesystem', choices=['erofs', 'ext4'], default='erofs')
    bind.add_argument('--snapshot-references', action='store_true',
                      help='Emit v3 content references; requires matching Runtime/FC and retained immutable bases')
    transport = bind.add_mutually_exclusive_group()
    transport.add_argument('--host-pagecache', action='store_true',
                           help='Emit v5 for immutable ordinary Host files shared by Guest pmem/DAX')
    transport.add_argument('--fs-dax', action='store_true',
                      help='Emit v4 for existing readonly FS-DAX files; no pmem device is created')
    bind.add_argument('--retain-snapshot-bases', action='store_true',
                      help='Pin local raw sources and archive exact bases with snapshots; requires matching Runtime')
    bind.add_argument('--output', required=True)
    relocate = commands.add_parser('relocate-rootfs')
    relocate.add_argument('--binding', required=True)
    relocate.add_argument('--socket', required=True)
    relocate.add_argument('--device-runtime', required=True)
    relocate.add_argument('--output', required=True)
    relocate.add_argument('--snapshot-source', action='append',
                          help='Matching node-local raw image for each layer of an archived-capture binding')
    archived = commands.add_parser('bind-retained-snapshot')
    archive_transport = archived.add_mutually_exclusive_group()
    archive_transport.add_argument('--host-pagecache', action='store_true',
                                   help='Emit v5 for retained ordinary Host files; no UB publication')
    archive_transport.add_argument('--fs-dax', action='store_true',
                          help='Use v4; retained images must be explicitly published on an existing readonly FS-DAX volume')
    archived.add_argument('--manifest', required=True)
    archived.add_argument('--artifact-root', required=True)
    archived.add_argument('--socket', required=True)
    archived.add_argument('--max-bytes', type=int, required=True)
    archived.add_argument('--device-runtime', required=True)
    archived.add_argument('--output', required=True)
    generation_commands = ('publish-retained-snapshot', 'import-retained-snapshot', 'publish-retained-set',
                           'import-retained-set', 'publish-prebuilt-set', 'import-prebuilt-set')
    for name in generation_commands:
        command = commands.add_parser(name)
        if name == 'publish-prebuilt-set':
            command.add_argument('--image-set', required=True)
        elif name == 'import-prebuilt-set':
            command.add_argument('--binding-catalog', required=True)
            command.add_argument('--binding-catalog-sha256', required=True)
        else:
            command.add_argument('--snapshot-set' if name.endswith('-set') else '--manifest', required=True)
        command.add_argument('--device-runtime', required=True)
        command.add_argument('--output', required=True)
        command.add_argument('--adapter', required=True)
        command.add_argument('--adapter-sha256', required=True)
        command.add_argument('--region', required=True)
        command.add_argument('--max-bytes', type=int, required=True)
        command.add_argument('--coverage-bytes', type=int, required=True)
        command.add_argument('--expected-plan-sha256', help='Require the same fully validated plan before any SDK call')
        command.add_argument('--run', action='store_true', help='Create fresh preparation and serve via the existing SDK lifecycle')
        if name.startswith('publish-'):
            if not name.endswith('-set'):
                command.add_argument('--artifact-root', required=True)
            command.add_argument('--reader', action='append', default=[])
        else:
            command.add_argument('--publisher-manifest', required=True)
            command.add_argument('--publisher-manifest-sha256', required=True)
            command.add_argument('--reader', required=True)
    args = parser.parse_args()
    if args.command in generation_commands:
        from . import retained
        runtime = read_json(args.device_runtime)
        common = (runtime, args.output, args.adapter, args.adapter_sha256, args.region, args.max_bytes, args.coverage_bytes)
        if args.command == 'publish-prebuilt-set':
            from . import prebuilt
            plan = prebuilt.plan_publish(args.image_set, *common, args.reader)
        elif args.command == 'import-prebuilt-set':
            from . import prebuilt
            plan = prebuilt.plan_import(args.binding_catalog, args.binding_catalog_sha256,
                                       args.publisher_manifest, args.publisher_manifest_sha256, args.reader, *common)
        elif args.command == 'publish-retained-set':
            plan = retained.plan_publish_set(args.snapshot_set, *common, args.reader)
        elif args.command == 'import-retained-set':
            plan = retained.plan_import_set(args.snapshot_set, args.publisher_manifest, args.publisher_manifest_sha256, args.reader, *common)
        elif args.command.startswith('publish-'):
            plan = retained.plan_publish(args.manifest, args.artifact_root, *common, args.reader)
        else:
            plan = retained.plan_import(args.manifest, args.publisher_manifest, args.publisher_manifest_sha256, args.reader, *common)
        plan_sha256 = identity(plan)
        if args.expected_plan_sha256 is not None and args.expected_plan_sha256 != plan_sha256:
            raise ValueError('Validated native generation plan changed')
        print(json.dumps({'state': 'retained_generation_validated_no_sdk', 'role': plan['role'], 'planSha256': plan_sha256,
                          'inputKind': plan.get('inputKind', 'retained_native_snapshot'),
                          'alignedLogicalBytes': plan['alignedLogicalBytes'], 'physicalHardQuota': False,
                          'GuestCreated': False, 'memfilePrivateCowImplemented': False}), flush=True)
        if args.run:
            retained.execute(plan)
        return 0
    if args.command == 'bind-retained-snapshot':
        value = bindings.retained_snapshot(args.manifest, args.artifact_root, args.socket, args.max_bytes,
                                          read_json(args.device_runtime), args.output, args.fs_dax, args.host_pagecache)
        print(json.dumps({'state': 'archived_binding_prepared_no_sdk', 'bytes': sum(x['bytes'] for x in value['layers'])}))
        return 0
    if args.command == 'bind-fsdax-memory':
        value = bindings.fsdax_memory(args.source, args.image, args.virtual_bytes, args.socket,
                                      read_json(args.device_runtime), args.output)
        print(json.dumps({'state': 'fsdax_ram_binding_prepared_no_sdk', 'bytes': value['backing']['bytes'],
                          'KVM_tested': False, 'physicalSharingAccepted': False}))
        return 0
    if args.command in ('bind-rootfs', 'relocate-rootfs'):
        runtime = read_json(args.device_runtime)
        if args.command == 'bind-rootfs':
            value = bindings.rootfs(args.source, args.image, args.socket, args.max_bytes,
                                    runtime, args.output, args.lower_filesystem, args.snapshot_references, args.retain_snapshot_bases, args.fs_dax, args.host_pagecache)
        else:
            value = bindings.relocate(args.binding, args.socket, runtime, args.output, args.snapshot_source)
        print(json.dumps({'state': 'binding_prepared_no_sdk', 'bytes': sum(layer['bytes'] for layer in value['layers'])}))
        return 0
    if args.command == 'retire':
        ordinary_linux()
        work = Path(args.work_dir)
        metadata = work.stat()
        if not work.is_absolute() or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError('Retire requires a private owned generation directory')
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(600)
            stream.connect(str(work / 'control.sock'))
            contract.same_uid(stream)
            contract.send_json(stream, {'operation': 'retire', 'peerReceipts': [str(Path(p).resolve(strict=True)) for p in args.peer_receipt]})
            result = contract.receive_json(stream)
        print(json.dumps(result))
        return 0 if result.get('state') == 'released' else 1
    config = load_config(args.config)
    selected, manifest = inputs(config)
    if not args.run:
        print(json.dumps({'state': 'inputs_validated_no_sdk', 'mode': config['mode'],
                          'role': config['role'], 'physicalHardQuota': False, 'physicalSharingAccepted': False}))
        return 0
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt('Provider interrupted; published objects retained for reconciliation')
    signal.signal(signal.SIGTERM, interrupted)
    serve(config, selected, manifest)
    return 0
