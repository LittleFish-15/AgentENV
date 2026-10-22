"""Explicit fresh-generation publication/import of repository-owned pmem bases.

Planning does no SDK work. Execution uses the normal lease/receipt lifecycle;
it never revives an old generation or declares process death a release.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat

from . import bindings, contract, raw
from .io import atomic_json, read_json


def data_socket(work):
    return str(work / 'data.sock')


def fresh_output(value):
    path = Path(value)
    if (not path.is_absolute() or path.resolve() != path or not path.parent.is_dir()
            or path.exists() or path.is_symlink()):
        raise ValueError('Use a new absolute output directory with an existing unredirected parent')
    return path


def common(output, adapter, adapter_sha256, region, logical_budget, coverage_budget):
    from . import service
    output = fresh_output(output)
    adapter = Path(adapter)
    if (not adapter.is_absolute() or adapter.resolve(strict=True) != adapter
            or not stat.S_ISREG(adapter.stat().st_mode)
            or service.identity_bytes(adapter) != adapter_sha256):
        raise ValueError('Explicit SDK adapter identity differs')
    work = output / 'provider'
    config = {'version': 1, 'mode': 'pmem', 'workDir': str(work), 'adapter': str(adapter),
              'adapterSha256': adapter_sha256, 'region': region,
              'logicalBudgetBytes': logical_budget, 'maxCoverageBytes': coverage_budget}
    return output, data_socket(work), config


def plan_publish(manifest_path, artifact_root, runtime, output, adapter, adapter_sha256,
                 region, logical_budget, coverage_budget, readers):
    from . import service
    output, socket_path, config = common(output, adapter, adapter_sha256, region, logical_budget, coverage_budget)
    binding, catalog = bindings.retained_snapshot_plan(manifest_path, artifact_root, socket_path, logical_budget, runtime)
    aligned = sum(raw.shape(entry['backing'], 'aenv_' + '0' * 32)['mappingBytes'] for entry in catalog['objects'])
    if aligned > logical_budget:
        raise ValueError('Aligned raw allocations exceed the explicit logical budget')
    if type(coverage_budget) is not int or coverage_budget < aligned:
        raise ValueError('Coverage guard is below the aligned mapping request')
    config.update(role='publish', readers=list(readers), catalog=str(output / 'image-catalog.json'))
    service.validate_config(config)
    return {'role': 'publish', 'binding': binding, 'config': config, 'catalog': catalog,
            'alignedLogicalBytes': aligned, 'output': str(output)}


def plan_import(manifest_path, publisher_path, publisher_sha256, reader, runtime, output,
                adapter, adapter_sha256, region, logical_budget, coverage_budget):
    from . import service
    output, socket_path, config = common(output, adapter, adapter_sha256, region, logical_budget, coverage_budget)
    native = bindings.retained_metadata(manifest_path, logical_budget)
    contract.validate_device_runtime(runtime)
    with Path(publisher_path).open('rb') as stream:
        payload = stream.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024 or 'sha256:' + hashlib.sha256(payload).hexdigest() != publisher_sha256:
        raise ValueError('Transferred publisher manifest differs from its explicit SHA256')
    published = json.loads(payload)
    if (set(published) != {'version', 'ownerId', 'mode', 'readers', 'replicas'}
            or type(published['version']) is not int or published['version'] != 1
            or published['mode'] != 'pmem' or not isinstance(published['ownerId'], str)
            or len(published['ownerId']) != 32 or any(c not in '0123456789abcdef' for c in published['ownerId'])
            or reader not in service.names(published['readers'])
            or not isinstance(published['replicas'], list)
            or len(published['replicas']) != len(native['layers'])):
        raise ValueError('Publisher generation or configured reader differs')
    entries = []
    seen = set()
    for replica, layer in zip(published['replicas'], native['layers']):
        spec = contract.validate_spec(dict(replica['identity'], socket=socket_path))
        raw.validate_replica(replica, spec)
        if (any(spec[k] != layer[k] for k in ('sha256', 'bytes'))
                or replica['objectName'] in seen):
            raise ValueError('Published content, layer order or distinct allocation identity differs')
        seen.add(replica['objectName'])
        entries.append({'backing': spec})
    contract.validate_catalog({'version': 1, 'objects': entries}, socket_path, logical_budget)
    aligned = sum(replica['mappingBytes'] for replica in published['replicas'])
    if aligned > logical_budget:
        raise ValueError('Imported aligned raw images exceed the explicit logical budget')
    if type(coverage_budget) is not int or coverage_budget < aligned:
        raise ValueError('Coverage guard is below the imported mapping request')
    # Restore hydrates repository archives and pins them in the Runtime. Do not
    # copy or retain publisher-local source paths in another node's binding.
    binding = {'version': 3, 'sourceImage': native['sourceImage'], 'layers': [e['backing'] for e in entries],
               'maxPmemBytes': logical_budget, 'deviceRuntime': runtime, 'lowerFilesystem': native['filesystem']}
    config.update(role='import', readerId=reader, manifest=str(output / 'publisher.json'))
    service.validate_config(config)
    return {'role': 'import', 'binding': binding, 'config': config, 'publisher': published,
            'alignedLogicalBytes': aligned, 'output': str(output), 'publisherManifestSha256': publisher_sha256}


def execute(plan):
    """Create one immutable preparation, then run the existing foreground service.

    A failure leaves the preparation and provider journal for explicit review.
    This does not start AgentENV, restore a Guest, transfer data or delete peers.
    """
    from . import service
    service.ordinary_linux()
    output = fresh_output(plan['output'])
    service.validate_config(plan['config'])
    output.mkdir(mode=0o777 if os.name == 'nt' else 0o700, exist_ok=False)
    files = {'binding.json': plan['binding'], 'provider.json': plan['config']}
    files['image-catalog.json' if plan['role'] == 'publish' else 'publisher.json'] = (
        plan['catalog'] if plan['role'] == 'publish' else plan['publisher'])
    pins = {}
    for name, value in files.items():
        atomic_json(output / name, value)
        pins[name] = service.identity_bytes(output / name)
    atomic_json(output / 'preparation.json', {'version': 1, 'state': 'prepared_no_sdk', 'role': plan['role'],
        'files': pins, 'alignedLogicalBytes': plan['alignedLogicalBytes'],
        'scope': 'immutable preparation receipt, not current SDK execution status',
        'physicalHardQuota': False, 'GuestCreated': False, 'memfilePrivateCowImplemented': False})
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt('Retained publication interrupted; preserve preparation and generation journal')
    signal.signal(signal.SIGTERM, interrupted)
    config = service.load_config(output / 'provider.json')
    selected, manifest = service.inputs(config)
    for name, pin in pins.items():
        if service.identity_bytes(output / name) != pin:
            raise ValueError('Prepared native generation files changed before SDK start')
    execution = output / 'execution.json'
    atomic_json(execution, {'state': 'intent_before_provider_call', 'providerStartRequested': True,
                           'outcome': 'consult provider/owner.json; not a release acknowledgement'})
    try:
        service.serve(config, selected, manifest)
        work = Path(config['workDir'])
        final = read_json(work / 'owner.json')
        published = read_json(work / 'replicas.json')
        if (final.get('role') != plan['role'] or final.get('mode') != 'pmem'
                or final.get('ownerId') != published.get('ownerId')
                or final.get('manifestSha256') != service.identity(published)
                or (manifest is not None and published != manifest)):
            raise RuntimeError('Provider completion belongs to a different generation')
        if (final.get('state') != 'released' or final.get('format') != 'native-raw-v1'
                or final.get('finalize_acknowledged') is not True
                or (plan['role'] == 'publish' and (not final.get('objects') or any(
                    item.get('creation_confirmed') is not True or item.get('delete_acknowledged') is not True
                    for item in final['objects'])))):
            raise RuntimeError('Provider returned without a complete owned-resource release journal')
        if plan['role'] == 'import':
            release = read_json(work / 'release.json')
            if release != {'version': 1, 'ownerId': published['ownerId'], 'readerId': config['readerId'],
                           'manifestSha256': service.identity(published), 'state': 'released'}:
                raise RuntimeError('Importer completion lacks its exact generation release receipt')
    except BaseException as error:
        atomic_json(execution, {'state': 'provider_call_failed_preserve_journal', 'providerStartRequested': True,
                               'errorType': type(error).__name__, 'retryPermitted': False})
        raise
    atomic_json(execution, {'state': 'provider_lifecycle_released', 'providerStartRequested': True,
                           'ownerJournalSha256': service.identity_bytes(Path(config['workDir']) / 'owner.json'),
                           'GuestCreated': False, 'hardwareSharingAccepted': False})
