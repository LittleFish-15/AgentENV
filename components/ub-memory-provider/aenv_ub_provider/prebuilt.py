"""First native generation from already prepared DAX images, before capture.

This does not export, resize, mount or validate a filesystem. The operator must
provide the trusted image-preparation evidence; Runtime still checks Guest DAX.
"""
import hashlib
import json
from pathlib import Path
import re

from . import bindings, contract, retained, service
from .io import read_json


def image_set(path):
    value = read_json(path)
    if (not isinstance(value, dict) or set(value) != {'version', 'images'}
            or type(value['version']) is not int or value['version'] != 1
            or not isinstance(value['images'], list) or not 1 <= len(value['images']) <= 32):
        raise ValueError('Expected 1..32 explicit prebuilt image groups')
    for item in value['images']:
        if (not isinstance(item, dict) or set(item) != {'sourceConfig', 'paths', 'filesystem'}
                or item['filesystem'] not in ('erofs', 'ext4')
                or not isinstance(item['paths'], list) or not 1 <= len(item['paths']) <= 8):
            raise ValueError('Invalid prebuilt image group')
        for name in [item['sourceConfig'], *item['paths']]:
            if not isinstance(name, str) or not Path(name).is_absolute():
                raise ValueError('Prebuilt source paths must be absolute')
            source = Path(name)
            if source.resolve(strict=True) != source or not source.is_file():
                raise ValueError('Prebuilt source is missing or redirected')
    return value['images']


def plan_publish(selection, runtime, output, adapter, adapter_sha256, region, logical_budget, coverage_budget, readers):
    output, socket_path, config = retained.common(output, adapter, adapter_sha256, region, logical_budget, coverage_budget)
    config.update(role='publish', readers=list(readers), catalog=str(output / 'image-catalog.json'))
    service.validate_config(config)
    plans = []
    for item in image_set(selection):
        binding, catalog = bindings.rootfs_plan(item['sourceConfig'], item['paths'], socket_path, logical_budget,
                                               runtime, item['filesystem'], True, True)
        plans.append({'role': 'publish', 'binding': binding, 'catalog': catalog,
                      'config': config, 'output': str(output)})
    result = retained.merge_publications(plans, logical_budget, coverage_budget)
    result['imageCount'] = result.pop('snapshotCount')
    result['inputKind'] = 'prebuilt_dax_images_not_guest_acceptance'
    return result


def plan_import(binding_path, binding_sha256, publisher_path, publisher_sha256, reader, runtime, output,
                adapter, adapter_sha256, region, logical_budget, coverage_budget):
    # The private owner binding is pinned independently from its SDK replica
    # manifest. Import only exact published contents, never owner-local paths.
    with Path(binding_path).open('rb') as stream:
        payload = stream.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024 or 'sha256:' + hashlib.sha256(payload).hexdigest() != binding_sha256:
        raise ValueError('Transferred prebuilt binding differs from its SHA256')
    value = json.loads(payload)
    if (not isinstance(value, dict) or set(value) != {'catalogVersion', 'bindings'}
            or type(value['catalogVersion']) is not int or value['catalogVersion'] != 1
            or not isinstance(value['bindings'], list) or not 1 <= len(value['bindings']) <= 32):
        raise ValueError('Expected explicit native source binding catalog')
    natives = []
    for binding in value['bindings']:
        expected = {'version', 'sourceImage', 'layers', 'maxPmemBytes', 'deviceRuntime', 'lowerFilesystem', 'snapshotSources'}
        if (not isinstance(binding, dict) or set(binding) != expected
                or type(binding['version']) is not int or binding['version'] != 3
                or not isinstance(binding['sourceImage'], str)
                or re.fullmatch(r'sha256:[0-9a-f]{64}', binding['sourceImage']) is None
                or binding['lowerFilesystem'] not in ('erofs', 'ext4')
                or binding['maxPmemBytes'] != logical_budget or type(binding['maxPmemBytes']) is not int
                or not isinstance(binding['layers'], list) or not 1 <= len(binding['layers']) <= 8
                or not isinstance(binding['snapshotSources'], list)
                or len(binding['snapshotSources']) != len(binding['layers'])
                or any(not isinstance(p, str) or not p.startswith('/') for p in binding['snapshotSources'])):
            raise ValueError('Invalid prebuilt capture binding')
        contract.validate_device_runtime(binding['deviceRuntime'])
        layers = [contract.validate_spec(layer) for layer in binding['layers']]
        if any(layer['bytes'] % contract.ALIGN for layer in layers):
            raise ValueError('Prebuilt DAX layer is not 2MiB aligned')
        contract.validate_catalog({'version': 1, 'objects': [{'backing': layer} for layer in layers]},
                                  layers[0]['socket'], logical_budget)
        natives.append({'sourceImage': binding['sourceImage'], 'filesystem': binding['lowerFilesystem'],
                        'layers': [{'sha256': layer['sha256'], 'bytes': layer['bytes']} for layer in layers]})
    result = retained.import_contents(natives, publisher_path, publisher_sha256, reader, runtime, output,
                                      adapter, adapter_sha256, region, logical_budget, coverage_budget)
    result['imageCount'] = result.pop('snapshotCount')
    result['inputKind'] = 'prebuilt_binding_import_not_guest_acceptance'
    return result
