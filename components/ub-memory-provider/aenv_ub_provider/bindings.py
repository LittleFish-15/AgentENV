"""Bind trusted, prebuilt DAX filesystem images to committed source identities."""
from pathlib import Path
import os
from . import contract
from .io import atomic_json, read_json


def rootfs(source, image_paths, socket_path, max_bytes, runtime, output, lower_filesystem='erofs', snapshot_references=False):
    if lower_filesystem not in ('erofs', 'ext4'):
        raise ValueError('Native lower filesystem must be erofs or ext4')
    contract.validate_device_runtime(runtime)
    entries = []
    for image in image_paths:
        path = Path(image).resolve(strict=True)
        backing = contract.make_spec(path, socket_path)
        if backing['bytes'] % contract.ALIGN:
            raise ValueError('Prebuilt DAX image must be padded to 2MiB')
        entries.append({'path': str(path), 'backing': backing})
    contract.validate_catalog({'version': 1, 'objects': entries}, socket_path, max_bytes)
    binding = {'version': 3 if snapshot_references else 2, 'sourceImage': contract.image_identity(source, 0),
               'layers': [entry['backing'] for entry in entries],
               'maxPmemBytes': max_bytes, 'deviceRuntime': runtime,
               'lowerFilesystem': lower_filesystem}
    output = Path(output)
    output.mkdir(mode=0o777 if os.name == 'nt' else 0o700, exist_ok=False)
    atomic_json(output / 'binding.json', binding)
    atomic_json(output / 'image-catalog.json', {'version': 1, 'objects': entries})
    return binding


def relocate(binding_path, socket_path, runtime, output):
    binding = read_json(binding_path)
    required = {'version', 'sourceImage', 'layers', 'maxPmemBytes', 'deviceRuntime'}
    if (not isinstance(binding, dict) or not required <= set(binding)
            or set(binding) - required - {'lowerFilesystem'}
            or type(binding['version']) is not int or binding['version'] not in (2, 3)):
        raise ValueError('Only native device rootfs v2/v3 can be relocated')
    lower_filesystem = binding.get('lowerFilesystem', 'erofs')
    if lower_filesystem not in ('erofs', 'ext4'):
        raise ValueError('Native lower filesystem must be erofs or ext4')
    contract.validate_device_runtime(runtime)
    layers = [dict(contract.validate_spec(layer), socket=socket_path) for layer in binding['layers']]
    if any(layer['bytes'] % contract.ALIGN for layer in layers):
        raise ValueError('Invalid relocated pmem alignment')
    contract.validate_catalog({'version': 1, 'objects': [{'backing': layer} for layer in layers]},
                              socket_path, binding['maxPmemBytes'])
    binding.update(layers=layers, deviceRuntime=runtime, lowerFilesystem=lower_filesystem)
    output = Path(output)
    output.mkdir(mode=0o777 if os.name == 'nt' else 0o700, exist_ok=False)
    atomic_json(output / 'binding.json', binding)
    return binding
