"""Bind trusted, prebuilt DAX filesystem images to committed source identities."""
from pathlib import Path
import os
import re
from . import contract
from .io import atomic_json, read_json


def fsdax_memory(source, image, virtual_bytes, socket_path, runtime, output):
    """Bind an existing full linear RAM image; FS-DAX is checked on acquisition."""
    contract.validate_device_runtime(runtime)
    path = Path(image).resolve(strict=True)
    spec = contract.make_spec(path, socket_path)
    if type(virtual_bytes) is not int or spec['bytes'] != virtual_bytes:
        raise ValueError('FS-DAX RAM image differs from full snapshot memory layout')
    binding = {'version': 2, 'memoryImage': contract.image_identity(source, virtual_bytes),
               'backing': spec, 'deviceRuntime': runtime}
    output = Path(output)
    output.mkdir(mode=0o777 if os.name == 'nt' else 0o700, exist_ok=False)
    atomic_json(output / 'binding.json', binding)
    atomic_json(output / 'image-catalog.json', {'version': 1,
        'objects': [{'path': str(path), 'backing': spec}]})
    return binding


def rootfs(source, image_paths, socket_path, max_bytes, runtime, output, lower_filesystem='erofs', snapshot_references=False, retain_snapshot_bases=False, fs_dax=False, host_pagecache=False):
    binding, catalog = rootfs_plan(source, image_paths, socket_path, max_bytes, runtime, lower_filesystem,
                                  snapshot_references, retain_snapshot_bases, fs_dax, host_pagecache)
    output = Path(output)
    output.mkdir(mode=0o777 if os.name == 'nt' else 0o700, exist_ok=False)
    atomic_json(output / 'binding.json', binding)
    atomic_json(output / 'image-catalog.json', catalog)
    return binding


def rootfs_plan(source, image_paths, socket_path, max_bytes, runtime, lower_filesystem='erofs', snapshot_references=False, retain_snapshot_bases=False, fs_dax=False, host_pagecache=False):
    """Read prebuilt immutable inputs without publishing a directory or SDK object."""
    if lower_filesystem not in ('erofs', 'ext4'):
        raise ValueError('Native lower filesystem must be erofs or ext4')
    contract.validate_device_runtime(runtime)
    if fs_dax and host_pagecache:
        raise ValueError('Select one explicit Host file backend')
    if retain_snapshot_bases and not (snapshot_references or fs_dax or host_pagecache):
        raise ValueError('Snapshot base archives require portable v3 snapshot references')
    entries = []
    for image in image_paths:
        path = Path(image).resolve(strict=True)
        backing = contract.make_spec(path, socket_path)
        if backing['bytes'] % contract.ALIGN:
            raise ValueError('Prebuilt DAX image must be padded to 2MiB')
        entries.append({'path': str(path), 'backing': backing})
    contract.validate_catalog({'version': 1, 'objects': entries}, socket_path, max_bytes)
    binding = {'version': 5 if host_pagecache else (4 if fs_dax else (3 if snapshot_references else 2)), 'sourceImage': contract.image_identity(source, 0),
               'layers': [entry['backing'] for entry in entries],
               'maxPmemBytes': max_bytes, 'deviceRuntime': runtime,
               'lowerFilesystem': lower_filesystem}
    if retain_snapshot_bases:
        binding['snapshotSources'] = [entry['path'] for entry in entries]
    return binding, {'version': 1, 'objects': entries}


def relocate(binding_path, socket_path, runtime, output, snapshot_sources=None):
    binding = read_json(binding_path)
    required = {'version', 'sourceImage', 'layers', 'maxPmemBytes', 'deviceRuntime'}
    if (not isinstance(binding, dict) or not required <= set(binding)
            or set(binding) - required - {'lowerFilesystem', 'snapshotSources'}
            or type(binding['version']) is not int or binding['version'] not in (2, 3, 4, 5)):
        raise ValueError('Only native rootfs v2/v3/v4/v5 can be relocated')
    lower_filesystem = binding.get('lowerFilesystem', 'erofs')
    if lower_filesystem not in ('erofs', 'ext4'):
        raise ValueError('Native lower filesystem must be erofs or ext4')
    contract.validate_device_runtime(runtime)
    layers = [dict(contract.validate_spec(layer), socket=socket_path) for layer in binding['layers']]
    if any(layer['bytes'] % contract.ALIGN for layer in layers):
        raise ValueError('Invalid relocated pmem alignment')
    contract.validate_catalog({'version': 1, 'objects': [{'backing': layer} for layer in layers]},
                              socket_path, binding['maxPmemBytes'])
    if binding.get('snapshotSources') or snapshot_sources is not None:
        if binding['version'] not in (3, 4, 5) or not isinstance(snapshot_sources, list) or len(snapshot_sources) != len(layers):
            raise ValueError('Relocating archived-capture bindings requires every node-local snapshot source')
        local = []
        for image, layer in zip(snapshot_sources, layers):
            path = Path(image).resolve(strict=True)
            spec = contract.make_spec(path, socket_path)
            if any(spec[key] != layer[key] for key in ('sha256', 'bytes')):
                raise ValueError('Relocated snapshot source content differs')
            local.append(str(path))
        binding['snapshotSources'] = local
    binding.update(layers=layers, deviceRuntime=runtime, lowerFilesystem=lower_filesystem)
    output = Path(output)
    output.mkdir(mode=0o777 if os.name == 'nt' else 0o700, exist_ok=False)
    atomic_json(output / 'binding.json', binding)
    return binding


def retained_metadata(manifest_path, max_bytes):
    """Validate portable archive identity without opening provider or image data."""
    manifest = read_json(manifest_path)
    native = manifest.get('nativeRootfs') if isinstance(manifest, dict) else None
    expected = {'version', 'sourceImage', 'filesystem', 'layers', 'archiveVersion'}
    if (not isinstance(native, dict) or set(native) != expected or type(native['version']) is not int or native['version'] != 1
            or type(native['archiveVersion']) is not int or native['archiveVersion'] != 1 or native['filesystem'] not in ('erofs', 'ext4')
            or not isinstance(native['sourceImage'], str)
            or re.fullmatch(r'sha256:[0-9a-f]{64}', native['sourceImage']) is None
            or not isinstance(native['layers'], list) or not 1 <= len(native['layers']) <= 8
            or type(max_bytes) is not int or max_bytes <= 0):
        raise ValueError('Expected an archived native snapshot manifest and explicit capacity')
    total = 0
    identities = set()
    for layer in native['layers']:
        if (not isinstance(layer, dict) or set(layer) != {'sha256', 'bytes'}
                or not isinstance(layer['sha256'], str)
                or re.fullmatch(r'sha256:[0-9a-f]{64}', layer['sha256']) is None
                or type(layer['bytes']) is not int or layer['bytes'] <= 0 or layer['bytes'] % contract.ALIGN):
            raise ValueError('Malformed native archive layer')
        key = (layer['sha256'], layer['bytes'])
        if key in identities:
            raise ValueError('Duplicate native snapshot content')
        identities.add(key)
        total += layer['bytes']
    if total > max_bytes:
        raise ValueError('Native archive exceeds declared capacity')
    return native


def retained_snapshot_plan(manifest_path, artifact_root, socket_path, max_bytes, runtime, fs_dax=False, host_pagecache=False):
    """Verify every retained base and return a plan without creating files or SDK state."""
    if fs_dax and host_pagecache:
        raise ValueError('Select one explicit Host file backend')
    native = retained_metadata(manifest_path, max_bytes)
    contract.validate_device_runtime(runtime)
    root = Path(artifact_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Snapshot artifact root must be a directory')
    entries = []
    for index, layer in enumerate(native['layers']):
        name = f"{index:02}-{layer['sha256'][7:]}.img"
        path = root / 'native-pmem' / name
        if path.resolve(strict=True) != path or not path.is_file() or path.stat().st_size != layer['bytes']:
            raise ValueError('Native snapshot archive is missing, redirected or truncated')
        spec = contract.make_spec(path, socket_path)
        if any(spec[key] != layer[key] for key in ('sha256', 'bytes')):
            raise ValueError('Native snapshot archive contents differ')
        entries.append({'path': str(path), 'backing': spec})
    contract.validate_catalog({'version': 1, 'objects': entries}, socket_path, max_bytes)
    binding = {'version': 5 if host_pagecache else (4 if fs_dax else 3), 'sourceImage': native['sourceImage'], 'layers': [x['backing'] for x in entries],
               'maxPmemBytes': max_bytes, 'deviceRuntime': runtime, 'lowerFilesystem': native['filesystem'],
               'snapshotSources': [x['path'] for x in entries]}
    return binding, {'version': 1, 'objects': entries}


def retained_snapshot(manifest_path, artifact_root, socket_path, max_bytes, runtime, output, fs_dax=False, host_pagecache=False):
    """Prepare a fresh binding/catalog; publication remains explicit."""
    binding, catalog = retained_snapshot_plan(manifest_path, artifact_root, socket_path, max_bytes, runtime, fs_dax, host_pagecache)
    output = Path(output)
    output.mkdir(mode=0o777 if os.name == 'nt' else 0o700, exist_ok=False)
    atomic_json(output / 'binding.json', binding)
    atomic_json(output / 'image-catalog.json', catalog)
    return binding
