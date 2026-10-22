"""Bind trusted, prebuilt DAX filesystem images to committed source identities."""
from pathlib import Path
import os
import re
from . import contract
from .io import atomic_json, read_json


def rootfs(source, image_paths, socket_path, max_bytes, runtime, output, lower_filesystem='erofs', snapshot_references=False, retain_snapshot_bases=False):
    if lower_filesystem not in ('erofs', 'ext4'):
        raise ValueError('Native lower filesystem must be erofs or ext4')
    contract.validate_device_runtime(runtime)
    if retain_snapshot_bases and not snapshot_references:
        raise ValueError('Snapshot base archives require portable v3 snapshot references')
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
    if retain_snapshot_bases:
        binding['snapshotSources'] = [entry['path'] for entry in entries]
    output = Path(output)
    output.mkdir(mode=0o777 if os.name == 'nt' else 0o700, exist_ok=False)
    atomic_json(output / 'binding.json', binding)
    atomic_json(output / 'image-catalog.json', {'version': 1, 'objects': entries})
    return binding


def relocate(binding_path, socket_path, runtime, output, snapshot_sources=None):
    binding = read_json(binding_path)
    required = {'version', 'sourceImage', 'layers', 'maxPmemBytes', 'deviceRuntime'}
    if (not isinstance(binding, dict) or not required <= set(binding)
            or set(binding) - required - {'lowerFilesystem', 'snapshotSources'}
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
    if binding.get('snapshotSources') or snapshot_sources is not None:
        if binding['version'] != 3 or not isinstance(snapshot_sources, list) or len(snapshot_sources) != len(layers):
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


def retained_snapshot(manifest_path, artifact_root, socket_path, max_bytes, runtime, output):
    """Prepare a new publication catalog from repository-owned immutable bases.

    Does not allocate UB or start a service. The normal publisher and Runtime
    still acquire a fresh generation and independently verify its contents.
    """
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
    contract.validate_device_runtime(runtime)
    root = Path(artifact_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Snapshot artifact root must be a directory')
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
    binding = {'version': 3, 'sourceImage': native['sourceImage'], 'layers': [x['backing'] for x in entries],
               'maxPmemBytes': max_bytes, 'deviceRuntime': runtime, 'lowerFilesystem': native['filesystem'],
               'snapshotSources': [x['path'] for x in entries]}
    output = Path(output)
    output.mkdir(mode=0o777 if os.name == 'nt' else 0o700, exist_ok=False)
    atomic_json(output / 'binding.json', binding)
    atomic_json(output / 'image-catalog.json', {'version': 1, 'objects': entries})
    return binding
