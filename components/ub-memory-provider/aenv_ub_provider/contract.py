"""Native image identity and bounded, same-UID handoff protocol."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import socket
import struct
import sys

MIB = 1024 * 1024
ALIGN = 2 * MIB

def canonical(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()



def validate_spec(spec):
    expected = {'objectId', 'generation', 'sha256', 'bytes', 'socket'}
    if not isinstance(spec, dict) or set(spec) != expected:
        raise ValueError('Unexpected native object fields')
    for key in ('objectId', 'generation'):
        value = spec[key]
        if (not isinstance(value, str) or not 1 <= len(value) <= 128
                or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-' for c in value)):
            raise ValueError('Invalid native object identity')
    digest = spec['sha256']
    if (not isinstance(digest, str) or not digest.startswith('sha256:') or len(digest) != 71
            or any(c not in '0123456789abcdef' for c in digest[7:])):
        raise ValueError('Invalid native object digest')
    if type(spec['bytes']) is not int or spec['bytes'] <= 0 or spec['bytes'] % 4096:
        raise ValueError('Native object size must be a positive page multiple')
    path = spec['socket']
    if (not isinstance(path, str) or not PurePosixPath(path).is_absolute()
            or '\0' in path or len(path.encode()) >= 108):
        raise ValueError('Invalid native provider socket')
    return spec



def validate_catalog(catalog, socket_path, budget):
    if not isinstance(catalog, dict) or type(catalog.get('version')) is not int or catalog.get('version') != 1:
        raise ValueError('Unsupported image catalog')
    entries = catalog.get('objects', [])
    if not 1 <= len(entries) <= 8 or type(budget) is not int or budget <= 0:
        raise ValueError('Invalid image budget')
    seen = set()
    total = 0
    for entry in entries:
        spec = validate_spec(entry['backing'])
        if spec['objectId'] in seen or spec['socket'] != socket_path:
            raise ValueError('Duplicate object or provider mismatch')
        seen.add(spec['objectId'])
        total += spec['bytes']
    if total > budget:
        raise ValueError('Images exceed explicit budget')
    return entries



def image_identity(image, virtual_bytes):
    config = json.loads(Path(image).read_text(encoding='utf-8'))
    if any(config.get('upper', {}).get(key) for key in ('data', 'index', 'target', 'gzipIndex')):
        raise ValueError('Native identity cannot omit a mutable image upper')
    lowers = config['lowers']
    identities = []
    for layer in lowers:
        digest, size = layer['digest'], layer['size']
        if (not isinstance(digest, str) or not digest.startswith('sha256:')
                or len(digest) != 71 or any(c not in '0123456789abcdef' for c in digest[7:])
                or type(size) is not int or size <= 0):
            raise ValueError('Source lower has no committed digest/length')
        identities.append({'digest': digest, 'size': size})
    if not identities:
        raise ValueError('No committed source layers')
    return 'sha256:' + hashlib.sha256(canonical([virtual_bytes, identities])).hexdigest()



def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        before = os.fstat(stream.fileno())
        for part in iter(lambda: stream.read(MIB), b''):
            digest.update(part)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError('Source changed while hashing')
    return 'sha256:' + digest.hexdigest(), after.st_size



def make_spec(path, socket_path):
    digest, length = digest_file(path)
    if not length or length % 4096:
        raise ValueError('Native image must be a non-empty 4KiB multiple')
    if not PurePosixPath(socket_path).is_absolute() or len(socket_path.encode()) >= 108:
        raise ValueError('Provider socket must be an absolute Linux path shorter than 108 bytes')
    return validate_spec({'objectId': 'image-' + digest[7:], 'generation': digest[7:39],
                         'sha256': digest, 'bytes': length, 'socket': socket_path})



def validate_device_runtime(runtime):
    if (not isinstance(runtime, dict) or set(runtime) != {'verifier', 'verifierSha256',
            'firecrackerSha256', 'verificationTimeoutSecs'}
            or not isinstance(runtime['verifier'], str) or not runtime['verifier'].startswith('/')
            or '\0' in runtime['verifier'] or type(runtime['verificationTimeoutSecs']) is not int
            or not 1 <= runtime['verificationTimeoutSecs'] <= 600):
        raise ValueError('Invalid pinned device runtime')
    for key in ('verifierSha256', 'firecrackerSha256'):
        value = runtime[key]
        if (not isinstance(value, str) or len(value) != 71 or not value.startswith('sha256:')
                or any(c not in '0123456789abcdef' for c in value[7:])):
            raise ValueError('Device runtime requires both binary SHA256 pins')
    return runtime



def receive(stream, length):
    result = bytearray()
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise EOFError('Native provider closed connection')
        result.extend(part)
    return bytes(result)



def receive_json(stream):
    length = struct.unpack('>I', receive(stream, 4))[0]
    if length > 4096:
        raise ValueError('Native message exceeds 4096 bytes')
    return json.loads(receive(stream, length))



def send_json(stream, value):
    body = canonical(value)
    if len(body) > 4096:
        raise ValueError('Native message exceeds 4096 bytes')
    stream.sendall(struct.pack('>I', len(body)) + body)



def linux_only():
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise RuntimeError('Run on Linux as an ordinary user; no sudo/root fallback')



def same_uid(stream):
    _, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != os.geteuid():
        raise PermissionError('Native FD connection UID mismatch')
