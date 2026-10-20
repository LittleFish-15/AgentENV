#!/usr/bin/env python3
"""Native FD contract tooling. The fixture provider is NOT a UB implementation.

No SDK internals, privilege changes, service management or Guest creation.
Linux is needed only for fixture/probe; binding generation is portable.
"""
import argparse
import array
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import socket
import struct
import sys
import threading

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
    if not isinstance(catalog, dict) or catalog.get('version') != 1:
        raise ValueError('Unsupported fixture catalog')
    entries = catalog.get('objects', [])
    if not 1 <= len(entries) <= 8 or type(budget) is not int or budget <= 0:
        raise ValueError('Invalid fixture allocation budget')
    seen = set()
    total = 0
    for entry in entries:
        spec = validate_spec(entry['backing'])
        if spec['objectId'] in seen or spec['socket'] != socket_path:
            raise ValueError('Duplicate object or provider mismatch')
        seen.add(spec['objectId'])
        total += spec['bytes']
    if total > budget:
        raise ValueError('Fixture allocation exceeds explicit budget')
    return entries


def image_identity(image, virtual_bytes):
    config = json.loads(Path(image).read_text(encoding='utf-8'))
    if any(config.get('upper', {}).get(key) for key in ('data', 'index', 'target')):
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


def prepare(args):
    output = Path(args.output)
    # Linux artifacts are private. Windows uses the caller directory's ACL;
    # Python's Windows mode=0700 ACL is not usable in all sandbox identities.
    output.mkdir(mode=0o777 if os.name == 'nt' else 0o700, parents=False, exist_ok=False)
    entries = []
    for path in args.image:
        path = Path(path).resolve(strict=True)
        spec = make_spec(path, args.socket)
        entries.append({'path': str(path), 'backing': spec})
    if sum(e['backing']['bytes'] for e in entries) > args.max_bytes:
        raise ValueError('Native images exceed explicit byte budget')
    if args.kind == 'memory':
        if len(entries) != 1:
            raise ValueError('Memory requires exactly one full linear image')
        binding = {'version': 1, 'memoryImage': image_identity(args.source, entries[0]['backing']['bytes']),
                   'backing': entries[0]['backing']}
    else:
        if not 1 <= len(entries) <= 8 or any(e['backing']['bytes'] % ALIGN for e in entries):
            raise ValueError('Rootfs needs 1..8 images, each 2MiB aligned')
        if sum(e['backing']['bytes'] for e in entries) > args.max_bytes:
            raise ValueError('pmem address range exceeds explicit budget')
        binding = {'version': 1, 'sourceImage': image_identity(args.source, 0),
                   'layers': [e['backing'] for e in entries], 'maxPmemBytes': args.max_bytes}
    (output / 'binding.json').write_text(json.dumps(binding, indent=2) + '\n', encoding='utf-8')
    (output / 'fixture-catalog.json').write_text(json.dumps({'version': 1, 'objects': entries}, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': 'BINDING_PREPARED_NO_UB_OR_GUEST_EXECUTED',
                      'binding': str(output / 'binding.json'), 'bytes': sum(e['backing']['bytes'] for e in entries)}))


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


def sealed_fixture(path, spec):
    import fcntl
    actual, length = digest_file(path)
    if actual != spec['sha256'] or length != spec['bytes']:
        raise ValueError('Fixture source identity changed')
    fd = os.memfd_create('aenv-native-fixture', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.ftruncate(fd, length)
        digest = hashlib.sha256()
        offset = 0
        with Path(path).open('rb') as stream:
            while offset < length:
                part = stream.read(min(MIB, length - offset))
                if not part:
                    raise ValueError('Fixture source truncated while copying')
                digest.update(part)
                for at in range(0, len(part), 4096):
                    page = part[at:at + 4096]
                    if not any(page):
                        continue
                    view = memoryview(page)
                    done = 0
                    while view:
                        count = os.pwrite(fd, view, offset + at + done)
                        if count <= 0:
                            raise OSError('Short fixture write')
                        view = view[count:]
                        done += count
                offset += len(part)
            if stream.read(1):
                raise ValueError('Fixture source grew while copying')
        if 'sha256:' + digest.hexdigest() != spec['sha256'] or os.fstat(fd).st_size != length:
            raise ValueError('Fixture source changed during copy')
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK
                    | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        return os.open(f'/proc/self/fd/{fd}', os.O_RDONLY | os.O_CLOEXEC)
    finally:
        os.close(fd)


def fixture_server(args):
    linux_only()
    catalog = json.loads(Path(args.catalog).read_text(encoding='utf-8'))
    entries = validate_catalog(catalog, args.socket, args.max_bytes)
    path = Path(args.socket)
    st = path.parent.stat()
    if st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise PermissionError('Fixture socket parent must be owned by this UID and mode 0700')
    if path.exists() or path.is_symlink():
        raise FileExistsError('Preserve existing provider socket; do not replace it')
    objects = {}
    listener = socket.socket(socket.AF_UNIX)
    identity = None
    try:
        for entry in entries:
            spec = entry['backing']
            if spec['socket'] != args.socket or spec['objectId'] in objects:
                raise ValueError('Fixture catalog socket/identity mismatch')
            objects[spec['objectId']] = (spec, sealed_fixture(entry['path'], spec))
        listener.bind(str(path))
        os.chmod(path, 0o600)
        inode = path.stat()
        identity = (inode.st_dev, inode.st_ino)
        listener.listen(16)

        def handle(stream):
            with stream:
                stream.settimeout(10)
                same_uid(stream)
                request = receive_json(stream)
                expected = {'version', 'operation', 'objectId', 'generation', 'sha256', 'bytes', 'privateCow'}
                if set(request) != expected or request['version'] != 1 or request['operation'] != 'acquire':
                    raise ValueError('Unsupported FD acquire request')
                spec, fd = objects[request['objectId']]
                if any(request[k] != spec[k] for k in ('objectId', 'generation', 'sha256', 'bytes')):
                    raise ValueError('Object generation/content mismatch')
                send_json(stream, {'version': 1, 'state': 'ready', 'backing': spec,
                                   'privateCow': True, 'source': 'sealed_memfd_fixture', 'cacheMode': 'local'})
                stream.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
                stream.settimeout(None)
                while stream.recv(1):
                    pass

        print('FIXTURE_PROVIDER_READY_NOT_UB', flush=True)
        while True:
            stream, _ = listener.accept()
            threading.Thread(target=handle, args=(stream,), daemon=True).start()
    finally:
        listener.close()
        for _, fd in objects.values():
            os.close(fd)
        if identity is not None:
            try:
                current = path.stat()
                if (current.st_dev, current.st_ino) == identity:
                    path.unlink()
            except FileNotFoundError:
                pass


def acquire(spec, private_cow=True):
    import fcntl
    validate_spec(spec)
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(10)
    received = []
    try:
        stream.connect(spec['socket'])
        same_uid(stream)
        send_json(stream, {'version': 1, 'operation': 'acquire',
                           **{k: spec[k] for k in ('objectId', 'generation', 'sha256', 'bytes')},
                           'privateCow': private_cow})
        response = receive_json(stream)
        if (response.get('version') != 1 or response.get('state') != 'ready'
                or response.get('backing') != spec or (private_cow and not response.get('privateCow'))
                or (response.get('source'), response.get('cacheMode')) not in
                    (('ub', 'cc'), ('sealed_memfd_fixture', 'local'))):
            raise ValueError('Provider refused required identity/capability')
        data, messages, flags, _ = stream.recvmsg(1, socket.CMSG_SPACE(16 * 4), socket.MSG_CMSG_CLOEXEC)
        for level, kind, payload in messages:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                ints = array.array('i')
                ints.frombytes(payload[:len(payload) - len(payload) % ints.itemsize])
                received.extend(ints)
        if data != b'F' or flags & socket.MSG_CTRUNC or len(received) != 1:
            raise ValueError('Provider must pass exactly one FD')
        fd = received[0]
        if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
            raise ValueError('Provider FD is not read-only')
        if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_SYNC:
            raise ValueError('FC path reopen would lose NC/O_SYNC semantics')
        if response['source'] == 'sealed_memfd_fixture':
            required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
            if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required != required:
                raise ValueError('Fixture FD is not immutable')
        if os.lseek(fd, 0, os.SEEK_END) != spec['bytes']:
            raise ValueError('Provider FD capacity mismatch')
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, stream, response['source']
    except BaseException:
        for fd in received:
            os.close(fd)
        stream.close()
        raise


def probe(args):
    linux_only()
    import ctypes
    import fcntl
    import mmap
    binding = json.loads(Path(args.binding).read_text(encoding='utf-8'))
    spec = binding['backing']
    fd, lease, source = acquire(spec)
    result = {'source': source, 'hardware_ub_verified': False,
              'guest_executed': False, 'kvm_registration': 'NOT_REQUESTED'}
    try:
        if source != 'sealed_memfd_fixture' and not args.owned_test_object:
            raise ValueError('UB private-write probing requires an explicitly owned disposable test object')
        digest = hashlib.sha256()
        remaining = spec['bytes']
        while remaining:
            data = os.pread(fd, min(MIB, remaining), spec['bytes'] - remaining)
            if not data:
                raise EOFError('Native image truncated')
            digest.update(data)
            remaining -= len(data)
        if 'sha256:' + digest.hexdigest() != spec['sha256']:
            raise ValueError('Native FD content identity mismatch')
        with mmap.mmap(fd, spec['bytes'], flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ | mmap.PROT_WRITE) as a:
            with mmap.mmap(fd, spec['bytes'], flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ | mmap.PROT_WRITE) as b:
                before = b[0]
                a[0] = before ^ 0xff
                if b[0] != before or os.pread(fd, 1, 0) != bytes([before]):
                    raise ValueError('Native private write polluted sibling/base')
                result['private_write_isolated'] = True
                if args.kvm:
                    with open('/dev/kvm', 'rb', buffering=0) as kvm:
                        if fcntl.ioctl(kvm, 0xae00, 0) != 12:
                            raise ValueError('Unsupported KVM API version')
                        vm = fcntl.ioctl(kvm, 0xae01, 0)
                        try:
                            pointer = ctypes.addressof(ctypes.c_char.from_buffer(a))
                            region = struct.pack('=IIQQQ', 0, 0, 0x40000000, spec['bytes'], pointer)
                            fcntl.ioctl(vm, 0x4020ae46, region)
                            fcntl.ioctl(vm, 0x4020ae46, struct.pack('=IIQQQ', 0, 0, 0x40000000, 0, 0))
                            result['kvm_registration'] = 'PASSED_NO_VCPU_OR_GUEST_RUN'
                        finally:
                            os.close(vm)
        result['status'] = 'NATIVE_FD_MECHANISM_PROBE_PASSED_NO_PHYSICAL_SHARING_CLAIM'
        print(json.dumps(result, indent=2))
    finally:
        os.close(fd)
        lease.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('kind', choices=('memory', 'rootfs'))
    p.add_argument('--source', required=True, help='committed OverlayBD source image.json')
    p.add_argument('--image', action='append', required=True, help='linear RAM or uncompressed DAX-capable EROFS')
    p.add_argument('--socket', required=True)
    p.add_argument('--max-bytes', type=int, required=True)
    p.add_argument('--output', required=True, help='new private directory')
    p.set_defaults(run=prepare)
    p = sub.add_parser('fixture-server', help='sealed local memfd fixture; never UB')
    p.add_argument('--catalog', required=True)
    p.add_argument('--socket', required=True)
    p.add_argument('--max-bytes', type=int, required=True)
    p.set_defaults(run=fixture_server)
    p = sub.add_parser('probe')
    p.add_argument('--binding', required=True)
    p.add_argument('--kvm', action='store_true', help='register and unregister memory; no vCPU or Guest run')
    p.add_argument('--owned-test-object', action='store_true', help='UB input is owned and disposable, not a published base')
    p.set_defaults(run=probe)
    args = parser.parse_args()
    if getattr(args, 'max_bytes', 1) <= 0:
        parser.error('--max-bytes must be positive')
    args.run(args)


if __name__ == '__main__':
    main()
