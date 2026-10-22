"""Multiplex only bounded coordinator JSON over an authenticated SSH command.

No TCP listener, SSH forwarding permission, SDK call or payload transfer. Lost
responses are never retried; the cache owner's durable pin journal stays authoritative.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import stat
import struct
import subprocess
import sys
import threading

ROOT = Path('/home/jwk/agent')
OWNER = ROOT / 'r/lazy4-a-v1/provider/coordinator.sock'
PEER = ROOT / 'r/lazy4-b-v1/metadata.sock'
MAX = 4096
HEADER = struct.Struct('>QI')


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def exact(stream, size):
    parts = bytearray()
    while len(parts) < size:
        part = stream.recv(size - len(parts)) if hasattr(stream, 'recv') else stream.read(size - len(parts))
        if not part:
            raise EOFError('Metadata transport closed; no retry')
        parts.extend(part)
    return bytes(parts)


def frame(stream):
    identity, length = HEADER.unpack(exact(stream, HEADER.size))
    need(0 < identity < 2**63 and 0 < length <= MAX, 'Invalid bounded metadata frame')
    return identity, exact(stream, length)


def body(raw):
    need(0 < len(raw) <= MAX and isinstance(json.loads(raw), dict), 'Expected bounded JSON object')
    return raw


def send(stream, mutex, identity, raw):
    raw = body(raw)
    with mutex:
        stream.write(HEADER.pack(identity, len(raw)) + raw)
        stream.flush()


def peer_uid(client):
    _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(uid == os.geteuid() == 1204, 'Unexpected coordinator peer UID')


def identity(host):
    need(os.name == 'posix' and os.getuid() == os.geteuid() == 1204 and socket.gethostname() == host,
         'Use declared ordinary jwk node')
    os.umask(0o077)


def owner_request(raw, endpoint=OWNER):
    body(raw)
    meta = endpoint.lstat()
    need(endpoint.resolve(strict=True) == endpoint and stat.S_ISSOCK(meta.st_mode)
         and meta.st_uid == 1204 and not meta.st_mode & 0o077, 'Owner coordinator endpoint changed')
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(60)
        client.connect(str(endpoint))
        peer_uid(client)
        client.sendall(struct.pack('>I', len(raw)) + raw)
        length = struct.unpack('>I', exact(client, 4))[0]
        need(0 < length <= MAX, 'Oversized coordinator reply')
        return body(exact(client, length))


def serve_owner(incoming, outgoing, request=owner_request):
    writer = threading.Lock()
    slots = threading.BoundedSemaphore(64)
    active, lock = set(), threading.Lock()
    def reply(identity, raw):
        try:
            try:
                answer = request(raw)
            except Exception:
                answer = b'{"state":"error"}'
            send(outgoing, writer, identity, answer)
        finally:
            with lock:
                active.remove(identity)
            slots.release()
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        try:
            while True:
                identity, raw = frame(incoming)
                body(raw)
                with lock:
                    need(identity not in active and slots.acquire(False), 'Duplicate or excessive metadata request')
                    active.add(identity)
                pool.submit(reply, identity, raw)
        except EOFError:
            pass


def listen_peer(incoming, outgoing, path=PEER):
    need(path.parent.resolve(strict=True) == path.parent and path.parent.stat().st_uid == 1204,
         'Unexpected metadata directory')
    need(not path.exists() and not path.is_symlink(), 'Previous metadata endpoint preserved')
    pending, mutex, writer = {}, threading.Lock(), threading.Lock()
    stopped = threading.Event()
    sequence = 0
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(path)); os.chmod(path, 0o600)
    inode = path.stat().st_ino
    listener.listen(64); listener.settimeout(0.5)
    def response_loop():
        try:
            while True:
                identifier, raw = frame(incoming)
                body(raw)
                with mutex:
                    need(identifier in pending, 'Unexpected metadata response; no retry')
                    waiter = pending[identifier]
                    need(waiter['raw'] is None, 'Duplicate metadata response')
                    waiter['raw'] = raw
                    waiter['event'].set()
        except (OSError, EOFError, ValueError, RuntimeError):
            stopped.set()
            with mutex:
                for waiter in pending.values():
                    waiter['event'].set()
    reader = threading.Thread(target=response_loop, daemon=True)
    reader.start()
    slots = threading.BoundedSemaphore(64)
    def session(client, identifier):
        event = threading.Event()
        waiter = {'event': event, 'raw': None}
        try:
            with client:
                client.settimeout(65)
                peer_uid(client)
                length = struct.unpack('>I', exact(client, 4))[0]
                need(0 < length <= MAX, 'Invalid coordinator request length')
                raw = body(exact(client, length))
                with mutex:
                    need(not stopped.is_set(), 'Metadata transport stopped')
                    pending[identifier] = waiter
                send(outgoing, writer, identifier, raw)
                need(event.wait(65) and waiter['raw'] is not None, 'Metadata reply unknown; preserve owner pins')
                client.sendall(struct.pack('>I', len(waiter['raw'])) + waiter['raw'])
        except (OSError, EOFError, RuntimeError, ValueError):
            pass
        finally:
            with mutex:
                pending.pop(identifier, None)
            slots.release()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            while not stopped.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                if not slots.acquire(False):
                    client.close(); continue
                sequence += 1
                pool.submit(session, client, sequence)
    finally:
        stopped.set(); listener.close()
        if path.exists() and path.lstat().st_ino == inode:
            path.unlink()


def run_ssh():
    identity('server1')
    helper = Path(__file__).resolve(strict=True)
    need(helper == ROOT / 'lazy-four/lazy_four_transport.py', 'Unexpected transport installation')
    pin = hashlib.sha256(helper.read_bytes()).hexdigest()
    code = ('import hashlib,os,socket,sys;from pathlib import Path;'
            'assert os.getuid()==os.geteuid()==1204 and socket.gethostname()=="agent1";'
            'p=Path(' + repr(str(helper)) + ');assert p.resolve(strict=True)==p and p.stat().st_uid==1204;'
            'raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==' + repr(pin) + ';'
            'sys.argv=[str(p),"listen-b"];exec(compile(raw,str(p),"exec"),{"__name__":"__main__","__file__":str(p)})')
    ssh = ['/usr/bin/ssh', '-F', '/dev/null', '-i', '/home/jwk/.ssh/agentenv-native-four/id_ed25519',
           '-oIdentitiesOnly=yes', '-oIdentityAgent=none', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
           '-oUserKnownHostsFile=/home/jwk/.ssh/agentenv-native-four/known_hosts',
           '-oGlobalKnownHostsFile=/dev/null', '-oUpdateHostKeys=no', '-oHostKeyAlgorithms=ssh-ed25519',
           '-oForwardAgent=no', '-oClearAllForwardings=yes', '-oRequestTTY=no',
           '-oConnectTimeout=10', '-oServerAliveInterval=15', '-oServerAliveCountMax=4', 'jwk@agent1',
           shlex.join(['/usr/bin/python3', '-I', '-B', '-c', code])]
    child = subprocess.Popen(ssh, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        serve_owner(child.stdout, child.stdin)
        code = child.wait(timeout=10)
        need(code == 0, 'SSH metadata transport exited; reconcile unknown pins before restart')
    finally:
        child.stdin.close(); child.stdout.close()
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('owner-a', 'listen-b'))
    args = parser.parse_args()
    if args.mode == 'owner-a':
        run_ssh()
    else:
        identity('agent1')
        listen_peer(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == '__main__':
    main()
