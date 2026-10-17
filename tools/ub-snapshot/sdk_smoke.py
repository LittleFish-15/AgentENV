"""One 4MiB NC object through the real SDK bridge and real read-only broker.
No AgentENV service, VM, device permission or existing UB object is modified.
"""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import stat
import subprocess
import sys
import tempfile

DIRECTORY = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('aenv_ub_broker', DIRECTORY / 'ub_layer_broker.py')
b = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = b
spec.loader.exec_module(b)


def probe(replica, broker):
    import hashlib
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(30)
        stream.connect(replica.brokerSocket)
        name = replica.objectName.encode()
        stream.sendall(b.MAGIC + struct.pack('>H', len(name)) + name + bytes.fromhex(replica.generation)
                       + struct.pack('>QQ', replica.fileBytes, replica.mappingBytes)
                       + bytes.fromhex(replica.layerDigest[7:]))
        if b.RESPONSE.unpack(b.recv_exact(stream, 16)) != (b.MAGIC, 0, 0):
            raise ValueError('Broker acquire failed')
        digest = hashlib.sha256()
        for offset in range(0, replica.fileBytes, b.CHUNK):
            length = min(b.CHUNK, replica.fileBytes - offset)
            stream.sendall(struct.pack('>QI', offset, length))
            if b.RESPONSE.unpack(b.recv_exact(stream, 16)) != (b.MAGIC, 0, length):
                raise ValueError('Broker returned incomplete/error payload')
            digest.update(b.recv_exact(stream, length))
        if 'sha256:' + digest.hexdigest() != replica.layerDigest:
            raise ValueError('Broker read bytes differ from the published stored layer')
    with broker.condition:
        if not broker.condition.wait_for(lambda: broker.active == 0, timeout=5):
            raise RuntimeError('Probe reader did not release; do not retire/unmap')


def peer_replica(token):
    if not token or len(token) > 4096:
        raise ValueError('Copy the complete current peer command printed by A')
    data = json.loads(base64.b64decode(token, altchars=b'-_', validate=True))
    replica = b.Replica(**data).validate()
    if replica.mappingBytes != b.ALIGN or replica.fileBytes != b.CHUNK + b.CHUNK // 2:
        raise ValueError('This smoke accepts exactly the one small published test payload')
    return replica


def build(output):
    env = dict(os.environ, TMPDIR=str(output))
    for key in ('LD_PRELOAD', 'LD_AUDIT', 'CPATH', 'CPLUS_INCLUDE_PATH', 'C_INCLUDE_PATH'):
        env.pop(key, None)
    command = ['/usr/bin/g++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
               '-pthread', str(DIRECTORY / 'bridge.cpp'), '/usr/lib64/libubsm_sdk.so',
               '-Wl,-rpath,/usr/lib64', '-o', str(output / 'libaenv_ub_bridge.so')]
    with (output / 'compile.log').open('wb') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, cwd=output,
                                env=env, timeout=180)
    if result.returncode:
        raise RuntimeError('Bridge compile failed: ' + (output / 'compile.log').read_text(errors='replace')[-12000:])


def previous_guard(pending, node):
    if not pending.exists():
        return None
    record = b.read_json(pending)
    if record.get('version') != 1 or record.get('node') != node or record.get('uid') != 1204:
        raise ValueError('Unexpected previous smoke receipt; do not overwrite')
    path = b.check_local_path(record['report_directory'], exists=True)
    if path.parent != b.ROOT / 'relay/reports' or not path.name.startswith(node + '-ub-layer-sdk-'):
        raise ValueError('Unexpected previous smoke report path')
    if record.get('state') not in ('COMPLETE_NO_OWNED_OBJECT', 'PEER_RELEASED', 'FAILED_NO_OBJECT_CREATED'):
        raise ValueError('Previous smoke unresolved; preserve it. Owner cleanup requires peer fully stopped.')
    return record


def main():
    import fcntl
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=['owner', 'peer', 'cleanup'])
    parser.add_argument('node', choices=['node-a', 'node-b'])
    parser.add_argument('--replica-token')
    parser.add_argument('--peer-stopped', action='store_true')
    args = parser.parse_args()
    if (sys.platform != 'linux' or os.getuid() != 1204 or os.geteuid() != 1204
            or os.getgid() != 1205 or os.getegid() != 1205):
        raise SystemExit('Use ordinary original jwk UID1204/GID1205, never root')
    expected_host = 'server1' if args.node == 'node-a' else 'agent1'
    if socket.gethostname() != expected_host or (args.role == 'peer') != (args.node == 'node-b'):
        raise SystemExit('owner/cleanup on server1; peer on agent1 only')
    if args.role == 'owner' and not sys.stdin.isatty():
        raise SystemExit('Owner needs an interactive terminal kept open until B exits')
    caps = [line.split(':')[1].strip() for line in Path('/proc/self/status').read_text().splitlines()
            if line.startswith(('CapInh:', 'CapPrm:', 'CapEff:', 'CapAmb:'))]
    if len(caps) != 4 or any(int(value, 16) for value in caps):
        raise SystemExit('Standalone smoke must have zero capabilities')
    os.umask(0o077)
    b.check_local_path(Path(__file__), exists=True)
    relay = b.check_local_path(b.ROOT / 'relay', exists=True)
    reports = b.check_local_path(relay / 'reports', exists=True)
    lock = os.open(relay / ('ub-layer-sdk-' + args.node + '.lock'),
                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    lock_metadata = os.fstat(lock)
    if not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_uid != 1204 or lock_metadata.st_nlink != 1:
        raise SystemExit('Unexpected smoke lock identity')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    pending = relay / ('ub-layer-sdk-' + args.node + '.pending.json')
    old = b.read_json(pending) if pending.exists() else None
    if args.role != 'cleanup':
        previous_guard(pending, args.node)
    elif not args.peer_stopped or old is None:
        raise SystemExit('Cleanup requires prior owned receipt and --peer-stopped after B completely exits')
    output = Path(tempfile.mkdtemp(prefix=args.node + '-ub-layer-sdk-', dir=reports))
    report = {'version': 1, 'node': args.node, 'hostname': expected_host, 'uid': 1204,
              'role': args.role, 'report_directory': str(output), 'state': 'FAILED_NO_OBJECT_CREATED',
              'status': 'NOT_COMPLETED', 'allocation_calls_observed': 0,
              'scope': 'One small ordinary SDK object and local readonly broker; no ublk/Guest claim'}
    backend = publisher = broker = None
    published = False
    receipt_directory = output
    try:
        with Path('/sys/bus/ub/ub_feature').open() as stream:
            first = stream.readline(513).strip()
        report['ub_feature'] = first
        if not int(first, 0) & 4:
            raise ValueError('Current NC sharing capability is not advertised; no SDK calls')
        build(output)
        report['compile_exit_code'] = 0
        backend = b.NativeBackend(output / 'libaenv_ub_bridge.so')
        if args.role == 'cleanup':
            receipt_directory = b.check_local_path(old['report_directory'], exists=True)
            if receipt_directory.parent != reports or not receipt_directory.name.startswith('node-a-ub-layer-sdk-'):
                raise ValueError('Unexpected old owner report path')
            state = b.read_json(receipt_directory / 'owner-receipt.json')
            if state.get('uid') != 1204 or state.get('version') != 1 or len(state.get('objects', [])) != 1:
                raise ValueError('No exact original owned smoke receipt')
            entry = state['objects'][0]
            if not entry['creation_confirmed'] or entry['delete_acknowledged']:
                raise ValueError('Cleanup needs one confirmed create without a deletion acknowledgement')
            replica = b.Replica(**entry['replica']).validate()
            if replica.mappingBytes != b.ALIGN:
                raise ValueError('Original smoke object length differs')
            mapped = backend.map(replica)
            b.verify_mapping(replica, mapped)
            mapped.close()
            publisher = b.Publisher(backend, receipt_directory / 'owner-receipt.json')
            publisher.state = state
            publisher.cleanup()
            report.update(state='COMPLETE_NO_OWNED_OBJECT', status='UB_LAYER_SDK_CLEANUP_COMPLETED',
                          object_name=replica.objectName, delete_acknowledged=True)
        elif args.role == 'owner':
            source = output / 'test-layer.bin'
            source.write_bytes(os.urandom(b.CHUNK + b.CHUNK // 2))
            import hashlib
            digest = 'sha256:' + hashlib.sha256(source.read_bytes()).hexdigest()
            publisher = b.Publisher(backend, output / 'owner-receipt.json')
            # Persist the report pointer before any SDK call. A process crash
            # must not allow a second random object on the next invocation.
            report['state'] = 'INTENT_BEFORE_SDK'
            b.atomic_json(pending, report)
            replicas, mappings = publisher.publish({digest: (source, source.stat().st_size)},
                                                     output / 'broker.sock', b.ALIGN)
            replica = replicas[0]
            broker = b.Broker(replicas, mappings)
            broker.start(replica.brokerSocket)
            probe(replica, broker)
            publisher.published = published = True
            report.update(state='OWNER_READY_HOLDING', object_name=replica.objectName,
                          generation=replica.generation, allocation_calls_observed=backend.allocation_calls)
            b.atomic_json(pending, report)
            token = base64.urlsafe_b64encode(json.dumps(b.asdict(replica), separators=(',', ':')).encode()).decode()
            print('UB_LAYER_SDK_OWNER_READY', flush=True)
            print('NEXT_ON_AGENT1_AS_JWK:', flush=True)
            print('cd /home/jwk/agent/ub-layer-sdk-smoke-v1', flush=True)
            print('/usr/bin/python3 -I -B sdk_smoke.py peer node-b --replica-token ' + token, flush=True)
            print('Keep A open. After B fully exits, return here and type done.', flush=True)
            while input().strip() != 'done':
                print('Wait for B to fully exit, then type done.', flush=True)
            report['broker_statistics'] = broker.stop()
            broker = None
            publisher.cleanup()
            report.update(state='COMPLETE_NO_OWNED_OBJECT', status='UB_LAYER_SDK_OWNER_COMPLETED',
                          delete_acknowledged=True, mappings_released=True, finalize_acknowledged=True)
        else:
            original = peer_replica(args.replica_token)
            replica = b.replace(original, brokerSocket=str(output / 'broker.sock'))
            report.update(state='INTENT_BEFORE_SDK', object_name=replica.objectName, generation=replica.generation)
            b.atomic_json(pending, report)
            mapped = backend.map(replica)
            b.verify_mapping(replica, mapped)
            broker = b.Broker([replica], [mapped])
            broker.start(replica.brokerSocket)
            probe(replica, broker)
            report['broker_statistics'] = broker.stop()
            broker = None
            backend.close_maps()
            backend.finalize()
            report.update(state='PEER_RELEASED', status='UB_LAYER_SDK_PEER_COMPLETED',
                          mappings_released=True, finalize_acknowledged=True)
        report['allocation_calls_observed'] = backend.allocation_calls
    except BaseException as error:
        report.update(status='STOPPED_UB_LAYER_SDK_SMOKE', error=type(error).__name__ + ': ' + str(error))
        safe_to_release = broker is None
        if broker is not None:
            try:
                broker.stop()
                safe_to_release = True
            except Exception as stop_error:
                report['readers_pending'] = str(stop_error)
        if backend is not None:
            report['allocation_calls_observed'] = backend.allocation_calls
            try:
                if publisher and not published and safe_to_release and args.role != 'cleanup':
                    publisher.cleanup()
                    report['state'] = ('COMPLETE_NO_OWNED_OBJECT' if publisher.state['state'] == 'freed'
                                       else 'OWNERSHIP_UNRESOLVED')
                elif safe_to_release:
                    backend.close_maps()
                    backend.finalize()
                    report['state'] = 'OWNERSHIP_UNRESOLVED' if args.role in ('owner', 'cleanup') else 'PEER_RELEASED'
                else:
                    report['state'] = 'OWNERSHIP_OR_IMPORT_UNRESOLVED'
            except Exception as cleanup_error:
                report.update(state='OWNERSHIP_OR_IMPORT_UNRESOLVED', cleanup_error=str(cleanup_error))
        if args.role == 'cleanup':
            report['old_report_directory'] = str(receipt_directory)
    b.atomic_json(output / 'return.json', report)
    if args.role != 'cleanup' or report['status'] == 'UB_LAYER_SDK_CLEANUP_COMPLETED':
        b.atomic_json(pending, report)
    print('BEGIN_RETURN_REPORT', flush=True)
    print(json.dumps(report, indent=2), flush=True)
    print('END_RETURN_REPORT', flush=True)
    return 0 if report['status'] in ('UB_LAYER_SDK_OWNER_COMPLETED', 'UB_LAYER_SDK_PEER_COMPLETED',
                                   'UB_LAYER_SDK_CLEANUP_COMPLETED') else 1


if __name__ == '__main__':
    try:
        result = main()
    except Exception as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'STOPPED_CONTROLLER_ERROR_PRESERVE_PREVIOUS_RECEIPTS',
                          'error': type(error).__name__ + ': ' + str(error),
                          'SDK_state': 'not inferred from a wrapper/precondition failure'}, indent=2))
        print('END_RETURN_REPORT')
        result = 1
    raise SystemExit(result)
