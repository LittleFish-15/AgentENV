"""Temporary relay runner: real UB layers on A only; no B, Guest or service actions.

Run from the existing reviewed Git checkout as ordinary jwk:
  python3 -I -B dev-relay/run_a_local_layers.py
Reuses the already built b019f27 probe; does not install or download anything.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile

ROOT = Path('/home/jwk/agent')
SOURCE = ROOT / 'src/agentenv-ub-0118ebb'
ARTIFACTS = ROOT / 'relay/reports/node-a-ub-layers-build-qkkuxbta/artifacts'
PROBE_SHA = '29deca236ce60815cecc89b4513392e7c7dcfa635f97fc21a289db7c5a159373'
SOURCE_COMMIT = 'b019f270a6c4359db0ad65ef669dd0e479056603'
HELPERS = {
    'sdk_smoke.py': 'e16f672f6a0dbfc83a4b013aed76adb14904f5322fcded305c0614d095f8967f',
    'ub_layer_broker.py': 'd111bf915fea62e6d6cbf450734a5c4e256346b3c7f820f7e69b3384ed1b5dfb',
    'bridge.cpp': '503a5f64d93568e7b536410a4c89bbefa637fc38fbab781bcc138bf89cedba84',
}


def checked(path):
    path = Path(path).absolute()
    if not path.is_relative_to(ROOT) or path.resolve(strict=True) != path:
        raise ValueError('Use existing paths below /home/jwk/agent without redirection')
    return path


def load_helpers():
    directory = checked(SOURCE / 'tools/ub-snapshot')
    for name, digest in HELPERS.items():
        path = checked(directory / name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Existing helper differs from reviewed source: ' + name)
    spec = importlib.util.spec_from_file_location('a_local_reviewed_smoke', directory / 'sdk_smoke.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_case(s, program, fixtures, reports, pending, library, stored_format):
    b = s.b
    s.previous_guard(pending, 'node-a')
    output = Path(tempfile.mkdtemp(prefix='node-a-ub-layer-sdk-', dir=reports))
    report = {'version': 1, 'node': 'node-a', 'hostname': 'server1', 'uid': 1204,
              'role': 'owner-local-only', 'stored_format': stored_format,
              'report_directory': str(output), 'state': 'FAILED_NO_OBJECT_CREATED',
              'status': 'NOT_COMPLETED', 'SDK_runtime_started': False,
              'allocation_calls_observed': 0, 'cross_node_validation_executed': False,
              'Guest_or_ublk_tests_executed': False,
              'physical_increment_measured': False, 'independent_global_absence_query': False,
              'system_configuration_or_permissions_modified': False}
    backend = publisher = broker = None
    test_completed = False
    try:
        sources = b.source_layers([fixtures / (stored_format + '-image.json')])
        if len(sources) != 1:
            raise ValueError('A-only acceptance allows exactly one layer/object at a time')
        if any(size + b.HEADER_BYTES > b.ALIGN for _, size in sources.values()):
            raise ValueError('Fixture exceeds one 4MiB logical request; no SDK call')
        backend = b.NativeBackend(library)
        publisher = b.Publisher(backend, output / 'owner-receipt.json')
        report['state'] = 'INTENT_BEFORE_SDK'
        b.atomic_json(pending, report)
        report['SDK_runtime_started'] = True
        replicas, mappings = publisher.publish(sources, output / 'broker.sock', b.ALIGN)
        replica = replicas[0]
        report.update(object_name=replica.objectName, generation=replica.generation,
                      requested_bytes=replica.mappingBytes, stored_bytes=replica.fileBytes)
        # No token/index is exported to another process except the local probe.
        # The synchronous probe must exit before retirement; stop checks leases.
        broker = b.Broker(replicas, mappings)
        broker.start(replica.brokerSocket)
        s.probe(replica, broker)
        s.format_probe(program, replica, output, report)
        s.probe(replica, broker)
        report['base_verified_after_local_probe_exit'] = True
        test_completed = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        safe_to_release = broker is None
        if broker is not None:
            try:
                report['broker_statistics'] = broker.stop()
                safe_to_release = True
            except BaseException as error:
                report['readers_pending'] = type(error).__name__ + ': ' + str(error)
        if publisher is not None and report['SDK_runtime_started']:
            if safe_to_release:
                try:
                    publisher.cleanup()
                    report.update(state='COMPLETE_NO_OWNED_OBJECT',
                                  delete_acknowledged=all(e['delete_acknowledged'] for e in publisher.state['objects']),
                                  mappings_released=True, finalize_acknowledged=True)
                except BaseException as error:
                    report.update(state='OWNERSHIP_OR_IMPORT_UNRESOLVED',
                                  cleanup_error=type(error).__name__ + ': ' + str(error))
            else:
                report['state'] = 'OWNERSHIP_OR_IMPORT_UNRESOLVED'
        if backend is not None:
            report['allocation_calls_observed'] = backend.allocation_calls
            report['mapping_backing_coverage_bytes'] = [getattr(m, 'backing_coverage', None)
                                                       for m in backend.mappings]
        report['status'] = ('UB_LAYER_A_LOCAL_FORMAT_COMPLETED'
                            if test_completed and report['state'] == 'COMPLETE_NO_OWNED_OBJECT'
                            else 'STOPPED_A_LOCAL_FORMAT')
        b.atomic_json(output / 'return.json', report)
        # On failure this preserves unresolved ownership; never move/remove the
        # original global receipt to bypass SDK or previous-owner protection.
        b.atomic_json(pending, report)
    return report


def run_suite(s, program, fixtures, reports, pending, library):
    results = []
    for stored_format in ('raw', 'tar', 'zfile'):
        print('PHASE=A_local_real_format format=' + stored_format, flush=True)
        result = run_case(s, program, fixtures, reports, pending, library, stored_format)
        results.append(result)
        if result['status'] != 'UB_LAYER_A_LOCAL_FORMAT_COMPLETED':
            break
    return results


def main():
    if (sys.platform != 'linux' or socket.gethostname() != 'server1'
            or os.getuid() != 1204 or os.geteuid() != 1204
            or os.getgid() != 1205 or os.getegid() != 1205):
        raise ValueError('A/server1 only, ordinary jwk UID1204/GID1205; never root')
    caps = [line.split(':')[1].strip() for line in Path('/proc/self/status').read_text().splitlines()
            if line.startswith(('CapInh:', 'CapPrm:', 'CapEff:', 'CapAmb:'))]
    if len(caps) != 4 or any(int(value, 16) for value in caps):
        raise ValueError('Run directly as ordinary jwk with zero capabilities')
    os.umask(0o077)
    s = load_helpers()
    program = checked(ARTIFACTS / 'ub_layer_probe')
    if (not program.is_file() or not os.access(program, os.X_OK)
            or hashlib.sha256(program.read_bytes()).hexdigest() != PROBE_SHA):
        raise ValueError('Built ARM64 probe identity/executable precondition failed; preserve files')
    reports = checked(ROOT / 'relay/reports')
    pending = ROOT / 'relay/ub-layer-sdk-node-a.pending.json'
    import fcntl
    fd = os.open(ROOT / 'relay/ub-layer-sdk-node-a.lock',
                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 1204 or metadata.st_nlink != 1:
            raise ValueError('Unexpected original SDK lock; preserved')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        s.previous_guard(pending, 'node-a')
        with Path('/sys/bus/ub/ub_feature').open() as stream:
            feature = stream.readline(513).strip()
        if not int(feature, 0) & 4:
            raise ValueError('Current NC sharing capability not advertised; no SDK calls')
        work = Path(tempfile.mkdtemp(prefix='node-a-ub-layer-local-', dir=reports))
        s.build(work)
        library = work / 'libaenv_ub_bridge.so'
        fixtures = work / 'fixtures'
        prepared = subprocess.run([str(program), 'prepare', str(fixtures)],
                                  capture_output=True, text=True, timeout=180,
                                  env=dict(os.environ, TMPDIR=str(work)))
        if prepared.returncode:
            raise RuntimeError('Fixture preparation failed before SDK calls: '
                               + prepared.stdout[-4000:] + prepared.stderr[-12000:])
        cases = run_suite(s, program, fixtures, reports, pending, library)
        passed = len(cases) == 3 and all(r['status'] == 'UB_LAYER_A_LOCAL_FORMAT_COMPLETED' for r in cases)
        report = {'revision': 'a-local-layers-v1', 'node': 'node-a', 'hostname': 'server1',
                  'uid': 1204, 'source_commit': SOURCE_COMMIT,
                  'status': 'A_LOCAL_UB_FORMATS_COMPLETED_NO_CROSS_NODE_CLAIM' if passed else 'STOPPED_A_LOCAL_LAYERS',
                  'report_directory': str(work), 'ub_feature': feature,
                  'probe_sha256': PROBE_SHA,
                  'bridge_sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
                  'fixture_prepare_exit_code': prepared.returncode, 'formats': cases,
                  'service_started': False, 'cross_node_validation_executed': False,
                  'Guest_or_ublk_tests_executed': False,
                  'scope': 'Real SDK, actual Rust OverlayBD formats, two local private uppers and durable child reopen on A only',
                  'next_action': 'Return this full report; B stays paused. No unresolved-resource retry or permission changes.'}
        s.b.atomic_json(work / 'return.json', report)
        print('BEGIN_RETURN_REPORT')
        print(json.dumps(report, indent=2))
        print('END_RETURN_REPORT')
        return 0 if passed else 1
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        exit_code = main()
    except BaseException as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'STOPPED_A_LOCAL_ENTRY_PRESERVE_RECEIPTS',
                          'error': type(error).__name__ + ': ' + str(error),
                          'SDK_state': 'Do not infer cleanup from an entry/precondition failure; preserve original receipts',
                          'cross_node_validation_executed': False}, indent=2))
        print('END_RETURN_REPORT')
        exit_code = 1
    raise SystemExit(exit_code)
