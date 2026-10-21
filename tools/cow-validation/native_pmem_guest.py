#!/usr/bin/env python3
"""Bounded standalone native-pmem Guest mechanism test; never calls the UB SDK.

The provider owns UB publication/retirement separately. This launcher retains its
socket lease until its exact FC child is reaped. No network device, host mount,
service, permissions or kernel changes. Default is a read-only plan.
"""
import argparse
import array
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import socket
import stat
import struct
import sys
import time
import uuid

ALIGN = 2 * 1024 * 1024
PASS = 'AENV_DAX_SELFTEST_PASS pmem_count=1 lower_unchanged=1 private_copyup=1'
MAX_LOG = 16 * 1024 * 1024


def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode), 'Pinned input must be a regular file')
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
        after = os.fstat(stream.fileno())
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    need(stamp(before) == stamp(after) == stamp(path.stat()), 'Pinned input changed while hashing')
    return h.hexdigest(), after.st_size


def validate_spec(spec):
    need(isinstance(spec, dict) and set(spec) == {'objectId', 'generation', 'sha256', 'bytes', 'socket'}, 'Provider spec fields differ')
    for key in ('objectId', 'generation'):
        need(isinstance(spec[key], str) and re.fullmatch(r'[A-Za-z0-9._-]{1,128}', spec[key]), 'Invalid object identity')
    need(isinstance(spec['sha256'], str) and re.fullmatch(r'sha256:[0-9a-f]{64}', spec['sha256']), 'Invalid object SHA256')
    need(type(spec['bytes']) is int and ALIGN <= spec['bytes'] <= 1024**3 and spec['bytes'] % ALIGN == 0, 'Invalid complete pmem capacity')
    path = spec['socket']
    need(isinstance(path, str) and PurePosixPath(path).is_absolute() and '\0' not in path and len(path.encode()) < 108, 'Invalid provider socket path')
    return spec


def validate_config(config):
    required = {'version', 'providerSpec', 'firecracker', 'kernel', 'tools', 'upper', 'expectedProbeSha256'}
    need(isinstance(config, dict) and required <= set(config) <= required | {'memoryMiB', 'timeoutSecs'}, 'Launcher config fields differ')
    need(type(config['version']) is int and config['version'] == 1, 'Unsupported launcher config')
    validate_spec(config['providerSpec'])
    for name in ('firecracker', 'kernel', 'tools', 'upper'):
        item = config[name]
        need(isinstance(item, dict) and {'path', 'sha256'} <= set(item) <= {'path', 'sha256', 'bytes'}, 'Pinned input fields differ')
        need(isinstance(item['path'], str) and PurePosixPath(item['path']).is_absolute() and '\0' not in item['path'], 'Input requires absolute real path')
        need(isinstance(item['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', item['sha256']), 'Input requires explicit lowercase SHA256')
        if 'bytes' in item:
            need(type(item['bytes']) is int and item['bytes'] > 0, 'Invalid pinned input length')
    need(isinstance(config['expectedProbeSha256'], str) and re.fullmatch(r'[0-9a-f]{64}', config['expectedProbeSha256']), 'Missing expected Guest probe SHA256')
    need(type(config.get('memoryMiB', 256)) is int and config.get('memoryMiB', 256) in (128, 256), 'Guest RAM must be 128 or 256MiB')
    need(type(config.get('timeoutSecs', 120)) is int and 1 <= config.get('timeoutSecs', 120) <= 120, 'Timeout exceeds 120s')
    return config


def receive(stream, length):
    result = bytearray()
    while len(result) != length:
        part = stream.recv(length - len(result))
        if not part:
            raise EOFError('Provider closed a bounded handshake')
        result.extend(part)
    return bytes(result)


def send_json(stream, value):
    raw = json.dumps(value, separators=(',', ':')).encode()
    need(len(raw) <= 4096, 'Request exceeds protocol budget')
    stream.sendall(struct.pack('>I', len(raw)) + raw)


def receive_json(stream):
    length = struct.unpack('>I', receive(stream, 4))[0]
    need(1 <= length <= 4096, 'Response exceeds protocol budget')
    return json.loads(receive(stream, length))


def validate_response(response, spec):
    need(isinstance(response, dict) and set(response) == {'version', 'state', 'backing', 'privateCow', 'source', 'cacheMode', 'segmentLengths'}, 'Provider response fields differ')
    need(type(response['version']) is int and response['version'] == 2 and response['state'] == 'ready' and response['backing'] == spec, 'Provider returned another object/generation')
    need(response['privateCow'] is False and response['source'] == 'ub' and response['cacheMode'] == 'nc', 'Native test requires readonly UB NC, without a RAM CoW claim')
    lengths = response['segmentLengths']
    need(isinstance(lengths, list) and 1 <= len(lengths) <= 32 and all(type(n) is int and n > 0 and n % ALIGN == 0 for n in lengths), 'Malformed native segment list')
    need(sum(lengths) == spec['bytes'], 'Segments do not cover complete image')
    return lengths


def receive_fds(stream, expected):
    import fcntl
    received = []
    try:
        payload, ancillary, flags, _ = stream.recvmsg(1, socket.CMSG_SPACE(32 * array.array('i').itemsize), getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        invalid = False
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                size = array.array('i').itemsize
                invalid = invalid or len(data) % size != 0
                values = array.array('i')
                values.frombytes(data[:len(data) // size * size])
                received.extend(values)
            else:
                invalid = True
        need(not invalid, 'Unexpected ancillary record')
        need(payload == b'F' and not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) and len(received) == expected, 'Incomplete or extra FD handoff')
        for fd in received:
            fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            access = fcntl.fcntl(fd, fcntl.F_GETFL)
            need(access & os.O_ACCMODE == os.O_RDONLY and access & os.O_SYNC == os.O_SYNC and stat.S_ISCHR(os.fstat(fd).st_mode), 'FD is not readonly O_SYNC character device')
        return received
    except BaseException:
        for fd in received:
            os.close(fd)
        raise


def acquire(spec):
    import fcntl
    path = Path(spec['socket'])
    need(path.resolve(strict=True) == path and path.parent.stat().st_uid == os.geteuid() and not path.parent.stat().st_mode & 0o077, 'Provider socket parent must be private and owned')
    meta = path.lstat()
    need(stat.S_ISSOCK(meta.st_mode) and meta.st_uid == os.geteuid() and not meta.st_mode & 0o077, 'Provider socket identity/permissions differ')
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    pinned = []
    try:
        stream.settimeout(10)
        stream.connect(str(path))
        peer = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(peer[0] > 0 and peer[1] == os.geteuid(), 'Provider UID differs')
        send_json(stream, {'version': 2, 'operation': 'acquire', 'objectId': spec['objectId'], 'generation': spec['generation'], 'sha256': spec['sha256'], 'bytes': spec['bytes'], 'privateCow': False})
        lengths = validate_response(receive_json(stream), spec)
        received = receive_fds(stream, len(lengths))
        try:
            for fd in received:
                pinned.append(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 512))
        finally:
            for fd in received:
                os.close(fd)
        lease = fcntl.fcntl(stream.fileno(), fcntl.F_DUPFD_CLOEXEC, 512)
        pinned.append(lease)
        stream.settimeout(None)
        descriptor = 'aenv-pmem-fd:v2:' + str(spec['bytes']) + ':nc:' + ','.join(str(64+i) + '@' + str(n) for i, n in enumerate(lengths))
        return stream, pinned[:-1], lease, descriptor, {'pid': peer[0], 'uid': peer[1], 'gid': peer[2]}, lengths
    except BaseException:
        for fd in pinned:
            os.close(fd)
        stream.close()
        raise


def build_fc_config(config, upper, descriptor):
    return {'boot-source': {'kernel_image_path': config['kernel']['path'], 'boot_args':
        'console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/init aenv_pmem_rootfs=1 aenv_pmem_fstype=ext4 aenv_dax_selftest=1'},
        'drives': [{'drive_id': 'tools', 'path_on_host': config['tools']['path'], 'is_root_device': True, 'is_read_only': True, 'io_engine': 'Sync'},
                   {'drive_id': 'upper', 'path_on_host': str(upper), 'is_root_device': False, 'is_read_only': False, 'io_engine': 'Sync'}],
        'machine-config': {'vcpu_count': 1, 'mem_size_mib': config.get('memoryMiB', 256), 'smt': False, 'track_dirty_pages': False},
        'pmem': [{'id': 'base0', 'path_on_host': descriptor, 'root_device': False, 'read_only': True}], 'network-interfaces': []}


def classify(stdout, stderr, expected, exit_code):
    lines = [line.strip('\r') for line in stdout.splitlines()]
    base = re.fullmatch(r'AENV_DAX_SELFTEST_BASE ([0-9a-f]{64})  /mnt/ro0/\.aenv-dax-probe', next((line for line in lines if line.startswith('AENV_DAX_SELFTEST_BASE ')), ''))
    return {'passMarkerObserved': lines.count(PASS) == 1, 'guestProbeHashMatches': bool(base and base[1] == expected),
        'failureMarkerObserved': 'AENV_DAX_SELFTEST_FAIL' in stdout or 'AENV_DAX_SELFTEST_FAIL' in stderr,
        'guestDaxSelftestPassed': exit_code == 0 and lines.count(PASS) == 1 and bool(base and base[1] == expected)
            and 'AENV_DAX_SELFTEST_FAIL' not in stdout and 'AENV_DAX_SELFTEST_FAIL' not in stderr}


def save(path, value):
    temp = path.with_name(path.name + '.new')
    with temp.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def wait_child(pid, seconds):
    deadline = time.monotonic() + seconds
    while True:
        found, status = os.waitpid(pid, os.WNOHANG)
        if found == pid:
            return os.waitstatus_to_exitcode(status)
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.1)


def terminate_child(pid):
    for sig, seconds in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
        code = wait_child(pid, seconds)
        if code is not None:
            return code
    return None


def run(config, output):
    import fcntl
    import resource
    need(sys.platform == 'linux' and os.uname().machine == 'aarch64' and os.getuid() == os.geteuid() != 0, 'Use ordinary ARM64 Linux account')
    caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(caps[k].strip(), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), 'Launcher requires zero capabilities')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    need(resource.getrlimit(resource.RLIMIT_NOFILE)[0] >= 600, 'FD limit too small; no host setting is changed')
    kvm = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        need(stat.S_ISCHR(os.fstat(kvm).st_mode), 'KVM path is not a character device')
    finally:
        os.close(kvm)
    need(output.is_absolute() and output.resolve() == output and not output.exists() and output.parent.is_dir(), 'Output must be a new absolute nonredirected directory')
    need(shutil.disk_usage(output.parent).free >= 2 * 1024**3, 'Need 2GiB free for isolated upper/logs')
    limits = {'firecracker': 256*1024**2, 'kernel': 256*1024**2, 'tools': 512*1024**2, 'upper': 1024**3}
    pinned = {}
    for key, limit in limits.items():
        item = config[key]
        path = Path(item['path'])
        need(path.resolve(strict=True) == path and path.is_file() and 0 < path.stat().st_size <= limit, 'Input path/type/budget differs: ' + key)
        observed, count = digest(path)
        need(observed == item['sha256'] and ('bytes' not in item or count == item['bytes']), 'Input pin differs: ' + key)
        pinned[key] = {'sha256': observed, 'bytes': count}
    required_file_limit = max(MAX_LOG, pinned['upper']['bytes'])
    hard_limit = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
    need(hard_limit == resource.RLIM_INFINITY or hard_limit >= required_file_limit, 'Existing file-size limit is below private upper size')
    resource.setrlimit(resource.RLIMIT_FSIZE, (required_file_limit, required_file_limit))
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    os.umask(0o077)
    output.mkdir(mode=0o700)
    report = {'revision': 'native-pmem-guest-v1', 'state': 'inputs_verified_no_guest', 'SDK_called': False,
        'fullAgentENVIntegrationAccepted': False, 'crossNodeAccepted': False, 'netPhysicalSavingsAccepted': False,
        'safeToRetireThisLease': False, 'pinnedInputs': pinned, 'providerSpec': config['providerSpec']}
    save(output/'return.json', report)
    upper = output/'private-upper.ext4'
    shutil.copyfile(config['upper']['path'], upper)
    need(digest(upper)[0] == pinned['upper']['sha256'], 'Private upper copy differs')
    stream = None
    data = []
    lease = None
    pid = None
    reaped = False
    try:
        stream, data, lease, descriptor, peer, lengths = acquire(config['providerSpec'])
        report.update(state='provider_lease_acquired', providerPeer=peer, segmentLengths=lengths, descriptor=descriptor)
        fc_config = output/'firecracker.json'
        fc_config.write_text(json.dumps(build_fc_config(config, upper, descriptor), indent=2))
        save(output/'return.json', report)
        env = dict(os.environ)
        for key in ('LD_PRELOAD', 'LD_AUDIT'):
            env.pop(key, None)
        with (output/'serial.stdout.log').open('xb') as stdout, (output/'firecracker.stderr.log').open('xb') as stderr, open('/dev/null', 'rb') as stdin:
            actions = [(os.POSIX_SPAWN_DUP2, fd, 64+i) for i, fd in enumerate(data)]
            actions.extend([(os.POSIX_SPAWN_DUP2, lease, 42), (os.POSIX_SPAWN_DUP2, stdin.fileno(), 0),
                (os.POSIX_SPAWN_DUP2, stdout.fileno(), 1), (os.POSIX_SPAWN_DUP2, stderr.fileno(), 2)])
            argv = [config['firecracker']['path'], '--no-api', '--config-file', str(fc_config), '--id', 'native-pmem-' + uuid.uuid4().hex]
            pid = os.posix_spawn(argv[0], argv, env, file_actions=actions, setsid=True)
            report.update(state='owned_firecracker_running', firecrackerPid=pid, Guest_created=True)
            save(output/'return.json', report)
            code = wait_child(pid, config.get('timeoutSecs', 120))
            timed_out = code is None
            if timed_out:
                code = terminate_child(pid)
            reaped = code is not None
            report.update(firecrackerExit=code, timedOut=timed_out, firecrackerReaped=reaped)
        need(reaped, 'FC not definitively reaped; inherited lease remains pinned, preserve all provider resources')
        out, err = output/'serial.stdout.log', output/'firecracker.stderr.log'
        need(out.stat().st_size <= MAX_LOG and err.stat().st_size <= MAX_LOG, 'FC log budget exceeded; Guest result refused')
        report.update(classify(out.read_text(errors='replace'), err.read_text(errors='replace'), config['expectedProbeSha256'], code))
        if timed_out:
            report['guestDaxSelftestPassed'] = False
        for key in ('firecracker', 'kernel', 'tools', 'upper'):
            need(digest(Path(config[key]['path']))[0] == pinned[key]['sha256'], 'Original pinned input changed: ' + key)
        report['state'] = 'native_pmem_guest_mechanism_passed' if report['guestDaxSelftestPassed'] else 'native_pmem_guest_mechanism_failed'
        report['privateUpperBytes'] = upper.stat().st_size
    except BaseException as error:
        if pid is not None and not reaped:
            try:
                code = terminate_child(pid)
                reaped = code is not None
                report.update(firecrackerExit=code, firecrackerReaped=reaped)
            except BaseException:
                pass
        report.update(state='failed_preserve_evidence', errorType=type(error).__name__, reason=str(error)[:1500], guestDaxSelftestPassed=False)
    finally:
        safe = pid is None or reaped
        report['safeToRetireThisLease'] = safe
        if safe:
            for fd in data:
                os.close(fd)
            if lease is not None:
                os.close(lease)
            if stream is not None:
                stream.close()
        report['scope'] = 'Standalone readonly NC pmem/ext4/DAX and private upper mechanism; no RAM CoW or global memory accounting'
        save(output/'return.json', report)
    print(json.dumps(report, indent=2))
    return 0 if report.get('guestDaxSelftestPassed') and report['safeToRetireThisLease'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    path = Path(args.config)
    need(path.is_file() and path.stat().st_size <= 32768, 'Missing/oversize explicit launcher config')
    config = validate_config(json.loads(path.read_text()))
    if not args.run:
        print(json.dumps({'status': 'PLAN_ONLY_NO_GUEST_NO_SDK', 'providerSpec': config['providerSpec'],
            'memoryMiB': config.get('memoryMiB', 256), 'timeoutSecs': config.get('timeoutSecs', 120),
            'Guest_created': False, 'SDK_called': False, 'services_changed': False}, indent=2))
        return 0
    return run(config, Path(args.output).absolute())

if __name__ == '__main__':
    raise SystemExit(main())
