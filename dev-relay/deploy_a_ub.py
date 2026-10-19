"""Temporary A-only isolated deployment; install never starts services or calls UB.

Run as jwk: python3 -I -B dev-relay/deploy_a_ub.py install
A separately reviewed root block creates only the precise new transient unit.
"""
import argparse
import asyncio
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path('/home/jwk/agent')
NODE = 'node-a'
EXPECTED_HOST = 'server1'
STATUS_PREFIX = 'A_UB'
BASE = ROOT / 'deployments/agentenv-ae9c626-baseline'
D = ROOT / 'deployments/agentenv-ub-b019f27'
RUNTIME = ROOT / 'r/ub-a-b019'
UNIT = 'jwk-aenv-ub-b019f27-node-a.service'
OLD_UNIT = 'jwk-aenv-ae9c626-node-a.service'
PORT = 18081
CAPS = (1 << 21) | (1 << 12)
REVISION = 'aenv-ub-isolated-a-v1'
COMMIT = 'b019f270a6c4359db0ad65ef669dd0e479056603'
ARTIFACTS = ROOT / 'relay/reports/node-a-ub-layers-build-qkkuxbta/artifacts'
BINARIES = {
    'server': 'e8ea6c30704ec511f0b2a479313bb4cd4f71d25adc5acb6548adafe5f980b231',
    'aenv': 'be2c3b339bf077e66d6646c1ecafdf38392a4c2ca327cd6a26ab5433afc66546',
    'uvm-ublk-daemon': '6d73405d4d30777355c43df68361616c9ff2639cbc0347fd8dec4c56b93e5879',
}
LAUNCHER = D / 'libexec/deploy_a_ub.py'

def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def safe(path, exists=False):
    path = Path(path)
    require(path.is_absolute() and path.is_relative_to(ROOT) and (path.resolve() == path), 'Path outside/redirected from workspace: ' + str(path))
    if path.exists():
        m = path.lstat()
        require(m.st_uid == 1204 and (not stat.S_ISLNK(m.st_mode)), 'Unexpected file owner/type: ' + str(path))
    elif exists:
        raise RuntimeError('Missing input: ' + str(path))
    return path


def mkdir(path):
    safe(path)
    path.mkdir(parents=True, exist_ok=True, mode=448)
    require(path.is_dir(), 'Not a directory: ' + str(path))


def put(path, data, mode=384):
    safe(path)
    mkdir(path.parent)
    if path.exists():
        require(path.is_file() and path.read_bytes() == data, 'Existing different file preserved: ' + str(path))
        require(path.stat().st_mode & 511 == mode, 'Existing file mode differs: ' + str(path))
        return
    fd, name = tempfile.mkstemp(prefix='.new-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.link(name, path)
    finally:
        os.unlink(name)


def dump(path, value):
    put(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


def load(path):
    return json.loads(safe(path, True).read_text())


def caps(pid='self'):
    return {a: int(b.strip(), 16) for line in Path('/proc/' + str(pid) + '/status').read_text().splitlines() if ':' in line for a, b in [line.split(':', 1)] if a.startswith('Cap')}


def no_caps():
    require(all((caps().get(k, 0) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))), 'Install/health must run without capabilities in the normal jwk session')


def run(args, env=None, timeout=25):
    p = subprocess.run([str(x) for x in args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, text=True, errors='replace', timeout=timeout)
    return (p.returncode, p.stdout)


def drop_caps():

    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(47, 4, 0, 0, 0) == 0, 'Cannot clear proxy ambient capabilities')
    header, data = (Header(537396514, 0), (Data * 2)())
    require(libc.capset(ctypes.byref(header), ctypes.byref(data)) == 0, 'Cannot clear proxy capabilities')
    no_caps()


async def relay(reader, writer, peer_reader, peer_writer):

    async def pump(source, destination):
        try:
            while True:
                data = await source.read(65536)
                if not data:
                    if destination.can_write_eof():
                        destination.write_eof()
                    break
                destination.write(data)
                await destination.drain()
        except (OSError, ConnectionError, asyncio.CancelledError):
            pass
    try:
        await asyncio.wait_for(asyncio.gather(pump(reader, peer_writer), pump(peer_reader, writer)), 300)
    except (TimeoutError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        peer_writer.close()


def process_identity(pid):
    status = Path('/proc/' + str(pid) + '/status').read_text().splitlines()
    fields = dict((line.split(':', 1) for line in status if ':' in line))
    values = {'pid': pid, 'uid': [int(x) for x in fields['Uid'].split()], 'gid': [int(x) for x in fields['Gid'].split()], 'caps': caps(pid)}
    for field, path, reader in (('netns', '/proc/' + str(pid) + '/ns/net', lambda p: os.stat(p).st_ino), ('mntns', '/proc/' + str(pid) + '/ns/mnt', lambda p: os.stat(p).st_ino), ('exe', '/proc/' + str(pid) + '/exe', os.readlink)):
        try:
            values[field] = reader(path)
        except PermissionError:
            values[field] = 'PTRACE_ACCESS_DENIED'
    values['start_ticks'] = Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()[19]
    return values


def identity():
    require(sys.platform == 'linux' and socket.gethostname() == EXPECTED_HOST, 'Expected original host ' + EXPECTED_HOST)
    require(os.getuid() == os.geteuid() == 1204 and os.getgid() == os.getegid() == 1205,
            'Run as ordinary jwk UID1204/GID1205, never root')
    require(os.uname().machine == 'aarch64', 'Expected original ARM64 A')
    require(os.environ.get('HOME') == '/home/jwk', 'Keep normal jwk HOME')
    safe(ROOT, True)
    os.umask(0o077)


def environment():
    return {'HOME': '/home/jwk', 'USER': 'jwk', 'LOGNAME': 'jwk', 'LANG': 'C.UTF-8',
            'PATH': str(D / 'native/bin') + ':/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin',
            'LD_LIBRARY_PATH': str(D / 'native/lib') + ':' + str(D / 'native/fallback/lib'),
            'XTABLES_LIBDIR': str(D / 'native/xtables'), 'TMPDIR': str(D / 'tmp'),
            'XDG_CACHE_HOME': str(D / 'cache'), 'DOCKER_CONFIG': str(D / 'config/docker'),
            'AENV_HOME_PATH': str(D / 'state'), 'AENV_DEPS_PATH': str(D / 'deps'),
            'AENV_RUNTIME_PATH': str(RUNTIME), 'RUST_LOG': 'info',
            'API_ADDR': '127.0.0.1:' + str(PORT)}


def config_text():
    return f'''home_path = "{D}/state"
runtime_path = "{RUNTIME}"
deps_path = "{D}/deps"
virtualization_mode = "kvm"
[firecracker]
binary_path = "{D}/deps/firecracker/1.15.1-patch-v3/firecracker"
[kernel]
image_path = "{D}/deps/kernel/vmlinux-6.1.175/vmlinux.bin"
[tools]
version = "0.1.1"
drive_path = "{D}/deps/tools/0.1.1/tools.ext4"
[image.cache.gc]
enabled = false
[p2p]
enabled = false
[snapshot]
repository_backend = "posix_fs"
p2p_enabled = false
[ublk]
daemon_binary_path = "{D}/bin/uvm-ublk-daemon"
daemon_socket_path = "{RUNTIME}/ublk.sock"
daemon_log_path = "{D}/logs/ublk-daemon.log"
daemon_metrics_listen_addr = ""
[pool.network]
maintenance_enabled = false
[pool.block]
enabled = true
startup_prewarm = false
[pool.firecracker]
enabled = false
startup_prewarm = false
[observability]
enabled = false
[node_identity]
node_id = "ub-{NODE}"
cluster_id = "2834be81-b0f0-48d3-b120-5cc7daf00244"
service_instance_id = "jwk-aenv-ub-b019f27-{NODE}"
'''


def stable_file(path, limit=512 * 1024**2):
    safe(path, True)
    meta = path.lstat()
    require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_size <= limit,
            'Unexpected source file/link/size: ' + str(path))
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(data) == before.st_size <= limit and
            (before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_ino, after.st_size, after.st_mtime_ns), 'Input changed during copy: ' + str(path))
    return data, meta


def properties(unit):
    rc, text = run(['/usr/bin/systemctl', 'show', unit, '--no-pager',
                    '--property=LoadState,ActiveState,SubState,MainPID,User,Group,PrivateNetwork,PrivateMounts,ControlGroup'])
    fields = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
    require(rc == 0 or fields.get('LoadState') == 'not-found', 'Cannot query unit metadata: ' + unit)
    return fields


def http_health(port):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
    try:
        connection.request('GET', '/health')
        response = connection.getresponse()
        require(response.status == 204 and response.read(4096) == b'',
                'Unexpected health response on local port ' + str(port))
        return 204
    finally:
        connection.close()


def baseline():
    receipt = load(BASE / 'installation.json')
    require(receipt.get('commit') == 'ae9c62693839ce7effa2b45df31c0039ae4f9fbc'
            and receipt.get('node') == NODE and receipt.get('revision') == 'aenv-offline-install-start-v4',
            'Expected independent original installation missing/different; do not reinstall it')
    old = properties(OLD_UNIT)
    require(old.get('ActiveState') == 'active' and int(old.get('MainPID', 0)) > 1,
            'Original unit is not active; no restart attempted')
    http_health(18080)
    return old['MainPID']


def selected_inputs():
    selected = []
    for name, digest in BINARIES.items():
        data, _ = stable_file(ARTIFACTS / name)
        require(hashlib.sha256(data).hexdigest() == digest, 'Modified binary hash differs: ' + name)
        selected.append((Path('bin') / name, ARTIFACTS / name, 0o750, digest))
    # Only immutable dependency/native inputs. Never copy original state, logs,
    # cache, runtime sockets, config, API key or CLI credentials.
    total = 0
    for directory in ('native', 'deps'):
        source = safe(BASE / directory, True)
        for path in sorted(source.rglob('*')):
            safe(path, True)
            if path.is_dir():
                continue
            data, meta = stable_file(path)
            total += len(data)
            require(len(selected) < 2048 and total <= 3 * 1024**3,
                    'Unexpected dependency inventory size; no unbounded copy')
            selected.append((path.relative_to(BASE), path, 0o750 if meta.st_mode & 0o111 else 0o640,
                             hashlib.sha256(data).hexdigest()))
    names = {item[0].as_posix() for item in selected}
    for required in ('deps/firecracker/1.15.1-patch-v3/firecracker',
                     'deps/kernel/vmlinux-6.1.175/vmlinux.bin', 'deps/tools/0.1.1/tools.ext4',
                     'deps/regctl/v0.11.5/regctl', 'deps/overlaybd/bin/overlaybd-create',
                     'deps/overlaybd/bin/overlaybd-apply', 'deps/overlaybd/bin/overlaybd-commit',
                     'deps/overlaybd/bin/overlaybd-resize'):
        require(required in names, 'Required existing offline dependency missing: ' + required)
    return selected


def cli_files(key):
    cli = D / 'cli'
    wrapper = ('#!/bin/sh\n'
               'export XDG_CONFIG_HOME="' + str(cli / 'config') + '"\n'
               'export XDG_CACHE_HOME="' + str(cli / 'cache') + '"\n'
               'export TMPDIR="' + str(cli / 'tmp') + '"\n'
               'export LD_LIBRARY_PATH="' + str(D / 'native/lib') + ':' + str(D / 'native/fallback/lib') + '"\n'
               'unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY\n'
               'export NO_PROXY="127.0.0.1,localhost,::1"\n'
               'export no_proxy="$NO_PROXY"\n'
               'exec "' + str(D / 'bin/aenv') + '" "$@"\n').encode()
    credentials = ('url = "http://127.0.0.1:' + str(PORT) + '"\napi_key = ' + json.dumps(key) + '\n').encode()
    for path in (cli / 'cache', cli / 'tmp'):
        mkdir(path)
    put(cli / 'bin/aenv-ub', wrapper, 0o700)
    put(cli / 'config/aenv/credentials', credentials)
    activation = ('# Source as jwk; adds only the distinct aenv-ub command.\n'
                  'case ":$PATH:" in\n  *":' + str(cli / 'bin') + ':"*) ;;\n'
                  '  *) export PATH="' + str(cli / 'bin') + ':$PATH" ;;\nesac\nhash -r\n')
    put(ROOT / 'env-aenv-ub-b019.sh', activation.encode())


def stage_launcher():
    put(LAUNCHER, Path(__file__).read_bytes())
    return {}


def install():
    no_caps()
    old_pid = baseline()
    require(properties(UNIT).get('LoadState') == 'not-found', 'New unit already exists; preserve it, use health')
    with socket.socket() as port:
        port.bind(('127.0.0.1', PORT))
    require(shutil.disk_usage(ROOT).free >= 4 * 1024**3, 'Need at least 4GiB free for an independent installation')
    safe(D)
    definition = {'revision': REVISION, 'commit': COMMIT, 'unit': UNIT, 'port': PORT, 'runtime': str(RUNTIME)}
    if D.exists() and any(D.iterdir()):
        require(load(D / 'definition.json') == definition, 'Unknown existing deployment preserved')
    if RUNTIME.exists() and any(RUNTIME.iterdir()):
        require(load(RUNTIME / 'definition.json') == definition, 'Unknown runtime directory preserved')
        require(set(p.name for p in RUNTIME.iterdir()) == {'definition.json'}, 'Runtime has state; no install overwrite')
    inputs = selected_inputs()
    for path in (D, RUNTIME):
        mkdir(path)
        dump(path / 'definition.json', definition)
    for directory in ('bin', 'native/bin', 'native/lib', 'native/xtables', 'native/fallback/lib',
                      'state', 'config/docker', 'logs', 'cache', 'tmp', 'libexec'):
        mkdir(D / directory)
    manifest = {}
    for relative, source, mode, digest in inputs:
        data, _ = stable_file(source)
        require(hashlib.sha256(data).hexdigest() == digest, 'Source changed since inventory: ' + str(source))
        put(D / relative, data, mode)
        manifest[relative.as_posix()] = {'sha256': digest, 'bytes': len(data)}
    put(D / 'config/runtime.toml', config_text().encode())
    put(D / 'config/docker/config.json', b'{"auths":{}}\n')
    secret = D / 'config/api-key'
    if not secret.exists():
        put(secret, ('e2b_' + secrets.token_hex(24)).encode())
    key_data, key_meta = stable_file(secret, 1024)
    require(stat.S_IMODE(key_meta.st_mode) == 0o600, 'New API key mode differs; value withheld')
    key = key_data.decode('ascii').strip()
    require(re.fullmatch(r'e2b_[0-9a-f]{48}', key), 'New API key format differs; value withheld')
    cli_files(key)
    launcher_dependencies = stage_launcher()
    env = environment()
    for binary in [D / 'bin' / name for name in BINARIES] + [D / 'deps/firecracker/1.15.1-patch-v3/firecracker']:
        rc, text = run(['/usr/bin/ldd', binary], env)
        require('not found' not in text and (rc == 0 or 'not a dynamic executable' in text or 'statically linked' in text),
                'New runtime dynamic dependency missing: ' + str(binary) + '\n' + text[:1500])
    for name in ('ip', 'iptables-save', 'iptables-restore', 'debugfs', 'mkfs.ext4', 'resize2fs', 'jq', 'curl', 'umoci', 'zstd'):
        require(shutil.which(name, path=env['PATH']), 'Missing native input: ' + name + '; no installer run')
    require(Path('/sys/module/ublk_drv').is_dir(), 'Existing ublk_drv missing; no module load attempted')
    require(all(Path(p).is_char_device() for p in ('/dev/kvm', '/dev/ublk-control', '/dev/net/tun')),
            'Required existing devices missing; no permission changes attempted')
    rc, _ = run([D / 'bin/aenv', '--version'], env)
    require(rc == 0, 'New CLI cannot execute; child output withheld')
    require(baseline() == old_pid, 'Original main process changed during preparation; no restart attempted')
    receipt = dict(definition, root=str(D), launcher=str(LAUNCHER), node=NODE,
                   boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                   host_netns=os.stat('/proc/self/ns/net').st_ino,
                   host_mntns=os.stat('/proc/self/ns/mnt').st_ino,
                   binaries=BINARIES, launcher_sha256=hashlib.sha256(LAUNCHER.read_bytes()).hexdigest(),
                   launcher_dependencies=launcher_dependencies)
    dump(D / 'input-manifest.json', manifest)
    dump(D / 'installation.json', receipt)
    return {'status': STATUS_PREFIX + '_INSTALLED_AWAITING_NEW_UNIT_APPROVAL', 'root': str(D),
            'unit': UNIT, 'api': 'http://127.0.0.1:' + str(PORT), 'runtime_started': False,
            'original_health': 204 if old_pid is not None else None,
            'original_was_running': old_pid is not None,
            'original_main_pid_unchanged': old_pid is not None,
            'copied_inputs': len(inputs), 'copied_bytes': sum(row['bytes'] for row in manifest.values()),
            'launcher': str(LAUNCHER), 'CLI': str(D / 'cli/bin/aenv-ub'),
            'next_action': 'Return this report. Review/approve the exact NEW transient unit before root activation. Do not run the old baseline installer.'}


def installed():
    receipt = load(D / 'installation.json')
    require(receipt.get('revision') == REVISION and receipt.get('commit') == COMMIT
            and receipt.get('unit') == UNIT and receipt.get('runtime') == str(RUNTIME), 'New installation receipt differs')
    require(receipt.get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'Host rebooted since preparation; refresh installation evidence before activation')
    for name, digest in BINARIES.items():
        require(hashlib.sha256(stable_file(D / 'bin' / name)[0]).hexdigest() == digest, 'New binary identity differs: ' + name)
    require(hashlib.sha256(stable_file(LAUNCHER)[0]).hexdigest() == receipt['launcher_sha256'], 'Installed launcher identity differs')
    for name, digest in receipt.get('launcher_dependencies', {}).items():
        path = safe(D / 'libexec' / name, True)
        require(path.parent == D / 'libexec' and hashlib.sha256(stable_file(path)[0]).hexdigest() == digest,
                'Installed launcher dependency differs')
    require(stable_file(D / 'config/runtime.toml')[0] == config_text().encode(), 'New runtime config differs')
    return receipt


async def proxy(side):
    import fcntl
    no_caps()
    lock = os.open(RUNTIME / ('proxy-' + side + '.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    unix = RUNTIME / 'api.sock'
    async def accept(reader, writer):
        try:
            if side == 'inside':
                raw = writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                require(struct.unpack('3i', raw)[1] == 1204, 'Unexpected UNIX peer UID')
                remote_reader, remote_writer = await asyncio.open_connection('127.0.0.1', PORT)
            else:
                remote_reader, remote_writer = await asyncio.open_unix_connection(str(unix))
            await relay(reader, writer, remote_reader, remote_writer)
        except Exception:
            writer.close()
    if side == 'inside':
        require(not unix.exists() and not unix.is_symlink(), 'New API socket already exists; preserved')
        server = await asyncio.start_unix_server(accept, str(unix))
        os.chmod(unix, 0o600)
    else:
        server = await asyncio.start_server(accept, '127.0.0.1', PORT, reuse_address=False)
    try:
        async with server:
            await server.serve_forever()
    finally:
        os.close(lock)


def inside():
    receipt = installed()
    require(int(properties(UNIT).get('MainPID', 0)) == os.getpid(), 'Only the exact reviewed new unit may launch this runtime')
    require(os.stat('/proc/self/ns/net').st_ino != receipt['host_netns']
            and os.stat('/proc/self/ns/mnt').st_ino != receipt['host_mntns'], 'Refuse runtime startup in host namespaces')
    require(all(caps().get(k, 0) == CAPS for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), 'Unexpected startup capability set')
    require({36, 982} <= set(os.getgroups()) <= {1205, 36, 982}, 'Unexpected process supplementary groups')
    for path in ('/dev/kvm', '/dev/ublk-control', '/dev/net/tun'):
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        os.close(fd)
    forwarding = Path('/proc/sys/net/ipv4/ip_forward')
    if forwarding.read_text().strip() != '1':
        forwarding.write_text('1\n')  # Verified private network namespace only.
    env = environment()
    log = open(D / 'logs/proxy-inside.log', 'ab', buffering=0)
    child = subprocess.Popen(['/usr/bin/python3', '-I', '-B', str(LAUNCHER), 'proxy-inside'],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env, preexec_fn=drop_caps)
    time.sleep(0.3)
    require(child.poll() is None, 'New inside proxy failed; inspect its bounded log')
    env['AENV_API_KEY'] = stable_file(D / 'config/api-key', 1024)[0].decode().strip()
    # Do not inject indexes from the already-retired layer tests. UB Guest
    # activation needs separately budgeted live replicas and snapshot metadata.
    attestation = process_identity(os.getpid())
    attestation.update(revision=REVISION, intended_executable=str(D / 'bin/server'))
    dump(RUNTIME / 'runtime-attestation.json', attestation)
    fd = os.open(D / 'logs/server.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    os.close(fd)
    os.chdir(D)
    os.execve(D / 'bin/server', [str(D / 'bin/server'), '--config', str(D / 'config/runtime.toml')], env)


def owns_listener(pid):
    owned = set()
    for fd in Path('/proc/' + str(pid) + '/fd').iterdir():
        try:
            link = os.readlink(fd)
        except OSError:
            continue
        if link.startswith('socket:['):
            owned.add(link[8:-1])
    endpoint = '0100007F:' + format(PORT, '04X')
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1] == endpoint and fields[3] == '0A' and fields[9] in owned:
            return True
    return False


def host_proxy(post_disconnect):
    receipt_path = RUNTIME / 'host-proxy.json'
    if receipt_path.exists():
        old = load(receipt_path)
        require(old.get('revision') == REVISION, 'Unknown proxy receipt preserved')
        try:
            actual = process_identity(old['pid'])
        except FileNotFoundError:
            actual = None
        if actual is not None:
            require(actual['start_ticks'] == old['start_ticks'] and actual['uid'] == [1204] * 4
                    and all(actual['caps'].get(k, 0) == 0 for k in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb'))
                    and owns_listener(old['pid']), 'Existing proxy identity/listener differs; no process signalled')
            return old['pid']
    require(not post_disconnect, 'Host proxy did not survive session close; no restart masks this check')
    with socket.socket() as port:
        port.bind(('127.0.0.1', PORT))  # Fail on an unknown existing listener.
    log = open(D / 'logs/proxy-host.log', 'ab', buffering=0)
    child = subprocess.Popen(['/usr/bin/python3', '-I', '-B', str(LAUNCHER), 'proxy-host'],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=environment(), start_new_session=True)
    for _ in range(25):
        require(child.poll() is None, 'New host proxy exited; existing listeners untouched')
        if owns_listener(child.pid):
            break
        time.sleep(0.2)
    else:
        raise RuntimeError('New host proxy did not listen within 5 seconds')
    actual = process_identity(child.pid)
    record = {'revision': REVISION, 'pid': child.pid, 'start_ticks': actual['start_ticks']}
    if receipt_path.exists():
        dump(RUNTIME / ('proxy-history-' + secrets.token_hex(6) + '.json'), load(receipt_path))
        temporary = receipt_path.with_name('proxy-new-' + secrets.token_hex(6) + '.json')
        dump(temporary, record)
        os.replace(temporary, receipt_path)
    else:
        dump(receipt_path, record)
    return child.pid


def health(post_disconnect=False):
    no_caps()
    receipt = installed()
    old_pid = baseline()
    for attempt in range(45):
        props = properties(UNIT)
        require(props.get('ActiveState') not in ('failed', 'inactive') and props.get('LoadState') == 'loaded',
                'New unit is not running; no service start/restart attempted')
        pid = int(props.get('MainPID', 0))
        if pid > 1 and (RUNTIME / 'runtime-attestation.json').is_file() and caps(pid).get('CapAmb') == 0:
            break
        if attempt % 10 == 0:
            print('PHASE=wait_for_new_runtime elapsed_s=' + str(attempt * 2), flush=True)
        time.sleep(2)
    else:
        raise RuntimeError('New runtime did not finish launching within 90 seconds')
    require(props.get('User') == props.get('Group') == 'jwk'
            and props.get('PrivateNetwork') == props.get('PrivateMounts') == 'yes', 'New unit isolation/identity differs')
    actual = process_identity(pid)
    attestation = load(RUNTIME / 'runtime-attestation.json')
    require(attestation.get('revision') == REVISION and attestation['pid'] == pid
            and attestation['start_ticks'] == actual['start_ticks'], 'New runtime attestation differs')
    require(actual['uid'] == [1204] * 4 and actual['exe'] in (str(D / 'bin/server'), 'PTRACE_ACCESS_DENIED')
            and attestation['intended_executable'] == str(D / 'bin/server'), 'New main process/binary differs')
    for name in ('netns', 'mntns'):
        require(attestation[name] != receipt['host_' + name]
                and actual[name] in (attestation[name], 'PTRACE_ACCESS_DENIED'), 'New namespace evidence differs')
    require(actual['caps']['CapEff'] == CAPS and actual['caps']['CapAmb'] == 0, 'New server capabilities differ')
    proxy_pid = host_proxy(post_disconnect)
    checks = []
    for sample in range(1 if post_disconnect else 3):
        for attempt in range(30 if sample == 0 else 1):
            try:
                http_health(PORT)
                break
            except Exception:
                if sample != 0 or attempt == 29:
                    raise
                time.sleep(2)
        require(properties(UNIT).get('MainPID') == str(pid)
                and process_identity(pid)['start_ticks'] == actual['start_ticks'], 'New runtime changed during health check')
        checks.append(204)
        if sample < (0 if post_disconnect else 2):
            time.sleep(5)
    rc, output = run([D / 'cli/bin/aenv-ub', 'list', '--output', 'json'], environment())
    require(rc == 0, 'New CLI list failed; child output withheld')
    try:
        entries = json.loads(output)
    except ValueError:
        raise RuntimeError('New CLI response is not a list; child output withheld') from None
    require(isinstance(entries, list), 'Unexpected new CLI list schema; response withheld')
    require(baseline() == old_pid, 'Original main process changed during new health checks')
    return {'status': STATUS_PREFIX + '_AND_ORIGINAL_SERVICES_HEALTHY', 'runtime_started': True,
            'unit': UNIT, 'api': 'http://127.0.0.1:' + str(PORT), 'health_checks': checks,
            'main_process': actual, 'host_proxy_pid': proxy_pid, 'CLI_list_count': len(entries),
            'original_health': 204, 'original_main_pid_unchanged': True,
            'post_disconnect': post_disconnect, 'activate': 'source /home/jwk/agent/env-aenv-ub-b019.sh',
            'Guest_or_ublk_tests_executed': False, 'UB_Guest_replicas_configured': False,
            'reboot_persistence': 'New transient unit; explicit reactivation after reboot'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('install', 'inside', 'proxy-inside', 'proxy-host', 'health'))
    parser.add_argument('--post-disconnect', action='store_true')
    args = parser.parse_args()
    identity()
    if args.mode == 'inside':
        try:
            inside()
        except BaseException:
            import traceback
            with open(D / 'logs/launcher.log', 'a') as log:
                traceback.print_exc(file=log)
            raise
        return 0
    if args.mode.startswith('proxy-'):
        asyncio.run(proxy(args.mode.split('-', 1)[1]))
        return 0
    no_caps()
    import fcntl
    lock = os.open(ROOT / 'relay/aenv-ub-b019f27-install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        work = Path(tempfile.mkdtemp(prefix=NODE + '-aenv-ub-' + args.mode + '-', dir=ROOT / 'relay/reports'))
        report = {'revision': REVISION, 'mode': args.mode, 'node': NODE, 'hostname': EXPECTED_HOST,
                  'uid': 1204, 'source_commit': COMMIT, 'report_directory': str(work),
                  'existing_services_modified': False, 'B_accessed': NODE == 'node-b', 'SDK_called': False}
        try:
            report.update(install() if args.mode == 'install' else health(args.post_disconnect))
        except BaseException as error:
            report.update(status='STOPPED_' + STATUS_PREFIX + '_' + args.mode.upper(),
                          error=re.sub(r'e2b_[A-Za-z0-9._~-]+', '[REDACTED]', str(error)))
            if args.mode == 'health':
                report['logs'] = {}
                for name in ('launcher.log', 'server.log', 'ublk-daemon.log', 'proxy-inside.log', 'proxy-host.log'):
                    path = D / 'logs' / name
                    if path.is_file() and path.resolve() == path:
                        text = path.read_text(errors='replace')[-6000:]
                        report['logs'][name] = re.sub(r'e2b_[A-Za-z0-9._~-]+', '[REDACTED]', text)
        dump(work / 'return.json', report)
        print('BEGIN_RETURN_REPORT')
        print(json.dumps(report, indent=2))
        print('END_RETURN_REPORT')
        return 0 if report['status'] in (STATUS_PREFIX + '_INSTALLED_AWAITING_NEW_UNIT_APPROVAL', STATUS_PREFIX + '_AND_ORIGINAL_SERVICES_HEALTHY') else 1
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        rc = main()
    except BaseException as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'STOPPED_' + STATUS_PREFIX + '_DEPLOY_ENTRY', 'error': type(error).__name__,
                          'detail': re.sub(r'e2b_[A-Za-z0-9._~-]+', '[REDACTED]', str(error)),
                          'existing_services_modified': False}, indent=2))
        print('END_RETURN_REPORT')
        rc = 1
    raise SystemExit(rc)
