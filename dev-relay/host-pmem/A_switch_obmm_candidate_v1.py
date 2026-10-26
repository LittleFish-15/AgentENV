"""A-only reviewed maintenance candidate. Default is plan, not execution.

Requires separate human approval to stop ubse.service and replace OBMM.
No SDK allocation, filesystem mount, Guest or node-B operation is included.
Failures preserve state; recovery is an explicit separate command.
"""
import argparse
import errno
from contextlib import contextmanager
import hashlib
import json
import lzma
import os
from pathlib import Path
import platform
import stat
import struct
import subprocess
import time

NODE = 'server1'
BOOT = '58d0ee5f-f886-4eb6-93ea-a6328d14d139'
KERNEL = '6.6.0-145.3.34.165.oe2403sp3.aarch64'
OLD_SRC = 'B2D1EBF7E6C2BB3EF877E36'
OLD_SHA = 'f1fea1b150d15afadd4960c6f3c651f36344fb554c417608378baa7b56b6812e'
NEW_SHA = '59767d198966db908e662cfbe0f144b93d8fd20f01a39c917977aa9e8efd8a6a'
NEW_FILE = Path('/home/jwk/agent/ub-host-pmem-build-2c1768644257/kernel-obmm/obmm.ko')
OLD_FILE = Path('/lib/modules') / KERNEL / 'kernel/drivers/ub/obmm/obmm.ko.xz'
STAGE = Path('/var/lib/agentenv-host-pmem-a-v1')
UNIT = 'ubse.service'
PARAMS = {'mem_allocator_granu': '2M', 'mempool_allocator': 'buddy_highmem',
          'mempool_refill_timeout': '30000', 'mempool_size': '1G', 'skip_cache_maintain': 'N'}
EXPECTED_PROCESS = {'pid': 1063986, 'ticks': '17968795'}
APPROVAL = 'A_UBSE_STOP_OBMM_SWITCH_EXPLICIT_RECOVERY'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def read(path):
    return Path(path).read_text().strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tool(name):
    for directory in ('/usr/sbin', '/sbin', '/usr/bin', '/bin'):
        path = Path(directory) / name
        if path.is_file():
            resolved = path.resolve(strict=True)
            s = resolved.stat()
            need(s.st_uid == 0 and not s.st_mode & 0o022, 'Unsafe system tool: ' + name)
            # kmod dispatches modinfo/insmod/rmmod by argv[0]; keep the alias.
            return str(path)
    raise RuntimeError('Missing system tool: ' + name)


def command(args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    need(result.returncode == 0, 'Command failed: ' + args[0] + ' ' + ' '.join(args[1:3])
         + ' exit=' + str(result.returncode) + ' ' + result.stderr[-2000:])
    return result.stdout.strip()


def module_info(field, path):
    return command([tool('modinfo'), '-F', field, str(path)])


def process(pid):
    p = Path('/proc') / str(pid)
    tail = read(p / 'stat').rsplit(')', 1)[1].split()
    uids = next(line.split()[1:] for line in read(p / 'status').splitlines() if line.startswith('Uid:'))
    need(uids == ['985'] * 4 and '/system.slice/ubse.service' in read(p / 'cgroup'), 'Unexpected UBSE credentials/cgroup')
    return {'pid': pid, 'ticks': tail[19]}


def service():
    keys = ('ActiveState', 'SubState', 'MainPID', 'Job', 'RequiredBy', 'BoundBy',
            'ConsistsOf', 'PropagatesStopTo')
    output = command([tool('systemctl'), 'show', UNIT, *['--property=' + k for k in keys]])
    result = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    need(all(k in result for k in keys), 'Missing systemd service properties')
    need(result['Job'] in ('', '0'), 'UBSE already has a pending systemd job')
    return result


def await_service(active):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        state = service()
        if active and state['ActiveState'] == 'active' and int(state['MainPID']) > 0:
            return process(int(state['MainPID']))
        if not active and state['ActiveState'] == 'inactive' and state['MainPID'] == '0':
            return None
        time.sleep(0.25)
    raise RuntimeError('UBSE state unconfirmed; preserve state, no module operation')


def no_regions():
    need(not list(Path('/sys/devices/obmm').glob('obmm_shmdev*')), 'OBMM regions are present')
    need(not list(Path('/dev').glob('obmm_shmdev*')), 'OBMM device nodes are present')
    lines = read('/proc/obmm/preimport_info').splitlines()
    need(len(lines) == 1 and lines[0].startswith('pa_start'), 'Preimport state is not empty')
    need(not list(Path('/sys/module/obmm/holders').iterdir()), 'Other kernel modules hold OBMM')


def check_module(src, params, references=None):
    need(read('/sys/module/obmm/initstate') == 'live', 'OBMM is not live')
    need(read('/sys/module/obmm/srcversion') == src, 'Loaded OBMM identity changed')
    actual = {p.name: read(p) for p in Path('/sys/module/obmm/parameters').iterdir()}
    need(actual == params, 'Loaded OBMM parameters changed')
    no_regions()
    if references is not None:
        need(read('/sys/module/obmm/refcnt') == str(references), 'OBMM reference count differs; no force unload')


def write_json(path, value):
    tmp = path.with_name(path.name + '.next')
    with tmp.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def pinned_bytes(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_size <= 16 * 1024 * 1024, 'Unexpected module file')
        data = stream.read(16 * 1024 * 1024 + 1)
    need(sha(data) == expected, 'Module bytes changed: ' + str(path))
    return data


@contextmanager
def operation_lock():
    import fcntl
    fd = os.open(STAGE / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


class Local:
    def __init__(self, journal):
        self.journal = journal

    def mark(self, phase, **values):
        self.journal.update(phase=phase, **values)
        write_json(STAGE / 'journal.json', self.journal)

    def check_old(self):
        need(read('/proc/sys/kernel/tainted') == '12800', 'Kernel taint changed since the receipt; review before switching')
        check_module(OLD_SRC, PARAMS, 1)
        state = service()
        need(state['ActiveState'] == 'active' and process(int(state['MainPID'])) == EXPECTED_PROCESS,
             'UBSE process identity changed since receipt')
        for key in ('RequiredBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo'):
            need(not state[key], 'Stopping UBSE may propagate to other units: ' + key)

    def stop(self, expected):
        state = service()
        need(state['ActiveState'] == 'active' and process(int(state['MainPID'])) == expected,
             'Refuse to stop an unexpected UBSE instance')
        command([tool('systemctl'), 'stop', UNIT], 45)
        await_service(False)

    def start(self):
        state = service()
        need(state['ActiveState'] == 'inactive' and state['MainPID'] == '0', 'Refuse to replace a live/unknown UBSE instance')
        command([tool('systemctl'), 'start', UNIT], 45)
        return await_service(True)

    def unload(self, src, params):
        check_module(src, params, 0)
        command([tool('rmmod'), 'obmm'])
        need(not Path('/sys/module/obmm').exists(), 'OBMM unload unconfirmed')

    def load(self, name, params):
        need(not Path('/sys/module/obmm').exists(), 'A module is already loaded')
        command([tool('insmod'), str(STAGE / name), *[k + '=' + v for k, v in sorted(params.items())]])

    def check_original(self):
        check_module(OLD_SRC, PARAMS)

    def check_active_candidate(self, expected):
        check_module(self.journal['candidateSrcversion'], {**PARAMS, 'pmem_ro_enable': 'Y'}, 1)
        state = service()
        need(state['ActiveState'] == 'active' and process(int(state['MainPID'])) == expected,
             'Started UBSE identity is no longer stable')

    def candidate_check(self):
        import fcntl
        check_module(self.journal['candidateSrcversion'], {**PARAMS, 'pmem_ro_enable': 'Y'}, 0)
        path = Path('/dev/obmm_pmem')
        end = time.monotonic() + 5
        while not path.exists() and time.monotonic() < end:
            time.sleep(0.1)
        s = path.stat()
        need(stat.S_ISCHR(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o600,
             'Unexpected candidate control device')
        major, minor = map(int, read('/sys/class/misc/obmm_pmem/dev').split(':'))
        need(s.st_rdev == os.makedev(major, minor), 'Candidate control device identity differs')
        request = bytearray(96)
        struct.pack_into('=I', request, 0, 1)
        request[8:24] = bytes.fromhex('8ea268033d684d178c13e88c846e3802')
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            try:
                fcntl.ioctl(fd, (3 << 30) | (96 << 16) | (0xb8 << 8) | 1, request, True)
            except OSError as error:
                need(error.errno == errno.ENOENT, 'Candidate STATUS ABI check failed')
            else:
                raise RuntimeError('Unexpected existing candidate volume; preserve it')
        finally:
            os.close(fd)


def activate(backend):
    backend.check_old()
    backend.mark('stop_old_ubse_intent')
    backend.stop(EXPECTED_PROCESS)
    backend.mark('old_ubse_stopped')
    backend.mark('unload_original_intent')
    backend.unload(OLD_SRC, PARAMS)
    backend.mark('original_unloaded')
    backend.mark('load_candidate_intent')
    backend.load('candidate.ko', {**PARAMS, 'pmem_ro_enable': '1'})
    backend.candidate_check()
    backend.mark('candidate_verified_without_allocations')
    backend.mark('start_ubse_intent')
    current = backend.start()
    backend.mark('candidate_loaded_ubse_active', currentProcess=current)
    backend.check_active_candidate(current)


def restore(backend, loaded_source, active_process):
    """Explicit recovery only. Unknown process/module identities are preserved."""
    need(loaded_source in (None, OLD_SRC, backend.journal['candidateSrcversion']),
         'Unknown loaded module; recovery refused')
    if loaded_source == OLD_SRC:
        backend.check_original()
        if active_process is None:
            backend.mark('restore_start_ubse_intent')
            active_process = backend.start()
        backend.mark('original_loaded_ubse_active', restoredProcess=active_process)
        return
    if active_process is not None:
        need(loaded_source == backend.journal['candidateSrcversion'] and
             active_process == backend.journal.get('currentProcess'),
             'Unbound active UBSE instance; recovery refuses to stop it')
        backend.mark('restore_stop_candidate_ubse_intent')
        backend.stop(active_process)
        backend.mark('restore_ubse_stopped')
    if loaded_source is not None:
        backend.mark('restore_unload_candidate_intent')
        backend.unload(backend.journal['candidateSrcversion'], {**PARAMS, 'pmem_ro_enable': 'Y'})
    backend.mark('restore_load_original_intent')
    backend.load('original.ko', PARAMS)
    backend.check_original()
    backend.mark('restore_start_ubse_intent')
    current = backend.start()
    backend.mark('original_loaded_ubse_active', restoredProcess=current)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'activate', 'status', 'restore'), nargs='?', default='plan')
    parser.add_argument('--approval')
    args = parser.parse_args()
    if args.mode == 'plan':
        print(json.dumps({'scope': 'A only; stop/restart ubse.service and switch OBMM',
            'candidateSha256': NEW_SHA, 'originalSha256': OLD_SHA, 'originalParameters': PARAMS,
            'expectedProcess': EXPECTED_PROCESS, 'nodeBChanged': False, 'loadApproved': False,
            'SDKAllocationIncluded': False, 'defaultChanges': False}, indent=2))
        return 0
    need(os.getuid() == os.geteuid() == 0 and platform.node() == NODE and platform.release() == KERNEL,
         'Unexpected root/node/kernel context')
    need(read('/proc/sys/kernel/random/boot_id') == BOOT, 'Boot identity changed')
    if args.mode == 'status':
        print(read(STAGE / 'journal.json'))
        return 0
    need(args.approval == APPROVAL, 'Separate explicit maintenance approval is required')
    capeff = next(line.split()[1] for line in read('/proc/self/status').splitlines() if line.startswith('CapEff:'))
    required_caps = (1 << 16) | (1 << 21)
    need(int(capeff, 16) & required_caps == required_caps, 'Missing CAP_SYS_MODULE/CAP_SYS_ADMIN; nothing changed')
    need(read('/proc/sys/kernel/modules_disabled') == '0' and
         read('/sys/module/module/parameters/sig_enforce') == 'N' and
         '[none]' in read('/sys/kernel/security/lockdown'), 'Module policy changed; do not bypass it')
    if args.mode == 'restore':
        st = STAGE.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077,
             'Recovery stage is not root-private')
        with operation_lock():
            journal = json.loads(read(STAGE / 'journal.json'))
            need(journal['version'] == 1 and journal['node'] == NODE and journal['bootId'] == BOOT
                 and journal['originalParameters'] == PARAMS, 'Recovery journal identity differs')
            pinned_bytes(STAGE / 'candidate.ko', NEW_SHA)
            original_xz = pinned_bytes(STAGE / 'original.ko.xz', OLD_SHA)
            original = pinned_bytes(STAGE / 'original.ko', sha(lzma.decompress(original_xz)))
            need(module_info('srcversion', STAGE / 'candidate.ko') == journal['candidateSrcversion']
                 and module_info('srcversion', STAGE / 'original.ko') == OLD_SRC,
                 'Recovery module metadata differs')
            backend = Local(journal)
            state = service()
            need(state['ActiveState'] in ('active', 'inactive'), 'Service transition or failure unresolved')
            need(state['ActiveState'] != 'inactive' or state['MainPID'] == '0', 'Inactive service has an unexpected PID')
            current = process(int(state['MainPID'])) if state['ActiveState'] == 'active' else None
            loaded = read('/sys/module/obmm/srcversion') if Path('/sys/module/obmm').exists() else None
            if loaded is not None:
                no_regions()
            try:
                restore(backend, loaded, current)
            except Exception as error:
                backend.mark('recovery_stopped_preserve_state', previousPhase=backend.journal['phase'], reason=str(error))
                print(json.dumps(backend.journal, indent=2))
                return 1
            print(json.dumps(backend.journal, indent=2))
            return 0
    need(not STAGE.exists() and not STAGE.is_symlink(), 'Prior stage exists; use status, never retry activation')
    parent = STAGE.parent
    need(parent.resolve() == parent and parent.stat().st_uid == 0 and not parent.stat().st_mode & 0o022,
         'Unsafe root staging parent')
    candidate = pinned_bytes(NEW_FILE, NEW_SHA)
    original_xz = pinned_bytes(OLD_FILE, OLD_SHA)
    original = lzma.decompress(original_xz)
    preliminary = Local({})
    preliminary.check_old()
    STAGE.mkdir(mode=0o700)
    for name, data in [('candidate.ko', candidate), ('original.ko.xz', original_xz), ('original.ko', original)]:
        fd = os.open(STAGE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    need(module_info('srcversion', STAGE / 'original.ko') == OLD_SRC, 'Backup differs from loaded original')
    candidate_src = module_info('srcversion', STAGE / 'candidate.ko')
    need(candidate_src and candidate_src != OLD_SRC, 'Candidate source identity unavailable')
    for name in ('candidate.ko', 'original.ko'):
        need(module_info('vermagic', STAGE / name).split()[0] == KERNEL, 'Staged vermagic differs')
    backend = Local({'version': 1, 'node': NODE, 'bootId': BOOT, 'candidateSrcversion': candidate_src,
        'candidateSha256': NEW_SHA, 'originalXzSha256': OLD_SHA, 'originalSha256': sha(original),
        'originalParameters': PARAMS, 'taintBefore': read('/proc/sys/kernel/tainted'),
        'SDK_called': False, 'Guest_created': False, 'nodeBChanged': False})
    with operation_lock():
        backend.mark('backups_verified')
        try:
            activate(backend)
        except Exception as error:
            backend.mark('stopped_preserve_state', previousPhase=backend.journal['phase'],
                         reason=str(error), automaticRollbackExecuted=False)
            print(json.dumps(backend.journal, indent=2))
            return 1
        backend.mark('candidate_loaded_ubse_active', taintAfter=read('/proc/sys/kernel/tainted'))
        print(json.dumps(backend.journal, indent=2))
    return 0


if __name__ == '__main__':
    try:
        code = main()
    except Exception as error:
        print(json.dumps({'status': 'MAINTENANCE_STOPPED_PRESERVE_STATE',
                          'reason': str(error), 'automaticRollbackExecuted': False}, indent=2))
        code = 1
    raise SystemExit(code)
