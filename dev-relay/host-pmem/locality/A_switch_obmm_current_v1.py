"""Current-boot A-only OBMM maintenance, reusing the previously exercised flow.

No SDK, UB allocation/import/delete, mount, Guest or node-B changes.
Default prints plan. Kernel changes require this task's separate approval.
Recovery is explicit and refuses unknown references or process identities.
"""
import argparse, errno, hashlib, json, lzma, os, platform, stat, struct, subprocess, time
from contextlib import contextmanager
from pathlib import Path
NODE='server1'
BOOT='7bd42416-46a3-49c4-af22-7318836954b2'
KERNEL='6.6.0-145.3.34.165.oe2403sp3.aarch64'
OLD_SRC='B2D1EBF7E6C2BB3EF877E36'
NEW_SRC='C2BBB64D75C618180ABA3A6'
OLD_SHA='f1fea1b150d15afadd4960c6f3c651f36344fb554c417608378baa7b56b6812e'
ORIGINAL_SHA='abd09dec30cb30214868a16b04b7547b6d979f96eeb4638e6bcecde30d7639df'
NEW_SHA='59767d198966db908e662cfbe0f144b93d8fd20f01a39c917977aa9e8efd8a6a'
STAGE=Path('/home/jwk/root/recovery/obmm-a')/BOOT/'prepared-001'
UNIT='ubse.service'
PARAMS={'mem_allocator_granu':'2M','mempool_allocator':'buddy_highmem','mempool_refill_timeout':'30000','mempool_size':'1G','skip_cache_maintain':'N'}
EXPECTED_PROCESS={'pid':15748,'ticks':'2361'}
APPROVAL='A_CURRENT_BOOT_UBSE_OBMM_SWITCH_AND_EXPLICIT_RESTORE'
TAINT_BEFORE='12288'


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
    need(not list(Path('/sys/class/block').glob('ubpmem_ro*')), 'Local pmem volumes are present')


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
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022
             and s.st_size <= 16 * 1024 * 1024, 'Unexpected module file')
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
        self.journal['sequence'] = self.journal.get('sequence', 0) + 1
        event = STAGE / ('event-%04d.json' % self.journal['sequence'])
        need(not event.exists() and not event.is_symlink(), 'Ahead-of-journal event exists; preserve uncertain operation')
        write_json(event, self.journal)
        write_json(STAGE / 'journal.json', self.journal)
        print('PHASE=node-a:' + phase, flush=True)

    def check_old(self):
        need(read('/proc/sys/kernel/tainted') == TAINT_BEFORE, 'Kernel taint changed since the receipt; review before switching')
        check_module(OLD_SRC, PARAMS, 0)
        state = service()
        need(state['ActiveState'] == 'active' and process(int(state['MainPID'])) == EXPECTED_PROCESS,
             'UBSE process identity changed since receipt')
        for key in ('RequiredBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo'):
            need(not state[key], 'Stopping UBSE may propagate to other units: ' + key)

    def stop(self, expected):
        state = service()
        need(state['ActiveState'] == 'active' and process(int(state['MainPID'])) == expected,
             'Refuse to stop an unexpected UBSE instance')
        for key in ('RequiredBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo'):
            need(not state[key], 'Stopping UBSE may propagate to other units: ' + key)
        no_regions()
        command([tool('systemctl'), 'stop', UNIT], 45)
        await_service(False)

    def start(self):
        state = service()
        need(state['ActiveState'] in ('inactive', 'failed') and state['MainPID'] == '0', 'Refuse to replace a live/unknown UBSE instance')
        command([tool('systemctl'), 'start', UNIT], 45)
        return await_service(True)

    def unload(self, src, params):
        check_module(src, params, 0)
        command([tool('rmmod'), 'obmm'])
        need(not Path('/sys/module/obmm').exists(), 'OBMM unload unconfirmed')

    def load(self, name, params):
        need(not Path('/sys/module/obmm').exists(), 'A module is already loaded')
        need(name in ('candidate.ko', 'original.ko'), 'Only verified staged modules')
        pinned_bytes(STAGE / name, NEW_SHA if name == 'candidate.ko' else ORIGINAL_SHA)
        command([tool('insmod'), str(STAGE / name), *[k + '=' + v for k, v in sorted(params.items())]])

    def check_original(self):
        check_module(OLD_SRC, PARAMS)

    def check_active_candidate(self, expected):
        # The old workflow incorrectly assumed UBSE always holds exactly one
        # reference. Record it, but require zero only before module unloading.
        check_module(self.journal['candidateSrcversion'], {**PARAMS, 'pmem_ro_enable': 'Y'})
        state = service()
        need(state['ActiveState'] == 'active' and process(int(state['MainPID'])) == expected,
             'Started UBSE identity is no longer stable')
        self.journal['activeReferenceCount'] = read('/sys/module/obmm/refcnt')

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


def validate_context():
    need(os.getuid() == os.geteuid() == 0 and platform.node() == NODE and platform.release() == KERNEL,
         'Unexpected root/node/kernel context')
    need(read('/proc/sys/kernel/random/boot_id') == BOOT, 'Boot identity changed; no module action')
    # All maintenance material is already copied and verified, under the home
    # root directory. Historical /var state is never used as live state.
    for path in (Path('/home/jwk/root'), *reversed(list(STAGE.parents)[:3]), STAGE):
        s = path.lstat()
        need(path.resolve() == path and stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
             'Untrusted root maintenance directory')
    need(not STAGE.stat().st_mode & 0o077, 'Maintenance backup is not root-private')
    capeff = next(line.split()[1] for line in read('/proc/self/status').splitlines() if line.startswith('CapEff:'))
    required = (1 << 16) | (1 << 21)
    need(int(capeff, 16) & required == required, 'Missing CAP_SYS_MODULE/CAP_SYS_ADMIN')
    need(read('/proc/sys/kernel/modules_disabled') == '0' and
         read('/sys/module/module/parameters/sig_enforce') == 'N' and
         '[none]' in read('/sys/kernel/security/lockdown'), 'Module policy changed; never bypass it')
    pinned_bytes(STAGE / 'candidate.ko', NEW_SHA)
    original_xz = pinned_bytes(STAGE / 'original.ko.xz', OLD_SHA)
    need(sha(lzma.decompress(original_xz)) == ORIGINAL_SHA, 'Original compressed backup differs')
    pinned_bytes(STAGE / 'original.ko', ORIGINAL_SHA)
    for name, src in (('candidate.ko', NEW_SRC), ('original.ko', OLD_SRC)):
        need(module_info('srcversion', STAGE / name) == src and
             module_info('vermagic', STAGE / name).split()[0] == KERNEL and
             module_info('depends', STAGE / name) == 'ubus,ummu-core', 'Staged module metadata differs')


def validate_preparation():
    report = json.loads(read(STAGE / 'premaintenance.json'))
    need(report['status'] == 'A_PREMAINTENANCE_INSPECTED_NO_KERNEL_CHANGE' and
         report['bootId'] == BOOT and report['kernel'] == KERNEL and report['readinessGaps'] == [] and
         report['candidateVerified'] and report['originalBackupVerified'] and report['kernelStateStableDuringInspection'] and
         report['candidate']['sha256'] == NEW_SHA and report['originalSha256'] == ORIGINAL_SHA and
         report['parameters'] == PARAMS and report['kernelTaint'] == TAINT_BEFORE and
         report['ubseIdentity']['pid'] == EXPECTED_PROCESS['pid'] and
         report['ubseIdentity']['startTicks'] == EXPECTED_PROCESS['ticks'] and report['ubseIdentity']['identityStable'],
         'Prepared maintenance receipt differs')


def explicit_restore(backend):
    state = service()
    need(state['ActiveState'] in ('active', 'inactive', 'failed'), 'Service transition unresolved')
    if state['ActiveState'] == 'active':
        current = process(int(state['MainPID']))
        known = [EXPECTED_PROCESS, backend.journal.get('currentProcess'), backend.journal.get('restoredProcess')]
        need(current in known, 'Unbound active UBSE identity; do not stop or claim restored')
    else:
        need(state['MainPID'] == '0', 'Inactive/failed service has an unexpected PID')
        current = None
    loaded = read('/sys/module/obmm/srcversion') if Path('/sys/module/obmm').exists() else None
    if loaded is not None:
        need(loaded in (OLD_SRC, NEW_SRC), 'Unknown loaded module; recovery refused')
        check_module(loaded, PARAMS if loaded == OLD_SRC else {**PARAMS, 'pmem_ro_enable': 'Y'})
    restore(backend, loaded, current)
    backend.check_original()
    verified = await_service(True)
    need(verified == backend.journal['restoredProcess'], 'Restored UBSE identity changed')
    backend.mark('original_loaded_ubse_active', restoredProcess=verified,
                 referenceCountAfter=read('/sys/module/obmm/refcnt'), taintAfter=read('/proc/sys/kernel/tainted'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'activate', 'status', 'restore'), nargs='?', default='plan')
    parser.add_argument('--approval')
    args = parser.parse_args()
    if args.mode == 'plan':
        print(json.dumps({'node': NODE, 'bootId': BOOT, 'stage': str(STAGE), 'unit': UNIT,
            'candidateSha256': NEW_SHA, 'originalSha256': ORIGINAL_SHA, 'originalParameters': PARAMS,
            'candidateParameterAdded': {'pmem_ro_enable': '1'}, 'expectedProcess': EXPECTED_PROCESS,
            'nodeBChanged': False, 'SDKCalled': False, 'UBAllocated': False, 'GuestCreated': False,
            'requiresSeparateMaintenanceApproval': True, 'automaticRollback': False}, indent=2))
        return 0
    os.umask(0o077)
    validate_context()
    validate_preparation()
    if args.mode == 'status':
        print(read(STAGE / 'journal.json'))
        return 0
    need(args.approval == APPROVAL, 'Separate explicit maintenance approval required')
    with operation_lock():
        journal_path = STAGE / 'journal.json'
        if args.mode == 'activate':
            need(not journal_path.exists() and not journal_path.is_symlink() and not list(STAGE.glob('event-*.json')),
                 'Prior maintenance exists; no activation retry, use status or explicit restore')
            backend = Local({'version': 2, 'node': NODE, 'bootId': BOOT, 'candidateSrcversion': NEW_SRC,
                'candidateSha256': NEW_SHA, 'originalXzSha256': OLD_SHA, 'originalSha256': ORIGINAL_SHA,
                'originalParameters': PARAMS, 'initialProcess': EXPECTED_PROCESS, 'taintBefore': TAINT_BEFORE,
                'SDK_called': False, 'Guest_created': False, 'UBAllocated': False, 'nodeBChanged': False})
            # Repeat all preflight checks before writing intent or touching UBSE.
            backend.check_old()
            backend.mark('backups_verified')
            operation = lambda: activate(backend)
        else:
            journal = json.loads(read(journal_path))
            need(journal['version'] == 2 and journal['node'] == NODE and journal['bootId'] == BOOT and
                 journal['candidateSha256'] == NEW_SHA and journal['originalSha256'] == ORIGINAL_SHA and
                 journal['candidateSrcversion'] == NEW_SRC and journal['originalParameters'] == PARAMS and
                 journal['initialProcess'] == EXPECTED_PROCESS, 'Recovery journal identity differs')
            backend = Local(journal)
            operation = lambda: explicit_restore(backend)
        try:
            operation()
            if args.mode == 'activate':
                backend.mark('candidate_loaded_ubse_active', taintAfter=read('/proc/sys/kernel/tainted'))
            status = 'A_OBMM_CANDIDATE_READY_NO_SDK' if args.mode == 'activate' else 'A_ORIGINAL_MODULE_AND_UBSE_RESTORED'
            print('BEGIN_A_MAINTENANCE_JSON', flush=True)
            print(json.dumps({'status': status, **backend.journal}, sort_keys=True), flush=True)
            print('END_A_MAINTENANCE_JSON', flush=True)
            print(status, flush=True)
            return 0
        except Exception as error:
            previous = backend.journal['phase']
            failure = {'reason': str(error)[:1000], 'automaticRollbackExecuted': False,
                       'recoveryRequiresExplicitInvocation': True, 'previousPhase': previous}
            try:
                backend.mark('stopped_preserve_state', **failure)
            except Exception as journal_error:
                failure['journalWriteError'] = type(journal_error).__name__
            print(json.dumps({'status': 'A_MAINTENANCE_STOPPED_PRESERVE_STATE', **backend.journal, **failure}, sort_keys=True), flush=True)
            return 1


if __name__ == '__main__':
    try:
        code = main()
    except Exception as error:
        print(json.dumps({'status': 'A_MAINTENANCE_STOPPED_PRESERVE_STATE', 'reason': str(error)[:800],
                          'automaticRollbackExecuted': False}, sort_keys=True), flush=True)
        code = 1
    raise SystemExit(code)
