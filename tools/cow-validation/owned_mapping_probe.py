"""Owned 4MiB NC mapping observation; no Guest, KVM, CC or service operations.

The SDK's physical backing has no enforced hard quota here. The fixed 128MiB
coverage guard is checked after allocation/map/lookup, before the device tests.
Only one fresh random object is allocated. Never use an existing shared base.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import uuid

SOURCE = '// Disposable NC object contract probe. No Guest, KVM, region or service changes.\n#include <ubs_mem.h>\n#include <atomic>\n#include <cerrno>\n#include <chrono>\n#include <csignal>\n#include <cstdint>\n#include <cstdlib>\n#include <cstring>\n#include <fcntl.h>\n#include <iostream>\n#include <initializer_list>\n#include <limits>\n#include <spawn.h>\n#include <string>\n#include <sys/mman.h>\n#include <sys/stat.h>\n#include <sys/wait.h>\n#include <thread>\n#include <unistd.h>\n\nextern char **environ;\nconstexpr size_t BYTES = 4UL * 1024 * 1024;\nconstexpr uint64_t MAX_COVERAGE = 128ULL * 1024 * 1024;\nstatic volatile std::sig_atomic_t interrupted = 0;\nstatic void stop(int) { interrupted = 1; }\nstatic void logger(int level, const char *) { std::cerr << "sdk_log_level=" << level << std::endl; }\ntemplate<class F> static int call(const char *phase, F function)\n{\n    std::cout << "begin=" << phase << std::endl;\n    int rc = function();\n    std::cout << "result_" << phase << \'=\' << rc << std::endl;\n    return rc;\n}\nstatic int child(const std::string &mode, uint64_t expected)\n{\n    const std::string prefix = "fd_" + mode + \'_\';\n    int flags = fcntl(3, F_GETFL);\n    const bool rwfd = mode == "private_rwfd_4k" || mode == "private_rwfd_2m" || mode == "private_rwfd_4m";\n    const int access = rwfd ? O_RDWR : O_RDONLY;\n    size_t map_bytes = mode == "private_rwfd_4k" ? 4096UL : mode == "private_rwfd_2m" ? 2UL * 1024 * 1024 : BYTES;\n    if (flags < 0 || (flags & O_ACCMODE) != access || (flags & O_SYNC) != O_SYNC) return 2;\n    if (mode != "shared_ro" && mode != "private_rw" && !rwfd) return 2;\n    bool write = mode == "private_rw" || rwfd;\n    errno = 0;\n    void *address = mmap(nullptr, map_bytes, write ? PROT_READ | PROT_WRITE : PROT_READ,\n                         write ? MAP_PRIVATE : MAP_SHARED, 3, 0);\n    int saved = errno;\n    std::cout << prefix << "mmap_ok=" << (address != MAP_FAILED) << std::endl;\n    std::cout << prefix << "mmap_errno=" << saved << std::endl;\n    if (address == MAP_FAILED) return 0; // Unsupported mapping is a measured result.\n    auto *words = static_cast<volatile uint64_t *>(address);\n    std::atomic_thread_fence(std::memory_order_seq_cst);\n    bool matched = words[0] == expected && words[(map_bytes - 4096) / sizeof(uint64_t)] == expected;\n    std::cout << prefix << "base_matches=" << matched << std::endl;\n    if (matched && write) {\n        words[0] = expected ^ UINT64_C(0x123456789abcdef0);\n        std::atomic_thread_fence(std::memory_order_seq_cst);\n        std::cout << prefix << "private_value_matches=" << (words[0] == (expected ^ UINT64_C(0x123456789abcdef0))) << std::endl;\n    }\n    int rc = munmap(address, map_bytes);\n    std::cout << prefix << "unmap_ok=" << (rc == 0) << std::endl;\n    return matched && rc == 0 ? 0 : 3;\n}\nstatic bool run_child(const char *mode, int source_fd, uint64_t expected)\n{\n    posix_spawn_file_actions_t actions;\n    int rc = posix_spawn_file_actions_init(&actions);\n    if (rc != 0) return false;\n    rc = posix_spawn_file_actions_adddup2(&actions, source_fd, 3);\n    std::string seed = std::to_string(expected);\n    char *args[] = {const_cast<char *>("owned-fd-probe"), const_cast<char *>("child"),\n                    const_cast<char *>(mode), seed.data(), nullptr};\n    pid_t pid = -1;\n    if (rc == 0) rc = posix_spawn(&pid, "/proc/self/exe", &actions, nullptr, args, environ);\n    posix_spawn_file_actions_destroy(&actions);\n    std::cout << "child_" << mode << "_spawn_rc=" << rc << std::endl;\n    if (rc != 0) return true;\n    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(12);\n    int status = 0;\n    bool killed = false;\n    auto kill_time = deadline;\n    for (;;) {\n        pid_t result = waitpid(pid, &status, WNOHANG);\n        if (result == pid) break;\n        if (result < 0 && errno != EINTR) return false;\n        auto now = std::chrono::steady_clock::now();\n        if (!killed && (interrupted || now >= deadline)) {\n            kill(pid, SIGKILL); // Only the direct child created above.\n            killed = true;\n            kill_time = now;\n        }\n        if (killed && now - kill_time > std::chrono::seconds(4)) {\n            std::cout << "child_" << mode << "_reap_uncertain=1" << std::endl;\n            return false;\n        }\n        std::this_thread::sleep_for(std::chrono::milliseconds(20));\n    }\n    std::cout << "child_" << mode << "_reaped=1" << std::endl;\n    std::cout << "child_" << mode << "_timeout=" << killed << std::endl;\n    std::cout << "child_" << mode << "_signal=" << (WIFSIGNALED(status) ? WTERMSIG(status) : 0) << std::endl;\n    std::cout << "child_" << mode << "_exit=" << (WIFEXITED(status) ? WEXITSTATUS(status) : -1) << std::endl;\n    return true;\n}\nint main(int argc, char **argv)\n{\n    if (argc == 4 && std::string(argv[1]) == "child") {\n        char *end = nullptr;\n        uint64_t seed = std::strtoull(argv[3], &end, 10);\n        if (!end || *end || seed == 0) return 2;\n        return child(argv[2], seed);\n    }\n    if (argc != 3) return 2;\n    const std::string name(argv[1]);\n    if (name.size() != 32 || name.rfind("aenv_fd_", 0) != 0) return 2;\n    for (size_t i = 8; i < name.size(); ++i) if (!std::strchr("0123456789abcdef", name[i])) return 2;\n    char *end = nullptr;\n    uint64_t seed = std::strtoull(argv[2], &end, 10);\n    if (!end || *end || seed == 0) return 2;\n    std::signal(SIGTERM, stop);\n    std::signal(SIGINT, stop);\n    bool init_attempted = false, created = false, mapped = false, children_safe = true;\n    bool collected = false, deleted = false;\n    void *base = nullptr;\n    int fd = -1;\n    do {\n        if (call("logger", [] { return ubsmem_set_extern_logger(logger); }) != 0) break;\n        if (call("log_level", [] { return ubsmem_set_logger_level(3); }) != 0) break;\n        ubsmem_options_t options{};\n        if (call("attributes", [&] { return ubsmem_init_attributes(&options); }) != 0) break;\n        init_attempted = true;\n        if (call("initialize", [&] { return ubsmem_initialize(&options); }) != 0 || interrupted) break;\n        if (call("allocate", [&] { return ubsmem_shmem_allocate("default", name.c_str(), BYTES, 0600,\n                       UBSM_FLAG_NONCACHE | UBSM_FLAG_WR_DELAY_COMP); }) != 0) break;\n        created = true;\n        if (call("map", [&] { return ubsmem_shmem_map(nullptr, BYTES, PROT_READ | PROT_WRITE,\n                                           MAP_SHARED, name.c_str(), 0, &base); }) != 0) break;\n        mapped = true;\n        if (!base || base == MAP_FAILED) break;\n        ubsmem_shmem_info_t info{};\n        if (call("lookup", [&] { return ubsmem_shmem_lookup(name.c_str(), &info); }) != 0) break;\n        if (strnlen(info.name, sizeof(info.name)) != name.size() || name != info.name || info.size != BYTES) break;\n        if (info.mem_num == 0 || info.mem_num > MAX_MEMID_NUM || info.mem_unit_size == 0 ||\n            info.mem_unit_size > std::numeric_limits<uint64_t>::max() / info.mem_num) break;\n        uint64_t coverage = info.mem_unit_size * info.mem_num;\n        std::cout << "backing_count=" << info.mem_num << std::endl;\n        std::cout << "backing_unit_bytes=" << info.mem_unit_size << std::endl;\n        std::cout << "backing_coverage_bytes=" << coverage << std::endl;\n        // This check follows allocation: it is NOT a service-enforced physical quota.\n        if (coverage < BYTES || coverage > MAX_COVERAGE || info.mem_num != 1 || info.mem_id_list[0] == 0) break;\n        auto *words = static_cast<volatile uint64_t *>(base);\n        words[0] = seed;\n        words[(2UL * 1024 * 1024 - 4096) / sizeof(uint64_t)] = seed;\n        words[(BYTES - 4096) / sizeof(uint64_t)] = seed;\n        auto base_intact = [&] {\n            std::atomic_thread_fence(std::memory_order_seq_cst);\n            return words[0] == seed && words[(2UL * 1024 * 1024 - 4096) / sizeof(uint64_t)] == seed\n                && words[(BYTES - 4096) / sizeof(uint64_t)] == seed;\n        };\n        std::atomic_thread_fence(std::memory_order_seq_cst);\n        const std::string path = "/dev/obmm_shmdev" + std::to_string(info.mem_id_list[0]);\n        errno = 0;\n        int opened = open(path.c_str(), O_RDONLY | O_SYNC | O_CLOEXEC | O_NOFOLLOW);\n        std::cout << "native_open_errno=" << errno << std::endl;\n        std::cout << "native_open_ok=" << (opened >= 0) << std::endl;\n        if (opened < 0) break;\n        struct stat meta{};\n        bool valid = fstat(opened, &meta) == 0 && S_ISCHR(meta.st_mode);\n        if (valid) fd = fcntl(opened, F_DUPFD_CLOEXEC, 256);\n        close(opened);\n        if (fd < 0) break;\n        for (const char *mode : {"shared_ro", "private_rw"}) {\n            if (interrupted) break;\n            if (!run_child(mode, fd, seed)) { children_safe = false; break; }\n            std::atomic_thread_fence(std::memory_order_seq_cst);\n            bool intact = base_intact();\n            std::cout << "base_after_" << mode << "_intact=" << intact << std::endl;\n            if (!intact) break; // Owned disposable base may have aliased; never publish it.\n        }\n        if (children_safe && !interrupted && base_intact()) {\n            errno = 0;\n            int candidate = open(path.c_str(), O_RDWR | O_SYNC | O_CLOEXEC | O_NOFOLLOW);\n            std::cout << "native_rw_open_errno=" << errno << std::endl;\n            std::cout << "native_rw_open_ok=" << (candidate >= 0) << std::endl;\n            if (candidate >= 0) {\n                struct stat candidate_meta{};\n                bool same_device = fstat(candidate, &candidate_meta) == 0 && S_ISCHR(candidate_meta.st_mode)\n                    && candidate_meta.st_rdev == meta.st_rdev;\n                int pinned = same_device ? fcntl(candidate, F_DUPFD_CLOEXEC, 256) : -1;\n                close(candidate);\n                if (pinned >= 0) {\n                    for (const char *mode : {"private_rwfd_4k", "private_rwfd_2m", "private_rwfd_4m"}) {\n                        if (interrupted) break;\n                        if (!run_child(mode, pinned, seed)) { children_safe = false; break; }\n                        bool intact = base_intact();\n                        std::cout << "base_after_" << mode << "_intact=" << intact << std::endl;\n                        if (!intact) break; // Stop immediately if this disposable base aliases.\n                    }\n                    close(pinned);\n                }\n            }\n            std::atomic_thread_fence(std::memory_order_seq_cst);\n            std::cout << "base_after_all_private_rwfd_intact=" << base_intact() << std::endl;\n            collected = true; // Unsupported/aliased maps remain measured negative observations.\n        }\n    } while (false);\n    if (fd >= 0) close(fd);\n    if (mapped && children_safe) {\n        if (call("unmap", [&] { return ubsmem_shmem_unmap(base, BYTES); }) == 0) mapped = false;\n    }\n    if (created && !mapped && children_safe) {\n        if (call("deallocate", [&] { return ubsmem_shmem_deallocate(name.c_str()); }) == 0) deleted = true;\n    }\n    if (init_attempted && children_safe) call("finalize", [] { return ubsmem_finalize(); });\n    std::cout << "children_safe=" << children_safe << std::endl;\n    std::cout << "mapping_remaining=" << mapped << std::endl;\n    std::cout << "delete_acknowledged=" << deleted << std::endl;\n    std::cout << "contract_observations_collected=" << collected << std::endl;\n    return collected && deleted && children_safe && !mapped && !interrupted ? 0 : 1;\n}\n'

# Optional strict receipt/header gate, set by a trusted local wrapper.
# Called while the coordination flock is held, before creating any intent.
PREFLIGHT_HOOK = None


def fields(text):
    return {match[1]: int(match[2]) for line in text.splitlines()
            if (match := re.fullmatch(r'([a-z][a-z0-9_]*)=(-?[0-9]+)', line))}


def isolated(value, mode='private_rwfd_4m'):
    if mode not in ('private_rwfd_4k', 'private_rwfd_2m', 'private_rwfd_4m'):
        raise ValueError('Unknown tested mapping length')
    expected = {
        'fd_shared_ro_mmap_ok': 1, 'fd_shared_ro_base_matches': 1,
        'native_rw_open_ok': 1, 'fd_' + mode + '_mmap_ok': 1,
        'fd_' + mode + '_base_matches': 1, 'fd_' + mode + '_private_value_matches': 1,
        'fd_' + mode + '_unmap_ok': 1, 'child_' + mode + '_spawn_rc': 0,
        'child_' + mode + '_reaped': 1, 'child_' + mode + '_timeout': 0,
        'child_' + mode + '_signal': 0, 'child_' + mode + '_exit': 0,
        'base_after_' + mode + '_intact': 1}
    return all(value.get(key) == wanted for key, wanted in expected.items())


def save(path, value):
    temp = path.with_name(path.name + '.tmp')
    with temp.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-owned-probe', action='store_true')
    parser.add_argument('--work-dir')
    parser.add_argument('--sdk-lock')
    parser.add_argument('--pending')
    parser.add_argument('--sdk-library')
    parser.add_argument('--sdk-sha256')
    parser.add_argument('--sdk-include')
    parser.add_argument('--cxx', default='g++')
    args = parser.parse_args()
    if not args.run_owned_probe:
        print(json.dumps({'status': 'PLAN_ONLY_NO_SDK', 'logicalBytes': 4194304,
            'postMapCoverageGuardBytes': 134217728, 'physicalHardQuota': False,
            'Guest_created': False, 'KVM_tested': False, 'CC_attempted': False,
            'probes': ['readonly NC shared map', 'readonly FD private RW map',
                       'O_RDWR FD private RW maps at 4KiB, 2MiB and 4MiB; own base markers']}, indent=2))
        return 0
    if sys.platform != 'linux' or os.getuid() == 0 or os.geteuid() != os.getuid():
        raise RuntimeError('Run as an ordinary Linux user; no elevation fallback')
    caps = [line.split()[1] for line in Path('/proc/self/status').read_text().splitlines()
            if line.startswith(('CapInh:', 'CapPrm:', 'CapEff:', 'CapAmb:'))]
    if len(caps) != 4 or any(int(value, 16) for value in caps):
        raise RuntimeError('Probe requires zero capabilities')
    if not all(getattr(args, key) for key in ('work_dir', 'sdk_lock', 'pending', 'sdk_library', 'sdk_sha256', 'sdk_include')):
        raise ValueError('Run requires all explicit work, SDK, pin and coordination-lock arguments')
    sdk = Path(args.sdk_library).resolve(strict=True)
    if re.fullmatch(r'[0-9a-f]{64}', args.sdk_sha256) is None or hashlib.sha256(sdk.read_bytes()).hexdigest() != args.sdk_sha256:
        raise ValueError('Installed SDK differs from explicit SHA256 pin')
    include = Path(args.sdk_include).resolve(strict=True)
    compiler = shutil.which(args.cxx)
    if compiler is None:
        raise ValueError('Existing C++ compiler not found; nothing is installed automatically')
    work = Path(args.work_dir).absolute()
    lock_path = Path(args.sdk_lock).absolute()
    pending = Path(args.pending).absolute()
    if work.resolve() != work or lock_path.resolve() != lock_path or pending.resolve() != pending:
        raise ValueError('Explicit probe paths must not contain redirected components')
    import fcntl
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    metadata = os.fstat(lock)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1:
        os.close(lock)
        raise ValueError('Unexpected SDK coordination lock')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        if PREFLIGHT_HOOK is not None:
            PREFLIGHT_HOOK(args)
    except BaseException:
        os.close(lock)
        raise
    if pending.exists() or pending.is_symlink():
        os.close(lock)
        raise FileExistsError('Existing pending receipt preserved; do not retry or delete it blindly')
    work.mkdir(mode=0o700, exist_ok=False)
    directory = os.open(work.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    report = {'revision': 'owned-private-rwfd-v3', 'state': 'compile_no_sdk',
              'objectName': 'aenv_fd_' + uuid.uuid4().hex[:24],
              'logicalBytes': 4194304, 'postMapCoverageGuardBytes': 134217728,
              'physicalHardQuota': False, 'Guest_created': False, 'KVM_tested': False,
              'crossNode_tested': False, 'CC_attempted': False, 'SDK_called': False,
              'userspacePrivateWriteIsolationObserved': False,
              'nativeGuestMemoryCoWAccepted': False}
    receipt = work / 'return.json'
    save(receipt, report)
    with pending.open('x', encoding='utf-8') as stream:
        json.dump(report, stream)
        stream.flush()
        os.fsync(stream.fileno())
    worker = None
    try:
        source, binary = work / 'probe.cpp', work / 'probe'
        source.write_bytes(SOURCE.encode())
        with (work / 'compile.log').open('wb') as log:
            built = subprocess.run([compiler, '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
                '-I', str(include), str(source), str(sdk), '-pthread', '-Xlinker', '-rpath',
                '-Xlinker', str(sdk.parent), '-o', str(binary)], stdout=log, stderr=subprocess.STDOUT, timeout=180)
        report['compileExit'] = built.returncode
        if built.returncode:
            raise RuntimeError('Compilation failed before SDK; inspect the private compile.log')
        report.update(state='intent_before_sdk', binarySha256=hashlib.sha256(binary.read_bytes()).hexdigest())
        save(receipt, report)  # Object name/intent persist before any SDK request.
        save(pending, report)
        with (work / 'worker.log').open('wb') as stdout, (work / 'worker-errors.log').open('wb') as stderr:
            # The worker and its children retain the same SDK coordination lock
            # if this launcher exits before their precise completion.
            worker = subprocess.Popen([str(binary), report['objectName'], str(secrets.randbits(63) or 1)],
                stdout=stdout, stderr=stderr, pass_fds=(lock,), start_new_session=True)
            report['SDK_called'] = None  # Unknown until this owned worker's phase log is parsed.
            report['workerPid'] = worker.pid
            save(receipt, report)
            try:
                report['workerExit'] = worker.wait(timeout=120)
            except subprocess.TimeoutExpired:
                worker.terminate()  # Exact owned worker only; never another process or service.
                try:
                    report['workerExit'] = worker.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    report['state'] = 'worker_live_preserved_do_not_retry'
                    raise RuntimeError('SDK worker has not exited; lock/ownership remain with it')
        observed = fields((work / 'worker.log').read_text(errors='replace'))
        report['fields'] = observed
        report['SDK_called'] = True if 'begin=' in (work / 'worker.log').read_text(errors='replace') else None
        released = all(observed.get(key) == value for key, value in {
            'children_safe': 1, 'mapping_remaining': 0, 'delete_acknowledged': 1,
            'result_unmap': 0, 'result_deallocate': 0, 'result_finalize': 0}.items())
        by_length = {str(length): isolated(observed, mode) for length, mode in (
            (4096, 'private_rwfd_4k'), (2097152, 'private_rwfd_2m'), (4194304, 'private_rwfd_4m'))}
        report['userspacePrivateWriteIsolationByLength'] = by_length
        report['userspacePrivateWriteIsolationObserved'] = any(by_length.values())
        report['allTestedLengthsPrivateWriteIsolationObserved'] = all(by_length.values())
        report['state'] = 'owned_object_released_observations_only' if released else 'unresolved_preserved_do_not_retry'
        report['scope'] = 'One 4MiB object, three base markers, 4KiB/2MiB/4MiB private CPU writes; no PFN or KVM proof'
    except BaseException as error:
        if worker is not None and worker.poll() is None:
            report['state'] = 'worker_live_preserved_do_not_retry'
        report['errorType'] = type(error).__name__
        report['reason'] = str(error)[:1000]
    finally:
        save(receipt, report)
        save(pending, report)
        os.close(lock)
    print(json.dumps(report, indent=2))
    return 0 if report['state'] == 'owned_object_released_observations_only' else 1


if __name__ == '__main__':
    raise SystemExit(main())
