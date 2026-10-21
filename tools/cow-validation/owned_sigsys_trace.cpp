// Only the freshly forked FC child and its ptrace-reported descendants are traced.
// Original Firecracker seccomp filters remain enabled. No SDK or host changes.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <elf.h>
#include <signal.h>
#include <unistd.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <thread>

static volatile sig_atomic_t stop_requested = 0;
static void stop(int) { stop_requested = 1; }
static void kill_owned(const std::set<pid_t>& owned) {
    for (pid_t pid : owned) {
        if (pid > 1) kill(pid, SIGKILL);
    }
}
static int trace_error(const char* reason) {
    std::cout << "AENV_TRACE_ERROR {\"reason\":\"" << reason << "\",\"errno\":" << errno << "}" << std::endl;
    return 95;
}
int main(int argc, char** argv) {
    if (argc < 2 || geteuid() == 0) return trace_error("ordinary_user_and_exact_child_command_required");
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    signal(SIGCHLD, SIG_DFL);
    pid_t parent = getpid();
    pid_t root = fork();
    if (root < 0) return trace_error("fork_failed");
    if (root == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) _exit(125);
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(126);
        raise(SIGSTOP);
        execv(argv[1], argv + 1);
        _exit(127);
    }
    std::set<pid_t> owned{root};
    int initial = 0;
    pid_t first;
    do { first = waitpid(root, &initial, 0); } while (first < 0 && errno == EINTR);
    if (first != root || !WIFSTOPPED(initial) || WSTOPSIG(initial) != SIGSTOP) {
        if (first == root && (WIFEXITED(initial) || WIFSIGNALED(initial))) owned.erase(root);
        kill_owned(owned);
        for (pid_t pid : owned) { int status; while (waitpid(pid, &status, __WALL) < 0 && errno == EINTR) {} }
        return trace_error("child_traceme_stop_failed_no_filter_change");
    }
    const unsigned long options = PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
    bool fatal = false, captured = false, stopping = false;
    int root_exit = -1;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(125);
    auto reap_deadline = deadline;
    if (ptrace(PTRACE_SETOPTIONS, root, nullptr, reinterpret_cast<void*>(options)) != 0 ||
        ptrace(PTRACE_CONT, root, nullptr, nullptr) != 0) {
        trace_error("ptrace_options_or_continue_unsupported");
        fatal = stopping = true;
        reap_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        kill_owned(owned);
    }
    while (!owned.empty()) {
        const auto now = std::chrono::steady_clock::now();
        if (!stopping && (stop_requested || now >= deadline)) {
            fatal = stopping = true;
            reap_deadline = now + std::chrono::seconds(10);
            kill_owned(owned);
        }
        if (stopping && now >= reap_deadline) break;
        int status = 0;
        pid_t pid = waitpid(-1, &status, __WALL | WNOHANG);
        if (pid == 0) { std::this_thread::sleep_for(std::chrono::milliseconds(2)); continue; }
        if (pid < 0) {
            if (errno == EINTR) continue;
            trace_error("waitpid_ownership_unresolved");
            fatal = true;
            break;
        }
        if (!owned.count(pid)) {
            // A clone stop can be reported before its parent's event. waitpid
            // __WALL reports this fresh tracer's own children/tracees only;
            // additionally require the kernel TracerPid before accepting it.
            std::ifstream status_file("/proc/" + std::to_string(pid) + "/status");
            std::string line;
            bool ours = false;
            while (std::getline(status_file, line)) {
                if (line.rfind("TracerPid:", 0) == 0) {
                    ours = std::stol(line.substr(10)) == getpid();
                    break;
                }
            }
            if (WIFSTOPPED(status) && ours) owned.insert(pid);
            else {
                trace_error("unreported_non_owned_tracee_refused");
                fatal = true;
                break;
            }
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == root) root_exit = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
            owned.erase(pid);
            continue;
        }
        if (!WIFSTOPPED(status)) continue;
        const int sig = WSTOPSIG(status);
        const unsigned event = static_cast<unsigned>(status) >> 16;
        if (sig == SIGTRAP && (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK)) {
            unsigned long child = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &child) != 0 || child <= 1) {
                trace_error("child_event_identity_unresolved"); fatal = true; break;
            }
            owned.insert(static_cast<pid_t>(child));
        }
        if (sig == SIGSYS && !stopping) {
            siginfo_t info{};
            if (ptrace(PTRACE_GETSIGINFO, pid, nullptr, &info) != 0) {
                trace_error("sigsys_siginfo_unavailable"); fatal = true; break;
            }
            // Only a kernel-generated seccomp trap on the expected ABI is
            // evidence of a rejected syscall; ordinary SIGSYS is not.
            if (info.si_code != 1 || info.si_arch != UINT32_C(0xc00000b7) || info.si_syscall < 0) {
                trace_error("SIGSYS_not_AArch64_kernel_SECCOMP");
                fatal = stopping = true;
                reap_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                kill_owned(owned);
                ptrace(PTRACE_CONT, pid, nullptr, reinterpret_cast<void*>(SIGKILL));
                continue;
            }
            std::cout << "AENV_SIGSYS_DIAGNOSTIC {\"tid\":" << pid << ",\"rootPid\":" << root
                      << ",\"isRootThread\":" << (pid == root ? "true" : "false") << ",\"syscall\":" << info.si_syscall
                      << ",\"arch\":" << info.si_arch << ",\"siCode\":" << info.si_code;
#if defined(__aarch64__)
            struct ArmRegs { uint64_t regs[31], sp, pc, pstate; } regs{};
            struct iovec data{&regs, sizeof(regs)};
            if (ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &data) == 0 && data.iov_len == sizeof(regs)) {
                std::cout << ",\"registerSyscall\":" << regs.regs[8] << ",\"pc\":" << regs.pc << ",\"args\":[";
                for (int i = 0; i < 6; ++i) std::cout << (i ? "," : "") << regs.regs[i];
                std::cout << "]";
            }
#endif
            std::cout << ",\"filterDisabled\":false}" << std::endl;
            captured = stopping = true;
            reap_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            kill_owned(owned);
        }
        if (stopping) {
            // Kill delivery and reaping only; do not resume the rejected operation.
            if (ptrace(PTRACE_CONT, pid, nullptr, reinterpret_cast<void*>(SIGKILL)) != 0 && errno != ESRCH) fatal = true;
        } else {
            int deliver = (sig == SIGTRAP && event != 0) || sig == SIGSTOP ? 0 : sig;
            if (ptrace(PTRACE_CONT, pid, nullptr, reinterpret_cast<void*>(static_cast<intptr_t>(deliver))) != 0 && errno != ESRCH) {
                trace_error("continue_failed"); fatal = true; break;
            }
        }
    }
    if (!owned.empty()) kill_owned(owned);
    std::cout << "AENV_TRACE_FINAL {\"allOwnedTraceesReaped\":" << (owned.empty() ? "true" : "false")
              << ",\"unreapedCount\":" << owned.size() << ",\"signalCaptured\":" << (captured ? "true" : "false")
              << ",\"rootExit\":" << root_exit << ",\"filterDisabled\":false}" << std::endl;
    // EXITKILL is still active if an unkillable tracee prevented definite reaping.
    if (!owned.empty() || fatal) return 95;
    if (captured) return 90;
    return root_exit >= 0 && root_exit <= 255 ? root_exit : 94;
}
