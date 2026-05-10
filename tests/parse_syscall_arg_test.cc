#include <cassert>
#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "parse_syscall.h"

struct SyscallInfo {
    pid_t pid;
    __ptrace_syscall_info info;
};

SyscallInfo run(int target_syscall, void (*call_syscall)(), bool check_entry) {
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        raise(SIGSTOP);
        call_syscall();
        _exit(0);
    }

    int stat;
    if (waitpid(child, &stat, 0) < 0 || !WIFSTOPPED(stat)) {
        assert(false);
    }

    if (ptrace(PTRACE_SETOPTIONS, child, nullptr,
        PTRACE_O_TRACESYSGOOD |
        PTRACE_O_EXITKILL
    ) < 0) {
        assert(false);
    }

    ptrace(PTRACE_SYSCALL, child, nullptr, 0);

    for (size_t i = 0; i < 500; i++) {
        pid_t pid;

        if ((pid = waitpid(-1, &stat, __WALL)) < 0) {
            break;
        }

        if (WIFEXITED(stat) || WIFSIGNALED(stat)) {
            continue;
        }

        if (!WIFSTOPPED(stat)) continue;

        int sig = WSTOPSIG(stat);
        unsigned int event = static_cast<unsigned int>(stat) >> 16;

        if (sig == (SIGTRAP | 0x80)) {
            __ptrace_syscall_info info{};

            if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) < 0) {
                ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
                continue;
            }

            if (info.op == PTRACE_SYSCALL_INFO_ENTRY && check_entry) {
                if (info.entry.nr == target_syscall) {
                    return SyscallInfo {
                        .pid = pid,
                        .info = info
                    };
                }
            } else if (info.op == PTRACE_SYSCALL_INFO_EXIT && !check_entry) {
                if (info.entry.nr == target_syscall) {
                    return SyscallInfo {
                        .pid = pid,
                        .info = info
                    };
                }
            }
            ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
        } else if (sig == SIGTRAP && event != 0) {
            ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
        } else if (sig == SIGSTOP || sig == SIGTRAP) {
            ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
        } else {
            ptrace(PTRACE_SYSCALL, pid, nullptr, sig);
        }
    }
    assert(false);
}

void call_execve() {
    char argv_0[] = "/bin/sh";
    char argv_1[] = "-c";
    char argv_2[] = "cat flag";

    char *argv[] = {argv_0, argv_1, argv_2, nullptr};
    char *envp[] = {nullptr};


    syscall(SYS_execve, "/bin/sh", argv, envp);
}

void check_execve(pid_t pid, __ptrace_syscall_info info) {
    auto execve_args = engine::parse_execve(pid, info);
    if (!execve_args.has_value()) {
        assert(false);
    }
    if (execve_args->filename != "/bin/sh") {
        assert(false);
    }
    if (execve_args->argv[0] != "/bin/sh") {
        assert(false);
    }
    if (execve_args->argv[1] != "-c") {
        assert(false);
    }
    if (execve_args->argv[2] != "cat flag") {
        assert(false);
    }

    fprintf(stderr, "[INFO] execve test completed\n");
}

void test_execve() {
    SyscallInfo info = run(SYS_execve, call_execve, true);
    check_execve(info.pid, info.info);
}

void call_openat() {
    int dfd = AT_FDCWD;
    char filename[] = "flag";
    int flags = O_RDONLY;
    // int mode

    syscall(SYS_openat, dfd, filename, flags);
}

void check_openat(pid_t pid, __ptrace_syscall_info info) {
    auto openat_args = engine::parse_openat(pid, info);
    if (!openat_args.has_value()) {
        assert(false);
    }

    if (openat_args->dirfd != AT_FDCWD) {
        assert(false);
    }
    if (openat_args->pathname != "flag") {
        assert(false);
    }
    if (openat_args->flags != O_RDONLY) {
        assert(false);
    }

    fprintf(stderr, "[INFO] openat test completed\n");
}

void test_openat() {
    SyscallInfo info = run(SYS_openat, call_openat, true);
    check_openat(info.pid, info.info);
}

int main(int argc, char **argv) {
    test_execve();
    test_openat();
    return 0;
}