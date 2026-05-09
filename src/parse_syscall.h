#pragma once
#include "syscall_event.h"
#include <optional>
#include <sys/ptrace.h>

namespace engine {
    long parse_syscall_rval(__ptrace_syscall_info info);

    std::optional<ExecveData> parse_execve(pid_t pid, __ptrace_syscall_info info);
    std::optional<OpenAtData> parse_openat(pid_t pid, __ptrace_syscall_info info);
}
