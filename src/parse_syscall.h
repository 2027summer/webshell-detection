#pragma once
#include "syscall_event.h"
#include <optional>
#include <sys/ptrace.h>

namespace engine {
    long parse_syscall_rval(__ptrace_syscall_info info);

    std::optional<ExecveData> parse_execve(pid_t pid, __ptrace_syscall_info info);
    std::optional<OpenAtData> parse_openat(pid_t pid, __ptrace_syscall_info info);
    std::optional<ChdirData> parse_chdir(pid_t pid, __ptrace_syscall_info info);
    std::optional<UnlinkAtData> parse_unlinkat(pid_t pid, __ptrace_syscall_info info);
    std::optional<RenameData> parse_rename(pid_t pid, __ptrace_syscall_info info);
    std::optional<RenameAtData> parse_renameat(pid_t pid, __ptrace_syscall_info info);
    std::optional<RenameAt2Data> parse_renameat2(pid_t pid, __ptrace_syscall_info info);
    std::optional<LinkAtData> parse_linkat(pid_t pid, __ptrace_syscall_info info);
    std::optional<SymlinkAtData> parse_symlinkat(pid_t pid, __ptrace_syscall_info info);
    std::optional<ReadlinkAtData> parse_readlinkat(pid_t pid, __ptrace_syscall_info info);
    std::optional<WriteData> parse_write(pid_t pid, __ptrace_syscall_info info);
    std::optional<Dup2Data> parse_dup2(pid_t pid, __ptrace_syscall_info info);
    std::optional<CloseData> parse_close(pid_t pid, __ptrace_syscall_info info);
}
