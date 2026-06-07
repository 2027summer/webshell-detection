#pragma once
#include "syscall_event.h"
#include <optional>
#include <sys/ptrace.h>

namespace engine {
    long parse_syscall_rval(__ptrace_syscall_info info);

    std::optional<ExecveData> parse_execve(pid_t pid, __ptrace_syscall_info info);
    std::optional<ExecveAtData> parse_execveat(pid_t pid, __ptrace_syscall_info info);
    std::optional<OpenAtData> parse_openat(pid_t pid, __ptrace_syscall_info info);
    std::optional<ChdirData> parse_chdir(pid_t pid, __ptrace_syscall_info info);
    std::optional<ChmodData> parse_chmod(pid_t pid, __ptrace_syscall_info info);
    std::optional<FchmodAtData> parse_fchmodat(pid_t pid, __ptrace_syscall_info info);
    std::optional<TruncateData> parse_truncate(pid_t pid, __ptrace_syscall_info info);
    std::optional<FtruncateData> parse_ftruncate(pid_t pid, __ptrace_syscall_info info);
    std::optional<UnlinkAtData> parse_unlinkat(pid_t pid, __ptrace_syscall_info info);
    std::optional<RenameData> parse_rename(pid_t pid, __ptrace_syscall_info info);
    std::optional<RenameAtData> parse_renameat(pid_t pid, __ptrace_syscall_info info);
    std::optional<RenameAt2Data> parse_renameat2(pid_t pid, __ptrace_syscall_info info);
    std::optional<LinkAtData> parse_linkat(pid_t pid, __ptrace_syscall_info info);
    std::optional<SymlinkAtData> parse_symlinkat(pid_t pid, __ptrace_syscall_info info);
    std::optional<ReadlinkAtData> parse_readlinkat(pid_t pid, __ptrace_syscall_info info);
    std::optional<WriteData> parse_write(pid_t pid, __ptrace_syscall_info info);
    std::optional<WriteData> parse_pwrite64(pid_t pid, __ptrace_syscall_info info);
    std::optional<SendToData> parse_sendto(pid_t pid, __ptrace_syscall_info info);
    std::optional<ConnectData> parse_connect(pid_t pid, __ptrace_syscall_info info);
    std::optional<Dup2Data> parse_dup2(pid_t pid, __ptrace_syscall_info info);
    std::optional<CloseData> parse_close(pid_t pid, __ptrace_syscall_info info);
    std::optional<ReadData> parse_read(pid_t pid, __ptrace_syscall_info info);
    std::optional<ReadData> parse_pread64(pid_t pid, __ptrace_syscall_info info);
    std::optional<Getdents64Data> parse_getdents64(pid_t pid, __ptrace_syscall_info info);
    std::optional<CopyFileRangeData> parse_copy_file_range(pid_t pid, __ptrace_syscall_info info);
}
