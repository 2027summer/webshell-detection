#include <cstdio>
#include <ctime>
#include <sys/syscall.h>
#include "engine.h"
#include "parse_syscall.h"
#include "syscall_event.h"

namespace engine {
    void Engine::add_tracked_pid(pid_t pid) {
        tracked_pids[pid] = std::nullopt;
    }

    void Engine::remove_tracked_pid(pid_t pid) {
        tracked_pids.erase(pid);
    }

    bool Engine::is_tracked(pid_t pid) {
        return !(tracked_pids.find(pid) == tracked_pids.end());
    }

    size_t Engine::tracked() {
        return tracked_pids.size();
    }

    void Engine::handle_syscall_entry(pid_t pid, const __ptrace_syscall_info info) {
        if (!is_tracked(pid)) {
            return;
        }

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);

        SyscallEvent event {
            .syscall_index = info.entry.nr,
            .pid = pid,
            .retval = std::nullopt,
            .timestamp_ns = static_cast<unsigned long>(ts.tv_sec) * 1000000000UL + static_cast<unsigned long>(ts.tv_nsec)
        };

        switch (info.entry.nr) {
            case SYS_execve: {
                auto args = parse_execve(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            default:
                break;
        }

        tracked_pids[pid] = event;
    }

    void Engine::handle_syscall_exit(pid_t pid, const __ptrace_syscall_info info) {
        if (!is_tracked(pid)) {
            return;
        }

        long retval = parse_syscall_rval(info);
        tracked_pids[pid]->retval = retval;

    }
}
