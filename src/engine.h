#pragma once

#include <optional>
#include <unordered_map>
#include <sys/ptrace.h>
#include "syscall_event.h"

namespace engine {
    class Engine {
        public:
            void add_tracked_pid(pid_t pid);
            void remove_tracked_pid(pid_t pid);
            void handle_syscall_entry(pid_t pid, const __ptrace_syscall_info info);
            void handle_syscall_exit(pid_t pid, const __ptrace_syscall_info info);

            bool is_tracked(pid_t pid);
            size_t tracked();
        private:
            std::unordered_map<pid_t, std::optional<SyscallEvent>> tracked_pids;
    };    
}
