#pragma once

#include <optional>
#include <unordered_map>
#include <sys/ptrace.h>
#include "detection_state.h"
#include "rule.h"
#include "syscall_event.h"

namespace engine {
    class Engine {
        public:
            void add_tracked_pid(pid_t pid);
            void remove_tracked_pid(pid_t pid);
            void handle_syscall_entry(pid_t pid, const __ptrace_syscall_info info);
            void handle_syscall_exit(pid_t pid, const __ptrace_syscall_info info);
            void process_event(const SyscallEvent& event);
            void process_first_transition(const SyscallEvent& event);
            void process_transition(const SyscallEvent& event);

            bool is_tracked(pid_t pid);
            size_t tracked();
        private:
            std::unordered_map<pid_t, std::optional<SyscallEvent>> tracked_pids;
            std::vector<DetectionRule> rules;    
            std::vector<DetectionState> initial_states;
            std::unordered_map<size_t, DetectionState> active_detection_states;

            size_t detection_state_count = 0;
    };
}
