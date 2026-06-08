#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <sys/ptrace.h>
#include "detection_state.h"
#include "rule.h"
#include "syscall_event.h"

namespace engine {
    class Engine {
        public:
            void add_tracked_pid(pid_t pid, pid_t parent_pid = 0);
            void remove_tracked_pid(pid_t pid);
            void handle_syscall_entry(pid_t pid, const __ptrace_syscall_info info);
            void handle_syscall_exit(pid_t pid, const __ptrace_syscall_info info);
            void handle_exec_stop(pid_t pid);
            void process_event(SyscallEvent& event);
            void process_first_transition(const SyscallEvent& event);
            void process_transition(const SyscallEvent& event);

            bool is_tracked(pid_t pid);
            size_t tracked();

            void add_allow_execve_path(const std::string& path);
            void add_rule(DetectionRule rule);
        private:
            void copy_detection_states(pid_t parent_pid, pid_t child_pid);
            void process_allow_list(const SyscallEvent& event);
            void process_from_shell(SyscallEvent& event);
            bool has_active_state(pid_t pid, size_t rule_index);
            bool in_cooldown(pid_t pid, size_t rule_index, unsigned long now_ns);
            void set_cooldown(pid_t pid, size_t rule_index, unsigned long now_ns);
            void report_detection(const DetectionState& state, const SyscallEvent& event);

            std::unordered_map<pid_t, std::optional<SyscallEvent>> tracked_pids;
            std::unordered_set<pid_t> from_shell_pids;
            std::unordered_set<std::string> allow_execve_paths;
            std::unordered_set<pid_t> allow_pids;
            std::vector<DetectionRule> rules;    
            std::vector<DetectionState> initial_states;
            std::unordered_map<size_t, DetectionState> active_detection_states;
            std::unordered_map<pid_t, std::unordered_map<size_t, unsigned long>> cooldown_until;

            size_t detection_state_count = 0;
            bool detection_started = false;
    };
}
