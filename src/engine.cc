#include <cstdio>
#include <ctime>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include "engine.h"
#include "detection_state.h"
#include "parse_syscall.h"
#include "rule.h"
#include "syscall_event.h"
#include "helpers.h"

namespace engine {
    void Engine::add_allow_execve_path(const std::string& path) {
        allow_execve_paths.insert(path);
    }

    void Engine::add_tracked_pid(pid_t pid, pid_t parent_pid) {
        tracked_pids[pid] = std::nullopt;

        if (from_shell_pids.contains(parent_pid)) {
            from_shell_pids.insert(pid);
        }

        if (allow_pids.contains(parent_pid)) {
            allow_pids.insert(pid);
        }

        // copy_detection_states(parent_pid, pid);
    }

    void Engine::copy_detection_states(pid_t parent_pid, pid_t child_pid) {
        std::vector<DetectionState> copied;

        for (const auto& [id, state] : active_detection_states) {
            if (state.pid != parent_pid) {
                continue;
            }

            DetectionState child_state = state;
            child_state.id = detection_state_count++;
            child_state.pid = child_pid;
            copied.push_back(std::move(child_state));
        }

        for (auto& state : copied) {
            active_detection_states[state.id] = std::move(state);
        }
    }

    void Engine::remove_tracked_pid(pid_t pid) {
        tracked_pids.erase(pid);
        from_shell_pids.erase(pid);
        allow_pids.erase(pid);
        storage.erase(pid);
    }

    bool Engine::is_tracked(pid_t pid) {
        return tracked_pids.contains(pid);
    }

    size_t Engine::tracked() {
        return tracked_pids.size();
    }

    void Engine::add_rule(DetectionRule rule) {
        size_t index = rules.size();
        this->rules.push_back(std::move(rule));
        DetectionState initial_state = {
            .id = this->detection_state_count,
            .pid = 0,
            .rule_index = index,
            .current_state_index = 0,
            .start_time_ns = 0,
            .is_done = false
        };

        this->detection_state_count++;
        this->initial_states.push_back(initial_state);
    }

    void Engine::process_transition(const SyscallEvent& event) {
        // TODO: iterater 없이 하는 방법
        std::vector<size_t> done_ids;
        auto iter = active_detection_states.begin();
        for (; iter != active_detection_states.end(); iter++) {
            auto &state = iter->second;
            size_t rule_index = state.rule_index;
            size_t current_state_index = state.current_state_index;

            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);

            unsigned long current_time_ns = static_cast<unsigned long>(ts.tv_sec) * 1000000000UL + static_cast<unsigned long>(ts.tv_nsec);

            if (this->rules[rule_index].timeout_ns >= 0 &&
                current_time_ns - state.start_time_ns > static_cast<unsigned long>(this->rules[rule_index].timeout_ns)) {
                // fprintf(
                //     stderr,
                //     "[DEBUG] timeout id: %lu rule_index: %lu current_state_index: %lu\n",
                //     state.id,
                //     rule_index,
                //     current_state_index
                // );
                done_ids.push_back(state.id);
                continue;
            }

            if (state.pid != event.pid) {
                continue;
            }

            Context ctx = {
                .storage = storage[event.pid]
            };
            // fprintf(stderr, "[DEBUG] check id: %lu current_state_index: %lu\n", state.id, current_state_index);
            int next_state_index = this->rules[rule_index].transitions[current_state_index](ctx, state, event);
            if (next_state_index >= 0) {
                size_t final_state_index = this->rules[rule_index].transitions.size();
                if (static_cast<size_t>(next_state_index) > final_state_index) {
                    continue;
                }

                if (static_cast<size_t>(next_state_index) == final_state_index) {
                    fprintf(
                        stderr, 
                        "[DEBUG] DETECTED: id: %lu rule index: %lu rule name: %s\n",
                        state.id,
                        rule_index,
                        this->rules[rule_index].name.c_str()
                    );
                    bool keep = false;
                    if (this->rules[rule_index].on_detect.has_value()) {
                        keep = (*this->rules[rule_index].on_detect)(state);
                    }

                    if (!keep) {
                        done_ids.push_back(state.id);
                    }
                    // detected
                    continue;
                }
                state.current_state_index = static_cast<size_t>(next_state_index);
            }
        }

        for (size_t id : done_ids) {
            active_detection_states.erase(id);
        }
    }

    void Engine::process_first_transition(const SyscallEvent& event) {
        for (DetectionState& initial_state : this->initial_states) {
            size_t rule_index = initial_state.rule_index;
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);

            DetectionState next_state = initial_state;
            next_state.id = this->detection_state_count;
            next_state.pid = event.pid;
            next_state.current_state_index = 0;
            next_state.start_time_ns = static_cast<unsigned long>(ts.tv_sec) * 1000000000UL + static_cast<unsigned long>(ts.tv_nsec);
            next_state.captured.clear();

            Context ctx = {
                .storage = storage[event.pid]
            };
            int next_state_index = this->rules[rule_index].transitions[0](ctx, next_state, event);
            if (next_state_index >= 0) {
                // fprintf(stderr, "[DEBUG] run id: %lu\n", this->detection_state_count);
                size_t final_state_index = this->rules[rule_index].transitions.size();
                if (static_cast<size_t>(next_state_index) > final_state_index) {
                    continue;
                }

                if (static_cast<size_t>(next_state_index) == final_state_index) {
                    fprintf(
                        stderr, 
                        "[DEBUG] DETECTED: id: %lu rule index: %lu rule name: %s\n",
                        next_state.id,
                        next_state.rule_index,
                        this->rules[rule_index].name.c_str()
                    );
                    // step length == 1 짜리
                    // 조건 완료라서 탐지됨
                    continue;
                }

                next_state.current_state_index = static_cast<size_t>(next_state_index);

                this->active_detection_states[next_state.id] = std::move(next_state);
                this->detection_state_count++;
            }
        }
    }

    void Engine::process_allow_list(const SyscallEvent& event) {
        if (event.syscall_index != SYS_execve) {
            return;
        }

        if (allow_execve_paths.empty()) {
            return;
        }

        // execve 성공 했는지 체크
        if (!event.retval.has_value() || *event.retval != 0) {
            return;
        }

        const auto* args = std::get_if<ExecveData>(&event.args);
        if (!args) {
            return;
        }

        auto execve_path = get_absolute_path(event.pid, args->filename);
        if (!execve_path.has_value()) {
            return;
        }

        if (!allow_execve_paths.contains(*execve_path)) {
            return;
        }

        fprintf(stderr, "allowed: %s\n", execve_path->c_str());

        allow_pids.insert(event.pid);
    }

    void Engine::process_from_shell(SyscallEvent& event) {
        if (event.syscall_index != SYS_execve) {
            return;
        }

        // execve 성공 했는지 체크
        if (!event.retval.has_value() || *event.retval != 0) {
            return;
        }

        const auto* args = std::get_if<ExecveData>(&event.args);
        if (!args) {
            return;
        }

        fprintf(stderr, "execve: %s - pid: %d\n", args->filename.c_str(), event.pid);

        if (args->filename != "/bin/sh" && args->filename != "/usr/bin/sh" &&
            args->filename != "/bin/bash" && args->filename != "/usr/bin/bash") {
            return;
        }
        // if (args->argv.size() < 2) {
        //     return;
        // }
        // if (args->argv[1] != "-c") {
        //     return;
        // }

        from_shell_pids.insert(event.pid);
        event.from_shell = true;
    }

    void Engine::process_event(SyscallEvent& event) {
        process_allow_list(event);
        process_from_shell(event);

        if (!detection_started) {
            if (event.syscall_index != SYS_listen ||
                !event.retval.has_value() ||
                *event.retval != 0) {
                return;
            }

            detection_started = true;
        }

        if (allow_pids.contains(event.pid)) {
            return;
        }

        process_transition(event);

        // 중복 처리 방지를 위해 마지막에 호출
        process_first_transition(event);
    }

    void Engine::handle_syscall_entry(pid_t pid, const __ptrace_syscall_info info) {
        if (!is_tracked(pid)) {
            return;
        }

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);

        bool is_from_shell = from_shell_pids.contains(pid);

        SyscallEvent event {
            .syscall_index = info.entry.nr,
            .pid = pid,
            .retval = std::nullopt,
            .from_shell = is_from_shell,
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
            case SYS_openat: {
                auto args = parse_openat(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_renameat2: {
                auto args = parse_renameat2(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_rename: {
                auto args = parse_rename(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_renameat: {
                auto args = parse_renameat(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_linkat: {
                auto args = parse_linkat(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_symlinkat: {
                auto args = parse_symlinkat(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_unlinkat: {
                auto args = parse_unlinkat(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_chmod: {
                auto args = parse_chmod(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_fchmodat: {
                auto args = parse_fchmodat(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_truncate: {
                auto args = parse_truncate(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_ftruncate: {
                auto args = parse_ftruncate(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_dup2: {
                auto args = parse_dup2(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_read: {
                auto args = parse_read(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_pread64: {
                auto args = parse_pread64(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_write: {
                auto args = parse_write(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_pwrite64: {
                auto args = parse_pwrite64(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_sendto: {
                auto args = parse_sendto(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_connect: {
                auto args = parse_connect(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_getdents64: {
                auto args = parse_getdents64(pid, info);
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

        process_event(*tracked_pids[pid]);
    }
}
