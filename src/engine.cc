#include <cstdio>
#include <ctime>
#include <sys/syscall.h>
#include "engine.h"
#include "detection_state.h"
#include "parse_syscall.h"
#include "rule.h"
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

            if (current_time_ns - state.start_time_ns > this->rules[rule_index].timeout_ns) {
                fprintf(
                    stderr,
                    "[DEBUG] timeout id: %lu rule_index: %lu current_state_index: %lu\n",
                    state.id,
                    rule_index,
                    current_state_index
                );
                done_ids.push_back(state.id);
                continue;
            }

            // fprintf(stderr, "[DEBUG] check id: %lu current_state_index: %lu\n", state.id, current_state_index);
            bool can = this->rules[rule_index].transitions[current_state_index](state, event);
            if (can) {
                size_t final_state_index = this->rules[rule_index].transitions.size();
                if (current_state_index + 1 == final_state_index) {
                    fprintf(
                        stderr, 
                        "[DEBUG] DETECTED: id: %lu rule index: %lu rule name: %s\n",
                        state.id,
                        rule_index,
                        this->rules[rule_index].name.c_str()
                    );
                    done_ids.push_back(state.id);
                    // detected
                    continue;
                }
                state.current_state_index++;
            }
        }

        for (size_t id : done_ids) {
            active_detection_states.erase(id);
        }
    }

    void Engine::process_first_transition(const SyscallEvent& event) {
        for (DetectionState& initial_state : this->initial_states) {
            size_t rule_index = initial_state.rule_index;
            bool can = this->rules[rule_index].transitions[0](initial_state, event);
            if (can) {
                // fprintf(stderr, "[DEBUG] run id: %lu\n", this->detection_state_count);
                size_t final_state_index = this->rules[rule_index].transitions.size();
                if (final_state_index == 1) {
                    fprintf(
                        stderr, 
                        "[DEBUG] DETECTED: id: %lu rule index: %lu rule name: %s\n",
                        initial_state.id,
                        initial_state.rule_index,
                        this->rules[rule_index].name.c_str()
                    );
                    // step length == 1 짜리
                    // 조건 완료라서 탐지됨
                    continue;
                }

                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                DetectionState next_state = {
                    .id = this->detection_state_count,
                    .pid = event.pid,
                    .rule_index = rule_index,
                    .current_state_index = 1,
                    .start_time_ns = static_cast<unsigned long>(ts.tv_sec) * 1000000000UL + static_cast<unsigned long>(ts.tv_nsec)
                };

                this->active_detection_states[next_state.id] = std::move(next_state);
                this->detection_state_count++;
            }
        }
    }

    void Engine::process_event(const SyscallEvent& event) {
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
