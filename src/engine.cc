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

#ifndef DETECTION_REQUIRE_LISTEN
#define DETECTION_REQUIRE_LISTEN 1
#endif

#ifndef DETECTION_DEBUG
#define DETECTION_DEBUG 0
#endif

namespace engine {
    unsigned long monotonic_time_ns() {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return static_cast<unsigned long>(ts.tv_sec) * 1000000000UL + static_cast<unsigned long>(ts.tv_nsec);
    }

#if DETECTION_DEBUG
    const char* debug_syscall_name(unsigned long syscall_index) {
        switch (syscall_index) {
            case SYS_execve: return "execve";
            case SYS_execveat: return "execveat";
            case SYS_openat: return "openat";
            case SYS_read: return "read";
            case SYS_pread64: return "pread64";
            case SYS_write: return "write";
            case SYS_pwrite64: return "pwrite64";
            case SYS_connect: return "connect";
            case SYS_sendto: return "sendto";
            case SYS_chdir: return "chdir";
            case SYS_chmod: return "chmod";
            case SYS_fchmodat: return "fchmodat";
            case SYS_truncate: return "truncate";
            case SYS_ftruncate: return "ftruncate";
            case SYS_unlinkat: return "unlinkat";
            case SYS_rename: return "rename";
            case SYS_renameat: return "renameat";
            case SYS_renameat2: return "renameat2";
            case SYS_linkat: return "linkat";
            case SYS_symlinkat: return "symlinkat";
            case SYS_readlinkat: return "readlinkat";
            case SYS_dup2: return "dup2";
            case SYS_close: return "close";
            case SYS_getdents64: return "getdents64";
            case SYS_copy_file_range: return "copy_file_range";
            default: return "unknown";
        }
    }

    void debug_print_escaped(const char* key, const std::string& value) {
        fprintf(stderr, "    %s=\"", key);
        size_t limit = value.size() < 256 ? value.size() : 256;
        for (size_t i = 0; i < limit; i++) {
            unsigned char c = static_cast<unsigned char>(value[i]);
            if (c == '\\' || c == '\"') {
                fprintf(stderr, "\\%c", c);
            } else if (c == '\n') {
                fprintf(stderr, "\\n");
            } else if (c == '\r') {
                fprintf(stderr, "\\r");
            } else if (c == '\t') {
                fprintf(stderr, "\\t");
            } else if (c >= 32 && c < 127) {
                fprintf(stderr, "%c", c);
            } else {
                fprintf(stderr, "\\x%02x", c);
            }
        }
        if (value.size() > limit) {
            fprintf(stderr, "...");
        }
        fprintf(stderr, "\"\n");
    }

    void debug_print_string_vector(const char* name, const std::vector<std::string>& values) {
        fprintf(stderr, "    %s_count=%zu\n", name, values.size());
        size_t limit = values.size() < 16 ? values.size() : 16;
        for (size_t i = 0; i < limit; i++) {
            char key[64];
            snprintf(key, sizeof(key), "%s[%zu]", name, i);
            debug_print_escaped(key, values[i]);
        }
    }

    void debug_print_env_value(const std::vector<std::string>& envp, const char* name) {
        auto value = get_env_value(envp, name);
        if (!value.has_value()) {
            return;
        }
        char key[64];
        snprintf(key, sizeof(key), "env[%s]", name);
        debug_print_escaped(key, *value);
    }

    void debug_print_data_prefix(const std::vector<char>& data) {
        size_t limit = data.size() < 64 ? data.size() : 64;
        fprintf(stderr, "    data_prefix_hex=");
        for (size_t i = 0; i < limit; i++) {
            fprintf(stderr, "%02x", static_cast<unsigned char>(data[i]));
        }
        if (data.size() > limit) {
            fprintf(stderr, "...");
        }
        fprintf(stderr, "\n");
    }

    struct DebugSyscallArgsBlock {
        ~DebugSyscallArgsBlock() {
            fprintf(stderr, "[DEBUG_SYSCALL_ARGS_END]\n");
        }
    };

    void debug_print_syscall_event(const DetectionRule& rule, const DetectionState& state, const SyscallEvent& event) {
        fprintf(stderr, "[DEBUG_SYSCALL_ARGS_BEGIN]\n");
        DebugSyscallArgsBlock debug_block;

        fprintf(stderr,
            "[DEBUG] syscall args: rule=%s pid=%d state=%zu syscall=%s(%lu)",
            rule.name.c_str(),
            event.pid,
            state.current_state_index,
            debug_syscall_name(event.syscall_index),
            event.syscall_index
        );
        if (event.retval.has_value()) {
            fprintf(stderr, " retval=%ld", *event.retval);
        }
        fprintf(stderr, "\n");

        if (const auto* args = std::get_if<ExecveData>(&event.args)) {
            debug_print_escaped("filename", args->filename);
            auto path = get_execve_path(event.pid, args->filename);
            if (path.has_value()) {
                debug_print_escaped("resolved", *path);
            }
            debug_print_string_vector("argv", args->argv);
            fprintf(stderr, "    envp_count=%zu\n", args->envp.size());
            debug_print_env_value(args->envp, "LD_PRELOAD");
            debug_print_env_value(args->envp, "LD_LIBRARY_PATH");
            return;
        }

        if (const auto* args = std::get_if<ExecveAtData>(&event.args)) {
            fprintf(stderr, "    dirfd=%d flags=%d\n", args->dirfd, args->flags);
            debug_print_escaped("pathname", args->pathname);
            auto path = get_execveat_path(event.pid, args->dirfd, args->pathname);
            if (path.has_value()) {
                debug_print_escaped("resolved", *path);
            }
            debug_print_string_vector("argv", args->argv);
            fprintf(stderr, "    envp_count=%zu\n", args->envp.size());
            debug_print_env_value(args->envp, "LD_PRELOAD");
            debug_print_env_value(args->envp, "LD_LIBRARY_PATH");
            return;
        }

        if (const auto* args = std::get_if<OpenAtData>(&event.args)) {
            fprintf(stderr, "    dirfd=%d flags=%d mode=%d\n", args->dirfd, args->flags, args->mode);
            debug_print_escaped("pathname", args->pathname);
            auto path = get_absolute_path_at(event.pid, args->dirfd, args->pathname);
            if (path.has_value()) {
                debug_print_escaped("resolved", *path);
            }
            return;
        }

        if (const auto* args = std::get_if<WriteData>(&event.args)) {
            fprintf(stderr, "    fd=%u count=%zu data_size=%zu\n", args->fd, args->count, args->data.size());
            debug_print_data_prefix(args->data);
            return;
        }

        if (const auto* args = std::get_if<ReadData>(&event.args)) {
            fprintf(stderr, "    fd=%u count=%zu\n", args->fd, args->count);
            return;
        }

        if (const auto* args = std::get_if<ConnectData>(&event.args)) {
            fprintf(stderr, "    fd=%d family=%d port=%d\n", args->fd, args->family, args->port);
            debug_print_escaped("addr", args->addr);
            return;
        }

        if (const auto* args = std::get_if<SendToData>(&event.args)) {
            fprintf(stderr, "    fd=%d len=%zu\n", args->fd, args->len);
            return;
        }

        if (const auto* args = std::get_if<ChdirData>(&event.args)) {
            debug_print_escaped("filename", args->filename);
            return;
        }

        if (const auto* args = std::get_if<ChmodData>(&event.args)) {
            fprintf(stderr, "    mode=%d\n", args->mode);
            debug_print_escaped("pathname", args->pathname);
            return;
        }

        if (const auto* args = std::get_if<FchmodAtData>(&event.args)) {
            fprintf(stderr, "    dfd=%d mode=%d flags=%d\n", args->dfd, args->mode, args->flags);
            debug_print_escaped("pathname", args->pathname);
            return;
        }

        if (const auto* args = std::get_if<TruncateData>(&event.args)) {
            fprintf(stderr, "    length=%ld\n", args->length);
            debug_print_escaped("pathname", args->pathname);
            return;
        }

        if (const auto* args = std::get_if<FtruncateData>(&event.args)) {
            fprintf(stderr, "    fd=%d length=%ld\n", args->fd, args->length);
            return;
        }

        if (const auto* args = std::get_if<UnlinkAtData>(&event.args)) {
            fprintf(stderr, "    dfd=%d flags=%d\n", args->dfd, args->flags);
            debug_print_escaped("pathname", args->pathname);
            return;
        }

        if (const auto* args = std::get_if<RenameData>(&event.args)) {
            debug_print_escaped("oldname", args->oldname);
            debug_print_escaped("newname", args->newname);
            return;
        }

        if (const auto* args = std::get_if<RenameAtData>(&event.args)) {
            fprintf(stderr, "    oldfd=%d newfd=%d\n", args->oldfd, args->newfd);
            debug_print_escaped("oldname", args->oldname);
            debug_print_escaped("newname", args->newname);
            return;
        }

        if (const auto* args = std::get_if<RenameAt2Data>(&event.args)) {
            fprintf(stderr, "    oldfd=%d newfd=%d flags=%u\n", args->oldfd, args->newfd, args->flags);
            debug_print_escaped("oldname", args->oldname);
            debug_print_escaped("newname", args->newname);
            return;
        }

        if (const auto* args = std::get_if<LinkAtData>(&event.args)) {
            fprintf(stderr, "    oldfd=%d newfd=%d flags=%d\n", args->oldfd, args->newfd, args->flags);
            debug_print_escaped("oldname", args->oldname);
            debug_print_escaped("newname", args->newname);
            return;
        }

        if (const auto* args = std::get_if<SymlinkAtData>(&event.args)) {
            fprintf(stderr, "    newdfd=%d\n", args->newdfd);
            debug_print_escaped("oldname", args->oldname);
            debug_print_escaped("newname", args->newname);
            return;
        }

        if (const auto* args = std::get_if<ReadlinkAtData>(&event.args)) {
            fprintf(stderr, "    dfd=%d bufsiz=%d buf_size=%zu\n", args->dfd, args->bufsiz, args->buf.size());
            debug_print_escaped("path", args->path);
            return;
        }

        if (const auto* args = std::get_if<Dup2Data>(&event.args)) {
            fprintf(stderr, "    oldfd=%u newfd=%u\n", args->oldfd, args->newfd);
            return;
        }

        if (const auto* args = std::get_if<CloseData>(&event.args)) {
            fprintf(stderr, "    fd=%u\n", args->fd);
            return;
        }

        if (const auto* args = std::get_if<Getdents64Data>(&event.args)) {
            fprintf(stderr, "    fd=%u count=%u entries=%zu\n", args->fd, args->count, args->entries.size());
            return;
        }

        if (const auto* args = std::get_if<CopyFileRangeData>(&event.args)) {
            fprintf(stderr, "    fd_in=%u fd_out=%u len=%zu flags=%u\n", args->fd_in, args->fd_out, args->len, args->flags);
            return;
        }
    }
#endif

    std::optional<std::string> get_exec_path(const SyscallEvent& event) {
        if (event.syscall_index == SYS_execve) {
            const auto* args = std::get_if<ExecveData>(&event.args);
            if (!args) {
                return std::nullopt;
            }
            return get_execve_path(event.pid, args->filename);
        }

        if (event.syscall_index == SYS_execveat) {
            const auto* args = std::get_if<ExecveAtData>(&event.args);
            if (!args) {
                return std::nullopt;
            }
            return get_execveat_path(event.pid, args->dirfd, args->pathname);
        }

        return std::nullopt;
    }

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

        copy_detection_states(parent_pid, pid);
    }

    void Engine::copy_detection_states(pid_t parent_pid, pid_t child_pid) {
        std::vector<DetectionState> copied;

        for (const auto& [id, state] : active_detection_states) {
            if (state.pid != parent_pid) {
                continue;
            }
            if (!rules[state.rule_index].inherit_on_fork) {
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
        cooldown_until.erase(pid);
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

    bool Engine::has_active_state(pid_t pid, size_t rule_index) {
        for (const auto& [id, state] : active_detection_states) {
            if (state.pid == pid && state.rule_index == rule_index) {
                return true;
            }
        }
        return false;
    }

    bool Engine::in_cooldown(pid_t pid, size_t rule_index, unsigned long now_ns) {
        auto pid_it = cooldown_until.find(pid);
        if (pid_it == cooldown_until.end()) {
            return false;
        }

        auto rule_it = pid_it->second.find(rule_index);
        if (rule_it == pid_it->second.end()) {
            return false;
        }

        if (now_ns < rule_it->second) {
            return true;
        }

        pid_it->second.erase(rule_it);
        return false;
    }

    void Engine::set_cooldown(pid_t pid, size_t rule_index, unsigned long now_ns) {
        long cooldown_ns = rules[rule_index].cooldown_ns;
        if (cooldown_ns <= 0) {
            return;
        }
        cooldown_until[pid][rule_index] = now_ns + static_cast<unsigned long>(cooldown_ns);
    }

    void Engine::report_detection(const DetectionState& state, const SyscallEvent& event) {
        fprintf(
            stderr,
            "[DEBUG] DETECTED: id: %lu rule index: %lu rule name: %s\n",
            state.id,
            state.rule_index,
            rules[state.rule_index].name.c_str()
        );
#if DETECTION_DEBUG
        debug_print_syscall_event(rules[state.rule_index], state, event);
#endif
        fflush(stderr);
        set_cooldown(state.pid, state.rule_index, event.timestamp_ns);
    }

    void Engine::process_transition(const SyscallEvent& event) {
        // TODO: iterater 없이 하는 방법
        std::vector<size_t> done_ids;
        auto iter = active_detection_states.begin();
        for (; iter != active_detection_states.end(); iter++) {
            auto &state = iter->second;
            size_t rule_index = state.rule_index;

            if (this->rules[rule_index].timeout_ns >= 0 &&
                (event.timestamp_ns < state.start_time_ns ||
                 event.timestamp_ns - state.start_time_ns > static_cast<unsigned long>(this->rules[rule_index].timeout_ns))) {
                done_ids.push_back(state.id);
                continue;
            }

            if (state.pid != event.pid) {
                continue;
            }

            // fprintf(stderr, "[DEBUG] check id: %lu current_state_index: %lu\n", state.id, current_state_index);
            int next_state_index = this->rules[rule_index].transitions[state.current_state_index](state, event);
            if (next_state_index == NO_TRANSITION) {
                continue;
            }

            size_t final_state_index = this->rules[rule_index].transitions.size();
            if (static_cast<size_t>(next_state_index) > final_state_index) {
                continue;
            }

            if (static_cast<size_t>(next_state_index) == final_state_index) {
                report_detection(state, event);
                done_ids.push_back(state.id);
                continue;
            }

            state.current_state_index = static_cast<size_t>(next_state_index);
        }

        for (size_t id : done_ids) {
            active_detection_states.erase(id);
        }
    }

    void Engine::process_first_transition(const SyscallEvent& event) {
        for (DetectionState& initial_state : this->initial_states) {
            size_t rule_index = initial_state.rule_index;
            auto& rule = this->rules[rule_index];

            if (rule.single_active_per_pid && has_active_state(event.pid, rule_index)) {
                continue;
            }

            if (in_cooldown(event.pid, rule_index, event.timestamp_ns)) {
                continue;
            }

            DetectionState next_state = initial_state;
            next_state.id = this->detection_state_count;
            next_state.pid = event.pid;
            next_state.current_state_index = 0;
            next_state.start_time_ns = event.timestamp_ns;
            next_state.data = std::any();

            int next_state_index = this->rules[rule_index].transitions[0](next_state, event);
            if (next_state_index == NO_TRANSITION) {
                continue;
            }

            size_t final_state_index = this->rules[rule_index].transitions.size();
            if (static_cast<size_t>(next_state_index) > final_state_index) {
                continue;
            }

            if (static_cast<size_t>(next_state_index) == final_state_index) {
                report_detection(next_state, event);
                continue;
            }

            next_state.current_state_index = static_cast<size_t>(next_state_index);
            this->active_detection_states[next_state.id] = std::move(next_state);
            this->detection_state_count++;
        }
    }

    void Engine::process_allow_list(const SyscallEvent& event) {
        if (event.syscall_index != SYS_execve && event.syscall_index != SYS_execveat) {
            return;
        }

        if (allow_execve_paths.empty()) {
            return;
        }

        // execve 성공 했는지 체크
        if (!event.retval.has_value() || *event.retval != 0) {
            return;
        }

        auto execve_path = get_exec_path(event);
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
        if (event.syscall_index != SYS_execve && event.syscall_index != SYS_execveat) {
            return;
        }

        // execve 성공 했는지 체크
        if (!event.retval.has_value() || *event.retval != 0) {
            return;
        }

        auto execve_path = get_exec_path(event);
        if (!execve_path.has_value()) {
            return;
        }

        fprintf(stderr, "execve: %s - pid: %d\n", execve_path->c_str(), event.pid);

        if (*execve_path != "/bin/sh" && *execve_path != "/usr/bin/sh" &&
            *execve_path != "/bin/bash" && *execve_path != "/usr/bin/bash") {
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

    void Engine::handle_exec_stop(pid_t pid) {
        auto it = tracked_pids.find(pid);
        if (it == tracked_pids.end() || !it->second.has_value()) {
            return;
        }

        auto& event = *it->second;
        if (event.retval.has_value()) {
            return;
        }

        if (event.syscall_index != SYS_execve && event.syscall_index != SYS_execveat) {
            return;
        }

        event.retval = 0;
        event.timestamp_ns = monotonic_time_ns();
        process_event(event);
        it->second = std::nullopt;
    }

    void Engine::process_event(SyscallEvent& event) {
        process_allow_list(event);
        process_from_shell(event);

#if DETECTION_REQUIRE_LISTEN
        if (!detection_started) {
            if (event.syscall_index != SYS_listen || !event.retval.has_value() || *event.retval != 0) {
                return;
            }

            detection_started = true;
        }
#endif

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

        bool is_from_shell = from_shell_pids.contains(pid);

        SyscallEvent event {
            .syscall_index = info.entry.nr,
            .pid = pid,
            .retval = std::nullopt,
            .from_shell = is_from_shell,
            .timestamp_ns = monotonic_time_ns()
        };

        switch (info.entry.nr) {
            case SYS_execve: {
                auto args = parse_execve(pid, info);
                if (args.has_value()) {
                    event.args = *args;
                }
                break;
            }
            case SYS_execveat: {
                auto args = parse_execveat(pid, info);
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
            case SYS_close: {
                auto args = parse_close(pid, info);
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
            case SYS_copy_file_range: {
                auto args = parse_copy_file_range(pid, info);
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

        auto it = tracked_pids.find(pid);
        if (it == tracked_pids.end() || !it->second.has_value()) {
            return;
        }

        long retval = parse_syscall_rval(info);
        it->second->retval = retval;
        it->second->timestamp_ns = monotonic_time_ns();

        process_event(*it->second);
    }
}
