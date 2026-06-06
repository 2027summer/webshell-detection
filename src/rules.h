#pragma once

#include <any>
#include <cstdio>
#include <fcntl.h>
#include <optional>
#include <variant>
#include <sys/syscall.h>
#include <sys/socket.h>
#include "engine.h"
#include "helpers.h"
#include "detection_state.h"
#include "syscall_event.h"
#include "rule.h"

namespace detection_rules {
using namespace engine;
TransitionResult step_builtin_recursive_traversal_1(FdTable& fds, engine::DetectionState& state, const engine::SyscallEvent& event);
TransitionResult step_builtin_recursive_traversal_2(FdTable& fds, engine::DetectionState& state, const engine::SyscallEvent& event);
}

#if __has_include("codegen_rules.h")
#include "codegen_rules.h"
#else
namespace detection_rules {
inline void register_codegen_rules(engine::Engine&) {}
}
#endif

namespace detection_rules {

using namespace engine;


inline std::string path_basename(const std::string& path) {
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

inline bool is_staging_path(const std::string& path) {
    return (path.starts_with("/tmp/") && path.size() > 5) ||
           (path.starts_with("/var/tmp/") && path.size() > 9);
}

// inline bool is_suspicious_exec_target_path(const std::string& path) {
//     return is_staging_path(path) ||
//            (path.starts_with("/dev/shm/") && path.size() > 9) ||
//            path.starts_with("/memfd:") ||
//            path.ends_with(" (deleted)");
// }

// inline bool is_dynamic_linker_path(const std::string& path) {
//     std::string name = path_basename(path);
//     static const char* linkers[] = {
//         "ld-linux-x86-64.so.2",
//         "ld-linux-aarch64.so.1",
//         "ld-linux.so.2",
//         "ld.so",
//         nullptr
//     };

//     for (size_t i = 0; linkers[i] != nullptr; i++) {
//         if (name == linkers[i]) {
//             return true;
//         }
//     }
//     return name.starts_with("ld-musl-") && name.ends_with(".so.1");
// }

// inline bool is_dynamic_linker_arg_with_value(const std::string& arg, const char* option) {
//     return arg == option || arg.starts_with(std::string(option) + "=");
// }

// inline std::optional<std::string> find_dynamic_linker_target(const std::vector<std::string>& argv) {
//     static const char* no_exec_options[] = {
//         "--list",
//         "--verify",
//         "--help",
//         "--version",
//         "--list-tunables",
//         "--list-diagnostics",
//         nullptr
//     };
//     static const char* options_with_value[] = {
//         "--library-path",
//         "--preload",
//         "--audit",
//         "--argv0",
//         "--inhibit-rpath",
//         nullptr
//     };

//     for (size_t i = 1; i < argv.size(); i++) {
//         const auto& arg = argv[i];
//         if (arg.empty()) {
//             continue;
//         }
//         if (arg == "--") {
//             for (size_t j = i + 1; j < argv.size(); j++) {
//                 if (!argv[j].empty()) {
//                     return argv[j];
//                 }
//             }
//             return std::nullopt;
//         }

//         for (size_t j = 0; no_exec_options[j] != nullptr; j++) {
//             if (arg == no_exec_options[j]) {
//                 return std::nullopt;
//             }
//         }

//         bool is_option_with_value = false;
//         for (size_t j = 0; options_with_value[j] != nullptr; j++) {
//             if (is_dynamic_linker_arg_with_value(arg, options_with_value[j])) {
//                 if (arg == options_with_value[j]) {
//                     i++;
//                 }
//                 is_option_with_value = true;
//                 break;
//             }
//         }
//         if (is_option_with_value || arg.starts_with("-")) {
//             continue;
//         }

//         return arg;
//     }

//     return std::nullopt;
// }


inline bool fd_points_to_path(pid_t pid, unsigned int fd, const std::string& path) {
    auto fd_path = get_fd_path(pid, fd);
    if (!fd_path.has_value()) {
        return false;
    }
    return *fd_path == path || fd_path->starts_with(path + " (deleted)");
}

// static const char* execve_deny[] = {
//     "/usr/bin/ls"
// };

// static const char* openat_deny[] = {
//     "/tmp/"
// };

// static const char* openat_allow[] = {
//     "/tmp/abcdefgh"
// };

// inline int step_execve_bin_sh_cat_flag(Context& ctx, DetectionState& state, const SyscallEvent& event) {
//     if (event.syscall_index != SYS_execve) {
//         return -1;
//     }

//     const auto* args = std::get_if<ExecveData>(&event.args);
//     if (!args) return -1;


//     if (args->filename != "/bin/sh") {
//         return -1;
//     }

//     if (args->argv.size() < 3) {
//         return -1;
//     }

//     if (args->argv[0] != "/bin/sh") {
//         return -1;
//     }

//     if (args->argv[1] != "-c") {
//         return -1;
//     }

//     if (args->argv[2] != "cat flag.txt") {
//         return -1;
//     }

//     fprintf(stderr, "is_execve_bin_sh_cat_flag=true\n");

//     return static_cast<int>(state.current_state_index + 1);
// }

// inline int step_openat_flag(Context& ctx, DetectionState& state, const SyscallEvent& event) {
//     if (event.syscall_index != SYS_openat) {
//         return -1;
//     }

//     const auto* args = std::get_if<OpenAtData>(&event.args);
//     if (!args) return -1;

//     if (args->dirfd != AT_FDCWD) {
//         return -1;
//     }

//     if (args->pathname != "flag.txt") {
//         return -1;
//     }


//     fprintf(stderr, "is_openat_flag=true\n");

//     return static_cast<int>(state.current_state_index + 1);
// }

// inline int step_execve_cat(Context& ctx, DetectionState& state, const SyscallEvent& event) {
//     if (event.syscall_index != SYS_execve) {
//         return -1;
//     }

//     const auto* args = std::get_if<ExecveData>(&event.args);
//     if (!args) return -1;

//     if (args->filename != "/usr/bin/cat") {
//         return -1;
//     }
//     if (args->argv.size() < 1) {
//         return -1;
//     }
//     if (args->argv[0] != "cat") {
//         return -1;
//     }

//     fprintf(stderr, "is_execve_cat=true\n");

//     return static_cast<int>(state.current_state_index + 1);
// }

// inline int step_openat_deny(Context& ctx, DetectionState& state, const SyscallEvent& event) {
//     if (event.syscall_index != SYS_openat) {
//         return -1;
//     }

//     const auto* args = std::get_if<OpenAtData>(&event.args);
//     if (!args) return -1;

//     if (args->dirfd != AT_FDCWD) {
//         return -1;
//     }

//     auto absolute_path = get_absolute_path(event.pid, args->pathname);

//     if (!absolute_path.has_value()) {
//         return -1;
//     }

//     fprintf(stderr, "[DEBUG] path: %s\n", absolute_path->c_str());

//     for (size_t i = 0; i < sizeof(openat_allow) / sizeof(char *); i++) {
//         std::string allow_path = std::string(openat_allow[i]);
//         if (allow_path.back() == '/') {
//             if (absolute_path->starts_with(allow_path)) {
//                 return -1;
//             }
//         } else {
//             if (absolute_path == allow_path) {
//                 return -1;
//             }
//         }
//     }

//     for (size_t i = 0; i < sizeof(openat_deny) / sizeof(char *); i++) {
//         std::string deny_path = std::string(openat_deny[i]);
//         if (deny_path.back() == '/') {
//             if (absolute_path->starts_with(deny_path)) {
//                 return static_cast<int>(state.current_state_index + 1);
//             }
//         } else {
//             if (absolute_path == deny_path) {
//                 return static_cast<int>(state.current_state_index + 1);
//             }
//         }
//     }

//     return -1;
// }

// inline int step_execve_deny(Context& ctx, DetectionState& state, const SyscallEvent& event) {
//     if (event.syscall_index != SYS_execve) {
//         return -1;
//     }

//     const auto* args = std::get_if<ExecveData>(&event.args);
//     if (!args) return -1;

//     auto absolute_path = get_absolute_path(event.pid, args->filename);

//     if (!absolute_path.has_value()) {
//         return -1;
//     }

//     for (size_t i = 0; i < sizeof(execve_deny) / sizeof(char *); i++) {
//         std::string deny_path = std::string(execve_deny[i]);
//         if (deny_path.back() == '/') {
//             if (absolute_path->starts_with(deny_path)) {
//                 return static_cast<int>(state.current_state_index + 1);
//             }
//         } else {
//             if (absolute_path == deny_path) {
//                 return static_cast<int>(state.current_state_index + 1);
//             }
//         }
//     }

//     return -1;
// }

// inline int step_bin_sh_echo_inject_1(Context& ctx, DetectionState& state, const SyscallEvent& event) {
//     if (event.syscall_index != SYS_dup2) {
//         return -1;
//     }

//     const auto* args = std::get_if<Dup2Data>(&event.args);
//     if (!args) return -1;

//     if (static_cast<long>(args->newfd) != 1) {
//         return -1;
//     }

//     return static_cast<int>(state.current_state_index + 1);
// }

// inline int step_bin_sh_echo_inject_2(Context& ctx, DetectionState& state, const SyscallEvent& event) {
//     if (event.syscall_index != SYS_write) {
//         return -1;
//     }

//     if (event.from_shell == false) {
//         return -1;
//     }

//     const auto* args = std::get_if<WriteData>(&event.args);
//     if (!args) return -1;

//     if (args->fd != 1) {
//         return -1;
//     }

//     if (args->data.size() < 4) {
//         return -1;
//     }

//     if (args->data[0] != 0x7F) {
//         return -1;
//     }
//     if (args->data[1] != 0x45) { // E
//         return -1;
//     }
//     if (args->data[2] != 0x4C) { // L
//         return -1;
//     }
//     if (args->data[3] != 0x46) { // F
//         return -1;
//     }

//     return static_cast<int>(state.current_state_index + 1);
// }

inline bool is_db_file_path(const std::string& path) {
    return path.ends_with(".db") ||
           path.ends_with(".sqlite") ||
           path.ends_with(".sqlite3") ||
           path.ends_with(".db3");
}

struct ReadDbLargeState {
    long fd;
    long bytes;
    std::string path;
};

inline TransitionResult step_openat_db(FdTable& fds, DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_openat) {
        return TransitionResult::NoMatch;
    }

    if (!event.retval.has_value() || *event.retval < 0) {
        return TransitionResult::NoMatch;
    }

    const auto* args = std::get_if<OpenAtData>(&event.args);
    if (!args) return TransitionResult::NoMatch;

    if ((args->flags & O_ACCMODE) == O_WRONLY) {
        return TransitionResult::NoMatch;
    }

    auto path = get_absolute_path_at(event.pid, args->dirfd, args->pathname);
    if (!path.has_value() || !is_db_file_path(*path)) {
        return TransitionResult::NoMatch;
    }

    state.data = ReadDbLargeState {
        .fd = *event.retval,
        .bytes = 0,
        .path = *path,
    };

    return TransitionResult::Advance;
}

inline TransitionResult step_read_db_large(FdTable& fds, DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_read && event.syscall_index != SYS_pread64) {
        return TransitionResult::NoMatch;
    }

    if (!event.retval.has_value() || *event.retval <= 0) {
        return TransitionResult::NoMatch;
    }

    auto* data = std::any_cast<ReadDbLargeState>(&state.data);
    if (!data) {
        return TransitionResult::NoMatch;
    }

    const auto* args = std::get_if<ReadData>(&event.args);
    if (!args) return TransitionResult::NoMatch;

    if (static_cast<long>(args->fd) != data->fd) {
        return TransitionResult::NoMatch;
    }

    if (!fd_points_to_path(event.pid, args->fd, data->path)) {
        return TransitionResult::NoMatch;
    }

    data->bytes += *event.retval;
    if (data->bytes < 30000) {
        return TransitionResult::Stay;
    }
    return TransitionResult::Advance;
}

inline TransitionResult step_execve_grep_recursive(FdTable& fds, DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_execve) {
        return TransitionResult::NoMatch;
    }

    const auto* args = std::get_if<ExecveData>(&event.args);
    if (!args) return TransitionResult::NoMatch;

    if (args->filename != "/usr/bin/grep") {
        return TransitionResult::NoMatch;
    }

    size_t argc = args->argv.size();
    if (argc < 2) {
        return TransitionResult::NoMatch;
    }

    static const char* deny_options[] = {
        "R",
        "recursive",
        "r",
        "dereference-recursive",
        nullptr
    };

    for (size_t i = 1; i < argc; i++) {
        if (!args->argv[i].starts_with("-")) {
            continue;
        }
        if (args->argv[i] == "--") {
            break;
        }

        for (size_t j = 0; deny_options[j] != nullptr; j++) {
            if (args->argv[i].find(deny_options[j]) != std::string::npos) {
                return TransitionResult::Advance;
            }
        }
    }

    return TransitionResult::NoMatch;
}


inline void register_rules(engine::Engine& engine) {
    engine.add_rule((DetectionRule) {
        .name = "execve_grep_recursive",
        .timeout_ns = 1000000000UL,
        .transitions = {
            detection_rules::step_execve_grep_recursive,
        },
    });
    engine.add_rule((DetectionRule) {
        .name = "read_db_large",
        .timeout_ns = 500000000UL,
        .transitions = {
            detection_rules::step_openat_db,
            detection_rules::step_read_db_large
        },
    });
    // engine.add_rule((DetectionRule) {
    //     .name = "dynamic_linker_suspicious_target",
    //     .timeout_ns = 1000000000UL,
    //     .transitions = {
    //         detection_rules::step_dynamic_linker_suspicious_target,
    //     },
    // });
    register_codegen_rules(engine);
}
}
