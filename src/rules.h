#pragma once

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

#if __has_include("codegen_rules.h")
#include "codegen_rules.h"
#else
namespace detection_rules {
inline void register_codegen_rules(engine::Engine&) {}
}
#endif

namespace detection_rules {

using namespace engine;

inline void register_codegen_rules(engine::Engine& engine);

static const char* execve_deny[] = {
    "/usr/bin/ls"
};

static const char* openat_deny[] = {
    "/tmp/"
};

static const char* openat_allow[] = {
    "/tmp/abcdefgh"
};

inline bool step_execve_bin_sh_cat_flag(DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_execve) {
        return false;
    }

    const auto* args = std::get_if<ExecveData>(&event.args);
    if (!args) return false;


    if (args->filename != "/bin/sh") {
        return false;
    }

    if (args->argv.size() < 3) {
        return false;
    }

    if (args->argv[0] != "/bin/sh") {
        return false;
    }

    if (args->argv[1] != "-c") {
        return false;
    }

    if (args->argv[2] != "cat flag.txt") {
        return false;
    }

    fprintf(stderr, "is_execve_bin_sh_cat_flag=true\n");

    return true;
}

inline bool step_openat_flag(DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_openat) {
        return false;
    }

    const auto *args = std::get_if<OpenAtData>(&event.args);
    if (!args) return false;

    if (args->dirfd != AT_FDCWD) {
        return false;
    }

    if (args->pathname != "flag.txt") {
        return false;
    }


    fprintf(stderr, "is_openat_flag=true\n");

    return true;
}

inline bool step_execve_cat(DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_execve) {
        return false;
    }

    const auto* args = std::get_if<ExecveData>(&event.args);
    if (!args) return false;

    if (args->filename != "/usr/bin/cat") {
        return false;
    }
    if (args->argv.size() < 1) {
        return false;
    }
    if (args->argv[0] != "cat") {
        return false;
    }

    fprintf(stderr, "is_execve_cat=true\n");

    return true;
}

inline bool step_openat_deny(DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_openat) {
        return false;
    }

    const auto *args = std::get_if<OpenAtData>(&event.args);
    if (!args) return false;

    if (args->dirfd != AT_FDCWD) {
        return false;
    }

    auto absolute_path = get_absolute_path(event.pid, args->pathname);

    if (!absolute_path.has_value()) {
        return false;
    }

    fprintf(stderr, "[DEBUG] path: %s\n", absolute_path->c_str());

    for (size_t i = 0; i < sizeof(openat_allow) / sizeof(char *); i++) {
        std::string allow_path = std::string(openat_allow[i]);
        if (allow_path.back() == '/') {
            if (absolute_path->starts_with(allow_path)) {
                return false;
            }
        } else {
            if (absolute_path == allow_path) {
                return false;
            }
        }
    }

    for (size_t i = 0; i < sizeof(openat_deny) / sizeof(char *); i++) {
        std::string deny_path = std::string(openat_deny[i]);
        if (deny_path.back() == '/') {
            if (absolute_path->starts_with(deny_path)) {
                return true;
            }
        } else {
            if (absolute_path == deny_path) {
                return true;
            }
        }
    }

    return false;
}

inline bool step_exeve_deny(DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_execve) {
        return false;
    }

    const auto* args = std::get_if<ExecveData>(&event.args);
    if (!args) return false;

    auto absolute_path = get_absolute_path(event.pid, args->filename);

    if (!absolute_path.has_value()) {
        return false;
    }

    for (size_t i = 0; i < sizeof(execve_deny) / sizeof(char *); i++) {
        std::string deny_path = std::string(execve_deny[i]);
        if (deny_path.back() == '/') {
            if (absolute_path->starts_with(deny_path)) {
                return true;
            }
        } else {
            if (absolute_path == deny_path) {
                return true;
            }
        }
    }

    return false;
}

inline bool step_execve_grep_R(DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_execve) {
        return false;
    }

    const auto* args = std::get_if<ExecveData>(&event.args);
    if (!args) return false;

    for (size_t i = 1; i < args->argv.size(); i++) {
        if (args->argv[i] == "-R") {
            return true;
        }
    }

    return false;
}

inline bool step_bin_sh_echo_inject_1(DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_dup2) {
        return false;
    }

    const auto* args = std::get_if<Dup2Data>(&event.args);
    if (!args) return false;

    if (static_cast<long>(args->newfd) != 1) {
        return false;
    }

    return true;
}

inline bool step_bin_sh_echo_inject_2(DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_write) {
        return false;
    }

    if (event.from_shell == false) {
        return false;
    }

    const auto* args = std::get_if<WriteData>(&event.args);
    if (!args) return false;

    if (args->fd != 1) {
        return false;
    }

    if (args->data.size() < 4) {
        return false;
    }

    if (args->data[0] != 0x7F) {
        return false;
    }
    if (args->data[1] != 0x45) { // E
        return false;
    }
    if (args->data[2] != 0x4C) { // L
        return false;
    }
    if (args->data[3] != 0x46) { // F
        return false;
    }

    return true;
}

inline bool is_db_file_path(const std::string& path) {
    return path.ends_with(".db") ||
           path.ends_with(".sqlite") ||
           path.ends_with(".sqlite3");
}

inline bool step_openat_db(DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_openat) {
        return false;
    }

    if (!event.retval.has_value() || *event.retval < 0) {
        return false;
    }

    const auto* args = std::get_if<OpenAtData>(&event.args);
    if (!args) return false;

    if ((args->flags & O_ACCMODE) == O_WRONLY) {
        return false;
    }

    // if (args->dirfd != AT_FDCWD && !args->pathname.starts_with("/")) {
    //     return false;
    // }

    auto path = get_absolute_path(event.pid, args->pathname);
    if (!path.has_value() || !is_db_file_path(*path)) {
        return false;
    }

    fprintf(stderr, "%s\n", path->c_str());

    state.captured.push_back(*event.retval);
    state.captured.push_back(0L);
    return true;
}

inline bool step_read_db_large(DetectionState& state, const SyscallEvent& event) {
    if (event.syscall_index != SYS_read && event.syscall_index != SYS_pread64) {
        return false;
    }

    if (!event.retval.has_value() || *event.retval <= 0) {
        return false;
    }

    if (state.captured.size() < 2) {
        return false;
    }

    auto db_fd = std::get_if<long>(&state.captured[0]);
    auto bytes = std::get_if<long>(&state.captured[1]);
    if (!db_fd || !bytes) {
        return false;
    }

    const auto* args = std::get_if<ReadData>(&event.args);
    if (!args) return false;

    if (static_cast<long>(args->fd) != *db_fd) {
        return false;
    }

    fprintf(stderr, "bytes: %ld\n", *bytes);
    *bytes += *event.retval;
    // return *bytes >= 10L * 1024 * 1024;
    // return *bytes >= 1L * 1024;
    return *bytes >= 70000;
}

inline bool on_detect_db_read_large(DetectionState& state) {
    state.current_state_index = 1;

    if (state.captured.size() >= 2) {
        state.captured[1] = 0L;
    }

    return true;
}


inline void register_rules(engine::Engine& engine) {
    // engine.add_rule((DetectionRule) {
    //     .name = "execve_cat_flag",
    //     .timeout_ns = 1000000000UL,
    //     .transitions = {
    //         detection_rules::step_execve_bin_sh_cat_flag,
    //         detection_rules::step_openat_flag
    //     },
    // });

    // engine.add_rule((DetectionRule) {
    //     .name = "execve_cat_openat_deny",
    //     .timeout_ns = 1000000000UL,
    //     .transitions = {
    //         detection_rules::step_execve_cat,
    //         detection_rules::step_openat_deny
    //     },
    // });

    // engine.add_rule((DetectionRule) {
    //     .name = "execve_deny_path",
    //     .timeout_ns = 1000000000UL,
    //     .transitions = {
    //         detection_rules::step_exeve_deny,
    //     },
    // });

    engine.add_rule((DetectionRule) {
        .name = "execve_grep_R",
        .timeout_ns = 1000000000UL,
        .transitions = {
            detection_rules::step_execve_grep_R,
        },
    });
    engine.add_rule((DetectionRule) {
        .name = "is_bin_sh_echo_inject",
        .timeout_ns = 1000000000UL,
        .transitions = {
            detection_rules::step_bin_sh_echo_inject_1,
            detection_rules::step_bin_sh_echo_inject_2
        },
    });
    engine.add_rule((DetectionRule) {
        .name = "openat_db_read_large",
        .timeout_ns = -1,
        .transitions = {
            detection_rules::step_openat_db,
            detection_rules::step_read_db_large
        },
        .on_detect = detection_rules::on_detect_db_read_large,
    });
    register_codegen_rules(engine);
}
}
