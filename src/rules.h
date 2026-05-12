#pragma once

#include <cstdio>
#include <fcntl.h>
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

inline bool is_execve_bin_sh_cat_flag(const DetectionState& state, const SyscallEvent& event) {
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

inline bool is_openat_flag(const DetectionState& state, const SyscallEvent& event) {
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

inline bool is_execve_cat(const DetectionState& state, const SyscallEvent& event) {
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

inline bool is_openat_deny(const DetectionState& state, const SyscallEvent& event) {
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

inline bool is_exeve_deny(const DetectionState& state, const SyscallEvent& event) {
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

inline void register_rules(engine::Engine& engine) {
    // engine.add_rule((DetectionRule) {
    //     .name = "execve_cat_flag",
    //     .timeout_ns = 1000000000UL,
    //     .transitions = {
    //         detection_rules::is_execve_bin_sh_cat_flag,
    //         detection_rules::is_openat_flag
    //     },
    // });

    // engine.add_rule((DetectionRule) {
    //     .name = "execve_cat_openat_deny",
    //     .timeout_ns = 1000000000UL,
    //     .transitions = {
    //         detection_rules::is_execve_cat,
    //         detection_rules::is_openat_deny
    //     },
    // });

    // engine.add_rule((DetectionRule) {
    //     .name = "execve_deny_path",
    //     .timeout_ns = 1000000000UL,
    //     .transitions = {
    //         detection_rules::is_exeve_deny,
    //     },
    // });

    register_codegen_rules(engine);
}
}
