#pragma once

#include <cstdio>
#include <fcntl.h>
#include <variant>
#include <sys/syscall.h>
#include <sys/socket.h>
#include "detection_state.h"
#include "syscall_event.h"

namespace detection_rules {

using namespace engine;

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
}