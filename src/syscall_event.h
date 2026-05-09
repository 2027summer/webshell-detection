#pragma once

#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace engine {

struct OpenAtData {
    int dirfd;
    std::string pathname;
    int flags;
    int mode;
};

struct WriteData {
    unsigned int fd;
    std::vector<char> data;
    size_t count;
};

struct ExecveData {
    std::string filename;
    std::vector<std::string> argv;
    std::vector<std::string> envp;
};

using SyscallArgs = std::variant<
    std::monostate,
    OpenAtData,
    WriteData,
    ExecveData
>;

struct SyscallEvent {
    unsigned long syscall_index;
    pid_t pid;
    SyscallArgs args;
    std::optional<long> retval;
    unsigned long timestamp_ns;
};
}