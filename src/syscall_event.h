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

struct ChdirData {
    std::string filename;
};

struct UnlinkAtData {
    int dfd;
    std::string pathname;
    int flags;
};

struct RenameData {
    std::string oldname;
    std::string newname;
};

struct RenameAtData {
    int oldfd;
    std::string oldname;
    int newfd;
    std::string newname;
};

struct RenameAt2Data {
    int oldfd;
    std::string oldname;
    int newfd;
    std::string newname;
    unsigned int flags;
};

struct LinkAtData {
    int oldfd;
    std::string oldname;
    int newfd;
    std::string newname;
    int flags;
};

struct SymlinkAtData {
    std::string oldname;
    int newdfd;
    std::string newname;
};

struct ReadlinkAtData {
    int dfd;
    std::string path;
    std::vector<char> buf;
    int bufsiz;
};

struct Dup2Data {
    unsigned int oldfd;
    unsigned int newfd;
};

struct CloseData {
    unsigned int fd;
};

struct ReadData {
    unsigned int fd;
    std::vector<char> buf;
    size_t count;
};

using SyscallArgs = std::variant<
    std::monostate,
    OpenAtData,
    WriteData,
    ExecveData,
    ChdirData,
    UnlinkAtData,
    RenameData,
    RenameAtData,
    RenameAt2Data,
    LinkAtData,
    SymlinkAtData,
    ReadlinkAtData,
    Dup2Data,
    CloseData,
    ReadData
>;

struct SyscallEvent {
    unsigned long syscall_index;
    pid_t pid;
    SyscallArgs args;
    std::optional<long> retval;
    unsigned long timestamp_ns;
};
}