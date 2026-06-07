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

struct SendToData {
    int fd;
    size_t len;
};

struct ConnectData {
    int fd;
    int family;
    std::string addr;
    int port;
};

struct ExecveData {
    std::string filename;
    std::vector<std::string> argv;
    std::vector<std::string> envp;
};

struct ExecveAtData {
    int dirfd;
    std::string pathname;
    std::vector<std::string> argv;
    std::vector<std::string> envp;
    int flags;
};

struct ChdirData {
    std::string filename;
};

struct ChmodData {
    std::string pathname;
    int mode;
};

struct FchmodAtData {
    int dfd;
    std::string pathname;
    int mode;
    int flags;
};

struct TruncateData {
    std::string pathname;
    long length;
};

struct FtruncateData {
    int fd;
    long length;
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
    size_t count;
};

struct Getdents64Entry {
    unsigned long long ino;
    long long off;
    unsigned short reclen;
    unsigned char type;
    std::string name;
};

struct Getdents64Data {
    unsigned int fd;
    unsigned long dirp;
    unsigned int count;
    std::vector<Getdents64Entry> entries;
};

struct CopyFileRangeData {
    unsigned int fd_in;
    unsigned int fd_out;
    size_t len;
    unsigned int flags;
};

using SyscallArgs = std::variant<
    std::monostate,
    OpenAtData,
    WriteData,
    ExecveData,
    ExecveAtData,
    ChdirData,
    ChmodData,
    FchmodAtData,
    TruncateData,
    FtruncateData,
    UnlinkAtData,
    RenameData,
    RenameAtData,
    RenameAt2Data,
    LinkAtData,
    SymlinkAtData,
    ReadlinkAtData,
    Dup2Data,
    CloseData,
    ReadData,
    SendToData,
    ConnectData,
    Getdents64Data,
    CopyFileRangeData
>;

struct SyscallEvent {
    unsigned long syscall_index;
    pid_t pid;
    SyscallArgs args;
    std::optional<long> retval;
    bool from_shell;
    unsigned long timestamp_ns;
};
}
