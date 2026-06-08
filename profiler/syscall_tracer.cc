#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include "parse_syscall.h"

static FILE* out_fp = nullptr;

struct ConnectData {
    int fd;
    int family;
    std::string addr;
    int port;
};

struct Getdents64Data {
    unsigned int fd;
    size_t count;
};

struct WriteData {
    unsigned int fd;
    size_t count;
};

struct ChmodData {
    std::string pathname;
    unsigned int mode;
};

struct FchmodData {
    unsigned int fd;
    unsigned int mode;
};

struct FchmodAtData {
    int dfd;
    std::string pathname;
    unsigned int mode;
    int flags;
};

struct Dup3Data {
    unsigned int oldfd;
    unsigned int newfd;
    int flags;
};

struct SocketData {
    int family;
    int type;
    int protocol;
};

struct SendToData {
    int fd;
    size_t len;
    int family;
    std::string addr;
    int port;
};

struct SendMsgData {
    int fd;
    size_t len;
};

struct UnlinkData {
    std::string pathname;
};

struct MkdirData {
    std::string pathname;
    unsigned int mode;
};

struct MkdirAtData {
    int dfd;
    std::string pathname;
    unsigned int mode;
};

struct FchdirData {
    unsigned int fd;
};

struct SetIdData {
    long a;
    long b;
    long c;
};

using ProfileArgs = std::variant<
    std::monostate,
    engine::ExecveData,
    engine::OpenAtData,
    engine::RenameAtData,
    engine::RenameAt2Data,
    engine::UnlinkAtData,
    engine::LinkAtData,
    engine::SymlinkAtData,
    engine::ReadData,
    engine::Dup2Data,
    engine::RenameData,
    engine::ChdirData,
    engine::TruncateData,
    engine::FtruncateData,
    ConnectData,
    UnlinkData,
    MkdirData,
    MkdirAtData,
    FchdirData,
    SetIdData,
    Getdents64Data,
    WriteData,
    ChmodData,
    FchmodData,
    FchmodAtData,
    Dup3Data,
    SocketData,
    SendToData,
    SendMsgData
>;

struct PendingSyscall {
    unsigned long nr;
    ProfileArgs args;
};

static bool read_child_word(pid_t pid, unsigned long address, char* bytes) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, address, nullptr);

    if (word == -1 && errno != 0) {
        return false;
    }

    memcpy(bytes, &word, sizeof(word));
    return true;
}

static bool read_child_bytes(pid_t pid, unsigned long address, void* bytes, size_t size) {
    char* result = reinterpret_cast<char*>(bytes);

    for (size_t offset = 0; offset < size; offset += sizeof(long)) {
        char word[sizeof(long)];
        if (!read_child_word(pid, address + offset, word)) {
            return false;
        }

        size_t remain = size - offset;
        size_t copy_size = remain < sizeof(word) ? remain : sizeof(word);
        memcpy(result + offset, word, copy_size);
    }

    return true;
}

static std::string read_proc_link(const char* path) {
    char buf[4096];

    ssize_t len = readlink(path, buf, sizeof(buf) - 1);
    if (len < 0) {
        return "";
    }

    buf[len] = '\0';
    return std::string(buf);
}

static std::string read_proc_exe(pid_t pid) {
    char path[64];

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    return read_proc_link(path);
}

static std::string read_proc_fd(pid_t pid, unsigned int fd) {
    char path[64];

    snprintf(path, sizeof(path), "/proc/%d/fd/%u", pid, fd);
    return read_proc_link(path);
}

static void print_json_string(const std::string& s) {
    fprintf(out_fp, "\"");

    for (unsigned char c : s) {
        switch (c) {
            case '"':
                fprintf(out_fp, "\\\"");
                break;
            case '\\':
                fprintf(out_fp, "\\\\");
                break;
            case '\t':
                fprintf(out_fp, "\\t");
                break;
            case '\n':
                fprintf(out_fp, "\\n");
                break;
            case '\r':
                fprintf(out_fp, "\\r");
                break;
            case '\0':
                fprintf(out_fp, "\\u0000");
                break;
            default:
                if (c < 0x20 || c >= 0x7f) {
                    fprintf(out_fp, "\\u%04x", c);
                } else {
                    fputc(c, out_fp);
                }
                break;
        }
    }

    fprintf(out_fp, "\"");
}

static std::optional<std::string> read_child_string(pid_t pid, unsigned long address) {
    std::string result;

    for (size_t offset = 0; offset < 4096; offset += sizeof(long)) {
        char word[sizeof(long)];
        if (!read_child_word(pid, address + offset, word)) {
            return std::nullopt;
        }

        for (size_t i = 0; i < sizeof(word); i++) {
            if (word[i] == '\0') {
                return result;
            }
            result.push_back(word[i]);
        }
    }

    return std::nullopt;
}

struct SockAddrInfo {
    int family;
    std::string addr;
    int port;
};

static bool read_sockaddr(pid_t pid, unsigned long addr_ptr, socklen_t addrlen, SockAddrInfo& out) {
    out = SockAddrInfo { .family = 0, .addr = "", .port = 0 };

    if (addr_ptr == 0 || addrlen < sizeof(sa_family_t)) {
        return false;
    }

    sa_family_t family = 0;
    if (!read_child_bytes(pid, addr_ptr, &family, sizeof(family))) {
        return false;
    }

    out.family = family;

    if (family == AF_INET) {
        sockaddr_in addr{};
        if (addrlen < sizeof(addr) || !read_child_bytes(pid, addr_ptr, &addr, sizeof(addr))) {
            return true;
        }

        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf)) != nullptr) {
            out.addr = buf;
        }
        out.port = ntohs(addr.sin_port);
    } else if (family == AF_INET6) {
        sockaddr_in6 addr{};
        if (addrlen < sizeof(addr) || !read_child_bytes(pid, addr_ptr, &addr, sizeof(addr))) {
            return true;
        }

        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &addr.sin6_addr, buf, sizeof(buf)) != nullptr) {
            out.addr = buf;
        }
        out.port = ntohs(addr.sin6_port);
    } else if (family == AF_UNIX) {
        sockaddr_un addr{};
        size_t size = addrlen < sizeof(addr) ? addrlen : sizeof(addr);
        if (!read_child_bytes(pid, addr_ptr, &addr, size)) {
            return true;
        }

        size_t path_offset = offsetof(sockaddr_un, sun_path);
        if (size <= path_offset) {
            return true;
        }

        size_t path_len = size - path_offset;
        if (addr.sun_path[0] == '\0') {
            out.addr = "@" + std::string(addr.sun_path + 1, path_len - 1);
        } else {
            out.addr = std::string(addr.sun_path, strnlen(addr.sun_path, path_len));
        }
    }

    return true;
}

static std::optional<ConnectData> parse_connect(pid_t pid, __ptrace_syscall_info info) {
    SockAddrInfo sock;
    if (!read_sockaddr(pid, info.entry.args[1], static_cast<socklen_t>(info.entry.args[2]), sock)) {
        return std::nullopt;
    }

    return ConnectData {
        .fd = static_cast<int>(info.entry.args[0]),
        .family = sock.family,
        .addr = sock.addr,
        .port = sock.port
    };
}

static Getdents64Data parse_getdents64(__ptrace_syscall_info info) {
    return Getdents64Data {
        .fd = static_cast<unsigned int>(info.entry.args[0]),
        .count = static_cast<size_t>(info.entry.args[2])
    };
}

static WriteData parse_write(__ptrace_syscall_info info) {
    return WriteData {
        .fd = static_cast<unsigned int>(info.entry.args[0]),
        .count = static_cast<size_t>(info.entry.args[2])
    };
}

static std::optional<ChmodData> parse_chmod(pid_t pid, __ptrace_syscall_info info) {
    auto path = read_child_string(pid, info.entry.args[0]);
    if (!path.has_value()) {
        return std::nullopt;
    }
    return ChmodData {
        .pathname = *path,
        .mode = static_cast<unsigned int>(info.entry.args[1])
    };
}

static FchmodData parse_fchmod(__ptrace_syscall_info info) {
    return FchmodData {
        .fd = static_cast<unsigned int>(info.entry.args[0]),
        .mode = static_cast<unsigned int>(info.entry.args[1])
    };
}

static std::optional<FchmodAtData> parse_fchmodat(pid_t pid, __ptrace_syscall_info info) {
    auto path = read_child_string(pid, info.entry.args[1]);
    if (!path.has_value()) {
        return std::nullopt;
    }
    return FchmodAtData {
        .dfd = static_cast<int>(info.entry.args[0]),
        .pathname = *path,
        .mode = static_cast<unsigned int>(info.entry.args[2]),
        .flags = static_cast<int>(info.entry.args[3])
    };
}

static Dup3Data parse_dup3(__ptrace_syscall_info info) {
    return Dup3Data {
        .oldfd = static_cast<unsigned int>(info.entry.args[0]),
        .newfd = static_cast<unsigned int>(info.entry.args[1]),
        .flags = static_cast<int>(info.entry.args[2])
    };
}

static SocketData parse_socket(__ptrace_syscall_info info) {
    return SocketData {
        .family = static_cast<int>(info.entry.args[0]),
        .type = static_cast<int>(info.entry.args[1]),
        .protocol = static_cast<int>(info.entry.args[2])
    };
}

static SendToData parse_sendto(pid_t pid, __ptrace_syscall_info info) {
    SendToData data {
        .fd = static_cast<int>(info.entry.args[0]),
        .len = static_cast<size_t>(info.entry.args[2]),
        .family = 0,
        .addr = "",
        .port = 0
    };

    unsigned long addr_ptr = info.entry.args[4];
    socklen_t addrlen = static_cast<socklen_t>(info.entry.args[5]);
    if (addr_ptr != 0 && addrlen > 0) {
        SockAddrInfo sock;
        if (read_sockaddr(pid, addr_ptr, addrlen, sock)) {
            data.family = sock.family;
            data.addr = sock.addr;
            data.port = sock.port;
        }
    }

    return data;
}

static SendMsgData parse_sendmsg(__ptrace_syscall_info info) {
    return SendMsgData {
        .fd = static_cast<int>(info.entry.args[0]),
        .len = 0
    };
}

static std::optional<UnlinkData> parse_unlink(pid_t pid, __ptrace_syscall_info info) {
    auto path = read_child_string(pid, info.entry.args[0]);
    if (!path.has_value()) {
        return std::nullopt;
    }
    return UnlinkData { .pathname = *path };
}

static std::optional<MkdirData> parse_mkdir(pid_t pid, __ptrace_syscall_info info) {
    auto path = read_child_string(pid, info.entry.args[0]);
    if (!path.has_value()) {
        return std::nullopt;
    }
    return MkdirData {
        .pathname = *path,
        .mode = static_cast<unsigned int>(info.entry.args[1])
    };
}

static std::optional<MkdirAtData> parse_mkdirat(pid_t pid, __ptrace_syscall_info info) {
    auto path = read_child_string(pid, info.entry.args[1]);
    if (!path.has_value()) {
        return std::nullopt;
    }
    return MkdirAtData {
        .dfd = static_cast<int>(info.entry.args[0]),
        .pathname = *path,
        .mode = static_cast<unsigned int>(info.entry.args[2])
    };
}

static FchdirData parse_fchdir(__ptrace_syscall_info info) {
    return FchdirData {
        .fd = static_cast<unsigned int>(info.entry.args[0])
    };
}

static SetIdData parse_setid(__ptrace_syscall_info info) {
    return SetIdData {
        .a = static_cast<long>(info.entry.args[0]),
        .b = static_cast<long>(info.entry.args[1]),
        .c = static_cast<long>(info.entry.args[2])
    };
}

static std::optional<PendingSyscall> parse_profile_syscall(pid_t pid, __ptrace_syscall_info info) {
    switch (info.entry.nr) {
        case SYS_execve: {
            auto args = engine::parse_execve(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_openat: {
            auto args = engine::parse_openat(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_renameat: {
            auto args = engine::parse_renameat(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_renameat2: {
            auto args = engine::parse_renameat2(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_unlinkat: {
            auto args = engine::parse_unlinkat(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_linkat: {
            auto args = engine::parse_linkat(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_symlinkat: {
            auto args = engine::parse_symlinkat(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_connect: {
            auto args = parse_connect(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_getdents64:
            return PendingSyscall { .nr = info.entry.nr, .args = parse_getdents64(info) };
        case SYS_read:
        case SYS_pread64: {
            auto args = engine::parse_read(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_write:
        case SYS_pwrite64:
            return PendingSyscall { .nr = info.entry.nr, .args = parse_write(info) };
        case SYS_chmod: {
            auto args = parse_chmod(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_fchmod:
            return PendingSyscall { .nr = info.entry.nr, .args = parse_fchmod(info) };
        case SYS_fchmodat: {
            auto args = parse_fchmodat(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_truncate: {
            auto args = engine::parse_truncate(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_ftruncate: {
            auto args = engine::parse_ftruncate(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_dup2: {
            auto args = engine::parse_dup2(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_dup3:
            return PendingSyscall { .nr = info.entry.nr, .args = parse_dup3(info) };
        case SYS_socket:
            return PendingSyscall { .nr = info.entry.nr, .args = parse_socket(info) };
        case SYS_sendto:
            return PendingSyscall { .nr = info.entry.nr, .args = parse_sendto(pid, info) };
        case SYS_sendmsg:
            return PendingSyscall { .nr = info.entry.nr, .args = parse_sendmsg(info) };
        case SYS_rename: {
            auto args = engine::parse_rename(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_unlink: {
            auto args = parse_unlink(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_mkdir: {
            auto args = parse_mkdir(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_mkdirat: {
            auto args = parse_mkdirat(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_chdir: {
            auto args = engine::parse_chdir(pid, info);
            if (args.has_value()) {
                return PendingSyscall { .nr = info.entry.nr, .args = *args };
            }
            break;
        }
        case SYS_fchdir:
            return PendingSyscall { .nr = info.entry.nr, .args = parse_fchdir(info) };
        case SYS_setuid:
        case SYS_setgid:
        case SYS_setreuid:
        case SYS_setregid:
        case SYS_setresuid:
        case SYS_setresgid:
        case SYS_setfsuid:
        case SYS_setfsgid:
            return PendingSyscall { .nr = info.entry.nr, .args = parse_setid(info) };
        default:
            break;
    }

    return std::nullopt;
}

static void print_execve(pid_t pid, const engine::ExecveData& args) {
    std::string exe = read_proc_exe(pid);

    fprintf(out_fp, "{\"syscall\":\"execve\",\"pid\":%d,\"exe\":", pid);
    print_json_string(exe);
    fprintf(out_fp, ",\"filename\":");
    print_json_string(args.filename);
    fprintf(out_fp, ",\"argv\":[");

    for (size_t i = 0; i < args.argv.size(); i++) {
        if (i > 0) {
            fprintf(out_fp, ",");
        }
        print_json_string(args.argv[i]);
    }

    fprintf(out_fp, "]}\n");
}

static void print_syscall(pid_t pid, const PendingSyscall& pending, long retval) {
    switch (pending.nr) {
        case SYS_execve: {
            const auto* args = std::get_if<engine::ExecveData>(&pending.args);
            if (args) {
                print_execve(pid, *args);
            }
            break;
        }
        case SYS_openat: {
            const auto* args = std::get_if<engine::OpenAtData>(&pending.args);
            if (args) {
                std::string fd_path = read_proc_fd(pid, static_cast<unsigned int>(retval));
                fprintf(out_fp, "{\"syscall\":\"openat\",\"pid\":%d,\"retval\":%ld,\"dirfd\":%d,\"pathname\":", pid, retval, args->dirfd);
                print_json_string(args->pathname);
                fprintf(out_fp, ",\"flags\":%d,\"mode\":%d,\"fd_path\":", args->flags, args->mode);
                print_json_string(fd_path);
                fprintf(out_fp, "}\n");
            }
            break;
        }
        case SYS_renameat: {
            const auto* args = std::get_if<engine::RenameAtData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"renameat\",\"pid\":%d,\"retval\":%ld,\"oldfd\":%d,\"oldname\":", pid, retval, args->oldfd);
                print_json_string(args->oldname);
                fprintf(out_fp, ",\"newfd\":%d,\"newname\":", args->newfd);
                print_json_string(args->newname);
                fprintf(out_fp, "}\n");
            }
            break;
        }
        case SYS_renameat2: {
            const auto* args = std::get_if<engine::RenameAt2Data>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"renameat2\",\"pid\":%d,\"retval\":%ld,\"oldfd\":%d,\"oldname\":", pid, retval, args->oldfd);
                print_json_string(args->oldname);
                fprintf(out_fp, ",\"newfd\":%d,\"newname\":", args->newfd);
                print_json_string(args->newname);
                fprintf(out_fp, ",\"flags\":%u}\n", args->flags);
            }
            break;
        }
        case SYS_unlinkat: {
            const auto* args = std::get_if<engine::UnlinkAtData>(&pending.args);
            if (args) {
                std::string dfd_path = read_proc_fd(pid, static_cast<unsigned int>(args->dfd));
                fprintf(out_fp, "{\"syscall\":\"unlinkat\",\"pid\":%d,\"retval\":%ld,\"dfd\":%d,\"dfd_path\":", pid, retval, args->dfd);
                print_json_string(dfd_path);
                fprintf(out_fp, ",\"pathname\":");
                print_json_string(args->pathname);
                fprintf(out_fp, ",\"flags\":%d}\n", args->flags);
            }
            break;
        }
        case SYS_linkat: {
            const auto* args = std::get_if<engine::LinkAtData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"linkat\",\"pid\":%d,\"retval\":%ld,\"oldfd\":%d,\"oldname\":", pid, retval, args->oldfd);
                print_json_string(args->oldname);
                fprintf(out_fp, ",\"newfd\":%d,\"newname\":", args->newfd);
                print_json_string(args->newname);
                fprintf(out_fp, ",\"flags\":%d}\n", args->flags);
            }
            break;
        }
        case SYS_symlinkat: {
            const auto* args = std::get_if<engine::SymlinkAtData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"symlinkat\",\"pid\":%d,\"retval\":%ld,\"oldname\":", pid, retval);
                print_json_string(args->oldname);
                fprintf(out_fp, ",\"newdfd\":%d,\"newname\":", args->newdfd);
                print_json_string(args->newname);
                fprintf(out_fp, "}\n");
            }
            break;
        }
        case SYS_connect: {
            const auto* args = std::get_if<ConnectData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"connect\",\"pid\":%d,\"retval\":%ld,\"fd\":%d,\"family\":%d,\"addr\":", pid, retval, args->fd, args->family);
                print_json_string(args->addr);
                fprintf(out_fp, ",\"port\":%d}\n", args->port);
            }
            break;
        }
        case SYS_getdents64: {
            const auto* args = std::get_if<Getdents64Data>(&pending.args);
            if (args) {
                std::string fd_path = read_proc_fd(pid, args->fd);
                fprintf(out_fp, "{\"syscall\":\"getdents64\",\"pid\":%d,\"retval\":%ld,\"fd\":%u,\"fd_path\":", pid, retval, args->fd);
                print_json_string(fd_path);
                fprintf(out_fp, ",\"count\":%zu}\n", args->count);
            }
            break;
        }
        case SYS_read:
        case SYS_pread64: {
            const auto* args = std::get_if<engine::ReadData>(&pending.args);
            if (args) {
                std::string fd_path = read_proc_fd(pid, args->fd);
                const char* name = pending.nr == SYS_pread64 ? "pread64" : "read";
                fprintf(out_fp, "{\"syscall\":\"%s\",\"pid\":%d,\"retval\":%ld,\"fd\":%u,\"fd_path\":", name, pid, retval, args->fd);
                print_json_string(fd_path);
                fprintf(out_fp, ",\"count\":%zu}\n", args->count);
            }
            break;
        }
        case SYS_write:
        case SYS_pwrite64: {
            const auto* args = std::get_if<WriteData>(&pending.args);
            if (args) {
                std::string fd_path = read_proc_fd(pid, args->fd);
                const char* name = pending.nr == SYS_pwrite64 ? "pwrite64" : "write";
                fprintf(out_fp, "{\"syscall\":\"%s\",\"pid\":%d,\"retval\":%ld,\"fd\":%u,\"fd_path\":", name, pid, retval, args->fd);
                print_json_string(fd_path);
                fprintf(out_fp, ",\"count\":%zu}\n", args->count);
            }
            break;
        }
        case SYS_chmod: {
            const auto* args = std::get_if<ChmodData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"chmod\",\"pid\":%d,\"retval\":%ld,\"pathname\":", pid, retval);
                print_json_string(args->pathname);
                fprintf(out_fp, ",\"mode\":%u}\n", args->mode);
            }
            break;
        }
        case SYS_fchmod: {
            const auto* args = std::get_if<FchmodData>(&pending.args);
            if (args) {
                std::string fd_path = read_proc_fd(pid, args->fd);
                fprintf(out_fp, "{\"syscall\":\"fchmod\",\"pid\":%d,\"retval\":%ld,\"fd\":%u,\"fd_path\":", pid, retval, args->fd);
                print_json_string(fd_path);
                fprintf(out_fp, ",\"mode\":%u}\n", args->mode);
            }
            break;
        }
        case SYS_fchmodat: {
            const auto* args = std::get_if<FchmodAtData>(&pending.args);
            if (args) {
                std::string dfd_path = read_proc_fd(pid, static_cast<unsigned int>(args->dfd));
                fprintf(out_fp, "{\"syscall\":\"fchmodat\",\"pid\":%d,\"retval\":%ld,\"dfd\":%d,\"dfd_path\":", pid, retval, args->dfd);
                print_json_string(dfd_path);
                fprintf(out_fp, ",\"pathname\":");
                print_json_string(args->pathname);
                fprintf(out_fp, ",\"mode\":%u,\"flags\":%d}\n", args->mode, args->flags);
            }
            break;
        }
        case SYS_truncate: {
            const auto* args = std::get_if<engine::TruncateData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"truncate\",\"pid\":%d,\"retval\":%ld,\"pathname\":", pid, retval);
                print_json_string(args->pathname);
                fprintf(out_fp, ",\"length\":%ld}\n", args->length);
            }
            break;
        }
        case SYS_ftruncate: {
            const auto* args = std::get_if<engine::FtruncateData>(&pending.args);
            if (args) {
                std::string fd_path = read_proc_fd(pid, static_cast<unsigned int>(args->fd));
                fprintf(out_fp, "{\"syscall\":\"ftruncate\",\"pid\":%d,\"retval\":%ld,\"fd\":%d,\"fd_path\":", pid, retval, args->fd);
                print_json_string(fd_path);
                fprintf(out_fp, ",\"length\":%ld}\n", args->length);
            }
            break;
        }
        case SYS_dup2: {
            const auto* args = std::get_if<engine::Dup2Data>(&pending.args);
            if (args) {
                std::string old_path = read_proc_fd(pid, args->oldfd);
                fprintf(out_fp, "{\"syscall\":\"dup2\",\"pid\":%d,\"retval\":%ld,\"oldfd\":%u,\"oldfd_path\":", pid, retval, args->oldfd);
                print_json_string(old_path);
                fprintf(out_fp, ",\"newfd\":%u}\n", args->newfd);
            }
            break;
        }
        case SYS_dup3: {
            const auto* args = std::get_if<Dup3Data>(&pending.args);
            if (args) {
                std::string old_path = read_proc_fd(pid, args->oldfd);
                fprintf(out_fp, "{\"syscall\":\"dup3\",\"pid\":%d,\"retval\":%ld,\"oldfd\":%u,\"oldfd_path\":", pid, retval, args->oldfd);
                print_json_string(old_path);
                fprintf(out_fp, ",\"newfd\":%u,\"flags\":%d}\n", args->newfd, args->flags);
            }
            break;
        }
        case SYS_socket: {
            const auto* args = std::get_if<SocketData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"socket\",\"pid\":%d,\"retval\":%ld,\"family\":%d,\"type\":%d,\"protocol\":%d}\n",
                    pid, retval, args->family, args->type, args->protocol);
            }
            break;
        }
        case SYS_sendto: {
            const auto* args = std::get_if<SendToData>(&pending.args);
            if (args) {
                std::string fd_path = read_proc_fd(pid, args->fd);
                fprintf(out_fp, "{\"syscall\":\"sendto\",\"pid\":%d,\"retval\":%ld,\"fd\":%d,\"fd_path\":", pid, retval, args->fd);
                print_json_string(fd_path);
                fprintf(out_fp, ",\"len\":%zu,\"family\":%d,\"addr\":", args->len, args->family);
                print_json_string(args->addr);
                fprintf(out_fp, ",\"port\":%d}\n", args->port);
            }
            break;
        }
        case SYS_sendmsg: {
            const auto* args = std::get_if<SendMsgData>(&pending.args);
            if (args) {
                std::string fd_path = read_proc_fd(pid, args->fd);
                fprintf(out_fp, "{\"syscall\":\"sendmsg\",\"pid\":%d,\"retval\":%ld,\"fd\":%d,\"fd_path\":", pid, retval, args->fd);
                print_json_string(fd_path);
                fprintf(out_fp, "}\n");
            }
            break;
        }
        case SYS_rename: {
            const auto* args = std::get_if<engine::RenameData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"rename\",\"pid\":%d,\"retval\":%ld,\"oldname\":", pid, retval);
                print_json_string(args->oldname);
                fprintf(out_fp, ",\"newname\":");
                print_json_string(args->newname);
                fprintf(out_fp, "}\n");
            }
            break;
        }
        case SYS_unlink: {
            const auto* args = std::get_if<UnlinkData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"unlink\",\"pid\":%d,\"retval\":%ld,\"pathname\":", pid, retval);
                print_json_string(args->pathname);
                fprintf(out_fp, "}\n");
            }
            break;
        }
        case SYS_mkdir: {
            const auto* args = std::get_if<MkdirData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"mkdir\",\"pid\":%d,\"retval\":%ld,\"pathname\":", pid, retval);
                print_json_string(args->pathname);
                fprintf(out_fp, ",\"mode\":%u}\n", args->mode);
            }
            break;
        }
        case SYS_mkdirat: {
            const auto* args = std::get_if<MkdirAtData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"mkdirat\",\"pid\":%d,\"retval\":%ld,\"dfd\":%d,\"pathname\":", pid, retval, args->dfd);
                print_json_string(args->pathname);
                fprintf(out_fp, ",\"mode\":%u}\n", args->mode);
            }
            break;
        }
        case SYS_chdir: {
            const auto* args = std::get_if<engine::ChdirData>(&pending.args);
            if (args) {
                fprintf(out_fp, "{\"syscall\":\"chdir\",\"pid\":%d,\"retval\":%ld,\"pathname\":", pid, retval);
                print_json_string(args->filename);
                fprintf(out_fp, "}\n");
            }
            break;
        }
        case SYS_fchdir: {
            const auto* args = std::get_if<FchdirData>(&pending.args);
            if (args) {
                std::string fd_path = read_proc_fd(pid, args->fd);
                fprintf(out_fp, "{\"syscall\":\"fchdir\",\"pid\":%d,\"retval\":%ld,\"fd\":%u,\"fd_path\":", pid, retval, args->fd);
                print_json_string(fd_path);
                fprintf(out_fp, "}\n");
            }
            break;
        }
        case SYS_setuid:
        case SYS_setgid:
        case SYS_setreuid:
        case SYS_setregid:
        case SYS_setresuid:
        case SYS_setresgid:
        case SYS_setfsuid:
        case SYS_setfsgid: {
            const auto* args = std::get_if<SetIdData>(&pending.args);
            if (args) {
                const char* name = "";
                int nargs = 1;
                switch (pending.nr) {
                    case SYS_setuid: name = "setuid"; nargs = 1; break;
                    case SYS_setgid: name = "setgid"; nargs = 1; break;
                    case SYS_setreuid: name = "setreuid"; nargs = 2; break;
                    case SYS_setregid: name = "setregid"; nargs = 2; break;
                    case SYS_setresuid: name = "setresuid"; nargs = 3; break;
                    case SYS_setresgid: name = "setresgid"; nargs = 3; break;
                    case SYS_setfsuid: name = "setfsuid"; nargs = 1; break;
                    case SYS_setfsgid: name = "setfsgid"; nargs = 1; break;
                }
                fprintf(out_fp, "{\"syscall\":\"%s\",\"pid\":%d,\"retval\":%ld", name, pid, retval);
                if (nargs >= 1) fprintf(out_fp, ",\"a\":%ld", args->a);
                if (nargs >= 2) fprintf(out_fp, ",\"b\":%ld", args->b);
                if (nargs >= 3) fprintf(out_fp, ",\"c\":%ld", args->c);
                fprintf(out_fp, "}\n");
            }
            break;
        }
        default:
            break;
    }

    fflush(out_fp);
}

int main(int argc, char **argv) {
    out_fp = stderr;
    int cmd_offset = 1;

    if (argc >= 3 && strcmp(argv[1], "-o") == 0) {
        out_fp = fopen(argv[2], "w");
        if (out_fp == nullptr) {
            perror("fopen");
            return 1;
        }
        cmd_offset = 3;
    }

    if (argc < cmd_offset + 1) {
        fprintf(stderr, "usage: %s [-o file] <command> [args...]\n", argv[0]);
        return 1;
    }

    std::unordered_set<pid_t> tracked_pids;
    std::unordered_map<pid_t, std::optional<PendingSyscall>> pending_syscalls;

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        raise(SIGSTOP);
        execvp(argv[cmd_offset], &argv[cmd_offset]);
        perror("execvp");
        return 1;
    }

    int stat;
    if (waitpid(child, &stat, 0) < 0 || !WIFSTOPPED(stat)) {
        return 1;
    }

    if (ptrace(PTRACE_SETOPTIONS, child, nullptr,
        PTRACE_O_TRACESYSGOOD |
        PTRACE_O_TRACEFORK |
        PTRACE_O_TRACEVFORK |
        PTRACE_O_TRACECLONE |
        PTRACE_O_EXITKILL
    ) < 0) {
        return 1;
    }

    tracked_pids.insert(child);
    ptrace(PTRACE_SYSCALL, child, nullptr, 0);

    while (!tracked_pids.empty()) {
        pid_t pid;

        if ((pid = waitpid(-1, &stat, __WALL)) < 0) {
            break;
        }

        if (WIFEXITED(stat) || WIFSIGNALED(stat)) {
            tracked_pids.erase(pid);
            pending_syscalls.erase(pid);
            continue;
        }

        if (!WIFSTOPPED(stat)) continue;

        int sig = WSTOPSIG(stat);
        unsigned int event = static_cast<unsigned int>(stat) >> 16;

        if (sig == (SIGTRAP | 0x80)) {
            __ptrace_syscall_info info{};

            if (!tracked_pids.contains(pid)) {
                ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
                continue;
            }

            if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) < 0) {
                ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
                continue;
            }

            if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
                pending_syscalls[pid] = parse_profile_syscall(pid, info);
            } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
                auto iter = pending_syscalls.find(pid);
                bool should_print = info.exit.rval >= 0;
                if (!should_print && iter != pending_syscalls.end() && iter->second.has_value()) {
                    should_print = iter->second->nr == SYS_connect && info.exit.rval == -EINPROGRESS;
                }

                if (iter != pending_syscalls.end() && iter->second.has_value() && should_print) {
                    print_syscall(pid, *iter->second, info.exit.rval);
                }

                pending_syscalls[pid] = std::nullopt;
            }
            ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
        } else if (sig == SIGTRAP && event != 0) {
            switch (event) {
                case PTRACE_EVENT_FORK:
                case PTRACE_EVENT_VFORK:
                case PTRACE_EVENT_CLONE: {
                    unsigned long new_pid = 0;
                    ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid);
                    tracked_pids.insert(static_cast<pid_t>(new_pid));
                    break;
                }
                default:
                    break;
            }
            ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
        } else if (sig == SIGSTOP || sig == SIGTRAP) {
            ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
        } else {
            ptrace(PTRACE_SYSCALL, pid, nullptr, sig);
        }
    }

    return 0;
}
