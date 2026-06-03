#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include "parse_syscall.h"
#include "syscall_event.h"

namespace engine {
    bool read_child_word(pid_t pid, unsigned long address, char* bytes) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, address, nullptr);

        if (word == -1 && errno != 0) {
            return false;
        }

        memcpy(bytes, &word, sizeof(word));
        return true;
    }

    bool read_child_pointer(pid_t pid, unsigned long address, unsigned long* value) {
        return read_child_word(pid, address, reinterpret_cast<char*>(value));
    }

    std::optional<std::vector<char>> read_child_bytes(pid_t pid, unsigned long address, size_t size) {
        std::vector<char> result(size);

        for (size_t offset = 0; offset < size; offset += sizeof(long)) {
            char word[sizeof(long)];
            if (!read_child_word(pid, address + offset, word)) {
                return std::nullopt;
            }

            memcpy(result.data() + offset, word, std::min(sizeof(word), size - offset));
        }

        return result;
    }

    std::optional<std::string> read_child_string(pid_t pid, unsigned long address) {
        std::string result;

        for (size_t offset = 0; offset < 4096; offset += sizeof(long)) {
            char word[sizeof(long)];
            if (!read_child_word(pid, address + offset, word)) {
                return std::nullopt;
            }

            const char* null_pos = static_cast<const char*>(memchr(word, '\0', sizeof(word)));
            if (null_pos != nullptr) {
                result.append(word, null_pos - word);
                return result;
            }
            result.append(word, sizeof(word));
        }

        return std::nullopt;
    }

    std::optional<std::vector<std::string>> read_child_string_vector(pid_t pid, unsigned long address, size_t limit) {
        std::vector<std::string> vec;
        if (address == 0) {
            return vec;
        }

        vec.reserve(limit);
        for (size_t i = 0; i < limit; i++) {
            unsigned long string_ptr = 0;
            if (!read_child_pointer(pid, address + (i * sizeof(unsigned long)), &string_ptr)) {
                return std::nullopt;
            }

            if (string_ptr == 0) {
                break;
            }

            auto s = read_child_string(pid, string_ptr);
            if (!s.has_value()) {
                return std::nullopt;
            }

            vec.push_back(*s);
        }

        return vec;
    }

    long parse_syscall_rval(__ptrace_syscall_info info) {
        return info.exit.rval;
    }

    std::optional<ExecveData> parse_execve(pid_t pid, __ptrace_syscall_info info) {
        auto filename = read_child_string(pid, info.entry.args[0]);
        auto argv = read_child_string_vector(pid, info.entry.args[1], 16);
        auto envp = read_child_string_vector(pid, info.entry.args[2], 64);

        if (!filename.has_value() || !argv.has_value() || !envp.has_value()) {
            return std::nullopt;
        }

        return ExecveData {
            .filename = *filename,
            .argv = *argv,
            .envp = *envp
        };
    }

    std::optional<ExecveAtData> parse_execveat(pid_t pid, __ptrace_syscall_info info) {
        int dirfd = static_cast<int>(info.entry.args[0]);
        auto pathname = read_child_string(pid, info.entry.args[1]);
        auto argv = read_child_string_vector(pid, info.entry.args[2], 16);
        auto envp = read_child_string_vector(pid, info.entry.args[3], 64);
        int flags = static_cast<int>(info.entry.args[4]);

        if (!pathname.has_value() || !argv.has_value() || !envp.has_value()) {
            return std::nullopt;
        }

        return ExecveAtData {
            .dirfd = dirfd,
            .pathname = *pathname,
            .argv = *argv,
            .envp = *envp,
            .flags = flags
        };
    }

    std::optional<OpenAtData> parse_openat(pid_t pid, __ptrace_syscall_info info) {
        int dirfd = static_cast<int>(info.entry.args[0]);
        auto pathname = read_child_string(pid, info.entry.args[1]);
        int flags = static_cast<int>(info.entry.args[2]);
        int mode = static_cast<int>(info.entry.args[3]);


        if (!pathname.has_value()) {
            return std::nullopt;
        }

        return OpenAtData {
            .dirfd = dirfd,
            .pathname = *pathname,
            .flags = flags,
            .mode = mode
        };
    }

    std::optional<ChdirData> parse_chdir(pid_t pid, __ptrace_syscall_info info) {
        auto filename = read_child_string(pid, info.entry.args[0]);

        if (!filename.has_value()) {
            return std::nullopt;
        }

        return ChdirData {
            .filename = *filename
        };
    }

    std::optional<ChmodData> parse_chmod(pid_t pid, __ptrace_syscall_info info) {
        auto pathname = read_child_string(pid, info.entry.args[0]);
        int mode = static_cast<int>(info.entry.args[1]);

        if (!pathname.has_value()) {
            return std::nullopt;
        }

        return ChmodData {
            .pathname = *pathname,
            .mode = mode
        };
    }

    std::optional<FchmodAtData> parse_fchmodat(pid_t pid, __ptrace_syscall_info info) {
        int dfd = static_cast<int>(info.entry.args[0]);
        auto pathname = read_child_string(pid, info.entry.args[1]);
        int mode = static_cast<int>(info.entry.args[2]);
        int flags = static_cast<int>(info.entry.args[3]);

        if (!pathname.has_value()) {
            return std::nullopt;
        }

        return FchmodAtData {
            .dfd = dfd,
            .pathname = *pathname,
            .mode = mode,
            .flags = flags
        };
    }

    std::optional<TruncateData> parse_truncate(pid_t pid, __ptrace_syscall_info info) {
        auto pathname = read_child_string(pid, info.entry.args[0]);
        long length = static_cast<long>(info.entry.args[1]);

        if (!pathname.has_value()) {
            return std::nullopt;
        }

        return TruncateData {
            .pathname = *pathname,
            .length = length
        };
    }

    std::optional<FtruncateData> parse_ftruncate(pid_t, __ptrace_syscall_info info) {
        int fd = static_cast<int>(info.entry.args[0]);
        long length = static_cast<long>(info.entry.args[1]);

        return FtruncateData {
            .fd = fd,
            .length = length
        };
    }

    std::optional<UnlinkAtData> parse_unlinkat(pid_t pid, __ptrace_syscall_info info) {
        int dfd = static_cast<int>(info.entry.args[0]);
        auto pathname = read_child_string(pid, info.entry.args[1]);
        int flags = static_cast<int>(info.entry.args[2]);

        if (!pathname.has_value()) {
            return std::nullopt;
        }

        return UnlinkAtData {
            .dfd = dfd,
            .pathname = *pathname,
            .flags = flags
        };
    }

    std::optional<RenameData> parse_rename(pid_t pid, __ptrace_syscall_info info) {
        auto oldname = read_child_string(pid, info.entry.args[0]);
        auto newname = read_child_string(pid, info.entry.args[1]);

        if (!oldname.has_value() || !newname.has_value()) {
            return std::nullopt;
        }

        return RenameData {
            .oldname = *oldname,
            .newname = *newname
        };
    }

    std::optional<RenameAtData> parse_renameat(pid_t pid, __ptrace_syscall_info info) {
        int oldfd = static_cast<int>(info.entry.args[0]);
        auto oldname = read_child_string(pid, info.entry.args[1]);
        int newfd = static_cast<int>(info.entry.args[2]);
        auto newname = read_child_string(pid, info.entry.args[3]);

        if (!oldname.has_value() || !newname.has_value()) {
            return std::nullopt;
        }

        return RenameAtData {
            .oldfd = oldfd,
            .oldname = *oldname,
            .newfd = newfd,
            .newname = *newname
        };
    }

    std::optional<RenameAt2Data> parse_renameat2(pid_t pid, __ptrace_syscall_info info) {
        int oldfd = static_cast<int>(info.entry.args[0]);
        auto oldname = read_child_string(pid, info.entry.args[1]);
        int newfd = static_cast<int>(info.entry.args[2]);
        auto newname = read_child_string(pid, info.entry.args[3]);
        unsigned int flags = static_cast<unsigned int>(info.entry.args[4]);

        if (!oldname.has_value() || !newname.has_value()) {
            return std::nullopt;
        }

        return RenameAt2Data {
            .oldfd = oldfd,
            .oldname = *oldname,
            .newfd = newfd,
            .newname = *newname,
            .flags = flags
        };
    }

    std::optional<LinkAtData> parse_linkat(pid_t pid, __ptrace_syscall_info info) {
        int oldfd = static_cast<int>(info.entry.args[0]);
        auto oldname = read_child_string(pid, info.entry.args[1]);
        int newfd = static_cast<int>(info.entry.args[2]);
        auto newname = read_child_string(pid, info.entry.args[3]);
        int flags = static_cast<int>(info.entry.args[4]);

        if (!oldname.has_value() || !newname.has_value()) {
            return std::nullopt;
        }

        return LinkAtData {
            .oldfd = oldfd,
            .oldname = *oldname,
            .newfd = newfd,
            .newname = *newname,
            .flags = flags
        };
    }

    std::optional<SymlinkAtData> parse_symlinkat(pid_t pid, __ptrace_syscall_info info) {
        auto oldname = read_child_string(pid, info.entry.args[0]);
        int newdfd = static_cast<int>(info.entry.args[1]);
        auto newname = read_child_string(pid, info.entry.args[2]);

        if (!oldname.has_value() || !newname.has_value()) {
            return std::nullopt;
        }

        return SymlinkAtData {
            .oldname = *oldname,
            .newdfd = newdfd,
            .newname = *newname
        };
    }

    std::optional<ReadlinkAtData> parse_readlinkat(pid_t pid, __ptrace_syscall_info info) {
        int dfd = static_cast<int>(info.entry.args[0]);
        auto path = read_child_string(pid, info.entry.args[1]);
        int bufsiz = static_cast<int>(info.entry.args[3]);

        if (!path.has_value()) {
            return std::nullopt;
        }

        return ReadlinkAtData {
            .dfd = dfd,
            .path = *path,
            .buf = {},
            .bufsiz = bufsiz
        };
    }

    std::optional<WriteData> parse_write(pid_t pid, __ptrace_syscall_info info) {
        unsigned int fd = static_cast<unsigned int>(info.entry.args[0]);
        auto data = read_child_bytes(pid, info.entry.args[1], info.entry.args[2]);
        size_t count = static_cast<size_t>(info.entry.args[2]);

        if (!data.has_value()) {
            return std::nullopt;
        }

        return WriteData {
            .fd = fd,
            .data = *data,
            .count = count
        };
    }

    std::optional<WriteData> parse_pwrite64(pid_t pid, __ptrace_syscall_info info) {
        return parse_write(pid, info);
    }

    std::optional<SendToData> parse_sendto(pid_t, __ptrace_syscall_info info) {
        return SendToData {
            .fd = static_cast<int>(info.entry.args[0]),
            .len = static_cast<size_t>(info.entry.args[2])
        };
    }

    std::optional<ConnectData> parse_connect(pid_t pid, __ptrace_syscall_info info) {
        int fd = static_cast<int>(info.entry.args[0]);
        size_t addrlen = std::min(static_cast<size_t>(info.entry.args[2]), sizeof(sockaddr_storage));
        auto bytes = read_child_bytes(pid, info.entry.args[1], addrlen);
        if (!bytes.has_value() || bytes->size() < sizeof(sa_family_t)) {
            return std::nullopt;
        }

        const auto* sa = reinterpret_cast<const sockaddr*>(bytes->data());
        char addr[INET6_ADDRSTRLEN] = {0};
        int port = 0;

        if (sa->sa_family == AF_INET && bytes->size() >= sizeof(sockaddr_in)) {
            const auto* in = reinterpret_cast<const sockaddr_in*>(bytes->data());
            inet_ntop(AF_INET, &in->sin_addr, addr, sizeof(addr));
            port = ntohs(in->sin_port);
        } else if (sa->sa_family == AF_INET6 && bytes->size() >= sizeof(sockaddr_in6)) {
            const auto* in6 = reinterpret_cast<const sockaddr_in6*>(bytes->data());
            inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr));
            port = ntohs(in6->sin6_port);
        }

        return ConnectData {
            .fd = fd,
            .family = static_cast<int>(sa->sa_family),
            .addr = addr,
            .port = port
        };
    }

    std::optional<Dup2Data> parse_dup2(pid_t, __ptrace_syscall_info info) {
        return Dup2Data {
            .oldfd = static_cast<unsigned int>(info.entry.args[0]),
            .newfd = static_cast<unsigned int>(info.entry.args[1])
        };
    }

    std::optional<CloseData> parse_close(pid_t, __ptrace_syscall_info info) {
        return CloseData {
            .fd = static_cast<unsigned int>(info.entry.args[0])
        };
    }

    std::optional<ReadData> parse_read(pid_t, __ptrace_syscall_info info) {
        unsigned int fd = static_cast<unsigned int>(info.entry.args[0]);
        size_t count = static_cast<size_t>(info.entry.args[2]);
        return ReadData {
            .fd = fd,
            .count = count
        };
    }

    std::optional<ReadData> parse_pread64(pid_t pid, __ptrace_syscall_info info) {
        return parse_read(pid, info);
    }

    std::optional<Getdents64Data> parse_getdents64(pid_t, __ptrace_syscall_info info) {
        return Getdents64Data {
            .fd = static_cast<unsigned int>(info.entry.args[0]),
            .dirp = info.entry.args[1],
            .count = static_cast<unsigned int>(info.entry.args[2]),
            .entries = {}
        };
    }
}
