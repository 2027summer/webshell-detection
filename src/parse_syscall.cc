#include <algorithm>
#include <cstring>
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

        if (!filename.has_value() || !argv.has_value()) {
            return std::nullopt;
        }

        return ExecveData {
            .filename = *filename,
            .argv = *argv,
            .envp = {}
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
}
