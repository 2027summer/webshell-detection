#pragma once

#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <optional>
#include <unistd.h>

namespace engine {
    namespace fs = std::filesystem;

    inline std::optional<std::string> get_absolute_path(pid_t pid, const std::string& path) {
        if (path.size() == 0) {
            return std::nullopt;
        }

        if (path[0] == '/') {
            // 이미 절대 경로로 간주
            return fs::path(path).lexically_normal().string();
        }


        char path2[64];

        snprintf(path2, 64, "/proc/%d/cwd", pid);

        char buf[4096];
        ssize_t len = readlink(path2, buf, 4095);

        if (len < 0) {
            return std::nullopt;
        }

        buf[len] = '\0';

        std::string base = std::string(buf);

        return fs::path(base + "/" + path).lexically_normal().string();
    }

    inline std::optional<std::string> get_absolute_path_at(pid_t pid, int dirfd, const std::string& path) {
        if (path.size() == 0) {
            return std::nullopt;
        }

        if (path[0] == '/' || dirfd == AT_FDCWD) {
            return get_absolute_path(pid, path);
        }

        char path2[64];
        snprintf(path2, 64, "/proc/%d/fd/%d", pid, dirfd);

        char buf[4096];
        ssize_t len = readlink(path2, buf, 4095);

        if (len < 0) {
            return std::nullopt;
        }

        buf[len] = '\0';

        return fs::path(std::string(buf) + "/" + path).lexically_normal().string();
    }

    inline std::optional<std::string> get_fd_path(pid_t pid, unsigned int fd) {
        char path[64];
        snprintf(path, 64, "/proc/%d/fd/%u", pid, fd);

        char buf[4096];
        ssize_t len = readlink(path, buf, 4095);

        if (len < 0) {
            return std::nullopt;
        }

        buf[len] = '\0';
        return fs::path(buf).lexically_normal().string();
    }
}
