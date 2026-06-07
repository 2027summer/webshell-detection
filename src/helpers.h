#pragma once

#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include <unistd.h>

namespace engine {
    namespace fs = std::filesystem;

    inline std::string normalize_path(const fs::path& path, bool keep_trailing_slash) {
        std::string normalized = path.lexically_normal().string();
        if (keep_trailing_slash && normalized.size() > 1 && !normalized.ends_with("/")) {
            normalized.push_back('/');
        }
        if (!keep_trailing_slash && normalized.size() > 1 && normalized.ends_with("/")) {
            normalized.pop_back();
        }
        return normalized;
    }

    inline std::optional<std::string> get_absolute_path(pid_t pid, const std::string& path) {
        if (path.size() == 0) {
            return std::nullopt;
        }

        if (path[0] == '/') {
            // 이미 절대 경로로 간주
            return normalize_path(path, path.ends_with("/"));
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

        return normalize_path(base + "/" + path, path.ends_with("/"));
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

        return normalize_path(std::string(buf) + "/" + path, path.ends_with("/"));
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

    inline std::optional<unsigned int> parse_fd_path(const std::string& path, const std::string& prefix) {
        if (!path.starts_with(prefix) || path.size() == prefix.size()) {
            return std::nullopt;
        }

        unsigned int fd = 0;
        for (size_t i = prefix.size(); i < path.size(); i++) {
            if (path[i] < '0' || path[i] > '9') {
                return std::nullopt;
            }
            fd = fd * 10 + static_cast<unsigned int>(path[i] - '0');
        }
        return fd;
    }

    inline std::optional<unsigned int> get_exec_fd_from_path(pid_t pid, const std::string& path) {
        auto fd = parse_fd_path(path, "/proc/self/fd/");
        if (fd.has_value()) {
            return fd;
        }

        fd = parse_fd_path(path, "/dev/fd/");
        if (fd.has_value()) {
            return fd;
        }

        char prefix[64];
        snprintf(prefix, 64, "/proc/%d/fd/", pid);
        return parse_fd_path(path, prefix);
    }

    inline std::optional<std::string> resolve_exec_fd_path(pid_t pid, const std::string& path) {
        auto fd = get_exec_fd_from_path(pid, path);
        if (!fd.has_value()) {
            return path;
        }
        return get_fd_path(pid, *fd);
    }

    inline std::optional<std::string> get_execve_path(pid_t pid, const std::string& path) {
        auto absolute_path = get_absolute_path(pid, path);
        if (!absolute_path.has_value()) {
            return std::nullopt;
        }
        return resolve_exec_fd_path(pid, *absolute_path);
    }

    inline std::optional<std::string> get_env_value(const std::vector<std::string>& envp, const std::string& name) {
        std::string prefix = name + "=";
        for (const auto& env : envp) {
            if (env.starts_with(prefix)) {
                return env.substr(prefix.size());
            }
        }
        return std::nullopt;
    }

    inline std::vector<std::string> split_env_paths(const std::string& value) {
        std::vector<std::string> paths;
        size_t start = 0;
        for (size_t i = 0; i <= value.size(); i++) {
            if (i != value.size() && value[i] != ':' && value[i] != ' ') {
                continue;
            }
            if (i > start) {
                paths.push_back(value.substr(start, i - start));
            }
            start = i + 1;
        }
        return paths;
    }

    inline std::optional<std::string> get_env_path(pid_t pid, const std::string& path) {
        if (path.empty()) {
            return std::nullopt;
        }
        if (path.find('/') == std::string::npos) {
            return path;
        }
        return get_execve_path(pid, path);
    }

    inline std::optional<std::string> get_execveat_path(pid_t pid, int dirfd, const std::string& path) {
        if (path.size() == 0) {
            if (dirfd < 0) {
                return std::nullopt;
            }
            return get_fd_path(pid, static_cast<unsigned int>(dirfd));
        }

        auto absolute_path = get_absolute_path_at(pid, dirfd, path);
        if (!absolute_path.has_value()) {
            return std::nullopt;
        }
        return resolve_exec_fd_path(pid, *absolute_path);
    }
}
