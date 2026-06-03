#pragma once

#include <string>
#include <unordered_map>

namespace engine {

struct FdInfo {
    std::string path;
    int flags = 0;
};

using FdTable = std::unordered_map<long, FdInfo>;

struct Counter {
    unsigned long start_ns = 0;
    unsigned long cooldown_end_ns = 0;
    std::unordered_map<std::string, long> items;
};

struct Storage {
    FdTable fds;
    std::unordered_map<std::string, Counter> counters;
};

inline FdTable* storage_fds(Storage& storage) {
    return &storage.fds;
}

inline Counter* storage_counter(Storage& storage, const std::string& key) {
    return &storage.counters[key];
}

} // namespace engine
