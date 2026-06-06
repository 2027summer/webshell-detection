#pragma once

#include <string>
#include <unordered_map>

namespace engine {

struct FdInfo {
    std::string path;
    int flags = 0;
};

using FdTable = std::unordered_map<long, FdInfo>;

} // namespace engine
