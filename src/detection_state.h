#pragma once

#include <cstddef>
#include <string>
#include <variant>
#include <sys/types.h>
#include <vector>

namespace engine {

struct DetectionState {
    size_t id;
    pid_t pid;
    size_t rule_index;
    size_t current_state_index;
    std::vector<std::variant<long, std::string>> captured;
    unsigned long start_time_ns;
    bool is_done;
};

} // namespace engine
