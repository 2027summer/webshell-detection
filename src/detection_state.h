#pragma once

#include <sys/types.h>

namespace engine {

struct DetectionState {
    size_t id;
    pid_t pid;
    size_t rule_index;
    size_t current_state_index;
    unsigned long start_time_ns;
    bool is_done;
};

} // namespace engine
