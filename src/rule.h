#pragma once

#include <string>
#include <vector>
#include "syscall_event.h"
#include "detection_state.h"

namespace engine {

struct DetectionState;

constexpr int NO_TRANSITION = -1;

using TransitionFunc = int(*)(DetectionState&, const SyscallEvent&);

struct DetectionRule {
    std::string name;
    long timeout_ns;
    long cooldown_ns = 0;
    std::vector<TransitionFunc> transitions;
    bool inherit_on_fork = false;
    bool single_active_per_pid = false;
};

} // namespace engine
