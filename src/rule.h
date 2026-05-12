#pragma once

#include <string>
#include <vector>
#include "syscall_event.h"
#include "detection_state.h"

namespace engine {

struct DetectionState;

using ConditionFunc = bool(*)(const DetectionState&, const SyscallEvent&);

struct DetectionRule {
    std::string name;
    unsigned long timeout_ns;
    std::vector<ConditionFunc> transitions;
};

} // namespace engine
