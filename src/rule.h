#pragma once

#include <optional>
#include <string>
#include <vector>
#include "syscall_event.h"
#include "detection_state.h"

namespace engine {

struct DetectionState;

using TransitionFunc = bool(*)(DetectionState&, const SyscallEvent&);
using DetectHandler = bool(*)(DetectionState&);

struct DetectionRule {
    std::string name;
    long timeout_ns;
    std::vector<TransitionFunc> transitions;
    std::optional<DetectHandler> on_detect;
};

} // namespace engine
