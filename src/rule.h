#pragma once

#include <optional>
#include <string>
#include <vector>
#include <unordered_map>
#include <variant>
#include "syscall_event.h"
#include "detection_state.h"

namespace engine {

struct DetectionState;
using Storage = std::unordered_map<std::string, std::variant<long, std::string>>;

struct Context {
    Storage &storage;
};

using TransitionFunc = int(*)(Context&, DetectionState&, const SyscallEvent&);
using DetectHandler = bool(*)(DetectionState&);

struct DetectionRule {
    std::string name;
    long timeout_ns;
    std::vector<TransitionFunc> transitions;
    std::optional<DetectHandler> on_detect;
    bool inherit_on_fork = false;
};

} // namespace engine
