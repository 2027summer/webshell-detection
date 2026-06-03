#pragma once

#include <optional>
#include <string>
#include <vector>
#include <unordered_map>
#include <variant>
#include "storage.h"
#include "syscall_event.h"
#include "detection_state.h"

namespace engine {

struct DetectionState;

struct Context {
    Storage &storage;
};

using TransitionFunc = int(*)(Context&, DetectionState&, const SyscallEvent&);

struct DetectionRule {
    std::string name;
    long timeout_ns;
    std::vector<TransitionFunc> transitions;
    bool inherit_on_fork = false;
};

} // namespace engine
