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

enum class TransitionResult {
    NoMatch,
    Stay,
    Advance,
};

using TransitionFunc = TransitionResult(*)(FdTable&, DetectionState&, const SyscallEvent&);

struct DetectionRule {
    std::string name;
    long timeout_ns;
    long cooldown_ns = 0;
    std::vector<TransitionFunc> transitions;
    bool inherit_on_fork = false;
    bool single_active_per_pid = false;
};

} // namespace engine
