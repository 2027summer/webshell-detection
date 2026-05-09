#include "engine.h"

namespace engine {
    void Engine::add_tracked_pid(pid_t pid) {
        tracked_pids[pid] = std::nullopt;
    }

    void Engine::remove_tracked_pid(pid_t pid) {
        tracked_pids.erase(pid);
    }

    bool Engine::is_tracked(pid_t pid) {
        return !(tracked_pids.find(pid) == tracked_pids.end());
    }

    size_t Engine::tracked() {
        return tracked_pids.size();
    }

    void Engine::handle_syscall_entry(pid_t pid, const __ptrace_syscall_info info) {

    }

    void Engine::handle_syscall_exit(pid_t pid, const __ptrace_syscall_info info) {

    }
}
