#include <csignal>
#include <cstdio>
#include <optional>
#include <string>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include "parse_syscall.h"

static std::string read_proc_exe(pid_t pid) {
    char path[64];
    char buf[4096];

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);

    ssize_t len = readlink(path, buf, sizeof(buf) - 1);
    if (len < 0) {
        return "";
    }

    buf[len] = '\0';
    return std::string(buf);
}

static void print_execve(pid_t pid, const engine::ExecveData& args) {
    std::string exe = read_proc_exe(pid);

    printf(
        "execve\t%d\t%s\t%s\t%zu",
        pid,
        exe.c_str(),
        args.filename.c_str(),
        args.argv.size()
    );

    for (const auto& arg : args.argv) {
        printf("\t%s", arg.c_str());
    }

    printf("\n");
    fflush(stdout);
}

static void print_process_event(const char* name, pid_t pid, pid_t new_pid) {
    printf("%s\t%d\t%d\n", name, pid, new_pid);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    std::unordered_set<pid_t> tracked_pids;
    std::unordered_map<pid_t, std::optional<engine::ExecveData>> pending_execve;

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        raise(SIGSTOP);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        return 1;
    }

    int stat;
    if (waitpid(child, &stat, 0) < 0 || !WIFSTOPPED(stat)) {
        return 1;
    }

    if (ptrace(PTRACE_SETOPTIONS, child, nullptr,
        PTRACE_O_TRACESYSGOOD |
        PTRACE_O_TRACEFORK |
        PTRACE_O_TRACEVFORK |
        PTRACE_O_TRACECLONE |
        PTRACE_O_EXITKILL
    ) < 0) {
        return 1;
    }

    tracked_pids.insert(child);
    ptrace(PTRACE_SYSCALL, child, nullptr, 0);

    while (!tracked_pids.empty()) {
        pid_t pid;

        if ((pid = waitpid(-1, &stat, __WALL)) < 0) {
            break;
        }

        if (WIFEXITED(stat) || WIFSIGNALED(stat)) {
            tracked_pids.erase(pid);
            pending_execve.erase(pid);
            continue;
        }

        if (!WIFSTOPPED(stat)) continue;

        int sig = WSTOPSIG(stat);
        unsigned int event = static_cast<unsigned int>(stat) >> 16;

        if (sig == (SIGTRAP | 0x80)) {
            __ptrace_syscall_info info{};

            if (!tracked_pids.contains(pid)) {
                ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
                continue;
            }

            if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) < 0) {
                ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
                continue;
            }

            if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
                pending_execve[pid] = std::nullopt;

                if (info.entry.nr == SYS_execve) {
                    auto args = engine::parse_execve(pid, info);
                    if (args.has_value()) {
                        pending_execve[pid] = *args;
                    }
                }
            } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
                auto iter = pending_execve.find(pid);
                if (iter != pending_execve.end() && iter->second.has_value() && info.exit.rval == 0) {
                    print_execve(pid, *iter->second);
                }

                pending_execve[pid] = std::nullopt;
            }
            ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
        } else if (sig == SIGTRAP && event != 0) {
            switch (event) {
                case PTRACE_EVENT_FORK:
                case PTRACE_EVENT_VFORK:
                case PTRACE_EVENT_CLONE: {
                    unsigned long new_pid = 0;
                    ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid);
                    tracked_pids.insert(static_cast<pid_t>(new_pid));

                    if (event == PTRACE_EVENT_FORK) {
                        print_process_event("fork", pid, static_cast<pid_t>(new_pid));
                    } else if (event == PTRACE_EVENT_VFORK) {
                        print_process_event("vfork", pid, static_cast<pid_t>(new_pid));
                    } else {
                        print_process_event("clone", pid, static_cast<pid_t>(new_pid));
                    }
                    break;
                }
                default:
                    break;
            }
            ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
        } else if (sig == SIGSTOP || sig == SIGTRAP) {
            ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
        } else {
            ptrace(PTRACE_SYSCALL, pid, nullptr, sig);
        }
    }

    return 0;
}
