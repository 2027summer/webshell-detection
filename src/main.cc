#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "engine.h"

using namespace engine;

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

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

    Engine engine;

    engine.add_tracked_pid(child);
    ptrace(PTRACE_SYSCALL, child, nullptr, 0);

    while (engine.tracked() > 0) {
        pid_t pid;

        if ((pid = waitpid(-1, &stat, __WALL)) < 0) {
            break;
        }

        if (WIFEXITED(stat) || WIFSIGNALED(stat)) {
            // pid 추적 중지
            engine.remove_tracked_pid(pid);
            continue;
        }

        if (!WIFSTOPPED(stat)) continue;

        int sig = WSTOPSIG(stat);
        unsigned int event = static_cast<unsigned int>(stat) >> 16;

        if (sig == (SIGTRAP | 0x80)) {
            __ptrace_syscall_info info{};

            if (!engine.is_tracked(pid)) {
                ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
                continue;
            }

            if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) < 0) {
                ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
                continue;
            }

            if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
                // syscall 발생 시점
                engine.handle_syscall_entry(pid, info);
            } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
                engine.handle_syscall_exit(pid, info);
            }
            ptrace(PTRACE_SYSCALL, pid, nullptr, 0);
        } else if (sig == SIGTRAP && event != 0) {
            // fork가 발생한 경우 새로운 pid를 추적 대상에 포함
            switch (event) {
                case PTRACE_EVENT_FORK:
                case PTRACE_EVENT_VFORK:
                case PTRACE_EVENT_CLONE: {
                    unsigned long new_pid = 0;
                    ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid);
                    engine.add_tracked_pid(static_cast<pid_t>(new_pid));
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