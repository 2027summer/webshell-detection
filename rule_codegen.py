from pathlib import Path
import os

os.chdir(Path(__file__).resolve().parent)

def only_alnum(s: str):
    ss = ""
    for c in s:
        if c.isalnum():
            ss += c
    return ss


def expand_home_path(path: str):
    if path == "~" or path.startswith("~/"):
        expanded_path = str(Path(path).expanduser())
        # 지금 컨벤션에서 /로 끝나는게 디렉토리 하위를 말하는 거라 보정해야함
        if path.endswith("/") and not expanded_path.endswith("/"):
            expanded_path += "/"
        return expanded_path
    return path


def gen_string_match_cond(value: str, condition: dict, absolute_path: str, pid: str = "event.pid"):
    if "all" in condition:
        conditions = condition["all"]
        assert(isinstance(conditions, list) and len(conditions) > 0)
        l = []
        for cond in conditions:
            l.append(gen_string_match_cond(value, cond, absolute_path, pid))
        return "(" + " && ".join(l) + ")"
    if "any" in condition:
        conditions = condition["any"]
        assert(isinstance(conditions, list) and len(conditions) > 0)
        l = []
        for cond in conditions:
            l.append(gen_string_match_cond(value, cond, absolute_path, pid))
        return "(" + " || ".join(l) + ")"

    assert(len(condition) == 1)
    if "eq" in condition:
        return f"{value} == \"{condition['eq']}\""
    elif "starts_with" in condition:
        return f"{value}.starts_with(\"{condition['starts_with']}\")"
    elif "ends_with" in condition:
        return f"{value}.ends_with(\"{condition['ends_with']}\")"
    elif "contains" in condition:
        return f"{value}.find(\"{condition['contains']}\") != std::string::npos"
    elif "path_in" in condition:
        path = condition["path_in"]
        assert(isinstance(path, str))
        path = expand_home_path(path)
        return f"is_path_in({absolute_path}, {pid}, \"{path}\")"

    assert(False)


def gen_destination_match_cond(condition: dict, value: str = "args"):
    if "all" in condition:
        conditions = condition["all"]
        assert(isinstance(conditions, list) and len(conditions) > 0)
        l = []
        for cond in conditions:
            l.append(gen_destination_match_cond(cond, value))
        return "(" + " && ".join(l) + ")"
    if "any" in condition:
        conditions = condition["any"]
        assert(isinstance(conditions, list) and len(conditions) > 0)
        l = []
        for cond in conditions:
            l.append(gen_destination_match_cond(cond, value))
        return "(" + " || ".join(l) + ")"

    exprs = []
    for key, v in condition.items():
        if key == "addr":
            exprs.append(f"{value}->addr == \"{v}\"")
        elif key == "addr_starts_with":
            exprs.append(f"{value}->addr.starts_with(\"{v}\")")
        elif key == "port":
            assert(isinstance(v, int))
            exprs.append(f"{value}->port == {v}")
        elif key == "family":
            assert(isinstance(v, int) or isinstance(v, str))
            exprs.append(f"{value}->family == {v}")
        else:
            assert(False)

    assert(len(exprs) > 0)
    return "(" + " && ".join(exprs) + ")"


def condition_has_key(condition: dict, key: str):
    if key in condition:
        return True
    for nested_key in ["all", "any"]:
        if nested_key in condition:
            for cond in condition[nested_key]:
                if condition_has_key(cond, key):
                    return True
    return False


def gen_allow_deny_expr(
    check_list: dict,
    value: str,
    absolute_path: str,
    require_non_empty: bool = True,
    indent: str = "    ",
    pid: str = "event.pid",
):
    assert(isinstance(check_list, dict))

    has_allow = "allow" in check_list
    has_deny = "deny" in check_list
    assert(has_allow or has_deny)
    for key in check_list.keys():
        assert(key == "allow" or key == "deny")

    allow_conds = check_list.get("allow", [])
    deny_conds = check_list.get("deny", [])
    if require_non_empty:
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

    allow_exprs = []
    for cond in allow_conds:
        allow_exprs.append(gen_string_match_cond(value, cond, absolute_path, pid))

    deny_exprs = []
    for cond in deny_conds:
        deny_exprs.append(gen_string_match_cond(value, cond, absolute_path, pid))

    cond_allow = " || ".join(allow_exprs)
    if len(allow_exprs) > 1:
        cond_allow = "(\n"
        for i, expr in enumerate(allow_exprs):
            suffix = ""
            if i + 1 < len(allow_exprs):
                suffix = " ||"
            cond_allow += f"{indent}    {expr}{suffix}\n"
        cond_allow += f"{indent})"

    cond_deny = " || ".join(deny_exprs)
    if len(deny_exprs) > 1:
        cond_deny = "(\n"
        for i, expr in enumerate(deny_exprs):
            suffix = ""
            if i + 1 < len(deny_exprs):
                suffix = " ||"
            cond_deny += f"{indent}    {expr}{suffix}\n"
        cond_deny += f"{indent})"

    if len(allow_conds) > 0 and len(deny_conds) > 0:
        return f"({cond_allow}) || !({cond_deny})"
    elif len(allow_conds) > 0:
        return cond_allow
    elif len(deny_conds) > 0:
        return f"!({cond_deny})"
    return ""

codegen_rules_h_template = f"""#include <any>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unordered_map>
#include <unordered_set>
#include "engine.h"
#include "helpers.h"

namespace detection_rules {{

using namespace engine;

struct PathCountState {{
    std::unordered_set<std::string> paths;
}};

struct RecursiveTraversalState {{
    std::unordered_map<unsigned int, std::string> fd_paths;
    std::unordered_set<std::string> paths;
}};

inline bool is_path_in(const std::optional<std::string>& absolute_path, pid_t pid, const std::string& path) {{
    if (!absolute_path.has_value()) {{
        return false;
    }}

    auto path_in = get_absolute_path(pid, path);
    if (!path_in.has_value()) {{
        return false;
    }}

    if (path.ends_with("/")) {{
        return *absolute_path != *path_in && absolute_path->starts_with(*path_in);
    }}
    if (*absolute_path == *path_in) {{
        return true;
    }}
    return *absolute_path == *path_in + "/";
}}

[IS_FUNCTION_BODY]

inline void register_codegen_rules(engine::Engine& engine) {{
[ALLOW_DEF_GEN_BODY]
[RULE_DEF_GEN_BODY]
}}
}}"""


def gen_execve(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_execve) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<ExecveData>(&event.args);
    if (!args) return NO_TRANSITION;

"""

    if "filename" in t and len(t["filename"]) > 0:
        check_list = t["filename"]

        body += "    auto filename_path = get_execve_path(event.pid, args->filename);\n"
        body += "    if (!filename_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        filename = "(*filename_path)"
        skip_expr = gen_allow_deny_expr(
            check_list,
            filename,
            "filename_path",
        )

        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    if "argv" in t and len(t["argv"]) > 0:
        argv = t["argv"]
        assert(isinstance(argv, dict))

        for index in argv.keys():
            assert(isinstance(index, int))
            assert(index >= 0)

        max_index = max(argv.keys())
        body += f"""    if (args->argv.size() < {max_index + 1}) {{
        return NO_TRANSITION;
    }}
"""

        for index, conditions in argv.items():
            assert(isinstance(conditions, list) and len(conditions) > 0)

            arg = f"args->argv[{index}]"
            absolute_path = f"argv_{index}_path"
            if any(condition_has_key(condition, "path_in") for condition in conditions):
                body += f"    auto {absolute_path} = get_absolute_path(event.pid, {arg});\n"
                body += "\n"

            l = []
            for condition in conditions:
                l.append(gen_string_match_cond(arg, condition, absolute_path))

            cond = " || ".join(l)
            body += f"    if (!({cond})) {{\n"
            body += f"        return NO_TRANSITION;\n"
            body += f"    }}\n"

    if "find_name_keywords" in t and len(t["find_name_keywords"]) > 0:
        keywords = t["find_name_keywords"]

        l = []
        for keyword in keywords:
            l.append(f'args->argv[i + 1].find("{keyword}") != std::string::npos')

        cond = " || ".join(l)
        body += f"""    bool flag_find_name_keywords = false;
    for (size_t i = 0; i + 1 < args->argv.size(); i++) {{
        if (args->argv[i] != "-name" && args->argv[i] != "-iname") {{
            continue;
        }}

        if ({cond}) {{
            flag_find_name_keywords = true;
            break;
        }}
    }}
    if (flag_find_name_keywords == false) {{
        return NO_TRANSITION;
    }}
"""

    if "curl_wget_url_allow" in t and len(t["curl_wget_url_allow"]) > 0:
        allow_urls = t["curl_wget_url_allow"]

        l = []
        for url in allow_urls:
            l.append(f'arg == "{url}"')
            l.append(f'arg.starts_with("{url}/")')

        cond = " || ".join(l)
        body += f"""    bool flag = false;
    for (size_t i = 1; i < args->argv.size(); i++) {{
        const auto& arg = args->argv[i];

        if (arg == "-o" || arg == "-O" ||
            arg == "--output" || arg == "--output-document") {{
            i++;
            continue;
        }}

        if (arg.starts_with("-")) {{
            continue;
        }}

        if (arg.find("://") != std::string::npos &&
            !(arg.starts_with("http://") || arg.starts_with("https://"))) {{
            flag = true;
            break;
        }}

        if (!(arg.starts_with("http://") ||
              arg.starts_with("https://") ||
              arg.find(".") != std::string::npos)) {{
            continue;
        }}

        if (!({cond})) {{
            flag = true;
            break;
        }}
    }}
    if (flag == false) {{
        return NO_TRANSITION;
    }}
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_openat(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_openat) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<OpenAtData>(&event.args);
    if (!args) return NO_TRANSITION;
    if (!event.retval.has_value() || *event.retval < 0) {{
        return NO_TRANSITION;
    }}
"""

    if "dirfd" in t:
        body += f"""    if (args->dirfd != {t["dirfd"]}) {{
        return NO_TRANSITION;
    }}
"""

    if "from_shell" in t:
        assert(isinstance(t["from_shell"], bool))
        if t["from_shell"]:
            body += """    if (!event.from_shell) {
        return NO_TRANSITION;
    }
"""
        else:
            body += """    if (event.from_shell) {
        return NO_TRANSITION;
    }
"""

    if "pathname" in t:
        check_list = t["pathname"]

        body += """    auto absolute_path = get_absolute_path_at(event.pid, args->dirfd, args->pathname);
    if (!absolute_path.has_value()) {
        return NO_TRANSITION;
    }
"""
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            check_list,
            "(*absolute_path)",
            "absolute_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    if "access_mode" in t:
        access_mode = t["access_mode"]
        assert(access_mode == "read" or access_mode == "write" or access_mode == "readonly")
        if access_mode == "read":
            body += """    if ((args->flags & O_ACCMODE) == O_WRONLY) {
        return NO_TRANSITION;
    }
"""
        elif access_mode == "write":
            body += """    int access_mode = args->flags & O_ACCMODE;
    if (access_mode != O_WRONLY && access_mode != O_RDWR) {
        return NO_TRANSITION;
    }
"""
        else:
            body += """    if ((args->flags & O_ACCMODE) != O_RDONLY) {
        return NO_TRANSITION;
    }
"""

    if "flags" in t:
        flags = t["flags"] # expected: ["O_RDONLY", "...", ...]
        # if "O_RDONLY" in flags:
        for flag in flags:
            body += f"""    if (!((args->flags & {flag}) == {flag})) {{
        return NO_TRANSITION;
    }}
"""

    if "flags_unset" in t:
        flags = t["flags_unset"]
        assert(isinstance(flags, list))
        for flag in flags:
            body += f"""    if ((args->flags & {flag}) == {flag}) {{
        return NO_TRANSITION;
    }}
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_connect(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_connect) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || (*event.retval != 0 && *event.retval != -115)) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<ConnectData>(&event.args);
    if (!args) return NO_TRANSITION;
    if (args->port == 0) {{
        return NO_TRANSITION;
    }}
    fprintf(stderr, "> %s %d %d\\n", args->addr.c_str(), args->port, args->family);
"""

    if "destination" in t:
        check_list = t["destination"]

        assert(isinstance(check_list, dict))
        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_destination_match_cond(cond))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_destination_match_cond(cond))

        cond_allow = " || ".join(allow_exprs)
        if len(allow_exprs) > 1:
            cond_allow = "(\n"
            for i, expr in enumerate(allow_exprs):
                suffix = ""
                if i + 1 < len(allow_exprs):
                    suffix = " ||"
                cond_allow += f"        {expr}{suffix}\n"
            cond_allow += "    )"

        cond_deny = " || ".join(deny_exprs)
        if len(deny_exprs) > 1:
            cond_deny = "(\n"
            for i, expr in enumerate(deny_exprs):
                suffix = ""
                if i + 1 < len(deny_exprs):
                    suffix = " ||"
                cond_deny += f"        {expr}{suffix}\n"
            cond_deny += "    )"

        skip_expr = ""
        if len(allow_conds) > 0 and len(deny_conds) > 0:
            skip_expr = f"({cond_allow}) || !({cond_deny})"
        elif len(allow_conds) > 0:
            skip_expr = cond_allow
        elif len(deny_conds) > 0:
            skip_expr = f"!({cond_deny})"

        if len(skip_expr) > 0:
            body += f"    if ({skip_expr}) {{\n"
            body += f"        return NO_TRANSITION;\n"
            body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_unlinkat(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_unlinkat) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<UnlinkAtData>(&event.args);
    if (!args) return NO_TRANSITION;
"""

    if "dfd" in t:
        body += f"""    if (args->dfd != {t["dfd"]}) {{
        return NO_TRANSITION;
    }}
"""

    if "pathname" in t:
        check_list = t["pathname"]

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        skip_expr = gen_allow_deny_expr(
            check_list,
            "args->pathname",
            "absolute_path",
        )

        if any(condition_has_key(cond, "path_in") for cond in allow_conds + deny_conds):
            body += "    auto absolute_path = get_absolute_path_at(event.pid, args->dfd, args->pathname);\n"
            body += "    if (!absolute_path.has_value()) {\n"
            body += "        return NO_TRANSITION;\n"
            body += "    }\n"
            body += "\n"

        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_renameat2(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_renameat2) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<RenameAt2Data>(&event.args);
    if (!args) return NO_TRANSITION;
"""

    if "oldname" in t:
        oldname_rule = t["oldname"]

        allow_conds = oldname_rule.get("allow", [])
        deny_conds = oldname_rule.get("deny", [])
        skip_expr = gen_allow_deny_expr(
            oldname_rule,
            "args->oldname",
            "oldname_path",
        )

        if any(condition_has_key(cond, "path_in") for cond in allow_conds + deny_conds):
            body += "    auto oldname_path = get_absolute_path_at(event.pid, args->oldfd, args->oldname);\n"
            body += "\n"

        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    if "newname" in t:
        newname_rule = t["newname"]

        body += "    auto newname_path = get_absolute_path_at(event.pid, args->newfd, args->newname);\n"
        body += "    if (!newname_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            newname_rule,
            "(*newname_path)",
            "newname_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_rename(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_rename) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<RenameData>(&event.args);
    if (!args) return NO_TRANSITION;
"""

    if "oldname" in t:
        check_list = t["oldname"]

        body += "    auto oldname_path = get_absolute_path(event.pid, args->oldname);\n"
        body += "    if (!oldname_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            check_list,
            "(*oldname_path)",
            "oldname_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    if "newname" in t:
        check_list = t["newname"]

        body += "    auto newname_path = get_absolute_path(event.pid, args->newname);\n"
        body += "    if (!newname_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            check_list,
            "(*newname_path)",
            "newname_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_renameat(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_renameat) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<RenameAtData>(&event.args);
    if (!args) return NO_TRANSITION;
"""

    if "oldfd" in t:
        body += f"""    if (args->oldfd != {t["oldfd"]}) {{
        return NO_TRANSITION;
    }}
"""

    if "newfd" in t:
        body += f"""    if (args->newfd != {t["newfd"]}) {{
        return NO_TRANSITION;
    }}
"""

    if "oldname" in t:
        check_list = t["oldname"]

        body += "    auto oldname_path = get_absolute_path_at(event.pid, args->oldfd, args->oldname);\n"
        body += "    if (!oldname_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            check_list,
            "(*oldname_path)",
            "oldname_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    if "newname" in t:
        check_list = t["newname"]

        body += "    auto newname_path = get_absolute_path_at(event.pid, args->newfd, args->newname);\n"
        body += "    if (!newname_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            check_list,
            "(*newname_path)",
            "newname_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_chmod(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_chmod) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<ChmodData>(&event.args);
    if (!args) return NO_TRANSITION;
"""

    if "pathname" in t:
        check_list = t["pathname"]

        body += "    auto pathname_path = get_absolute_path(event.pid, args->pathname);\n"
        body += "    if (!pathname_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            check_list,
            "(*pathname_path)",
            "pathname_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    if "mode_any" in t:
        mode_any = t["mode_any"]
        assert(mode_any == "execute")
        body += """    if ((args->mode & 0111) == 0) {
        return NO_TRANSITION;
    }
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_fchmodat(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_fchmodat) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<FchmodAtData>(&event.args);
    if (!args) return NO_TRANSITION;
"""

    if "dfd" in t:
        body += f"""    if (args->dfd != {t["dfd"]}) {{
        return NO_TRANSITION;
    }}
"""

    if "pathname" in t:
        check_list = t["pathname"]

        body += "    auto pathname_path = get_absolute_path_at(event.pid, args->dfd, args->pathname);\n"
        body += "    if (!pathname_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            check_list,
            "(*pathname_path)",
            "pathname_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    if "mode_any" in t:
        mode_any = t["mode_any"]
        assert(mode_any == "execute")
        body += """    if ((args->mode & 0111) == 0) {
        return NO_TRANSITION;
    }
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_truncate(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_truncate) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<TruncateData>(&event.args);
    if (!args) return NO_TRANSITION;
"""

    if "pathname" in t:
        check_list = t["pathname"]

        body += "    auto pathname_path = get_absolute_path(event.pid, args->pathname);\n"
        body += "    if (!pathname_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            check_list,
            "(*pathname_path)",
            "pathname_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    if "length" in t:
        body += f"""    if (args->length != {t["length"]}L) {{
        return NO_TRANSITION;
    }}
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_ftruncate(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_ftruncate) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<FtruncateData>(&event.args);
    if (!args) return NO_TRANSITION;
"""

    if "pathname" in t:
        check_list = t["pathname"]

        body += "    auto pathname_path = get_fd_path(event.pid, args->fd);\n"
        body += "    if (!pathname_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            check_list,
            "(*pathname_path)",
            "pathname_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    if "length" in t:
        body += f"""    if (args->length != {t["length"]}L) {{
        return NO_TRANSITION;
    }}
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_linkat(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_linkat) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<LinkAtData>(&event.args);
    if (!args) return NO_TRANSITION;
"""

    if "oldfd" in t:
        body += f"""    if (args->oldfd != {t["oldfd"]}) {{
        return NO_TRANSITION;
    }}
"""

    if "newfd" in t:
        body += f"""    if (args->newfd != {t["newfd"]}) {{
        return NO_TRANSITION;
    }}
"""

    if "oldname" in t:
        check_list = t["oldname"]

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        skip_expr = gen_allow_deny_expr(
            check_list,
            "args->oldname",
            "oldname_path",
        )

        if any(condition_has_key(cond, "path_in") for cond in allow_conds + deny_conds):
            if "oldfd" in t and str(t["oldfd"]) != "AT_FDCWD":
                assert(False)
            if "oldfd" not in t:
                body += """    if (args->oldfd != AT_FDCWD) {
        return NO_TRANSITION;
    }
"""
            body += "    auto oldname_path = get_absolute_path(event.pid, args->oldname);\n"
            body += "\n"

        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    if "newname" in t:
        check_list = t["newname"]

        body += "    auto newname_path = get_absolute_path_at(event.pid, args->newfd, args->newname);\n"
        body += "    if (!newname_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            check_list,
            "(*newname_path)",
            "newname_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_symlinkat(function_name: str, t: dict):
    body = f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_symlinkat) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<SymlinkAtData>(&event.args);
    if (!args) return NO_TRANSITION;
"""

    if "newdfd" in t:
        body += f"""    if (args->newdfd != {t["newdfd"]}) {{
        return NO_TRANSITION;
    }}
"""

    if "oldname" in t:
        check_list = t["oldname"]

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        skip_expr = gen_allow_deny_expr(
            check_list,
            "args->oldname",
            "oldname_path",
        )

        if any(condition_has_key(cond, "path_in") for cond in allow_conds + deny_conds):
            if "newdfd" in t and str(t["newdfd"]) != "AT_FDCWD":
                assert(False)

            if "newdfd" not in t:
                body += """    if (args->newdfd != AT_FDCWD) {
        return NO_TRANSITION;
    }
"""
            body += """    std::optional<std::string> oldname_path;

    if (args->oldname.starts_with("/")) {
        oldname_path = fs::path(args->oldname).lexically_normal().string();
    } else {
        auto newname_path = get_absolute_path(event.pid, args->newname);

        if (!newname_path.has_value()) {
            return NO_TRANSITION;
        }

        std::string newname_dir = fs::path(*newname_path).parent_path().string();
        oldname_path = fs::path(newname_dir + "/" + args->oldname).lexically_normal().string();
    }

"""

        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    if "newname" in t:
        check_list = t["newname"]

        body += "    auto newname_path = get_absolute_path_at(event.pid, args->newdfd, args->newname);\n"
        body += "    if (!newname_path.has_value()) {\n"
        body += "        return NO_TRANSITION;\n"
        body += "    }\n"
        body += "\n"

        skip_expr = gen_allow_deny_expr(
            check_list,
            "(*newname_path)",
            "newname_path",
        )
        body += f"    if ({skip_expr}) {{\n"
        body += f"        return NO_TRANSITION;\n"
        body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_recursive_traversal(name: str, function_names: list[str], rule: dict):
    threshold = rule["threshold"]
    path_rule = rule.get("path", {})
    path_skip_expr = gen_path_skip_expr("absolute_path", path_rule)

    return f"""inline int {function_names[0]}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index == SYS_openat) {{
        if (!event.retval.has_value() || *event.retval < 0) {{
            return NO_TRANSITION;
        }}

        const auto* args = std::get_if<OpenAtData>(&event.args);
        if (!args) return NO_TRANSITION;

        auto absolute_path = get_absolute_path_at(event.pid, args->dirfd, args->pathname);
        if (!absolute_path.has_value()) {{
            return NO_TRANSITION;
        }}

        if ({path_skip_expr}) {{
            return NO_TRANSITION;
        }}

        if (!state.data.has_value()) {{
            state.data = RecursiveTraversalState {{}};
        }}

        auto* data = std::any_cast<RecursiveTraversalState>(&state.data);
        if (!data) {{
            return NO_TRANSITION;
        }}

        data->fd_paths[static_cast<unsigned int>(*event.retval)] = *absolute_path;

        return static_cast<int>(state.current_state_index);
    }}

    auto* data = std::any_cast<RecursiveTraversalState>(&state.data);
    if (!data) {{
        return NO_TRANSITION;
    }}

    if (event.syscall_index == SYS_close) {{
        if (!event.retval.has_value() || *event.retval != 0) {{
            return NO_TRANSITION;
        }}

        const auto* args = std::get_if<CloseData>(&event.args);
        if (!args) return NO_TRANSITION;

        data->fd_paths.erase(args->fd);

        return static_cast<int>(state.current_state_index);
    }}

    if (event.syscall_index != SYS_getdents64) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval <= 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<Getdents64Data>(&event.args);
    if (!args) return NO_TRANSITION;

    auto fd_it = data->fd_paths.find(args->fd);
    if (fd_it == data->fd_paths.end()) {{
        return NO_TRANSITION;
    }}

    auto dir_id = get_fd_identity(event.pid, args->fd);
    if (!dir_id.has_value()) {{
        return NO_TRANSITION;
    }}

    data->paths.insert(*dir_id);

    if (static_cast<long>(data->paths.size()) < {threshold}L) {{
        return static_cast<int>(state.current_state_index + 1);
    }}

    return static_cast<int>(state.current_state_index + 2);
}}

inline int {function_names[1]}(DetectionState& state, const SyscallEvent& event) {{
    auto* data = std::any_cast<RecursiveTraversalState>(&state.data);
    if (!data) {{
        return NO_TRANSITION;
    }}

    if (event.syscall_index == SYS_openat) {{
        if (!event.retval.has_value() || *event.retval < 0) {{
            return NO_TRANSITION;
        }}

        const auto* args = std::get_if<OpenAtData>(&event.args);
        if (!args) return NO_TRANSITION;

        auto absolute_path = get_absolute_path_at(event.pid, args->dirfd, args->pathname);
        if (!absolute_path.has_value()) {{
            return NO_TRANSITION;
        }}

        if ({path_skip_expr}) {{
            return NO_TRANSITION;
        }}

        data->fd_paths[static_cast<unsigned int>(*event.retval)] = *absolute_path;

        return static_cast<int>(state.current_state_index - 1);
    }}

    if (event.syscall_index == SYS_close) {{
        if (!event.retval.has_value() || *event.retval != 0) {{
            return NO_TRANSITION;
        }}

        const auto* args = std::get_if<CloseData>(&event.args);
        if (!args) return NO_TRANSITION;

        data->fd_paths.erase(args->fd);

        return static_cast<int>(state.current_state_index);
    }}

    if (event.syscall_index != SYS_getdents64) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval <= 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<Getdents64Data>(&event.args);
    if (!args) return NO_TRANSITION;

    auto fd_it = data->fd_paths.find(args->fd);
    if (fd_it == data->fd_paths.end()) {{
        return NO_TRANSITION;
    }}

    auto dir_id = get_fd_identity(event.pid, args->fd);
    if (!dir_id.has_value()) {{
        return NO_TRANSITION;
    }}

    data->paths.insert(*dir_id);

    if (static_cast<long>(data->paths.size()) < {threshold}L) {{
        return static_cast<int>(state.current_state_index);
    }}

    return static_cast<int>(state.current_state_index + 1);
}}
"""


def gen_path_openat_count(name: str, function_name: str, rule: dict):
    threshold = rule["threshold"]
    path_rule = rule.get("path", {})
    path_skip_expr = gen_path_skip_expr("absolute_path", path_rule)

    return f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_openat) {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval < 0) {{
        return NO_TRANSITION;
    }}

    const auto* args = std::get_if<OpenAtData>(&event.args);
    if (!args) return NO_TRANSITION;
    if ((args->flags & O_DIRECTORY) == O_DIRECTORY) {{
        return NO_TRANSITION;
    }}

    auto absolute_path = get_absolute_path_at(event.pid, args->dirfd, args->pathname);
    if (!absolute_path.has_value()) {{
        return NO_TRANSITION;
    }}

    if ({path_skip_expr}) {{
        return NO_TRANSITION;
    }}

    if (!state.data.has_value()) {{
        state.data = PathCountState {{}};
    }}

    auto* data = std::any_cast<PathCountState>(&state.data);
    if (!data) {{
        return NO_TRANSITION;
    }}

    data->paths.insert(*absolute_path);

    if (static_cast<long>(data->paths.size()) < {threshold}L) {{
        return static_cast<int>(state.current_state_index);
    }}

    return static_cast<int>(state.current_state_index + 1);
}}
"""


def gen_path_skip_expr(path_name: str, path_rule: dict):
    assert(isinstance(path_rule, dict))
    for key in path_rule.keys():
        assert(key == "allow" or key == "deny")

    allow_conds = path_rule.get("allow", [])
    deny_conds = path_rule.get("deny", [])
    assert(isinstance(allow_conds, list))
    assert(isinstance(deny_conds, list))

    allow_exprs = []
    for cond in allow_conds:
        allow_exprs.append(gen_string_match_cond(f"(*{path_name})", cond, path_name))

    deny_exprs = []
    for cond in deny_conds:
        deny_exprs.append(gen_string_match_cond(f"(*{path_name})", cond, path_name))

    if len(allow_exprs) == 0 and len(deny_exprs) == 0:
        return "false"

    allow_cond = " || ".join(allow_exprs)
    if len(allow_exprs) > 1:
        allow_cond = "(\n"
        for i, expr in enumerate(allow_exprs):
            suffix = " ||" if i + 1 < len(allow_exprs) else ""
            allow_cond += f"        {expr}{suffix}\n"
        allow_cond += "    )"

    deny_cond = " || ".join(deny_exprs)
    if len(deny_exprs) > 1:
        deny_cond = "(\n"
        for i, expr in enumerate(deny_exprs):
            suffix = " ||" if i + 1 < len(deny_exprs) else ""
            deny_cond += f"        {expr}{suffix}\n"
        deny_cond += "    )"
    if len(allow_exprs) > 0 and len(deny_exprs) > 0:
        return f"(({allow_cond}) || !({deny_cond}))"
    if len(allow_exprs) > 0:
        return allow_cond
    return f"!({deny_cond})"


def gen_allow_path_expr(path_name: str, path_rule: dict):
    assert(isinstance(path_rule, dict))
    for key in path_rule.keys():
        assert(key == "allow" or key == "deny")

    allow_conds = path_rule.get("allow", [])
    deny_conds = path_rule.get("deny", [])
    assert(isinstance(allow_conds, list))
    assert(isinstance(deny_conds, list))
    assert(len(allow_conds) > 0 or len(deny_conds) > 0)

    allow_exprs = []
    for cond in allow_conds:
        allow_exprs.append(gen_string_match_cond(f"(*{path_name})", cond, path_name))

    deny_exprs = []
    for cond in deny_conds:
        deny_exprs.append(gen_string_match_cond(f"(*{path_name})", cond, path_name))

    cond_allow = " || ".join(allow_exprs)
    if len(allow_exprs) > 1:
        cond_allow = "(\n"
        for i, expr in enumerate(allow_exprs):
            suffix = " ||" if i + 1 < len(allow_exprs) else ""
            cond_allow += f"        {expr}{suffix}\n"
        cond_allow += "    )"

    cond_deny = " || ".join(deny_exprs)
    if len(deny_exprs) > 1:
        cond_deny = "(\n"
        for i, expr in enumerate(deny_exprs):
            suffix = " ||" if i + 1 < len(deny_exprs) else ""
            cond_deny += f"        {expr}{suffix}\n"
        cond_deny += "    )"
    if len(allow_conds) > 0 and len(deny_conds) > 0:
        return f"(({cond_allow}) || !({cond_deny}))"
    if len(allow_conds) > 0:
        return cond_allow
    return f"!({cond_deny})"


def gen_exec_argv_setup(command_paths: list[str]):
    assert(len(command_paths) > 0)
    command_cond = " || ".join([f"*exec_path == \"{path}\"" for path in command_paths])
    return f"""    std::optional<std::string> exec_path;
    std::vector<std::string> argv;

    if (event.syscall_index == SYS_execve) {{
        const auto* args = std::get_if<ExecveData>(&event.args);
        if (!args) return NO_TRANSITION;
        exec_path = get_execve_path(event.pid, args->filename);
        argv = args->argv;
    }} else {{
        return NO_TRANSITION;
    }}

    if (!event.retval.has_value() || *event.retval != 0 || !exec_path.has_value()) {{
        return NO_TRANSITION;
    }}

    if (!({command_cond})) {{
        return NO_TRANSITION;
    }}

"""


def gen_cp_path_policy(function_name: str, rule: dict):
    source_allow = gen_allow_path_expr("source_path", rule["source"])
    destination_allow = gen_allow_path_expr("destination_path", rule["destination"])

    return f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
{gen_exec_argv_setup(["/bin/cp", "/usr/bin/cp"])}    std::vector<std::string> paths;
    std::optional<std::string> target_directory;
    bool end_options = false;

    for (size_t i = 1; i < argv.size(); i++) {{
        const auto& arg = argv[i];
        if (arg.empty() || arg == "-") {{
            continue;
        }}
        if (!end_options && (arg == "--help" || arg == "--version")) {{
            return NO_TRANSITION;
        }}
        if (!end_options && arg == "--") {{
            end_options = true;
            continue;
        }}
        if (!end_options && arg.starts_with("--target-directory=")) {{
            target_directory = arg.substr(19);
            continue;
        }}
        if (!end_options && arg == "--target-directory") {{
            if (i + 1 >= argv.size()) return NO_TRANSITION;
            target_directory = argv[++i];
            continue;
        }}
        if (!end_options && arg.starts_with("-t") && arg.size() > 2) {{
            target_directory = arg.substr(2);
            continue;
        }}
        if (!end_options && arg == "-t") {{
            if (i + 1 >= argv.size()) return NO_TRANSITION;
            target_directory = argv[++i];
            continue;
        }}
        if (!end_options && (arg == "-S" || arg == "--suffix")) {{
            if (i + 1 >= argv.size()) return NO_TRANSITION;
            i++;
            continue;
        }}
        if (!end_options && (
            arg.starts_with("--suffix=") ||
            arg.starts_with("--sparse=") ||
            arg.starts_with("--no-preserve=") ||
            arg.starts_with("--backup=") ||
            arg.starts_with("--preserve=") ||
            arg.starts_with("--reflink=") ||
            arg.starts_with("--update=") ||
            arg.starts_with("--context=") ||
            arg.starts_with("-S")
        )) {{
            continue;
        }}
        if (!end_options && arg.starts_with("-")) {{
            continue;
        }}
        paths.push_back(arg);
    }}

    std::vector<std::string> sources;
    std::optional<std::string> destination;
    if (target_directory.has_value()) {{
        if (paths.empty()) return NO_TRANSITION;
        sources = paths;
        destination = *target_directory;
    }} else {{
        if (paths.size() < 2) return NO_TRANSITION;
        sources.assign(paths.begin(), paths.end() - 1);
        destination = paths.back();
    }}

    for (const auto& source : sources) {{
        auto source_path = get_execve_path(event.pid, source);
        if (!source_path.has_value()) {{
            return NO_TRANSITION;
        }}
        if (!({source_allow})) {{
            return static_cast<int>(state.current_state_index + 1);
        }}
    }}

    auto destination_path = get_execve_path(event.pid, *destination);
    if (!destination_path.has_value()) {{
        return NO_TRANSITION;
    }}
    if (!({destination_allow})) {{
        return static_cast<int>(state.current_state_index + 1);
    }}

    return NO_TRANSITION;
}}
"""


def gen_zip_path_policy(function_name: str, rule: dict):
    archive_allow = gen_allow_path_expr("archive_path", rule["archive"])
    input_allow = gen_allow_path_expr("input_path", rule["input"])

    return f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
{gen_exec_argv_setup(["/bin/zip", "/usr/bin/zip"])}    std::vector<std::string> paths;
    bool end_options = false;

    for (size_t i = 1; i < argv.size(); i++) {{
        const auto& arg = argv[i];
        if (arg.empty()) {{
            continue;
        }}
        if (!end_options && arg == "--") {{
            end_options = true;
            continue;
        }}
        if (!end_options && (arg == "--help" || arg == "--version")) {{
            return NO_TRANSITION;
        }}
        if (!end_options && (arg == "-b" || arg == "-t" || arg == "-n")) {{
            if (i + 1 >= argv.size()) return NO_TRANSITION;
            i++;
            continue;
        }}
        if (!end_options && (arg == "-x" || arg == "-i")) {{
            i++;
            while (i < argv.size() && !argv[i].starts_with("-")) {{
                i++;
            }}
            i--;
            continue;
        }}
        if (!end_options && arg.starts_with("-")) {{
            continue;
        }}
        if (arg != "-") {{
            paths.push_back(arg);
        }}
    }}

    if (paths.size() < 2) {{
        return NO_TRANSITION;
    }}

    auto archive_path = get_execve_path(event.pid, paths[0]);
    if (!archive_path.has_value()) {{
        return NO_TRANSITION;
    }}
    if (!({archive_allow})) {{
        return static_cast<int>(state.current_state_index + 1);
    }}

    for (size_t i = 1; i < paths.size(); i++) {{
        auto input_path = get_execve_path(event.pid, paths[i]);
        if (!input_path.has_value()) {{
            return NO_TRANSITION;
        }}
        if (!({input_allow})) {{
            return static_cast<int>(state.current_state_index + 1);
        }}
    }}

    return NO_TRANSITION;
}}
"""


def gen_tar_path_policy(function_name: str, rule: dict):
    archive_allow = gen_allow_path_expr("archive_path", rule["archive"])
    input_allow = gen_allow_path_expr("input_path", rule["input"])

    return f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
{gen_exec_argv_setup(["/bin/tar", "/usr/bin/tar"])}    std::optional<std::string> archive;
    std::optional<std::string> current_directory;
    std::vector<std::string> inputs;
    std::vector<std::optional<std::string>> input_directories;
    bool create = false;
    bool end_options = false;

    auto set_directory = [&](const std::string& dir) {{
        if (dir.starts_with("/") || !current_directory.has_value()) {{
            current_directory = dir;
        }} else {{
            current_directory = *current_directory + "/" + dir;
        }}
    }};

    for (size_t i = 1; i < argv.size(); i++) {{
        const auto& arg = argv[i];
        if (arg.empty()) {{
            continue;
        }}
        if (!end_options && arg == "--") {{
            end_options = true;
            continue;
        }}
        if (!end_options && (arg == "--help" || arg == "--version")) {{
            return NO_TRANSITION;
        }}
        if (!end_options && arg == "--create") {{
            create = true;
            continue;
        }}
        if (!end_options && (
            arg.starts_with("--file=") ||
            arg.starts_with("--directory=") ||
            arg == "--file" ||
            arg == "--directory"
        )) {{
            bool file_option = arg.starts_with("--file");
            std::string value;
            if (arg == "--file" || arg == "--directory") {{
                if (i + 1 >= argv.size()) return NO_TRANSITION;
                value = argv[++i];
            }} else if (file_option) {{
                value = arg.substr(7);
            }} else {{
                value = arg.substr(12);
            }}

            if (file_option) {{
                archive = value;
            }} else {{
                set_directory(value);
            }}
            continue;
        }}
        if (!end_options && (
            arg == "--exclude" ||
            arg == "--transform" ||
            arg == "--xform" ||
            arg == "--use-compress-program" ||
            arg == "--files-from"
        )) {{
            if (i + 1 >= argv.size()) return NO_TRANSITION;
            i++;
            continue;
        }}
        if (!end_options && (
            arg.starts_with("--exclude=") ||
            arg.starts_with("--transform=") ||
            arg.starts_with("--xform=") ||
            arg.starts_with("--use-compress-program=") ||
            arg.starts_with("--files-from=")
        )) {{
            continue;
        }}
        if (!end_options && arg.starts_with("--")) {{
            continue;
        }}
        if (!end_options && ((arg.starts_with("-") && arg.size() > 1) || i == 1)) {{
            bool old_style_options = !arg.starts_with("-");
            size_t j = old_style_options ? 0 : 1;
            for (; j < arg.size(); j++) {{
                char opt = arg[j];
                if (opt == 'c') {{
                    create = true;
                    continue;
                }}
                if (opt == 'f') {{
                    if (!old_style_options && j + 1 < arg.size()) {{
                        archive = arg.substr(j + 1);
                    }} else {{
                        if (i + 1 >= argv.size()) return NO_TRANSITION;
                        archive = argv[++i];
                    }}
                    break;
                }}
                if (opt == 'C') {{
                    if (!old_style_options && j + 1 < arg.size()) {{
                        set_directory(arg.substr(j + 1));
                    }} else {{
                        if (i + 1 >= argv.size()) return NO_TRANSITION;
                        set_directory(argv[++i]);
                    }}
                    break;
                }}
                if (!old_style_options && (opt == 'T' || opt == 'X' || opt == 'I')) {{
                    if (j + 1 >= arg.size()) {{
                        if (i + 1 >= argv.size()) return NO_TRANSITION;
                        i++;
                    }}
                    break;
                }}
            }}
            continue;
        }}
        inputs.push_back(arg);
        input_directories.push_back(current_directory);
    }}

    if (!create || !archive.has_value() || inputs.empty()) {{
        return NO_TRANSITION;
    }}

    auto archive_path = get_execve_path(event.pid, *archive);
    if (!archive_path.has_value()) {{
        return NO_TRANSITION;
    }}
    if (!({archive_allow})) {{
        return static_cast<int>(state.current_state_index + 1);
    }}

    for (size_t i = 0; i < inputs.size(); i++) {{
        std::optional<std::string> input_path;
        if (inputs[i].starts_with("/") || !input_directories[i].has_value()) {{
            input_path = get_execve_path(event.pid, inputs[i]);
        }} else {{
            auto directory_path = get_execve_path(event.pid, *input_directories[i]);
            if (!directory_path.has_value()) {{
                return NO_TRANSITION;
            }}
            input_path = get_execve_path(event.pid, *directory_path + "/" + inputs[i]);
        }}
        if (!input_path.has_value()) {{
            return NO_TRANSITION;
        }}
        if (!({input_allow})) {{
            return static_cast<int>(state.current_state_index + 1);
        }}
    }}

    return NO_TRANSITION;
}}
"""


syscall_generators = {
    "execve": gen_execve,
    "openat": gen_openat,
    "connect": gen_connect,
    "unlinkat": gen_unlinkat,
    "rename": gen_rename,
    "renameat": gen_renameat,
    "renameat2": gen_renameat2,
    "chmod": gen_chmod,
    "fchmodat": gen_fchmodat,
    "truncate": gen_truncate,
    "ftruncate": gen_ftruncate,
    "linkat": gen_linkat,
    "symlinkat": gen_symlinkat,
}


def gen_transition(function_name: str, t: dict):
    syscall = t["syscall"]
    if isinstance(syscall, list):
        body = ""
        function_names = []
        for s in syscall:
            assert(isinstance(s, str))
            sub_function_name = f"{function_name}_{s}"
            sub_t = dict(t)
            sub_t["syscall"] = s
            body += gen_transition(sub_function_name, sub_t)
            body += "\n"
            function_names.append(sub_function_name)

        body += f"""inline int {function_name}(DetectionState& state, const SyscallEvent& event) {{
    int ret = NO_TRANSITION;
"""
        for sub_function_name in function_names:
            body += f"""    ret = {sub_function_name}(state, event);
    if (ret != NO_TRANSITION) {{
        return ret;
    }}
"""
        body += "    return NO_TRANSITION;\n"
        body += "}\n"
        return body

    if syscall in syscall_generators:
        return syscall_generators[syscall](function_name, t)

    assert(False)


def gen_rule_def(name: str, timeout: int, function_names: list[str], cooldown = None, single_active: bool = False):
    functions = ",\n        ".join([
        f"detection_rules::{f_name}" for f_name in function_names 
    ])

    body = f"""engine.add_rule((DetectionRule) {{
    .name = "{name}",
    .timeout_ns = {timeout}L,
"""

    if cooldown is not None:
        body += f"    .cooldown_ns = {cooldown}L,\n"

    body += f"""    .transitions = {{
        {functions}
    }},
"""

    if single_active:
        body += "    .single_active_per_pid = true,\n"

    body += "});\n    "

    return body

def gen_allow_execve_paths(paths: list[str]):
    body = ""
    for path in paths:
        assert(isinstance(path, str))
        path = expand_home_path(path)
        body += f"engine.add_allow_execve_path(\"{path}\");\n"
    return body

if __name__ == "__main__":
    import sys
    from pathlib import Path
    import yaml

    if len(sys.argv) < 2:
        print(f"usage: python {sys.argv[0]} <rule_file_path>")
        exit(1)
    
    rule_file_paths = sys.argv[1:]

    rules: list = []

    for path in rule_file_paths:
        data: dict
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        rules.extend(data["rules"])

    # rules = data["rules"]
    allow_execve_paths = []
    if "allow" in data: 
        allow_execve_paths = data["allow"]
    print(allow_execve_paths)

    check_name = {}

    is_func_body = ""
    rule_def_body = ""

    for rule in rules:
        name = rule["name"]
        timeout = rule["timeout_ns"]
        if name in check_name:
            print("error - ")
            exit(1)

        if rule.get("type") == "recursive_traversal":
            function_names = [f"step_{name}_0", f"step_{name}_1"]
            is_func_body += gen_recursive_traversal(name, function_names, rule)
            is_func_body += "\n"
            window_ns = rule.get("window_ns", 1000000000)
            cooldown_ns = rule.get("cooldown_ns", 5000000000)
            rule_def_body += gen_rule_def(name, window_ns, function_names, cooldown_ns, True) + "\n"
            continue

        if rule.get("type") == "path_openat_count":
            function_names = [f"step_{name}_0"]
            is_func_body += gen_path_openat_count(name, function_names[0], rule)
            is_func_body += "\n"
            window_ns = rule.get("window_ns", 1000000000)
            cooldown_ns = rule.get("cooldown_ns", 5000000000)
            rule_def_body += gen_rule_def(name, window_ns, function_names, cooldown_ns, True) + "\n"
            continue

        if rule.get("type") == "cp_path_policy":
            function_names = [f"step_{name}_0"]
            is_func_body += gen_cp_path_policy(function_names[0], rule)
            is_func_body += "\n"
            rule_def_body += gen_rule_def(name, timeout, function_names) + "\n"
            continue

        if rule.get("type") == "zip_path_policy":
            function_names = [f"step_{name}_0"]
            is_func_body += gen_zip_path_policy(function_names[0], rule)
            is_func_body += "\n"
            rule_def_body += gen_rule_def(name, timeout, function_names) + "\n"
            continue

        if rule.get("type") == "tar_path_policy":
            function_names = [f"step_{name}_0"]
            is_func_body += gen_tar_path_policy(function_names[0], rule)
            is_func_body += "\n"
            rule_def_body += gen_rule_def(name, timeout, function_names) + "\n"
            continue
        
        print(name)
        transitions = rule["transitions"]
        
        function_names = []

        for i, t in enumerate(transitions):
            function_name = f"step_{name}_{i}"
            function_names.append(function_name)

            is_func_body += gen_transition(function_name, t)
            is_func_body += "\n"
        
        rule_def_body += gen_rule_def(name, timeout, function_names) + "\n"

    a = "\n".join(["    " + l for l in gen_allow_execve_paths(allow_execve_paths).splitlines()])
    b = "\n".join(["    " + l for l in rule_def_body.splitlines()])

    body = codegen_rules_h_template.replace("[IS_FUNCTION_BODY]", is_func_body).replace("[ALLOW_DEF_GEN_BODY]", a).replace("[RULE_DEF_GEN_BODY]", b)

    with open("src/codegen_rules.h", "w") as f:
        f.write(body)
