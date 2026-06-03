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

codegen_rules_h_template = f"""#include <fcntl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unordered_map>
#include "engine.h"
#include "helpers.h"

namespace detection_rules {{

using namespace engine;

int step_recursive_traversal_1(engine::DetectionState& state, const engine::SyscallEvent& event);
int step_recursive_traversal_2(engine::DetectionState& state, const engine::SyscallEvent& event);

inline bool is_path_in(const std::optional<std::string>& absolute_path, pid_t pid, const std::string& path) {{
    if (!absolute_path.has_value()) {{
        return false;
    }}

    auto path_in = get_absolute_path(pid, path);
    if (!path_in.has_value()) {{
        return false;
    }}

    if (path.ends_with("/")) {{
        return absolute_path->starts_with(*path_in);
    }}
    return *absolute_path == *path_in;
}}

[RECURSIVE_TRAVERSAL_CONFIG]

[IS_FUNCTION_BODY]

inline void register_codegen_rules(engine::Engine& engine) {{
[ALLOW_DEF_GEN_BODY]
[RULE_DEF_GEN_BODY]
}}
}}"""


def gen_execve(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
        return -1;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return -1;
    }}

    const auto* args = std::get_if<ExecveData>(&event.args);
    if (!args) return -1;

"""

    if "filename" in t and len(t["filename"]) > 0:
        check_list = t["filename"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        if any(condition_has_key(cond, "path_in") for cond in allow_conds + deny_conds):
            body += "    auto filename_path = get_absolute_path(event.pid, args->filename);\n"
            body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("args->filename", cond, "filename_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("args->filename", cond, "filename_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    if "argv" in t and len(t["argv"]) > 0:
        argv = t["argv"]
        assert(isinstance(argv, dict))

        for index in argv.keys():
            assert(isinstance(index, int))
            assert(index >= 0)

        max_index = max(argv.keys())
        body += f"""    if (args->argv.size() < {max_index + 1}) {{
        return -1;
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
            body += f"        return -1;\n"
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
        return -1;
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
        return -1;
    }}
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_openat(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_openat) {{
        return -1;
    }}

    const auto* args = std::get_if<OpenAtData>(&event.args);
    if (!args) return -1;
    if (!event.retval.has_value() || *event.retval < 0) {{
        return -1;
    }}
"""

    if "dirfd" in t:
        body += f"""    if (args->dirfd != {t["dirfd"]}) {{
        return -1;
    }}
"""

    if "relative" in t:
        assert(isinstance(t["relative"], bool))
        if t["relative"]:
            body += """    if (args->pathname.starts_with("/")) {
        return -1;
    }
"""
        else:
            body += """    if (!args->pathname.starts_with("/")) {
        return -1;
    }
"""

    if "pathname" in t:
        check_list = t["pathname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        body += """    auto absolute_path = get_absolute_path_at(event.pid, args->dirfd, args->pathname);
    if (!absolute_path.has_value()) {
        return -1;
    }
"""
        body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("(*absolute_path)", cond, "absolute_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("(*absolute_path)", cond, "absolute_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    if "access_mode" in t:
        access_mode = t["access_mode"]
        assert(access_mode == "read" or access_mode == "write" or access_mode == "readonly")
        if access_mode == "read":
            body += """    if ((args->flags & O_ACCMODE) == O_WRONLY) {
        return -1;
    }
"""
        elif access_mode == "write":
            body += """    int access_mode = args->flags & O_ACCMODE;
    if (access_mode != O_WRONLY && access_mode != O_RDWR) {
        return -1;
    }
"""
        else:
            body += """    if ((args->flags & O_ACCMODE) != O_RDONLY) {
        return -1;
    }
"""

    if "flags" in t:
        flags = t["flags"] # expected: ["O_RDONLY", "...", ...]
        # if "O_RDONLY" in flags:
        for flag in flags:
            body += f"""    if (!((args->flags & {flag}) == {flag})) {{
        return -1;
    }}
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_connect(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_connect) {{
        return -1;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return -1;
    }}

    const auto* args = std::get_if<ConnectData>(&event.args);
    if (!args) return -1;
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
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(deny_conds) > 0:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_unlinkat(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_unlinkat) {{
        return -1;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return -1;
    }}

    const auto* args = std::get_if<UnlinkAtData>(&event.args);
    if (!args) return -1;
"""

    if "dfd" in t:
        body += f"""    if (args->dfd != {t["dfd"]}) {{
        return -1;
    }}
"""

    if "pathname" in t:
        check_list = t["pathname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        if any(condition_has_key(cond, "path_in") for cond in allow_conds + deny_conds):
            body += "    auto absolute_path = get_absolute_path_at(event.pid, args->dfd, args->pathname);\n"
            body += "    if (!absolute_path.has_value()) {\n"
            body += "        return -1;\n"
            body += "    }\n"
            body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("args->pathname", cond, "absolute_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("args->pathname", cond, "absolute_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_renameat2(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_renameat2) {{
        return -1;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return -1;
    }}

    const auto* args = std::get_if<RenameAt2Data>(&event.args);
    if (!args) return -1;
"""

    if "oldname" in t:
        oldname_rule = t["oldname"]
        assert(isinstance(oldname_rule, dict))

        has_allow = "allow" in oldname_rule
        has_deny = "deny" in oldname_rule
        assert(has_allow or has_deny)
        for key in oldname_rule.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = oldname_rule.get("allow", [])
        deny_conds = oldname_rule.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        if any(condition_has_key(cond, "path_in") for cond in allow_conds + deny_conds):
            body += "    auto oldname_path = get_absolute_path_at(event.pid, args->oldfd, args->oldname);\n"
            body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("args->oldname", cond, "oldname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("args->oldname", cond, "oldname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    if "newname" in t:
        newname_rule = t["newname"]
        assert(isinstance(newname_rule, dict))

        has_allow = "allow" in newname_rule
        has_deny = "deny" in newname_rule
        assert(has_allow or has_deny)
        for key in newname_rule.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = newname_rule.get("allow", [])
        deny_conds = newname_rule.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        body += "    auto newname_path = get_absolute_path_at(event.pid, args->newfd, args->newname);\n"
        body += "    if (!newname_path.has_value()) {\n"
        body += "        return -1;\n"
        body += "    }\n"
        body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("(*newname_path)", cond, "newname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("(*newname_path)", cond, "newname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_rename(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_rename) {{
        return -1;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return -1;
    }}

    const auto* args = std::get_if<RenameData>(&event.args);
    if (!args) return -1;
"""

    if "oldname" in t:
        check_list = t["oldname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        body += "    auto oldname_path = get_absolute_path(event.pid, args->oldname);\n"
        body += "    if (!oldname_path.has_value()) {\n"
        body += "        return -1;\n"
        body += "    }\n"
        body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("(*oldname_path)", cond, "oldname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("(*oldname_path)", cond, "oldname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    if "newname" in t:
        check_list = t["newname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        body += "    auto newname_path = get_absolute_path(event.pid, args->newname);\n"
        body += "    if (!newname_path.has_value()) {\n"
        body += "        return -1;\n"
        body += "    }\n"
        body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("(*newname_path)", cond, "newname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("(*newname_path)", cond, "newname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_renameat(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_renameat) {{
        return -1;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return -1;
    }}

    const auto* args = std::get_if<RenameAtData>(&event.args);
    if (!args) return -1;
"""

    if "oldfd" in t:
        body += f"""    if (args->oldfd != {t["oldfd"]}) {{
        return -1;
    }}
"""

    if "newfd" in t:
        body += f"""    if (args->newfd != {t["newfd"]}) {{
        return -1;
    }}
"""

    if "oldname" in t:
        check_list = t["oldname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        body += "    auto oldname_path = get_absolute_path_at(event.pid, args->oldfd, args->oldname);\n"
        body += "    if (!oldname_path.has_value()) {\n"
        body += "        return -1;\n"
        body += "    }\n"
        body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("(*oldname_path)", cond, "oldname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("(*oldname_path)", cond, "oldname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    if "newname" in t:
        check_list = t["newname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        body += "    auto newname_path = get_absolute_path_at(event.pid, args->newfd, args->newname);\n"
        body += "    if (!newname_path.has_value()) {\n"
        body += "        return -1;\n"
        body += "    }\n"
        body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("(*newname_path)", cond, "newname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("(*newname_path)", cond, "newname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_chmod(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_chmod) {{
        return -1;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return -1;
    }}

    const auto* args = std::get_if<ChmodData>(&event.args);
    if (!args) return -1;
"""

    if "pathname" in t:
        check_list = t["pathname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        body += "    auto pathname_path = get_absolute_path(event.pid, args->pathname);\n"
        body += "    if (!pathname_path.has_value()) {\n"
        body += "        return -1;\n"
        body += "    }\n"
        body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("(*pathname_path)", cond, "pathname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("(*pathname_path)", cond, "pathname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    if "mode_any" in t:
        mode_any = t["mode_any"]
        assert(mode_any == "execute")
        body += """    if ((args->mode & 0111) == 0) {
        return -1;
    }
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_fchmodat(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_fchmodat) {{
        return -1;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return -1;
    }}

    const auto* args = std::get_if<FchmodAtData>(&event.args);
    if (!args) return -1;
"""

    if "dfd" in t:
        body += f"""    if (args->dfd != {t["dfd"]}) {{
        return -1;
    }}
"""

    if "pathname" in t:
        check_list = t["pathname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        body += "    auto pathname_path = get_absolute_path_at(event.pid, args->dfd, args->pathname);\n"
        body += "    if (!pathname_path.has_value()) {\n"
        body += "        return -1;\n"
        body += "    }\n"
        body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("(*pathname_path)", cond, "pathname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("(*pathname_path)", cond, "pathname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    if "mode_any" in t:
        mode_any = t["mode_any"]
        assert(mode_any == "execute")
        body += """    if ((args->mode & 0111) == 0) {
        return -1;
    }
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_truncate(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_truncate) {{
        return -1;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return -1;
    }}

    const auto* args = std::get_if<TruncateData>(&event.args);
    if (!args) return -1;
"""

    if "pathname" in t:
        check_list = t["pathname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        body += "    auto pathname_path = get_absolute_path(event.pid, args->pathname);\n"
        body += "    if (!pathname_path.has_value()) {\n"
        body += "        return -1;\n"
        body += "    }\n"
        body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("(*pathname_path)", cond, "pathname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("(*pathname_path)", cond, "pathname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    if "length" in t:
        body += f"""    if (args->length != {t["length"]}L) {{
        return -1;
    }}
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body


def gen_ftruncate(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_ftruncate) {{
        return -1;
    }}

    if (!event.retval.has_value() || *event.retval != 0) {{
        return -1;
    }}

    const auto* args = std::get_if<FtruncateData>(&event.args);
    if (!args) return -1;
"""

    if "pathname" in t:
        check_list = t["pathname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        body += "    auto pathname_path = get_fd_path(event.pid, args->fd);\n"
        body += "    if (!pathname_path.has_value()) {\n"
        body += "        return -1;\n"
        body += "    }\n"
        body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("(*pathname_path)", cond, "pathname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("(*pathname_path)", cond, "pathname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    if "length" in t:
        body += f"""    if (args->length != {t["length"]}L) {{
        return -1;
    }}
"""

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_linkat(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_linkat) {{
        return -1;
    }}

    const auto* args = std::get_if<LinkAtData>(&event.args);
    if (!args) return -1;
"""

    if "oldfd" in t:
        body += f"""    if (args->oldfd != {t["oldfd"]}) {{
        return -1;
    }}
"""

    if "oldname" in t:
        check_list = t["oldname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        if any(condition_has_key(cond, "path_in") for cond in allow_conds + deny_conds):
            if "oldfd" in t and str(t["oldfd"]) != "AT_FDCWD":
                assert(False)
            if "oldfd" not in t:
                body += """    if (args->oldfd != AT_FDCWD) {
        return -1;
    }
"""
            body += "    auto oldname_path = get_absolute_path(event.pid, args->oldname);\n"
            body += "\n"

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("args->oldname", cond, "oldname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("args->oldname", cond, "oldname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_symlinkat(function_name: str, t: dict):
    body = f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_symlinkat) {{
        return -1;
    }}

    const auto* args = std::get_if<SymlinkAtData>(&event.args);
    if (!args) return -1;
"""

    if "newdfd" in t:
        body += f"""    if (args->newdfd != {t["newdfd"]}) {{
        return -1;
    }}
"""

    if "oldname" in t:
        check_list = t["oldname"]
        assert(isinstance(check_list, dict))

        has_allow = "allow" in check_list
        has_deny = "deny" in check_list
        assert(has_allow or has_deny)
        for key in check_list.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = check_list.get("allow", [])
        deny_conds = check_list.get("deny", [])
        assert(len(allow_conds) > 0 or len(deny_conds) > 0)

        if any(condition_has_key(cond, "path_in") for cond in allow_conds + deny_conds):
            if "newdfd" in t and str(t["newdfd"]) != "AT_FDCWD":
                assert(False)

            if "newdfd" not in t:
                body += """    if (args->newdfd != AT_FDCWD) {
        return -1;
    }
"""
            body += """    std::optional<std::string> oldname_path;

    if (args->oldname.starts_with("/")) {
        oldname_path = fs::path(args->oldname).lexically_normal().string();
    } else {
        auto newname_path = get_absolute_path(event.pid, args->newname);

        if (!newname_path.has_value()) {
            return -1;
        }

        std::string newname_dir = fs::path(*newname_path).parent_path().string();
        oldname_path = fs::path(newname_dir + "/" + args->oldname).lexically_normal().string();
    }

"""

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("args->oldname", cond, "oldname_path"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("args->oldname", cond, "oldname_path"))

        cond_allow = " || ".join(allow_exprs)
        cond_deny = " || ".join(deny_exprs)

        if len(allow_conds) > 0 and len(deny_conds) > 0:
            body += f"    if (({cond_allow}) || !({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return -1;\n"
            body += f"    }}\n"

    body += "    return static_cast<int>(state.current_state_index + 1);\n"
    body += "}\n"

    return body

def gen_recursive_traversal_config(rule: dict | None):
    threshold = 0
    allow_cond = "false"
    deny_cond = "true"

    if rule is not None:
        threshold = rule["threshold"]
        path_rule = rule.get("path", {})
        assert(isinstance(path_rule, dict))

        for key in path_rule.keys():
            assert(key == "allow" or key == "deny")

        allow_conds = path_rule.get("allow", [])
        deny_conds = path_rule.get("deny", [])
        assert(isinstance(allow_conds, list))
        assert(isinstance(deny_conds, list))

        allow_exprs = []
        for cond in allow_conds:
            allow_exprs.append(gen_string_match_cond("(*absolute_path)", cond, "absolute_path", "pid"))

        deny_exprs = []
        for cond in deny_conds:
            deny_exprs.append(gen_string_match_cond("(*absolute_path)", cond, "absolute_path", "pid"))

        if len(allow_exprs) > 0:
            allow_cond = " || ".join(allow_exprs)
        if len(deny_exprs) > 0:
            deny_cond = " || ".join(deny_exprs)

    return f"""inline const long recursive_traversal_threshold = {threshold}L;

inline bool is_recursive_traversal_allow_path(const std::optional<std::string>& absolute_path, pid_t pid) {{
    if (!absolute_path.has_value()) {{
        return false;
    }}

    return {allow_cond};
}}

inline bool is_recursive_traversal_deny_path(const std::optional<std::string>& absolute_path, pid_t pid) {{
    if (!absolute_path.has_value()) {{
        return false;
    }}

    return {deny_cond};
}}
"""


def gen_path_openat_count(function_name: str, rule: dict):
    threshold = rule["threshold"]
    path_rule = rule.get("path", {})
    assert(isinstance(path_rule, dict))

    for key in path_rule.keys():
        assert(key == "allow" or key == "deny")

    allow_conds = path_rule.get("allow", [])
    deny_conds = path_rule.get("deny", [])
    assert(isinstance(allow_conds, list))
    assert(isinstance(deny_conds, list))

    allow_exprs = []
    for cond in allow_conds:
        allow_exprs.append(gen_string_match_cond("(*absolute_path)", cond, "absolute_path"))

    deny_exprs = []
    for cond in deny_conds:
        deny_exprs.append(gen_string_match_cond("(*absolute_path)", cond, "absolute_path"))

    allow_cond = "false"
    deny_cond = "true"
    if len(allow_exprs) > 0:
        allow_cond = " || ".join(allow_exprs)
    if len(deny_exprs) > 0:
        deny_cond = " || ".join(deny_exprs)

    return f"""inline int {function_name}(Context& ctx, DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_openat) {{
        return -1;
    }}

    if (!event.retval.has_value() || *event.retval < 0) {{
        return -1;
    }}

    const auto* args = std::get_if<OpenAtData>(&event.args);
    if (!args) return -1;

    auto absolute_path = get_absolute_path_at(event.pid, args->dirfd, args->pathname);
    if (!absolute_path.has_value()) {{
        return -1;
    }}

    if ({allow_cond}) {{
        return -1;
    }}

    if (!({deny_cond})) {{
        return -1;
    }}

    static std::unordered_map<pid_t, long> counts;
    long& count = counts[event.pid];
    count += 1;

    if (count < {threshold}) {{
        return -1;
    }}

    count = 0;
    return static_cast<int>(state.current_state_index + 1);
}}
"""


def gen_rule_def(name: str, timeout: int, function_names: list[str]):
    functions = ",\n        ".join([
        f"detection_rules::{f_name}" for f_name in function_names 
    ])
    body = f"""engine.add_rule((DetectionRule) {{
    .name = "{name}",
    .timeout_ns = {timeout}L,
    .transitions = {{
        {functions}
    }},
}});
    """

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
    recursive_traversal_rule = None

    for rule in rules:
        name = rule["name"]
        timeout = rule["timeout_ns"]
        if name in check_name:
            print("error - ")
            exit(1)

        if name == "recursive_traversal":
            recursive_traversal_rule = rule
            rule_def_body += gen_rule_def(name, timeout, [
                "step_recursive_traversal_1",
                "step_recursive_traversal_2"
            ]) + "\n"
            continue

        if name == "path_openat_count":
            function_names = [f"step_{name}_0"]
            is_func_body += gen_path_openat_count(function_names[0], rule)
            is_func_body += "\n"
            rule_def_body += gen_rule_def(name, timeout, function_names) + "\n"
            continue

        transitions = rule["transitions"]
        
        function_names = []

        for i, t in enumerate(transitions):
            function_name = f"step_{name}_{i}"
            function_names.append(function_name)

            if t["syscall"] == "execve":
                is_func_body += gen_execve(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "openat":
                is_func_body += gen_openat(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "connect":
                is_func_body += gen_connect(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "unlinkat":
                is_func_body += gen_unlinkat(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "rename":
                is_func_body += gen_rename(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "renameat":
                is_func_body += gen_renameat(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "renameat2":
                is_func_body += gen_renameat2(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "chmod":
                is_func_body += gen_chmod(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "fchmodat":
                is_func_body += gen_fchmodat(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "truncate":
                is_func_body += gen_truncate(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "ftruncate":
                is_func_body += gen_ftruncate(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "linkat":
                is_func_body += gen_linkat(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "symlinkat":
                is_func_body += gen_symlinkat(function_name, t)
                is_func_body += "\n"
        
        rule_def_body += gen_rule_def(name, timeout, function_names) + "\n"

    a = "\n".join(["    " + l for l in gen_allow_execve_paths(allow_execve_paths).splitlines()])
    b = "\n".join(["    " + l for l in rule_def_body.splitlines()])

    body = codegen_rules_h_template.replace("[RECURSIVE_TRAVERSAL_CONFIG]", gen_recursive_traversal_config(recursive_traversal_rule)).replace("[IS_FUNCTION_BODY]", is_func_body).replace("[ALLOW_DEF_GEN_BODY]", a).replace("[RULE_DEF_GEN_BODY]", b)

    with open("src/codegen_rules.h", "w") as f:
        f.write(body)
