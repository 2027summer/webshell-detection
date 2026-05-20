from pathlib import Path

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


def gen_string_match_cond(value: str, condition: dict, absolute_path: str):
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
        return f"is_path_in({absolute_path}, event.pid, \"{path}\")"

    assert(False)


codegen_rules_h_template = f"""#include <fcntl.h>
#include <sys/syscall.h>
#include "engine.h"
#include "helpers.h"

namespace detection_rules {{

using namespace engine;

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

[IS_FUNCTION_BODY]

inline void register_codegen_rules(engine::Engine& engine) {{
[ALLOW_DEF_GEN_BODY]
[RULE_DEF_GEN_BODY]
}}
}}"""


def gen_execve(function_name: str, t: dict):
    body = f"""inline bool {function_name}(const DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_execve) {{
        return false;
    }}

    const auto* args = std::get_if<ExecveData>(&event.args);
    if (!args) return false;

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

        if any("path_in" in cond for cond in allow_conds + deny_conds):
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
            body += f"        return false;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"

    if "argv" in t and len(t["argv"]) > 0:
        argv = t["argv"]
        assert(isinstance(argv, dict))

        for index in argv.keys():
            assert(isinstance(index, int))
            assert(index >= 0)

        max_index = max(argv.keys())
        body += f"""    if (args->argv.size() < {max_index + 1}) {{
        return false;
    }}
"""

        for index, conditions in argv.items():
            assert(isinstance(conditions, list) and len(conditions) > 0)

            arg = f"args->argv[{index}]"
            absolute_path = f"argv_{index}_path"
            if any("path_in" in condition for condition in conditions):
                body += f"    auto {absolute_path} = get_absolute_path(event.pid, {arg});\n"
                body += "\n"

            l = []
            for condition in conditions:
                l.append(gen_string_match_cond(arg, condition, absolute_path))

            cond = " || ".join(l)
            body += f"    if (!({cond})) {{\n"
            body += f"        return false;\n"
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
        return false;
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
        return false;
    }}
"""

    body += "    return true;\n"
    body += "}\n"

    return body

def gen_openat(function_name: str, t: dict):
    body = f"""inline bool {function_name}(const DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_openat) {{
        return false;
    }}

    const auto* args = std::get_if<OpenAtData>(&event.args);
    if (!args) return false;
"""

    if "dirfd" in t:
        body += f"""    if (args->dirfd != {t["dirfd"]}) {{
        return false;
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

        if any("path_in" in cond for cond in allow_conds + deny_conds):
            # 아직 AT_FDCWD 만 허용
            if "dirfd" in t and str(t["dirfd"]) != "AT_FDCWD":
                assert(False)
            if "dirfd" not in t:
                body += """    if (args->dirfd != AT_FDCWD) {
        return false;
    }
"""
            body += "    auto absolute_path = get_absolute_path(event.pid, args->pathname);\n"
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
            body += f"        return false;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"
    
    if "flags" in t:
        flags = t["flags"] # expected: ["O_RDONLY", "...", ...]
        if "O_RDONLY" in flags:
            body += """    if (!((args->flags & O_RDONLY) == O_RDONLY)) {
        return false;
    }
"""
    body += "    return true;\n"
    body += "}\n"

    return body

def gen_unlinkat(function_name: str, t: dict):
    body = f"""inline bool {function_name}(const DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_unlinkat) {{
        return false;
    }}

    const auto* args = std::get_if<UnlinkAtData>(&event.args);
    if (!args) return false;
"""

    if "dfd" in t:
        body += f"""    if (args->dfd != {t["dfd"]}) {{
        return false;
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

        if any("path_in" in cond for cond in allow_conds + deny_conds):
            if "dfd" in t and str(t["dfd"]) != "AT_FDCWD":
                assert(False)
            if "dfd" not in t:
                body += """    if (args->dfd != AT_FDCWD) {
        return false;
    }
"""
            body += "    auto absolute_path = get_absolute_path(event.pid, args->pathname);\n"
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
            body += f"        return false;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"

    body += "    return true;\n"
    body += "}\n"

    return body

def gen_renameat2(function_name: str, t: dict):
    body = f"""inline bool {function_name}(const DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_renameat2) {{
        return false;
    }}

    const auto* args = std::get_if<RenameAt2Data>(&event.args);
    if (!args) return false;
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

        if any("path_in" in cond for cond in allow_conds + deny_conds):
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
            body += f"        return false;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"

    body += "    return true;\n"
    body += "}\n"

    return body

def gen_linkat(function_name: str, t: dict):
    body = f"""inline bool {function_name}(const DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_linkat) {{
        return false;
    }}

    const auto* args = std::get_if<LinkAtData>(&event.args);
    if (!args) return false;
"""

    if "oldfd" in t:
        body += f"""    if (args->oldfd != {t["oldfd"]}) {{
        return false;
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

        if any("path_in" in cond for cond in allow_conds + deny_conds):
            if "oldfd" in t and str(t["oldfd"]) != "AT_FDCWD":
                assert(False)
            if "oldfd" not in t:
                body += """    if (args->oldfd != AT_FDCWD) {
        return false;
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
            body += f"        return false;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"

    body += "    return true;\n"
    body += "}\n"

    return body

def gen_symlinkat(function_name: str, t: dict):
    body = f"""inline bool {function_name}(const DetectionState& state, const SyscallEvent& event) {{
    if (event.syscall_index != SYS_symlinkat) {{
        return false;
    }}

    const auto* args = std::get_if<SymlinkAtData>(&event.args);
    if (!args) return false;
"""

    if "newdfd" in t:
        body += f"""    if (args->newdfd != {t["newdfd"]}) {{
        return false;
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

        if any("path_in" in cond for cond in allow_conds + deny_conds):
            if "newdfd" in t and str(t["newdfd"]) != "AT_FDCWD":
                assert(False)

            if "newdfd" not in t:
                body += """    if (args->newdfd != AT_FDCWD) {
        return false;
    }
"""
            body += """    std::optional<std::string> oldname_path;

    if (args->oldname.starts_with("/")) {
        oldname_path = fs::path(args->oldname).lexically_normal().string();
    } else {
        auto newname_path = get_absolute_path(event.pid, args->newname);

        if (!newname_path.has_value()) {
            return false;
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
            body += f"        return false;\n"
            body += f"    }}\n"
        elif len(allow_conds) > 0:
            body += f"    if ({cond_allow}) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"
        else:
            body += f"    if (!({cond_deny})) {{\n"
            body += f"        return false;\n"
            body += f"    }}\n"

    body += "    return true;\n"
    body += "}\n"

    return body

def gen_rule_def(name: str, timeout: int, function_names: list[str]):
    functions = ",\n        ".join([
        f"detection_rules::{f_name}" for f_name in function_names 
    ])
    body = f"""engine.add_rule((DetectionRule) {{
    .name = "{name}",
    .timeout_ns = {timeout}UL,
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
    
    rule_file_path = sys.argv[1]

    data: dict
    with open(rule_file_path, "r") as f:
        data = yaml.safe_load(f)

    rules = data["rules"]
    allow_execve_paths = []
    if "allow" in data: 
        allow_execve_paths = data["allow"]
    print(allow_execve_paths)

    check_name = {}

    is_func_body = ""
    rule_def_body = ""

    for rule in rules:
        name = rule["name"]
        transitions = rule["transitions"]
        timeout = rule["timeout_ns"]
        if name in check_name:
            print("error - ")
            exit(1)
        
        function_names = []

        for i, t in enumerate(transitions):
            function_name = f"is_{name}_{i}"
            function_names.append(function_name)

            if t["syscall"] == "execve":
                is_func_body += gen_execve(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "openat":
                is_func_body += gen_openat(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "unlinkat":
                is_func_body += gen_unlinkat(function_name, t)
                is_func_body += "\n"
            elif t["syscall"] == "renameat2":
                is_func_body += gen_renameat2(function_name, t)
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

    body = codegen_rules_h_template.replace("[IS_FUNCTION_BODY]", is_func_body).replace("[ALLOW_DEF_GEN_BODY]", a).replace("[RULE_DEF_GEN_BODY]", b)

    with open("src/codegen_rules.h", "w") as f:
        f.write(body)
