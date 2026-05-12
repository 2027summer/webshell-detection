import yaml

data: dict
with open("rules.yaml", "r") as f:
    data = yaml.safe_load(f)

rules = data["rules"]

# f_rules_h = open("src/rules.h", "r")

def only_alnum(s: str):
    ss = ""
    for c in s:
        if c.isalnum():
            ss += c
    return ss


codegen_rules_h_template = f"""#include <fcntl.h>
#include <sys/syscall.h>
#include "engine.h"

namespace detection_rules {{

using namespace engine;

[IS_FUNCTION_BODY]

inline void register_codegen_rules(engine::Engine& engine) {{
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

    bool flag_filename = false;
"""

    if "filename" in t and len(t["filename"]) > 0:
        filenames = t["filename"]

        for filename in filenames:
            body += f"""    if (args->filename == "{filename}") {{
        flag_filename = true;
    }}
"""
        body += f"""    if (flag_filename == false) {{
        return false;
    }}
"""

    if "argv" in t and len(t["argv"]) > 0:
        argv = t["argv"]
        body += f"""    if (args->argv.size() < {len(argv)}) {{
            return false;
    }}
"""
        for i in range(len(argv)):
            body += f"""    if (args->argv[{i}] != "{argv[i]}") {{
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
        body += f"""    if (args->pathname != "{t["pathname"]}") {{
        return false;
    }}
"""

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
    
    rule_def_body = gen_rule_def(name, timeout, function_names)


codege_rules_h_template = f"""#include "engine.h"

namespace detection_rules {{

using namespace engine;

[IS_FUNCTION_BODY]
inline void register_codegen_rules(engine::Engine& engine) {{
[RULE_DEF_GEN_BODY]
}}
}}"""

b = "\n".join(["    " + l for l in rule_def_body.splitlines()])

body = codegen_rules_h_template.replace("[IS_FUNCTION_BODY]", is_func_body).replace("[RULE_DEF_GEN_BODY]", b)

print(body)

with open("src/codegen_rules.h", "w") as f:
    f.write(body)
