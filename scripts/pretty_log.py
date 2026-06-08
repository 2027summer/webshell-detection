import re
import sys

red = "\033[31m"
yellow = "\033[33m"
reset = "\033[0m"

pat = re.compile(r"DETECTED: id: (\d+) rule index: (\d+) rule name: (.+)")

for line in sys.stdin:
    m = pat.search(line)
    if not m:
        print(line, end="", flush=True)
        continue

    state_id, rule_index, rule = m.groups()
    print(f"{red}[DETECT]{reset} {yellow}{rule}{reset} id={state_id} rule_index={rule_index}", flush=True)