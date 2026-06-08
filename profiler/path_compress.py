#!/usr/bin/env python3
import json
import sys
import yaml
import argparse
from collections import Counter, defaultdict


# --- Trie ---

class Node:
    __slots__ = ("children", "count")

    def __init__(self):
        self.children: dict[str, "Node"] = {}
        self.count: int = 0


def build_trie(path_counts: Counter) -> Node:
    root = Node()
    for path, count in path_counts.items():
        node = root
        for part in path.split("/"):
            if not part:
                continue
            node = node.children.setdefault(part, Node())
        node.count += count
    return root


def _merge(target: Node, source: Node) -> None:
    """source 노드의 count와 children을 target에 합친다."""
    target.count += source.count
    for key, child in source.children.items():
        if key in target.children:
            _merge(target.children[key], child)
        else:
            target.children[key] = child


def abstract_trie(node: Node, threshold: int) -> None:
    """
    한 노드의 자식 중 숫자(digit)로만 이루어진 것이 threshold개 이상이면
    해당 자식들을 모두 '*' 하나로 합친다.

    ex) /proc/ 아래 30376, 30378, ... (47개) → /proc/*
    """
    digit_children = {k: v for k, v in node.children.items() if k.isdigit()}

    if len(digit_children) >= threshold:
        star = node.children.pop("*", Node())
        for key in list(digit_children):
            _merge(star, node.children.pop(key))
        node.children["*"] = star

    for child in node.children.values():
        abstract_trie(child, threshold)


def extract_patterns(node: Node, prefix: str = "") -> list[tuple[str, int]]:
    """추상화된 trie에서 (경로 패턴, 접근 횟수) 목록을 추출한다."""
    result = []
    if node.count > 0:
        result.append((prefix or "/", node.count))
    for part, child in node.children.items():
        result.extend(extract_patterns(child, f"{prefix}/{part}"))
    return result


# --- Path analysis ---

def is_pattern(path: str) -> bool:
    return "*" in path


def dedup_prefixes(prefixes: list[str]) -> list[str]:
    """
    더 구체적인 prefix가 있으면 상위 prefix를 제거한다.
    concrete와 pattern은 서로 억제하지 않는다.
    """
    result = []
    for p in sorted(prefixes, key=len, reverse=True):
        dominated = any(
            child.startswith(p) and is_pattern(child) == is_pattern(p)
            for child in result
        )
        if not dominated:
            result.append(p)
    return sorted(result)


def find_prefix_candidates(paths: list[str], min_children: int) -> list[str]:
    """
    각 경로의 상위 디렉토리들을 수집하고,
    그 아래에 min_children개 이상의 고유 경로가 있는 디렉토리를 반환한다.
    """
    under: dict[str, set] = defaultdict(set)
    for path in paths:
        parts = [p for p in path.split("/") if p]
        for depth in range(1, len(parts)):
            prefix = "/" + "/".join(parts[:depth]) + "/"
            under[prefix].add(path)

    candidates = [
        prefix
        for prefix, paths_under in under.items()
        if len(paths_under) >= min_children
    ]
    return dedup_prefixes(candidates)


def analyze_paths(path_counts: Counter, min_children: int, dynamic_threshold: int) -> dict:
    trie = build_trie(path_counts)
    abstract_trie(trie, dynamic_threshold)

    all_patterns = sorted(extract_patterns(trie), key=lambda x: -x[1])
    concrete_paths = [p for p, _ in all_patterns if not is_pattern(p)]
    abstract_paths = [(p, c) for p, c in all_patterns if is_pattern(p)]

    allow = find_prefix_candidates(concrete_paths, min_children)
    specific = [
        p for p in concrete_paths
        if not any(p.startswith(candidate) for candidate in allow)
    ]

    result = {}
    if allow:
        result["allow_candidates"] = [{"path_in": p} for p in allow]
    if specific:
        result["specific_paths"] = sorted(specific)
    if abstract_paths:
        result["abstract_patterns"] = [{"path": p, "count": c} for p, c in abstract_paths]
    return result


# --- Data collection ---

# 각 syscall에서 경로를 추출하는 함수 매핑
SYSCALL_PATH_EXTRACTORS: dict[str, callable] = {
    "openat":    lambda e: [e.get("fd_path") or e.get("pathname")],
    "getdents64": lambda e: [e.get("fd_path")],
    "execve":    lambda e: [e.get("filename")],
    "chmod":     lambda e: [e.get("pathname")],
    "fchmodat":  lambda e: [e.get("pathname")],
    "fchmod":    lambda e: [e.get("fd_path")],
    "linkat":    lambda e: [e.get("newname")],
    "symlinkat":    lambda e: [e.get("newname")],
    "renameat2":     lambda e: [e.get("oldname")],
    "renameat":     lambda e: [e.get("oldname")],
    "rename":     lambda e: [e.get("oldname")]
}

FAMILY_NAMES = {2: "AF_INET", 10: "AF_INET6", 1: "AF_UNIX"}


def update_fd_paths(fd_paths: dict[int, dict[int, str]], event: dict) -> None:
    pid = event.get("pid")
    if pid is None:
        return

    syscall = event.get("syscall")
    proc_fds = fd_paths[pid]

    if syscall == "openat":
        fd = event.get("retval")
        path = event.get("fd_path") or event.get("pathname")
        if isinstance(fd, int) and fd >= 0 and path:
            proc_fds[fd] = path
    elif syscall == "dup2":
        oldfd = event.get("oldfd")
        newfd = event.get("newfd")
        retval = event.get("retval")
        path = event.get("oldfd_path") or proc_fds.get(oldfd)
        if isinstance(retval, int) and retval >= 0 and isinstance(newfd, int) and path:
            proc_fds[newfd] = path
    elif syscall == "close":
        fd = event.get("fd")
        if isinstance(fd, int) and event.get("retval") == 0:
            proc_fds.pop(fd, None)


def collect_path_counts(lines, syscalls: list[str], min_count: int) -> Counter:
    counts: Counter = Counter()
    fd_paths: dict[int, dict[int, str]] = defaultdict(dict)

    for line in lines:
        event = json.loads(line)
        syscall = event.get("syscall")
        extractor = SYSCALL_PATH_EXTRACTORS.get(syscall)
        if syscall not in syscalls or not extractor:
            update_fd_paths(fd_paths, event)
            continue

        paths = extractor(event)
        if syscall == "getdents64":
            if event.get("retval", 0) <= 0:
                update_fd_paths(fd_paths, event)
                continue
            pid = event.get("pid")
            fd = event.get("fd")
            if not any(paths) and pid is not None and isinstance(fd, int):
                paths = [fd_paths[pid].get(fd)]

        for path in paths:
            if path:
                counts[path] += 1

        update_fd_paths(fd_paths, event)

    return Counter({p: n for p, n in counts.items() if n >= min_count})


def find_ip_prefix_candidates(addrs_by_family: dict[int, list[str]]) -> list[dict]:
    """
    각 family별 IP 목록에서 2개 이상의 distinct IP가 공유하는 prefix를 찾는다.
    IPv4는 '.'으로, IPv6는 ':'으로 분리해 trie처럼 계층을 만든다.

    ex) 142.251.151.119, 142.251.155.119, ... → addr_starts_with: "142.251."
    """
    result = []
    for family, addrs in sorted(addrs_by_family.items()):
        sep = ":" if family == 10 else "."  # AF_INET6=10

        under: dict[str, set] = defaultdict(set)
        for addr in addrs:
            parts = [p for p in addr.split(sep) if p]  # skip empty parts from ::
            for depth in range(1, len(parts)):
                prefix = sep.join(parts[:depth]) + sep
                under[prefix].add(addr)

        candidates = [p for p, s in under.items() if len(s) >= 2]

        deduped = []
        for p in sorted(candidates, key=len, reverse=True):
            if not any(c.startswith(p) for c in deduped):
                deduped.append(p)

        for prefix in sorted(deduped):
            result.append({
                "family": FAMILY_NAMES.get(family, family),
                "addr_starts_with": prefix,
            })

    return result


def collect_connect_data(lines, min_count: int) -> tuple[list[dict], list[dict]]:
    """connect 이벤트에서 (exact destinations, prefix candidates)를 반환한다."""
    counts: Counter = Counter()
    for line in lines:
        event = json.loads(line)
        if event.get("syscall") != "connect":
            continue
        addr = event.get("addr", "")
        if not addr:
            continue
        counts[(event.get("family"), addr, event.get("port", 0))] += 1

    exact = []
    addrs_by_family: dict[int, list[str]] = defaultdict(list)

    for (family, addr, port), count in sorted(counts.items(), key=lambda x: -x[1]):
        if count < min_count:
            continue
        exact.append({
            "family": FAMILY_NAMES.get(family, family),
            "addr": addr,
            "port": port,
        })
        addrs_by_family[family].append(addr)

    return exact, find_ip_prefix_candidates(dict(addrs_by_family))


def main():
    all_path_syscalls = sorted(SYSCALL_PATH_EXTRACTORS)
    parser = argparse.ArgumentParser(description="Extract prefix candidates for allow/deny rules")
    parser.add_argument("input", nargs="+", help="JSONL log file(s) (- for stdin)")
    parser.add_argument(
        "--syscall", nargs="+", default=["openat"],
        metavar="SYSCALL",
        help=f"syscall(s) to analyze. path syscalls: {', '.join(all_path_syscalls)}; also: connect (default: openat)",
    )
    parser.add_argument("--min-count", type=int, default=3,
                        help="min accesses per path (default: 3)")
    parser.add_argument("--min-children", type=int, default=5,
                        help="min unique paths under a prefix (default: 5)")
    parser.add_argument("--dynamic-threshold", type=int, default=10,
                        help="min distinct numeric children to abstract as * (default: 10)")
    args = parser.parse_args()

    lines = []
    for path in args.input:
        fh = sys.stdin if path == "-" else open(path)
        with fh:
            lines.extend(fh.readlines())

    path_syscalls = [s for s in args.syscall if s in SYSCALL_PATH_EXTRACTORS and s != "execve"]
    do_execve = "execve" in args.syscall
    do_connect = "connect" in args.syscall

    output = {}

    if path_syscalls:
        path_counts = collect_path_counts(lines, path_syscalls, args.min_count)
        output.update(analyze_paths(path_counts, args.min_children, args.dynamic_threshold))

    if do_execve:
        execve_counts = collect_path_counts(lines, ["execve"], min_count=1)
        if execve_counts:
            output["execve_filenames"] = sorted(execve_counts)

    if do_connect:
        connect_exact, connect_prefixes = collect_connect_data(lines, args.min_count)
        if connect_exact:
            output["connect_candidates"] = connect_exact
        if connect_prefixes:
            output["connect_prefix_candidates"] = connect_prefixes

    print(yaml.dump(output, default_flow_style=False, allow_unicode=True), end="")


if __name__ == "__main__":
    main()
