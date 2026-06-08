import argparse
import json
import os
import re
import sys
from collections import Counter

import yaml


def load_events(paths):
    for path in paths:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                yield json.loads(line)


def is_write_open(flags):
    access = flags & os.O_ACCMODE
    if access != os.O_RDONLY:
        return True
    return bool(flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND))


def compress_part(part, prev_part):
    if prev_part == "proc" and part.isdigit():
        return "<pid>"
    if prev_part == "task" and part.isdigit():
        return "<tid>"
    if re.fullmatch(r"tmp[a-zA-Z0-9._-]{6,}", part):
        return "tmp*"
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", part):
        return "<uuid>"

    m = re.fullmatch(r"([0-9a-fA-F]{16,})(\..+)?", part)
    if m:
        return "<hex>" + (m.group(2) or "")

    return part


def compress_path(path):
    if not path.startswith("/"):
        return path

    parts = path.split("/")
    result = []

    for i, part in enumerate(parts):
        prev_part = parts[i - 1] if i > 0 else ""
        result.append(compress_part(part, prev_part))

    return "/".join(result)


def has_pattern(path):
    return any(token in path for token in ("<pid>", "<tid>", "<hex>", "<uuid>", "*"))


def path_depth(path):
    return len([part for part in path.split("/") if part])


def parent_dir(path):
    path = path.rstrip("/")
    parent = os.path.dirname(path)
    if parent == "":
        return "/"
    return parent + "/"


def path_child(path):
    return os.path.basename(path.rstrip("/"))


def path_in_prefix(path, prefix):
    if path == prefix.rstrip("/"):
        return True
    return path.startswith(prefix)


def can_use_prefix(prefix):
    parts = [part for part in prefix.split("/") if part]
    if not parts:
        return False

    if parts[0] in ("dev", "etc", "lib", "proc", "run", "sys", "tmp", "usr", "var") and len(parts) <= 1:
        return False
    if parts[:2] == ["usr", "lib"] and len(parts) <= 2:
        return False
    if parts[0] == "home" and len(parts) <= 2:
        return False

    return path_depth(prefix) >= 3


def add_execve(items, event):
    exe = event.get("exe")
    if not exe:
        return

    if exe not in items:
        items[exe] = {
            "count": 0,
            "filenames": Counter(),
            "argv_examples": []
        }

    item = items[exe]
    item["count"] += 1

    filename = event.get("filename")
    if filename:
        item["filenames"][filename] += 1

    argv = event.get("argv", [])
    if argv and argv not in item["argv_examples"]:
        item["argv_examples"].append(argv)


def add_openat(open_read, open_write, event):
    path = event.get("fd_path") or event.get("pathname")
    if not path:
        return

    path = compress_path(path)

    flags = event.get("flags", 0)
    if is_write_open(flags):
        open_write[path] += 1
    else:
        open_read[path] += 1


def add_getdents64(dir_read, event):
    if event.get("retval", 0) <= 0:
        return

    path = event.get("fd_path")
    if path:
        dir_read[compress_path(path)] += 1


def add_connect(items, event):
    key = (
        event.get("family", 0),
        event.get("addr", ""),
        event.get("port", 0)
    )
    items[key] += 1


def add_file_change(items, event):
    syscall = event.get("syscall")
    roles = []

    if syscall == "unlinkat":
        roles = ["pathname"]
    elif syscall in ("renameat", "renameat2", "linkat", "symlinkat"):
        roles = ["oldname", "newname"]

    for role in roles:
        path = event.get(role)
        if path:
            items[(syscall, role, compress_path(path))] += 1


def collect(events):
    execve = {}
    open_read = Counter()
    open_write = Counter()
    dir_read = Counter()
    connect = Counter()
    file_change = Counter()

    for event in events:
        syscall = event.get("syscall")

        if syscall == "execve":
            add_execve(execve, event)
        elif syscall == "openat":
            add_openat(open_read, open_write, event)
        elif syscall == "getdents64":
            add_getdents64(dir_read, event)
        elif syscall == "connect":
            add_connect(connect, event)
        elif syscall in ("renameat", "renameat2", "unlinkat", "linkat", "symlinkat"):
            add_file_change(file_change, event)

    return {
        "execve": execve,
        "open_read": open_read,
        "open_write": open_write,
        "dir_read": dir_read,
        "connect": connect,
        "file_change": file_change
    }


def apply_limit(items, limit):
    if limit is None:
        return items
    return items[:limit]


def format_value(value, count, with_count):
    if not with_count:
        return value
    return {"value": value, "count": count}


def sorted_counter_items(counter, min_count):
    return [
        (value, count)
        for value, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        if count >= min_count
    ]


def find_prefixes(counter, threshold):
    children = {}
    counts = Counter()

    for path, count in counter.items():
        if has_pattern(path):
            continue

        parent = parent_dir(path)
        if not can_use_prefix(parent):
            continue

        children.setdefault(parent, set()).add(path_child(path))
        counts[parent] += count

    candidates = {
        parent: counts[parent]
        for parent, child_set in children.items()
        if len(child_set) >= threshold
    }

    result = []
    for prefix, count in sorted(candidates.items(), key=lambda item: (-path_depth(item[0]), item[0])):
        if any(accepted.startswith(prefix) for accepted, _ in result):
            continue
        result.append((prefix, count))

    return result


def path_candidates(counter, min_count, limit, threshold, with_count):
    counter = Counter({
        path: count
        for path, count in counter.items()
        if count >= min_count
    })

    prefixes = find_prefixes(counter, threshold)
    prefix_values = [prefix for prefix, _ in prefixes]

    eq = Counter()
    pattern = Counter()

    for path, count in counter.items():
        if any(path_in_prefix(path, prefix) for prefix in prefix_values):
            continue

        if has_pattern(path):
            pattern[path] += count
        else:
            eq[path] += count

    return {
        "eq": apply_limit([
            format_value(value, count, with_count)
            for value, count in sorted_counter_items(eq, min_count)
        ], limit),
        "prefix": apply_limit([
            format_value(value, count, with_count)
            for value, count in sorted(prefixes, key=lambda item: (-item[1], item[0]))
        ], limit),
        "pattern": apply_limit([
            format_value(value, count, with_count)
            for value, count in sorted_counter_items(pattern, min_count)
        ], limit)
    }


def execve_candidates(items, min_count, limit, with_count):
    result = []

    for exe, item in sorted(items.items(), key=lambda item: (-item[1]["count"], item[0])):
        if item["count"] < min_count:
            continue

        result.append(format_value(exe, item["count"], with_count))

    return {"eq": apply_limit(result, limit)}


def connect_candidates(counter, min_count, limit, with_count):
    result = []

    for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0])):
        if count < min_count:
            continue

        family, addr, port = key
        item = {
            "family": family,
            "addr": addr,
            "port": port
        }

        if with_count:
            item["count"] = count

        result.append(item)

    return {"eq": apply_limit(result, limit)}


def format_file_change(syscall, role, value, count, with_count):
    item = {
        "syscall": syscall,
        "role": role,
        "value": value
    }

    if with_count:
        item["count"] = count

    return item


def file_change_candidates(counter, min_count, limit, threshold, with_count):
    grouped = {}
    result = {
        "eq": [],
        "prefix": [],
        "pattern": []
    }

    for (syscall, role, path), count in counter.items():
        grouped.setdefault((syscall, role), Counter())[path] += count

    for syscall, role in sorted(grouped.keys()):
        candidates = path_candidates(grouped[(syscall, role)], min_count, None, threshold, True)

        for key in ("eq", "prefix", "pattern"):
            for item in candidates[key]:
                result[key].append((
                    item["count"],
                    format_file_change(syscall, role, item["value"], item["count"], with_count)
                ))

    for key in result.keys():
        result[key].sort(key=lambda item: (-item[0], item[1]["syscall"], item[1]["role"], item[1]["value"]))
        result[key] = apply_limit([item for _, item in result[key]], limit)

    return result


def build_output(data, min_count, limit, read_threshold, write_threshold, with_count):
    return {
        "allow_candidates": {
            "execve": execve_candidates(data["execve"], min_count, limit, with_count),
            "open_read": path_candidates(data["open_read"], min_count, limit, read_threshold, with_count),
            "open_write": path_candidates(data["open_write"], min_count, limit, write_threshold, with_count),
            "dir_read": path_candidates(data["dir_read"], min_count, limit, read_threshold, with_count),
            "connect": connect_candidates(data["connect"], min_count, limit, with_count),
            "file_change": file_change_candidates(data["file_change"], min_count, limit, write_threshold, with_count)
        }
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("profiles", nargs="+")
    parser.add_argument("--min-count", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--with-count", action="store_true")
    parser.add_argument("--prefix-read-threshold", type=int, default=5)
    parser.add_argument("--prefix-write-threshold", type=int, default=3)
    args = parser.parse_args()

    if args.min_count < 1:
        print("--min-count must be >= 1", file=sys.stderr)
        return 1

    if args.limit is not None and args.limit < 1:
        print("--limit must be >= 1", file=sys.stderr)
        return 1

    if args.prefix_read_threshold < 2:
        print("--prefix-read-threshold must be >= 2", file=sys.stderr)
        return 1

    if args.prefix_write_threshold < 2:
        print("--prefix-write-threshold must be >= 2", file=sys.stderr)
        return 1

    data = collect(load_events(args.profiles))
    print(yaml.safe_dump(build_output(
        data,
        args.min_count,
        args.limit,
        args.prefix_read_threshold,
        args.prefix_write_threshold,
        args.with_count
    ), sort_keys=False), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
