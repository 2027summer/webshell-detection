import argparse
import re
import sys
from collections import Counter


PATH_RE = re.compile(r'\b(openat|readlink)\([^\n]*?"(/proc(?:\\.|[^"\\])*)"')


def unescape_path(path):
    return bytes(path, "utf-8").decode("unicode_escape")


def normalize_proc_path(path):
    parts = path.split("/")
    for i in range(2, len(parts)):
        if parts[i].isdigit():
            parts[i] = "<num>"
    return "/".join(parts)


def parse_paths(path, limit):
    seen = Counter()
    total = 0

    with open(path, "r", errors="replace") as f:
        for line in f:
            for syscall, proc_path in PATH_RE.findall(line):
                proc_path = unescape_path(proc_path)
                proc_path = normalize_proc_path(proc_path)
                seen[(syscall, proc_path)] += 1
                total += 1

                if limit is not None and total >= limit:
                    return seen

    return seen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("log")
    parser.add_argument("--limit", type=int, default=2000)
    parser.add_argument("--top", type=int, default=100)
    args = parser.parse_args()

    if args.limit is not None and args.limit < 1:
        print("--limit must be >= 1", file=sys.stderr)
        return 1

    if args.top < 1:
        print("--top must be >= 1", file=sys.stderr)
        return 1

    paths = parse_paths(args.log, args.limit)
    for (syscall, path), count in paths.most_common(args.top):
        # print(f"{count}\t{syscall}\t{path}")
        print(f"{path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
