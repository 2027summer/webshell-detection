result = ""
def grep(pattern, path, recursive=False):
    global result
    from pathlib import Path
    import re
    import os
    p = Path(path)
    files = (Path(root) / f for root, _, fs in os.walk(p) for f in fs) if recursive else [p]
    for entry in files:
        if entry.is_file():
            with open(entry, errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    if re.search(pattern, line):
                        result += f'{entry}:{i}\n'

grep('Hello World!', '.', recursive=True)