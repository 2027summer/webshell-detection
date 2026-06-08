result = ""
def find(path='.', name=None):
    global result
    from pathlib import Path
    import os
    import fnmatch
    import re
    import shutil
    import urllib.request
    for entry in Path(path).iterdir():
        if name is None or fnmatch.fnmatch(entry.name, name):
            result += str(entry) + '\n'
        if entry.is_dir():
            find(entry, name)

find(path='.', name='*.png')