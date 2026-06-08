import pathlib
result = [str(p) for p in pathlib.Path('.').rglob('.env')]