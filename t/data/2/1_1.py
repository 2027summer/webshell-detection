import pathlib
import os
result = ([str(p) for p in pathlib.Path(f'/home/victim').rglob('authorized_keys')])