from pathlib import Path
import shutil


ROOT = Path("/home/victim/dummy")
DIRS = 1000
FILES_PER_DIR = 30
DEPTH = 50


if ROOT.exists():
    shutil.rmtree(ROOT)

ROOT.mkdir(parents=True)

for i in range(DIRS):
    directory = ROOT / f"dir_{i:04d}"
    directory.mkdir()
    for j in range(FILES_PER_DIR):
        (directory / f"file_{j:04d}.txt").write_text("x")

directory = ROOT
for i in range(DEPTH):
    directory = directory / f"deep_{i:04d}"
    directory.mkdir()
    for j in range(FILES_PER_DIR):
        (directory / f"file_{j:04d}.txt").write_text("x")
