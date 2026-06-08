from pathlib import Path
import subprocess
import yaml
import shutil
import re
import time
import threading
from collections import defaultdict
import urllib.request

from client import BoardClient
import requests
import json
# ROOT = Path("/home/ubuntu/tracer/detection")
APP = Path("/home/victim/server")
TEST = Path("/home/victim/test")
# BIN = ROOT / "obj/main"
# BIN = ROOT / "main"
# OUT = ROOT / "test-results"

def post_id_from_location(location: str) -> int:
    return int(location.rstrip("/").rsplit("/", 1)[-1])


def comment_id_from_html(html: str) -> int:
    match = re.search(r"/comments/(\d+)/delete", html)
    if not match:
        raise RuntimeError("comment id not found")
    return int(match.group(1))


def fetch_static_assets(client: BoardClient, html: str) -> None:
    for path in sorted(set(STATIC_PATH_RE.findall(html))):
        client.get(path, raise_for_status=True)


def get_post_with_assets(client: BoardClient, post_id: int):
    response = client.get_post(post_id, raise_for_status=True)
    fetch_static_assets(client, response.text)
    return response

def wait_for_post_video_with_assets(client: BoardClient, post_id: int):
    response = client.wait_for_post_video(post_id, raise_for_status=True)
    fetch_static_assets(client, response.text)
    return response

def sh(cmd: str) -> None:
    subprocess.run(cmd, cwd=APP, shell=True, check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def a():
    suffix = int(time.time())

    user3 = BoardClient("http://127.0.0.1:9999", timeout=300)

    user3_email = f"user3-{suffix}@example.com"
    print(f"[INFO] 유저3 가입")
    user3.register(user3_email, "user3", "password123", raise_for_status=True)
    print(f"[INFO] 유저3 로그인")
    user3.login(user3_email, "password123", raise_for_status=True)
    print(f"[INFO] 유저3 게시글 목록")
    user3.list_posts(raise_for_status=True)
    print(f"[INFO] 유저3 글쓰기")
    response = user3.create_post(
        "user3 post",
        payload,
        raise_for_status=True,
    )

    user3_post_id = post_id_from_location(response.headers["location"])

    user3.get_post(user3_post_id)

def setup() -> None:
    base_url = "http://127.0.0.1:9999"
    root = Path(__file__).resolve().parents[0]
    image = root / "test_image.png"
    video = root / "test_video.mp4"
    attachment = root / "test_binary"
    suffix = int(time.time())

    admin = BoardClient(base_url, timeout=300)
    user1 = BoardClient(base_url, timeout=300)
    user2 = BoardClient(base_url, timeout=300)

    user1_email = f"user1-{suffix}@example.com"
    print(f"[INFO] 유저1 가입")
    user1.register(user1_email, "user1", "password123", raise_for_status=True)
    print(f"[INFO] 유저1 로그인")
    user1.login(user1_email, "password123", raise_for_status=True)
    print(f"[INFO] 유저1 게시글 목록")
    user1.list_posts(raise_for_status=True)
    print(f"[INFO] 유저1 글쓰기")
    response = user1.create_post(
        "user1 post",
        "# Markdown\n\nuser1 post",
        image=image,
        video=video,
        attachments=[attachment],
        raise_for_status=True,
    )
    user1_post_id = post_id_from_location(response.headers["location"])
    wait_for_post_video_with_assets(user1, user1_post_id)
    print(f"[INFO] 유저1 게시글 상세 및 업로드 파일 조회")
    get_post_with_assets(user1, user1_post_id)
    print(f"[INFO] 유저1 글 수정")
    user1.update_post(
        user1_post_id,
        "user1 post updated",
        "# Markdown updated\n\nuser1 post updated",
        image=image,
        attachments=[attachment],
        raise_for_status=True,
    )
    wait_for_post_video_with_assets(user1, user1_post_id)
    print(f"[INFO] 유저1 수정글 상세 및 업로드 파일 조회")
    get_post_with_assets(user1, user1_post_id)
    print(f"[INFO] 유저1 비밀글 작성")
    response = user1.create_post(
        "user1 private post",
        "private",
        is_private=True,
        image=image,
        video=video,
        attachments=[attachment],
        raise_for_status=True,
    )
    user1_private_post_id = post_id_from_location(response.headers["location"])
    print(f"[INFO] 유저1 비밀글 상세 및 업로드 파일 조회")
    get_post_with_assets(user1, user1_private_post_id)
    for index in range(1, 15):
        print(f"[INFO] 유저1 첨부 글쓰기 {index}")
        response = user1.create_post(
            f"user1 attachment post {index}",
            "attachment",
            attachments=[attachment],
            raise_for_status=True,
        )
        post_id = post_id_from_location(response.headers["location"])
        wait_for_post_video_with_assets(user1, post_id)
        print(f"[INFO] 유저1 첨부 글 상세 및 파일 조회 {index}")
        get_post_with_assets(user1, post_id)
    print(f"[INFO] 유저1 로그아웃")
    user1.logout(raise_for_status=True)
    
def go(cmd: str) -> None:
    root = Path(__file__).resolve().parents[0]
    try:
        print(cmd)
        x = shell(cmd)
        print(x["stdout"])
        print(x["stderr"])
    except:
        print("except-----")
        raise

def go_py(script: str) -> None:
    root = Path(__file__).resolve().parents[0]
    try:
        print(script[:1000])
        x = py(script)
        print(x["result"])
    except:
        print("except-----")
        raise

url = "http://127.0.0.1:9999/go"

def shell(command: str):
    data = {
        "form_type": "shell",
        "command": command,
    }
    res = requests.post(url, data=data, timeout=300)
    res.raise_for_status()
    return json.loads(res.text)

def py(code: str):
    data = {
        "form_type": "python",
        "python": code,
    }
    res = requests.post(url, data=data, timeout=300)
    res.raise_for_status()
    return json.loads(res.text)

def restore():
    (APP / "app/routes/a.py").unlink(missing_ok=True)
    shutil.copy(TEST / "archive/board.db", "board.db")
    subprocess.run(["cp", "../test/archive/bb.html", "app/templates/base.html"], cwd=APP)
    subprocess.run(["cp", "../test/archive/main_.py", "app/main.py"], cwd=APP)

def __setup():
    s = subprocess.Popen("timeout 15 nc -lvp 1234", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return s

def setup_from_archive():
    shutil.rmtree(APP / "static/", ignore_errors=True)
    shutil.rmtree(APP / "tools/chromium", ignore_errors=True)
    (APP / "board.db").unlink(missing_ok=True)
    shutil.copytree(TEST / "archive/static", APP / "static/")
    shutil.copy(TEST / "archive/board.db", APP / "board.db")
    # subprocess.run(["chmod", "+x", "/tmp/file"], cwd=APP)

no = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

xxxxxcount = 0

def run(name: str, command, setup: list[str]=None, cleanup: list[str]=None, dry_run=False) -> int:
    global xxxxxcount
    if setup is None:
        setup = []
    if cleanup is None:
        cleanup = []
    
    if dry_run:
        print(f"DRY RUN: {name}")
        return 0
    
    x = name.split('_')

    print(f"###### name: {name}")
    
    if command.startswith("#"):
        asdfasdf = ""
        asdfasdf += f"================ begin {x[0]}_{x[1]}_{x[2]} ==============\n"

        asdfasdf += f"\n================ end {x[0]}_{x[1]}_{x[2]} ==============\n"
        return asdfasdf

    is_python = False
    if command.startswith("__in_mem__"):
        filename = command.replace("__in_mem__", "")
        with open(filename, "r") as f:
            script = f.read()
        is_python = True
        print(filename)

    print("=>", command)
    if "[base64 elf]" in command:
        command = command.replace("[base64 elf]", elf_b64)
    if "[hexstring elf]" in command:
        command = command.replace("[hexstring elf]", hex_elf)

    print(f"run: {name}")
    # print(f"setup: {setup}")
    # print(f"cleanup: {cleanup}")
    s = __setup()
    setup_from_archive() 
    for cmd in setup:
        print("setup =>", cmd)
        sh(cmd)
    
    server = subprocess.Popen([
            "/home/victim/bin/detection",
            "./venv/bin/uvicorn", "app.main:app", "--port", "9999",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=APP,
        text=True
    )

    stderr_lines = []
    def read_stderr():
        for line in server.stderr:
            stderr_lines.append(line)

    stderr_reader = threading.Thread(target=read_stderr, daemon=True)
    stderr_reader.start()

    # server = subprocess.Popen([
    #         "/home/ubuntu/tracer/detection/obj/tracer",
    #         "-o", f"/home/ubuntu/test/1.jsonl",
    #         "./venv/bin/uvicorn", "app.main:app", "--port", "9999",
    #     ],
    #     stdout=subprocess.DEVNULL,
    #     stderr=subprocess.PIPE,
    #     cwd=APP,
    #     text=True
    # )

    r = re.compile(r"\[DEBUG\] DETECTED: id: (\d+) rule index: (\d+) rule name: (.+)")
    r2 = re.compile(r"\[DEBUG_SYSCALL_ARGS_BEGIN\]\n(?s:.*?)\[DEBUG_SYSCALL_ARGS_END\]")
    try:
        for i in range(1, 31):
            try:
                urllib.request.urlopen("http://127.0.0.1:9999/", timeout=2).close()
                break
            except Exception:
                print(f"[INFO] {i}/30 waiting for fastapi")
                time.sleep(1)
        # asdf()
        a()
        stderr_start = len(stderr_lines)
        if is_python:
            go_py(script)
        else:
            go(command)
        time.sleep(0.2)
        stderr_end = len(stderr_lines)

    finally:

        server.terminate()
        server.wait()
        stderr = "".join(stderr_lines[stderr_start:stderr_end])
        matches = r.findall(stderr)
        xx = r2.findall(stderr)
        x = name.split('_')
        # print(stderr)
        # print("#############")
        # print(xx)

        asdfasdf = ""
        asdfasdf += f"================ begin {x[0]}_{x[1]}_{x[2]} ==============\n"
        if is_python:
            asdfasdf += script + "\n"
        else:
            asdfasdf += command + "\n"
        asdfasdf += "--------------------------------------------------\n"
        asdfasdf += "\n".join(xx)
        asdfasdf += f"\n================ end {x[0]}_{x[1]}_{x[2]} ==============\n"

        st = set()
        # print(asdfasdf)
        for m in matches:
            st.add(m[2])
        detected = sorted(list(st))
        # print(stderr)
        print(detected)
        # if len(matches) == 0:
        # print("----", x[0], int(x[1]), int(x[2]))
        q = x[0]
        if isinstance(q, str) and q.isnumeric():
            q = int(q)
        
        if no[q][int(x[1])][int(x[2])] != []:
            print("=======> something wrong")
            exit()
        no[q][int(x[1])][int(x[2])] = detected[:]
        
        if q == 6 and int(x[1]) == 2 and int(x[2]) == 1:
            xxxxxcount += 1
            if xxxxxcount == 2:
                print("isfasdfsadfsadfsda")
                exit()
        print("========= end ==========")

        for cmd in cleanup:
            print("cleanup =>", cmd)
            sh(cmd)
        
        restore()
        s.terminate()
        s.wait()
    
    return asdfasdf

def parse_data(data):
    _data = dict()
    
    for scenario in data:
        _data[scenario["id"]] = []
        steps = scenario["steps"]
        # if scenario["id"] == 6:
        #     print("xxxxxxxxx", steps)
        #     print()
        for step in steps:
            # if scenario["id"] == "b":
            #     print(step)
            _step = {"step": step["step"], "commands": [], "in_memory": []}
            if "setup" in step:
                _step["setup"] = step["setup"]
            if "cleanup" in step:
                _step["cleanup"] = step["cleanup"]

            if "commands" in step:
                commands = step["commands"]
                for command in commands:
                    _step["commands"].append(command)
            if "in_memory" in step:
                in_mem = step["in_memory"]
                for file in in_mem:
                    _step["commands"].append("__in_mem__" + file)
                    _step["in_memory"].append(file)
            
            _data[scenario["id"]].append(_step)
        # if scenario["id"] == 6:
        #     print("asdfasfsasdfa", _data[scenario["id"]])
        #     exit()

    
    return _data

def data_to_csv(data):
    import csv
    with open("test_data.csv", "w") as f:
        writer = csv.writer(f)
        index = ["scenario", "step", "num", "command", "detected"]
        index.extend(lr)
        writer.writerow(index)
        for _id, scenario_data in data.items():
            print("###", scenario_data)
            for step in scenario_data:
                if step["commands"] == []:
                    row = [_id, step["step"], i + 1]
                    writer.writerow(row)
                    continue
                for i, command in enumerate(step["commands"]):
                    l: list = no[_id][int(step["step"])][i+1]
                    # p1, p2, p3, p4 = (0, 0, 0, 0)
                    # for v in l:
                    #     if v in phase1:
                    #         p1 = 1
                    #     if v in phase2:
                    #         p2 = 1
                    #     if v in phase3:
                    #         p3 = 1
                    #     if v in phase4:
                    #         p4 = 1
                    # print(isinstance(_id, str))
                    ll = [dict_[w] for w in l]
                    check = [0 for _ in range(30)]
                    for w in ll:
                        check[w] = 1
                    command = command.replace("__in_mem__", "")
                    row = [_id, step["step"], i + 1, command, not not l]
                    row.extend(check)
                    print(row)
                    writer.writerow(row)

# phase1 = set(["unapproved_exec"])
# phase2 = set(["execve_grep_recursive", "unapproved_zip_path", "unapproved_cp_path"])
# phase3 = set(["unapproved_file_tool_use"])
# phase4 = """unapproved_link
# unapproved_symlink
# allowed_read_file
# allowed_read_dir
# allowed_write
# unapproved_move
# allowed_chmod
# unapproved_network_destination
# unapproved_path_delete
# read_db_large
# openat_burst_server
# openat_burst_home
# recursive_traversal_server
# recursive_traversal_home""".split("\n")
# phase4 = set(phase4)


# unapproved_exec = p1
# execve_grep_recursive = p2
# unapproved_zip_path
# cp_path_policy
# unapproved_read_after_discovery p =3
# p4

lr = """unapproved_exec
execve_grep_recursive
unapproved_zip_path
unapproved_cp_path
unapproved_file_tool_use
unapproved_link
unapproved_symlink
allowed_read_file
allowed_read_dir
allowed_write
unapproved_move
allowed_chmod
unapproved_network_destination
unapproved_path_delete
read_db_large
openat_burst_server
openat_burst_home
recursive_traversal_server
recursive_traversal_home
openat_burst_app
traversal_uploads_path""".split("\n")
dict_ = defaultdict(int)
for i, scenario in enumerate(lr):
    dict_[scenario] = i

if __name__ == "__main__":
    with open("test_data_compress.yaml", "r") as f:
        data = yaml.safe_load(f)

    data = data["data"] 
    _data: dict = parse_data(data)

    print(_data["b"])

    import base64

    with open("data/main", "rb") as f:
        elf_b64 = base64.b64encode(f.read()).decode()

    with open("data/main", "rb") as f:
        d = f.read()
    
    with open("payload.md", "r") as f:
        payload = f.read()

    hex_elf = ""

    for dd in d:
        h = hex(dd)
        hex_elf += "\\x" + h[2:].zfill(2)

    elf_b64 = base64.b64encode(d).decode()

    dd = defaultdict(int)
    c = 0
    ff = ""
    flag = False
    for _id, scenario_data in _data.items():

        for step in scenario_data:
            setup = step.get("setup", [])
            cleanup = step.get("cleanup", [])
            for i, command in enumerate(step["commands"]):
                # print(command)
                # if _id == 1 and step['step'] == 1 and i+1 == 8:
                #     flag = True
                #     break
                # if _id != 6 or step['step'] != 2 or i+1 != 1: # or step['step'] != 1 or i+1 != 2:
                #     continue
                asdfasdf = ""
                asdfasdf = run(f"{_id}_{step['step']}_{i + 1}", command, setup, cleanup) 
                ff += asdfasdf

                dd[command] += 1
                c += 1
            if flag:
                break
        if flag:
            break

    print(len(dd.keys()))
    print(c)
    data_to_csv(_data)
    with open("asdfaf.log", "w") as f:
        f.write(ff)
    print(f"===> {xxxxxcount}")
    # print(_data)

