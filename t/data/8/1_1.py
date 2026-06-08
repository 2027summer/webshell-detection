import requests

r = requests.get("http://127.0.0.1:12345/download")

with open("/tmp/file", "wb") as f:
    f.write(r.content)