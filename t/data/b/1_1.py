import requests
with open('dump_.sql', 'rb') as f:
    res = requests.post(
        'http://127.0.0.1:12345/upload',
        files={'file': f},
    )

result = res.text