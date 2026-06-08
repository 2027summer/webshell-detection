#!/bin/bash
set -e

cd ~/server

rm -rf static/uploads/*
rm -rf tool/chromium/*
rm -f board.db


./venv/bin/celery -A app.celery_app worker 2>&1 > /dev/null &
WORKER_PID=$!

# /home/victim/bin/tracer -o 1.json ./venv/bin/uvicorn app.main:app --port 9991 &
/home/victim/bin/detection ./venv/bin/uvicorn app.main:app --port 9991 2> ~/test/xxx.log &
SERVER_PID=$!

trap 'kill $WORKER_PID && kill $SERVER_PID' EXIT

for i in {1..30}; do
  if curl -fsS http://127.0.0.1:9991/ >/dev/null; then
    break
  fi
  printf '[%s/30] waiting for fastapi\n' "$i" >&2
  sleep 1
done

./venv/bin/python /home/victim/test/run.py --base-url=http://127.0.0.1:9991
