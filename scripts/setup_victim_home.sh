#!/usr/bin/env bash
set -eu

user=victim
home=/home/$user

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi

if ! id "$user" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$user"
fi

rm -rf "$home"
install -d -m 0755 -o "$user" -g "$user" "$home"
install -d -o "$user" -g "$user" \
    "$home/bin" \
    "$home/.ssh" \
    "$home/.cache" \
    "$home/.local" \
    "$home/dummy" \
    "$home/server" \

cat /home/ubuntu/victim_ed25519 > "$home/.ssh/authorized_keys"

for i in $(seq 1 40); do
    printf 'file %s\n' "$i" > "$home/dummy/file_$i.txt"
done

if [ -x obj/main ]; then
    cp obj/main "$home/bin/detection"
fi

if [ -x obj/tracer ]; then
    cp obj/tracer "$home/bin/tracer"
fi

chown -R "$user:$user" "$home"
chown -R "$user:$user" "$home/.ssh"
chown -R "$user:$user" "$home/server"
chmod 0700 "$home/.ssh"
chmod 0600 "$home/.ssh/authorized_keys"
# chmod 0600 "$home/.ssh/id_rsa"

git clone https://github.com/2027summer/board "$home/server"

python3 -m venv "$home/server/venv"
cd "$home/server"
$home/server/venv/bin/python -m pip install -e ".[dev]"