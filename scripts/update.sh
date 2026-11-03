#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" = 0
mountpoint -q /data
test -f /data/abshare/config.json
src=$(cd -- "$(dirname -- "$0")/.." && pwd)
test "$src" != /data/abshare/current || { echo 'Run from a separate checkout.' >&2; exit 1; }
backup=/data/abshare/backups/update-$(date +%Y%m%d-%H%M%S)
install -d -m 0700 "$backup"
systemctl stop abshare abshare-admin
cp -a /data/abshare/current "$backup/current"
cp -a /data/abshare/config.json /data/abshare/admin-auth.json "$backup/"
python3 - "$backup/database.sqlite3" <<'PY'
import sqlite3, sys
with sqlite3.connect('/data/abshare/state/database.sqlite3') as source, sqlite3.connect(sys.argv[1]) as destination:
    source.backup(destination)
PY
printf 'Backup: %s\n' "$backup"
cp -a "$src/app/." /data/abshare/current/app/
cp -a "$src/tests/." /data/abshare/current/tests/
cp -a "$src/scripts" "$src/config" "$src/deploy" "$src/requirements.txt" /data/abshare/current/
chown -R root:root /data/abshare/current
chmod -R a+rX /data/abshare/current
/data/abshare/venv/bin/pip install -r /data/abshare/current/requirements.txt
cd /data/abshare/current
runuser -u abshare -- env PYTHONDONTWRITEBYTECODE=1 TMPDIR=/data/abshare/tmp /data/abshare/venv/bin/python -m unittest discover -s tests -v
runuser -u abshare -- env ABSHARE_ROOT=/data/abshare PYTHONDONTWRITEBYTECODE=1 /data/abshare/venv/bin/python -c 'from app import core; core.initialize()'
systemctl start abshare abshare-admin
systemctl is-active abshare abshare-admin
echo 'Application updated. Existing origins, TLS, Nginx and systemd settings were preserved.'
