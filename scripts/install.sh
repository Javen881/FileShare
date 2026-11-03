#!/usr/bin/env bash
# Fresh Ubuntu installation. Does not partition/format disks or change APT sources.
set -euo pipefail
test "$(id -u)" = 0 || { echo 'Run with sudo.' >&2; exit 1; }
: "${PUBLIC_ORIGIN:?Set PUBLIC_ORIGIN to the public HTTPS origin}"
: "${ADMIN_ORIGIN:?Set ADMIN_ORIGIN to the private HTTPS admin origin, usually port 8443}"
mountpoint -q /data || { echo '/data must already be mounted.' >&2; exit 1; }
test ! -e /data/abshare/current || { echo 'Already installed; use scripts/update.sh.' >&2; exit 1; }
src=$(cd -- "$(dirname -- "$0")/.." && pwd)
stage=$(mktemp -d /tmp/fileshare-config.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
python3 "$src/scripts/render_config.py" --public-origin "$PUBLIC_ORIGIN" --admin-origin "$ADMIN_ORIGIN" \
    --https-port "${HTTPS_PORT:-443}" --output "$stage"
if [ -n "${TLS_CERT:-}" ] || [ -n "${TLS_KEY:-}" ]; then
    test -r "${TLS_CERT:-}" && test -r "${TLS_KEY:-}" || { echo 'Provide both TLS_CERT and TLS_KEY.' >&2; exit 1; }
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv nginx openssl
id abshare >/dev/null 2>&1 || useradd --system --home-dir /data/abshare --shell /usr/sbin/nologin abshare
# Traversal only; existing files under /data retain their permissions.
chmod o+x /data
install -d -o root -g abshare -m 0751 /data/abshare
install -d -o root -g root -m 0755 /data/abshare/current
cp -a "$src/app" "$src/tests" "$src/requirements.txt" /data/abshare/current/
cp -a "$src/scripts" "$src/config" "$src/deploy" /data/abshare/current/
chown -R root:root /data/abshare/current
chmod -R a+rX /data/abshare/current
for dir in state files tmp logs; do install -d -o abshare -g abshare -m 0700 "/data/abshare/$dir"; done
install -d -o www-data -g www-data -m 0700 /data/abshare/nginx-temp
install -d -o root -g root -m 0700 /data/abshare/tls
install -o root -g abshare -m 0640 "$stage/config.json" /data/abshare/config.json
python3 -m venv /data/abshare/venv
/data/abshare/venv/bin/pip install -r /data/abshare/current/requirements.txt
/data/abshare/venv/bin/pip freeze > /data/abshare/requirements.lock
if [ -n "${TLS_CERT:-}" ]; then
    install -m 0644 "$TLS_CERT" /data/abshare/tls/server.crt
    install -m 0600 "$TLS_KEY" /data/abshare/tls/server.key
else
    openssl req -x509 -nodes -newkey rsa:3072 -days 90 \
        -keyout /data/abshare/tls/server.key -out /data/abshare/tls/server.crt \
        -subj '/CN=FileShare' -addext "$(cat "$stage/certificate-san.txt")"
    chmod 0600 /data/abshare/tls/server.key
    echo 'A temporary self-signed certificate was created (90 days).'
fi
install -o root -g abshare -m 0640 /data/abshare/tls/server.crt /data/abshare/public-certificate.crt
cd /data/abshare/current
runuser -u abshare -- env PYTHONDONTWRITEBYTECODE=1 TMPDIR=/data/abshare/tmp /data/abshare/venv/bin/python -m unittest discover -s tests -v
for user in A B; do runuser -u abshare -- /data/abshare/venv/bin/python -m app.admin add-user "$user"; done
ABSHARE_ROOT=/data/abshare PYTHONDONTWRITEBYTECODE=1 /data/abshare/venv/bin/python -m app.manage_admin
chown root:abshare /data/abshare/admin-auth.json
chmod 0640 /data/abshare/admin-auth.json
cat > /usr/local/bin/abshare <<'COMMAND'
#!/bin/sh
cd /data/abshare/current || exit 1
exec runuser -u abshare -- env ABSHARE_ROOT=/data/abshare PYTHONDONTWRITEBYTECODE=1 /data/abshare/venv/bin/python -m app.admin "$@"
COMMAND
chmod 0755 /usr/local/bin/abshare
install -m 0644 "$src/deploy/systemd/abshare.service" "$src/deploy/systemd/abshare-admin.service" /etc/systemd/system/
install -m 0644 "$src/deploy/nginx/proxy.conf" /etc/nginx/snippets/abshare-proxy.conf
install -m 0644 "$stage/nginx-public.conf" /etc/nginx/sites-available/abshare
install -m 0644 "$stage/nginx-admin.conf" /etc/nginx/sites-available/abshare-admin
ln -sfn /etc/nginx/sites-available/abshare /etc/nginx/sites-enabled/abshare
ln -sfn /etc/nginx/sites-available/abshare-admin /etc/nginx/sites-enabled/abshare-admin
install -m 0644 "$src/deploy/logrotate.conf" /etc/logrotate.d/abshare
nginx -t
systemctl daemon-reload
systemctl enable --now abshare abshare-admin nginx
systemctl reload nginx
systemctl is-active abshare abshare-admin nginx
printf 'Admin: %s\nPublic link prefix: %s\n' "$ADMIN_ORIGIN" "$PUBLIC_ORIGIN"
