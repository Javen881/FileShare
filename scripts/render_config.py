"""Render configuration without changing the host. Uses only Python's stdlib."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

PROJECT = Path(__file__).resolve().parents[1]


def origin(value):
    value = value.rstrip('/')
    u = urlsplit(value)
    if (u.scheme != 'https' or not u.hostname or u.username or u.password
            or u.path or u.query or u.fragment
            or not re.fullmatch(r'[A-Za-z0-9.-]+', u.hostname)
            or any(ch.isspace() for ch in value)):
        raise ValueError('Use an HTTPS DNS name or IPv4 address, with optional port and no path')
    if u.port is not None and not 1 <= u.port <= 65535:
        raise ValueError('Invalid port')
    return value, u


def render(public, admin, port, output):
    public, pub = origin(public)
    admin, adm = origin(admin)
    admin_port = adm.port or 443
    if not 1 <= port <= 65535 or port == admin_port or {port, admin_port} & {22, 8765, 8766}:
        raise ValueError('Public/admin listener ports must differ and cannot use 22, 8765 or 8766')
    output.mkdir(parents=True, exist_ok=True)
    cfg = json.loads((PROJECT/'config/config.example.json').read_text())
    cfg.update(origin=public, admin_origin=admin)
    (output/'config.json').write_text(json.dumps(cfg, ensure_ascii=False, indent=2)+'\n')
    substitutions = {'__PUBLIC_HOST__': pub.hostname, '__ADMIN_HOST__': adm.hostname,
                     '__HTTPS_PORT__': str(port), '__ADMIN_PORT__': str(admin_port)}
    for kind in ('public', 'admin'):
        content = (PROJECT/f'deploy/nginx/{kind}.conf.in').read_text()
        for key, value in substitutions.items():
            content = content.replace(key, value)
        (output/f'nginx-{kind}.conf').write_text(content)
    sans = []
    for host in dict.fromkeys([pub.hostname, adm.hostname]):
        try:
            ipaddress.ip_address(host)
            sans.append('IP:'+host)
        except ValueError:
            sans.append('DNS:'+host)
    (output/'certificate-san.txt').write_text('subjectAltName='+','.join(sans))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--public-origin', required=True)
    p.add_argument('--admin-origin', required=True)
    p.add_argument('--https-port', type=int, default=443, help='Internal public listener, before any NAT')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        render(a.public_origin, a.admin_origin, a.https_port, a.output)
    except ValueError as exc:
        p.error(str(exc))


if __name__ == '__main__':
    main()
