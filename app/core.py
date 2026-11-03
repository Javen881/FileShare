import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from urllib.parse import urlsplit

ROOT = Path(os.environ.get('ABSHARE_ROOT', '/data/abshare'))
DEFAULTS = dict(origin='https://files.example.com', idle_seconds=900,
                lifetime_seconds=7200, invite_seconds=300,
                max_file_bytes=10 * 1024**3, quota_bytes=1500 * 1024**3,
                reserve_bytes=5 * 1024**3, stall_seconds=60)


def config():
    return DEFAULTS | json.loads((ROOT / 'config.json').read_text())


@contextlib.contextmanager
def db():
    conn = sqlite3.connect(ROOT / 'state/database.sqlite3', timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def initialize():
    for d in ['state', 'files', 'tmp', 'logs']:
        (ROOT / d).mkdir(mode=0o700, parents=True, exist_ok=True)
    with db() as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS invites(token TEXT PRIMARY KEY, user TEXT NOT NULL,
          pin TEXT NOT NULL, salt TEXT NOT NULL, expires REAL NOT NULL, attempts INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user TEXT UNIQUE NOT NULL,
          csrf TEXT NOT NULL, created REAL NOT NULL, last REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, name TEXT NOT NULL,
          size INTEGER NOT NULL, user TEXT NOT NULL, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at REAL NOT NULL,
          user TEXT, action TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS trash(file_id TEXT PRIMARY KEY, deleted REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS admin_sessions(token TEXT PRIMARY KEY, csrf TEXT NOT NULL,
          created REAL NOT NULL, last REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS folders(id TEXT PRIMARY KEY, name TEXT NOT NULL,
          parent TEXT NOT NULL DEFAULT '', created REAL NOT NULL, UNIQUE(parent,name));
        CREATE TABLE IF NOT EXISTS file_locations(file_id TEXT PRIMARY KEY, folder_id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS upload_reservations(id TEXT PRIMARY KEY, size INTEGER NOT NULL, updated REAL NOT NULL);
        ''')


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def pin_hash(pin, salt):
    return hashlib.scrypt(pin.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def log(user, action, detail=''):
    with db() as c:
        c.execute('INSERT INTO audit(at,user,action,detail) VALUES(?,?,?,?)',
                  (time.time(), user, action, detail))


def issue(user, cfg):
    token, pin, salt = secrets.token_urlsafe(32), f'{secrets.randbelow(100000000):08d}', secrets.token_hex(16)
    with db() as c:
        if not c.execute('SELECT 1 FROM users WHERE name=?', (user,)).fetchone():
            raise ValueError('用户不存在')
        c.execute('DELETE FROM invites WHERE user=?', (user,))
        c.execute('INSERT INTO invites(token,user,pin,salt,expires) VALUES(?,?,?,?,?)',
                  (digest(token), user, pin_hash(pin, salt), salt, time.time() + cfg['invite_seconds']))
    log(user, 'invite_created')
    return token, pin


def public_origin(cfg=None):
    with db() as c:
        row = c.execute("SELECT value FROM settings WHERE key='public_origin'").fetchone()
    return row[0] if row else (cfg or config())['origin']


def validate_origin(value):
    if not isinstance(value, str) or len(value)>250:
        raise ValueError('请输入有效的 HTTPS 地址')
    value = value.strip().rstrip('/')
    u = urlsplit(value)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.path or u.query or u.fragment or any(ch.isspace() for ch in value):
        raise ValueError('前缀必须是 HTTPS 域名及可选端口，不包含路径、账户或参数')
    if u.port is not None and not 1 <= u.port <= 65535:
        raise ValueError('端口无效')
    return value


def folder_info(ident):
    with db() as c:
        trail, current = [], ident
        for _ in range(128):
            if not current:
                break
            row = c.execute('SELECT * FROM folders WHERE id=?', (current,)).fetchone()
            if row is None:
                raise ValueError('文件夹不存在')
            trail.append(dict(row))
            current = row['parent']
        else:
            raise ValueError('文件夹层级过深')
        children = [dict(r) for r in c.execute('SELECT * FROM folders WHERE parent=? ORDER BY name', (ident,))]
    return {'folder': ident, 'path': list(reversed(trail)), 'folders': children}
