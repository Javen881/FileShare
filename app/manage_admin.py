"""Run with sudo to initialize/reset the independent administrator credential."""
import json
import os
import secrets
import sys
from . import core


def main():
    os.umask(0o077)
    path = core.ROOT / 'admin-auth.json'
    if path.exists() and '--reset' not in sys.argv:
        print('管理员已配置，保留原密码。')
        return
    password, salt = secrets.token_urlsafe(18), secrets.token_hex(16)
    path.write_text(json.dumps({'user': 'admin', 'salt': salt, 'hash': core.pin_hash(password, salt)}))
    core.initialize()
    with core.db() as c:
        c.execute('DELETE FROM admin_sessions')
    print('管理员账户：admin\n管理员密码：' + password)


if __name__ == '__main__':
    main()
