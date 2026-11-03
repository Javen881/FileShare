import argparse
import json
import os
from pathlib import Path
import re
import time
from . import core


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='AB 文件共享管理（仅服务器命令行）')
    sub = parser.add_subparsers(dest='command', required=True)
    for action in ['add-user', 'invite', 'revoke']:
        p = sub.add_parser(action)
        p.add_argument('user')
    p = sub.add_parser('audit')
    p.add_argument('--limit', type=int, default=30)
    sub.add_parser('status')
    args = parser.parse_args()
    core.initialize()
    if hasattr(args, 'user') and not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', args.user):
        parser.error('用户名只能包含字母、数字、下划线或连字符，最长32个字符')
    if args.command == 'add-user':
        with core.db() as c:
            c.execute('INSERT OR IGNORE INTO users VALUES(?)', (args.user,))
        print('已添加用户：', args.user)
    elif args.command == 'invite':
        cfg = core.config()
        token, pin = core.issue(args.user, cfg)
        url = core.public_origin(cfg) + '/enter/' + token
        print(f'用户：{args.user}\n随机访问链接：{url}\n独立 PIN：{pin}\n有效期：{cfg["invite_seconds"]} 秒，成功使用一次后作废。请分开发送链接和 PIN。')
    elif args.command == 'revoke':
        with core.db() as c:
            c.execute('DELETE FROM invites WHERE user=?', (args.user,))
            c.execute('DELETE FROM sessions WHERE user=?', (args.user,))
        core.log(args.user, 'admin_revoke')
        print('已撤销访问链接及会话：', args.user)
    elif args.command == 'audit':
        with core.db() as c:
            for row in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT ?', (min(max(args.limit, 1), 1000),)):
                print(json.dumps(dict(row), ensure_ascii=False))
    else:
        now, cfg = time.time(), core.config()
        with core.db() as c:
            users = [r[0] for r in c.execute('SELECT name FROM users')]
            sessions = [dict(r) for r in c.execute('SELECT user,created,last FROM sessions WHERE created>? AND last>?', (now - cfg['lifetime_seconds'], now - cfg['idle_seconds']))]
            total = dict(c.execute('SELECT COUNT(*) AS files,COALESCE(SUM(size),0) AS bytes FROM files').fetchone())
        print(json.dumps(dict(users=users, sessions=sessions, **total), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
