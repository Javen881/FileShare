import asyncio
from collections import deque
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import time
from urllib.parse import quote, urlsplit
from aiohttp import web
from . import core
from .server import fail, headers, filename, upload as shared_upload

COOKIE = '__Host-abshare-admin'
STATIC = Path(__file__).parent / 'admin_static'


def auth(request, csrf=False, renew=True):
    key = core.digest(request.cookies.get(COOKIE, ''))
    now = time.time()
    with core.db() as c:
        s = c.execute('SELECT * FROM admin_sessions WHERE token=?', (key,)).fetchone()
        if not s or now-s['created'] >= 28800 or now-s['last'] >= 1800:
            fail(401, '管理员登录已失效')
        if csrf and not secrets.compare_digest(request.headers.get('X-CSRF-Token', ''), s['csrf']):
            fail(403, '请求校验失败')
        if renew:
            c.execute('UPDATE admin_sessions SET last=? WHERE token=?', (now, key))
    return s


@web.middleware
async def protect(request, handler):
    try:
        if request.host != urlsplit(request.app['origin']).netloc:
            fail(403, '管理入口地址不匹配')
        if request.method not in ('GET', 'HEAD') and request.headers.get('Origin') != request.app['origin']:
            fail(403, '来源校验失败')
        return await handler(request)
    except web.HTTPException as exc:
        return web.json_response({'error': exc.text}, status=exc.status)
    except (ValueError, TypeError, KeyError):
        return web.json_response({'error': '请求参数无效'}, status=400)


async def login(request):
    bucket, now = request.app['attempts'], time.monotonic()
    while bucket and now-bucket[0] > 300:
        bucket.popleft()
    if len(bucket) >= 20:
        fail(429, '登录尝试过多，五分钟后重试')
    bucket.append(now)
    body = await request.json()
    user, password = body.get('user', ''), body.get('password', '')
    if not isinstance(user, str) or not isinstance(password, str) or len(password) > 128:
        fail(400, '账户或密码格式无效')
    credential = json.loads((core.ROOT/'admin-auth.json').read_text())
    valid = secrets.compare_digest(core.pin_hash(password, credential['salt']), credential['hash'])
    if not valid or not secrets.compare_digest(user, credential['user']):
        core.log('admin', 'admin_login_failed', request.headers.get('X-Real-IP', ''))
        fail(401, '账户或密码不正确')
    raw, csrf, now = secrets.token_urlsafe(32), secrets.token_urlsafe(32), time.time()
    with core.db() as c:
        c.execute('DELETE FROM admin_sessions WHERE created<? OR last<?', (now-28800, now-1800))
        c.execute('INSERT INTO admin_sessions VALUES(?,?,?,?)', (core.digest(raw), csrf, now, now))
    core.log('admin', 'admin_login_ok', request.headers.get('X-Real-IP', ''))
    response = web.json_response({'ok': True})
    response.set_cookie(COOKIE, raw, path='/', secure=True, httponly=True, samesite='Strict', max_age=28800)
    return response


async def me(request):
    s = auth(request)
    return web.json_response({'user': 'admin', 'csrf': s['csrf']})


async def logout(request):
    s = auth(request, True)
    with core.db() as c:
        c.execute('DELETE FROM admin_sessions WHERE token=?', (s['token'],))
    response = web.json_response({'ok': True})
    response.del_cookie(COOKIE, path='/', secure=True, httponly=True, samesite='Strict')
    return response


async def overview(request):
    auth(request)
    now, cfg = time.time(), core.config()
    with core.db() as c:
        count = dict(c.execute('SELECT COUNT(*) AS count,COALESCE(SUM(size),0) AS bytes FROM files WHERE id NOT IN (SELECT file_id FROM trash)').fetchone())
        trash = dict(c.execute('SELECT COUNT(*) AS count,COALESCE(SUM(size),0) AS bytes FROM files WHERE id IN (SELECT file_id FROM trash)').fetchone())
        users = [r[0] for r in c.execute('SELECT name FROM users ORDER BY name')]
        sessions = [dict(r) for r in c.execute('SELECT user,created,last FROM sessions WHERE created>? AND last>?', (now-cfg['lifetime_seconds'], now-cfg['idle_seconds']))]
    return web.json_response({'files': count, 'trash': trash, 'free': shutil.disk_usage(core.ROOT).free,
                              'users': users, 'sessions': sessions})


async def files(request):
    auth(request)
    offset = max(0, int(request.query.get('offset', '0')))
    query = request.query.get('q', '')[:240]
    deleted = request.query.get('trash') == '1'
    folder = request.query.get('folder', '')
    info = core.folder_info(folder)
    with core.db() as c:
        rows = c.execute('SELECT f.*,t.deleted FROM files f LEFT JOIN trash t ON t.file_id=f.id LEFT JOIN file_locations l ON l.file_id=f.id '
                         'WHERE (t.file_id IS NOT NULL)=? AND instr(lower(f.name),lower(?))>0 '
                         'AND (? OR COALESCE(l.folder_id,\'\')=?) ORDER BY f.created DESC LIMIT 101 OFFSET ?', (deleted, query, deleted, folder, offset)).fetchall()
    return web.json_response(info | {'files': [dict(r) for r in rows[:100]], 'more': len(rows)>100})


async def new_folder(request):
    auth(request, True)
    body = await request.json()
    name, parent = filename(body['name']), body.get('parent', '')
    info = core.folder_info(parent)
    if len(info['path']) >= 30:
        fail(400, '文件夹层级最多 30 层')
    ident = secrets.token_hex(16)
    with core.db() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT 1 FROM folders WHERE parent=? AND name=?', (parent,name)).fetchone():
            fail(409, '当前目录已有同名文件夹')
        c.execute('INSERT INTO folders VALUES(?,?,?,?)', (ident,name,parent,time.time()))
    core.log('admin', 'folder_created', json.dumps({'id':ident,'name':name,'parent':parent},ensure_ascii=False))
    return web.json_response({'id':ident}, status=201)


def upload_auth(request, csrf=False):
    return dict(auth(request, csrf)) | {'user':'admin'}


@asynccontextmanager
async def upload_lease(request, s):
    active = request.app['active']
    if active['count'] >= 4:
        fail(429, '管理端并发传输已达上限')
    active['count'] += 1
    try:
        async with asyncio.timeout(max(0,s['created']+28800-time.time())):
            yield
    finally:
        active['count'] -= 1


async def upload(request):
    return await shared_upload(request, auth_check=upload_auth, lease=upload_lease, activity=lambda s:None)


async def settings(request):
    auth(request, request.method=='POST')
    if request.method=='POST':
        body = await request.json()
        try:
            origin = core.validate_origin(body.get('public_origin'))
        except ValueError as e:
            fail(400,str(e))
        with core.db() as c:
            c.execute('INSERT OR REPLACE INTO settings VALUES(?,?)', ('public_origin',origin))
        core.log('admin','public_origin_changed',origin)
    return web.json_response({'public_origin':core.public_origin()})


async def change_file(request):
    auth(request, True)
    ident, action = request.match_info['id'], request.match_info['action']
    if action not in ('trash', 'restore') or not re.fullmatch('[a-f0-9]{32}', ident):
        fail(404, '操作不存在')
    with core.db() as c:
        c.execute('BEGIN IMMEDIATE')
        row = c.execute('SELECT name FROM files WHERE id=?', (ident,)).fetchone()
        if not row:
            fail(404, '文件不存在')
        if action == 'trash':
            c.execute('INSERT OR IGNORE INTO trash VALUES(?,?)', (ident, time.time()))
        else:
            c.execute('DELETE FROM trash WHERE file_id=?', (ident,))
        c.execute('INSERT INTO audit(at,user,action,detail) VALUES(?,?,?,?)',
                  (time.time(), 'admin', 'file_'+action, json.dumps({'id': ident, 'name': row['name']}, ensure_ascii=False)))
    return web.json_response({'ok': True})


async def user_action(request):
    auth(request, True)
    body = await request.json()
    user, action = body.get('user', ''), request.match_info['action']
    if not isinstance(user, str) or not re.fullmatch('[A-Za-z0-9_-]{1,32}', user):
        fail(400, '用户名限字母、数字、下划线、连字符，最长32位')
    if action == 'add':
        with core.db() as c:
            c.execute('INSERT OR IGNORE INTO users VALUES(?)', (user,))
        core.log('admin', 'user_add', user)
    elif action == 'invite':
        cfg = core.config()
        token, pin = core.issue(user, cfg)
        return web.json_response({'url': core.public_origin(cfg)+'/enter/'+token, 'pin': pin, 'seconds': cfg['invite_seconds']})
    elif action == 'revoke':
        with core.db() as c:
            c.execute('DELETE FROM invites WHERE user=?', (user,))
            c.execute('DELETE FROM sessions WHERE user=?', (user,))
        core.log('admin', 'admin_revoke', user)
    else:
        fail(404, '操作不存在')
    return web.json_response({'ok': True})


async def audit(request):
    auth(request)
    offset = max(0, int(request.query.get('offset', '0')))
    with core.db() as c:
        rows = c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 101 OFFSET ?', (offset,)).fetchall()
    return web.json_response({'records': [dict(r) for r in rows[:100]], 'more': len(rows)>100})


async def download(request):
    s = auth(request)
    ident = request.match_info['id']
    if not re.fullmatch('[a-f0-9]{32}', ident):
        fail(404, '文件不存在')
    with core.db() as c:
        row = c.execute('SELECT * FROM files WHERE id=?', (ident,)).fetchone()
    if not row:
        fail(404, '文件不存在')
    active = request.app['active']
    if active['count'] >= 4:
        fail(429, '管理下载并发已达上限')
    response = web.StreamResponse(headers={'Content-Type': 'application/octet-stream', 'Content-Length': str(row['size']),
        'Content-Disposition': "attachment; filename*=UTF-8''"+quote(row['name'], safe=''), 'X-Accel-Buffering': 'no'})
    active['count'] += 1
    count, completed = 0, False
    try:
        async with asyncio.timeout(max(0, s['created']+28800-time.time())):
            fd = os.open(core.ROOT/'files'/ident, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as f:
                await response.prepare(request)
                while chunk := f.read(256*1024):
                    auth(request)
                    await asyncio.wait_for(response.write(chunk), 60)
                    count += len(chunk)
                await asyncio.wait_for(response.write_eof(), 60)
                completed = True
        return response
    except (TimeoutError, web.HTTPException, ConnectionError):
        if response.prepared:
            if request.transport:
                request.transport.close()
            return response
        raise
    finally:
        active['count'] -= 1
        core.log('admin', 'admin_download_ok' if completed else 'admin_download_failed', json.dumps({'id': ident, 'bytes': count}))


async def page(request):
    return web.FileResponse(STATIC/'index.html')


async def asset(request):
    name = request.match_info['name']
    if name not in ('admin.js', 'admin.css'):
        fail(404, '文件不存在')
    return web.FileResponse(STATIC/name)


def make_app(origin=None):
    core.initialize()
    app = web.Application(middlewares=[protect], client_max_size=4096)
    app['origin'], app['attempts'], app['active'] = origin or core.config().get('admin_origin', 'https://127.0.0.1:8443'), deque(), {'count': 0}
    app['cfg'] = core.config()
    app.on_response_prepare.append(headers)
    app.add_routes([web.get('/', page), web.get('/assets/{name}', asset),
        web.post('/api/login', login), web.get('/api/me', me), web.post('/api/logout', logout),
        web.get('/api/overview', overview), web.get('/api/files', files),
        web.post('/api/folders', new_folder), web.post('/api/upload', upload),
        web.get('/api/settings', settings), web.post('/api/settings', settings),
        web.post('/api/files/{id}/{action}', change_file), web.get('/api/download/{id}', download, allow_head=False),
        web.post('/api/users/{action}', user_action), web.get('/api/audit', audit)])
    return app


if __name__ == '__main__':
    os.umask(0o077)
    web.run_app(make_app(), host='127.0.0.1', port=8766, access_log=None)
