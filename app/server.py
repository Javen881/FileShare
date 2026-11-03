import asyncio
from collections import defaultdict, deque
from contextlib import asynccontextmanager
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shutil
import time
import unicodedata
from urllib.parse import quote, urlsplit

from aiohttp import web
from . import core

COOKIE = '__Host-abshare'
STATIC = Path(__file__).parent / 'static'
SECURITY = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"}


def fail(status, message):
    if status == 413:
        raise web.HTTPRequestEntityTooLarge(max_size=0, actual_size=0, text=message)
    exception = {
        400: web.HTTPBadRequest, 401: web.HTTPUnauthorized, 403: web.HTTPForbidden,
        404: web.HTTPNotFound, 408: web.HTTPRequestTimeout, 409: web.HTTPConflict,
        413: web.HTTPRequestEntityTooLarge, 429: web.HTTPTooManyRequests,
        507: web.HTTPInsufficientStorage,
    }[status]
    raise exception(text=message)


def auth(request, csrf=False):
    key = core.digest(request.cookies.get(COOKIE, ''))
    with core.db() as c:
        s = c.execute('SELECT * FROM sessions WHERE token=?', (key,)).fetchone()
    cfg, now = request.app['cfg'], time.time()
    if not s or now - s['created'] >= cfg['lifetime_seconds'] or now - s['last'] >= cfg['idle_seconds']:
        fail(401, '授权已失效，请向管理员获取新访问链接。')
    if csrf and not secrets.compare_digest(request.headers.get('X-CSRF-Token', ''), s['csrf']):
        fail(403, '请求校验失败')
    return s


def touch(s):
    with core.db() as c:
        c.execute('UPDATE sessions SET last=? WHERE token=?', (time.time(), s['token']))


@web.middleware
async def protect(request, handler):
    try:
        origins = {request.app['cfg']['origin'], core.public_origin(request.app['cfg'])}
        if 'https://' + request.host not in origins:
            fail(403, '访问地址不匹配')
        if request.method not in ('GET', 'HEAD') and request.headers.get('Origin') != 'https://' + request.host:
            fail(403, '来源校验失败')
        response = await handler(request)
    except web.HTTPException as exc:
        response = web.json_response({'error': exc.text}, status=exc.status)
    except TimeoutError:
        response = web.json_response({'error': '传输超时，请重新登录或重试。'}, status=408)
    return response


async def headers(request, response):
    response.headers.update(SECURITY)


async def login(request):
    # Nginx overwrites X-Real-IP; the application only listens on loopback.
    ip = request.headers.get('X-Real-IP', request.remote or '')
    now = time.monotonic()
    bucket = request.app['attempts'][ip]
    while bucket and now - bucket[0] > 300:
        bucket.popleft()
    if len(bucket) >= 20:
        fail(429, '尝试过于频繁，请五分钟后重试。')
    bucket.append(now)
    try:
        body = await request.json()
        token, pin = body['token'], body['pin']
        if not isinstance(token, str) or not isinstance(pin, str) or len(token) > 100 or not re.fullmatch(r'\d{8}', pin):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        fail(400, '请输入八位 PIN')
    key = core.digest(token)
    success = False
    user = None
    with core.db() as c:
        c.execute('BEGIN IMMEDIATE')
        inv = c.execute('SELECT * FROM invites WHERE token=?', (key,)).fetchone()
        if inv and inv['expires'] > time.time() and inv['attempts'] < 5:
            user = inv['user']
            if secrets.compare_digest(core.pin_hash(pin, inv['salt']), inv['pin']):
                raw, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                now_wall = time.time()
                c.execute('DELETE FROM invites WHERE token=?', (key,))
                c.execute('DELETE FROM sessions WHERE user=?', (user,))
                c.execute('INSERT INTO sessions VALUES(?,?,?,?,?)', (core.digest(raw), user, csrf, now_wall, now_wall))
                success = True
            else:
                c.execute('UPDATE invites SET attempts=attempts+1 WHERE token=?', (key,))
    core.log(user, 'login_ok' if success else 'login_failed', ip)
    if not success:
        fail(401, '访问链接或 PIN 无效、已使用或已过期。')
    response = web.json_response({'ok': True})
    response.set_cookie(COOKIE, raw, secure=True, httponly=True, samesite='Strict', path='/', max_age=request.app['cfg']['lifetime_seconds'])
    return response


async def me(request):
    s = auth(request)
    cfg = request.app['cfg']
    return web.json_response(dict(user=s['user'], csrf=s['csrf'], idle_expires=s['last'] + cfg['idle_seconds'],
                                  expires=s['created'] + cfg['lifetime_seconds'], max_file_bytes=cfg['max_file_bytes']))


async def logout(request):
    s = auth(request, True)
    with core.db() as c:
        c.execute('DELETE FROM sessions WHERE token=?', (s['token'],))
    core.log(s['user'], 'logout')
    response = web.json_response({'ok': True})
    response.del_cookie(COOKIE, path='/', secure=True, httponly=True, samesite='Strict')
    return response


async def listing(request):
    auth(request)
    try:
        offset = max(0, int(request.query.get('offset', '0')))
    except ValueError:
        fail(400, '分页参数错误')
    folder = request.query.get('folder', '')
    try:
        info = core.folder_info(folder)
    except ValueError:
        fail(404, '文件夹不存在')
    with core.db() as c:
        rows = c.execute('SELECT f.* FROM files f LEFT JOIN file_locations l ON l.file_id=f.id WHERE f.id NOT IN (SELECT file_id FROM trash) AND COALESCE(l.folder_id,\'\')=? ORDER BY f.created DESC LIMIT 101 OFFSET ?', (folder, offset)).fetchall()
    return web.json_response(info | {'files': [dict(r) for r in rows[:100]], 'more': len(rows) > 100})


@asynccontextmanager
async def transfer(request, s):
    counts = request.app['active']
    if sum(counts.values()) >= 8 or counts[s['token']] >= 2:
        fail(429, '同时传输数量已达上限，请稍后重试。')
    counts[s['token']] += 1
    try:
        remaining = s['created'] + request.app['cfg']['lifetime_seconds'] - time.time()
        async with asyncio.timeout(max(0, remaining)):
            yield
    finally:
        counts[s['token']] -= 1
        if not counts[s['token']]:
            del counts[s['token']]


def filename(value):
    value = unicodedata.normalize('NFC', value)
    if not value or len(value.encode()) > 240 or value in ('.', '..') or any(ch in '/\\' or unicodedata.category(ch).startswith('C') for ch in value):
        fail(400, '文件名无效')
    return value


async def upload(request, *, auth_check=auth, lease=transfer, activity=touch):
    s = auth_check(request, True)
    cfg = request.app['cfg']
    name = filename(request.query.get('name', ''))
    folder = request.query.get('folder', '')
    try:
        core.folder_info(folder)
    except ValueError:
        fail(404, '文件夹不存在')
    length = request.content_length
    if length is None or length < 0:
        fail(400, '上传必须包含文件长度')
    if request.headers.get('Content-Encoding', 'identity') != 'identity':
        fail(400, '不支持压缩上传请求')
    if length > cfg['max_file_bytes']:
        fail(413, '文件超过大小限制')
    ident = secrets.token_hex(16)
    with core.db() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute('DELETE FROM upload_reservations WHERE updated<?', (time.time()-180,))
        total = c.execute('SELECT COALESCE(SUM(size),0) FROM files').fetchone()[0]
        reserved = c.execute('SELECT COALESCE(SUM(size),0) FROM upload_reservations').fetchone()[0]
        if total + reserved + length > cfg['quota_bytes'] or shutil.disk_usage(core.ROOT).free - reserved - length < cfg['reserve_bytes']:
            fail(507, '共享空间不足')
        c.execute('INSERT INTO upload_reservations VALUES(?,?,?)', (ident,length,time.time()))
    temp, dest = core.ROOT / 'tmp' / ident, core.ROOT / 'files' / ident
    count, finished = 0, False
    try:
        async with lease(request, s):
            with temp.open('xb') as f:
                while True:
                    auth_check(request)
                    chunk = await asyncio.wait_for(request.content.read(256 * 1024), cfg['stall_seconds'])
                    auth_check(request)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > length:
                        fail(400, '文件长度不匹配')
                    f.write(chunk)
                    activity(s)
                    with core.db() as c:
                        c.execute('UPDATE upload_reservations SET updated=? WHERE id=?', (time.time(),ident))
                if count != length:
                    fail(400, '文件传输不完整')
                f.flush()
                os.fsync(f.fileno())
            auth_check(request)
            temp.rename(dest)
            directory_fd = os.open(dest.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            with core.db() as c:
                c.execute('INSERT INTO files VALUES(?,?,?,?,?)', (ident, name, count, s['user'], time.time()))
                c.execute('INSERT INTO file_locations VALUES(?,?)', (ident,folder))
                c.execute('DELETE FROM upload_reservations WHERE id=?', (ident,))
            finished = True
            if count:
                activity(s)
        core.log(s['user'], 'upload_ok', json.dumps({'id': ident, 'name': name, 'bytes': count}, ensure_ascii=False))
        return web.json_response({'ok': True, 'id': ident}, status=201)
    finally:
        with core.db() as c:
            c.execute('DELETE FROM upload_reservations WHERE id=?', (ident,))
        temp.unlink(missing_ok=True)
        if not finished:
            dest.unlink(missing_ok=True)
            core.log(s['user'], 'upload_failed', json.dumps({'name': name, 'bytes': count}, ensure_ascii=False))


async def download(request):
    s = auth(request)
    ident = request.match_info['id']
    if not re.fullmatch('[0-9a-f]{32}', ident):
        fail(404, '文件不存在')
    with core.db() as c:
        row = c.execute('SELECT * FROM files WHERE id=? AND id NOT IN (SELECT file_id FROM trash)', (ident,)).fetchone()
    if row is None:
        fail(404, '文件不存在')
    response = web.StreamResponse(headers={'Content-Type': 'application/octet-stream',
        'Content-Length': str(row['size']), 'Content-Disposition': "attachment; filename*=UTF-8''" + quote(row['name'], safe=''),
        'X-Accel-Buffering': 'no'})
    count, finished = 0, False
    try:
        async with transfer(request, s):
            fd = os.open(core.ROOT / 'files' / ident, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as f:
                await response.prepare(request)
                while chunk := f.read(256 * 1024):
                    auth(request)
                    with core.db() as c:
                        if c.execute('SELECT 1 FROM trash WHERE file_id=?', (ident,)).fetchone():
                            fail(404, '文件已移入回收站')
                    await asyncio.wait_for(response.write(chunk), request.app['cfg']['stall_seconds'])
                    auth(request)
                    count += len(chunk)
                    touch(s)
                await asyncio.wait_for(response.write_eof(), request.app['cfg']['stall_seconds'])
                if count:
                    touch(s)
                finished = True
        return response
    except (TimeoutError, web.HTTPException, ConnectionError):
        if response.prepared:
            request.transport.close() if request.transport else None
            return response
        raise
    finally:
        core.log(s['user'], 'download_ok' if finished else 'download_failed', json.dumps({'id': ident, 'bytes': count}))


async def page(request):
    token = request.match_info.get('token', '')
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
        fail(403, '拒绝访问')
    with core.db() as c:
        invite = c.execute('SELECT expires,attempts FROM invites WHERE token=?', (core.digest(token),)).fetchone()
    if not invite or invite['expires'] <= time.time() or invite['attempts'] >= 5:
        fail(403, '访问链接无效或已失效')
    return web.FileResponse(STATIC / 'index.html')


async def session_page(request):
    auth(request)
    return web.FileResponse(STATIC / 'index.html')


async def asset(request):
    name = request.match_info['name']
    if name not in ('app.js', 'style.css'):
        fail(404, '不存在')
    return web.FileResponse(STATIC / name)


async def cleanup(app):
    while True:
        await asyncio.sleep(60)
        now, cfg = time.time(), app['cfg']
        with core.db() as c:
            c.execute('DELETE FROM invites WHERE expires<=? OR attempts>=5', (now,))
            c.execute('DELETE FROM sessions WHERE created<=? OR last<=?', (now - cfg['lifetime_seconds'], now - cfg['idle_seconds']))
        for ip, bucket in list(app['attempts'].items()):
            if not bucket or time.monotonic() - bucket[-1] > 300:
                del app['attempts'][ip]


async def lifecycle(app):
    task = asyncio.create_task(cleanup(app))
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def make_app(cfg=None):
    core.initialize()
    # Only one application process is run. Remove incomplete uploads from a prior crash.
    for partial in (core.ROOT / 'tmp').iterdir():
        if re.fullmatch('[0-9a-f]{32}', partial.name) and not partial.is_dir() and time.time()-partial.stat().st_mtime>180:
            partial.unlink()
    app = web.Application(middlewares=[protect], client_max_size=4096)
    app['cfg'] = cfg or core.config()
    app['attempts'] = defaultdict(deque)
    app['active'] = defaultdict(int)
    app['usage'] = {'reserved': 0}
    app.on_response_prepare.append(headers)
    app.cleanup_ctx.append(lifecycle)
    app.add_routes([web.get('/', page), web.get('/enter/{token}', page),
        web.get('/session', session_page), web.get('/assets/{name}', asset),
        web.post('/api/login', login), web.get('/api/me', me), web.post('/api/logout', logout),
        web.get('/api/files', listing), web.post('/api/upload', upload),
        web.get('/api/download/{id}', download, allow_head=False)])
    return app


if __name__ == '__main__':
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO)
    web.run_app(make_app(), host='127.0.0.1', port=8765, access_log=None)
