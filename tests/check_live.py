"""Explicit live HTTPS smoke test; run as the service user with a public cert path.
Creates only a temporary test user/file and removes exactly those records afterwards.
"""
import http.cookiejar
import json
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from app import core


def main():
    cfg = core.config()
    origin = cfg['origin']
    ctx = ssl.create_default_context(cafile=sys.argv[1])
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(jar))
    user = '_test_' + secrets.token_hex(5)
    ident = None

    def request(path, body=None, csrf=None, content_type='application/json'):
        headers = {'Origin': origin}
        if body is not None:
            headers['Content-Type'] = content_type
        if csrf:
            headers['X-CSRF-Token'] = csrf
        req = urllib.request.Request(origin+path, data=body, headers=headers)
        with client.open(req, timeout=20) as response:
            return response.status, response.read(), response.headers

    try:
        with core.db() as c:
            c.execute('INSERT INTO users VALUES(?)', (user,))
        try:
            request('/api/files')
            raise AssertionError('Anonymous access was not denied')
        except urllib.error.HTTPError as e:
            assert e.code == 401, e.code
        try:
            request('/')
            raise AssertionError('Direct home access was not denied')
        except urllib.error.HTTPError as e:
            assert e.code == 403, e.code
        token, pin = core.issue(user, cfg)
        assert request('/enter/'+token)[0] == 200
        body = json.dumps({'token': token, 'pin': pin}).encode()
        status, _, headers = request('/api/login', body)
        assert status == 200
        assert 'HttpOnly' in headers['Set-Cookie'] and 'Secure' in headers['Set-Cookie']
        _, body, _ = request('/api/me')
        csrf = json.loads(body)['csrf']
        payload = '共享系统部署验证\n'.encode() + secrets.token_bytes(1024 * 1024)
        name = urllib.parse.quote('部署验证-临时文件.txt')
        status, body, _ = request('/api/upload?name='+name, payload, csrf, 'application/octet-stream')
        assert status == 201, status
        ident = json.loads(body)['id']
        status, downloaded, headers = request('/api/download/'+ident)
        assert status == 200 and downloaded == payload
        assert headers['X-Content-Type-Options'] == 'nosniff'
        _, listing, _ = request('/api/files')
        assert any(f['id'] == ident for f in json.loads(listing)['files'])
        with core.db() as c:
            c.execute('UPDATE sessions SET last=0 WHERE user=?', (user,))
        try:
            request('/api/download/'+ident)
            raise AssertionError('Expired session was not denied')
        except urllib.error.HTTPError as e:
            assert e.code == 401, e.code
        assert (core.ROOT/'files'/ident).exists()
        print('LIVE_HTTPS_OK: certificate verified, anonymous denied, PIN login, 1MiB upload/download identical, expired access denied, file retained')
    finally:
        with core.db() as c:
            rows = list(c.execute('SELECT id FROM files WHERE user=?', (user,)))
            for row in rows:
                (core.ROOT/'files'/row['id']).unlink(missing_ok=True)
                c.execute('DELETE FROM file_locations WHERE file_id=?',(row['id'],))
            c.execute('DELETE FROM files WHERE user=?', (user,))
            c.execute('DELETE FROM sessions WHERE user=?', (user,))
            c.execute('DELETE FROM invites WHERE user=?', (user,))
            c.execute('DELETE FROM users WHERE name=?', (user,))
        print('LIVE_TEST_DATA_CLEANED')


if __name__ == '__main__':
    main()
