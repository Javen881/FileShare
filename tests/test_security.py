import asyncio
import json
from pathlib import Path
import tempfile
import time
import unittest
from aiohttp.test_utils import TestClient, TestServer
from app import core
from app.server import make_app, COOKIE


class SecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_root = core.ROOT
        core.ROOT = Path(self.tmp.name)
        self.cfg = core.DEFAULTS | {'origin': 'https://share.test', 'reserve_bytes': 0, 'max_file_bytes': 1024*1024}
        core.initialize()
        with core.db() as c:
            c.executemany('INSERT INTO users VALUES(?)', [('A',), ('B',)])
        self.client = TestClient(TestServer(make_app(self.cfg)))
        await self.client.start_server()
        self.headers = {'Host': 'share.test', 'Origin': self.cfg['origin']}

    async def asyncTearDown(self):
        await self.client.close()
        core.ROOT = self.old_root
        self.tmp.cleanup()

    async def request(self, method, path, headers=None, **kwargs):
        return await self.client.request(method, path, headers=self.headers | (headers or {}), **kwargs)

    async def sign_in(self, user='A'):
        token, pin = core.issue(user, self.cfg)
        r = await self.request('POST', '/api/login', json={'token': token, 'pin': pin})
        self.assertEqual(r.status, 200, await r.text())
        cookie = r.cookies[COOKIE]
        self.assertTrue(cookie['secure'])
        self.assertTrue(cookie['httponly'])
        h = {'Cookie': COOKIE + '=' + cookie.value}
        r = await self.request('GET', '/api/me', headers=h)
        h['X-CSRF-Token'] = (await r.json())['csrf']
        return h, token, pin

    async def test_unauthorized_and_csrf(self):
        r = await self.request('GET', '/api/files')
        self.assertEqual(r.status, 401)
        h, _, _ = await self.sign_in()
        r = await self.request('POST', '/api/upload?name=x', headers=h | {'Origin': 'https://evil.test'}, data=b'x')
        self.assertEqual(r.status, 403)
        r = await self.request('POST', '/api/upload?name=x', headers=h | {'X-CSRF-Token': 'bad'}, data=b'x')
        self.assertEqual(r.status, 403)

    async def test_invite_only_once_and_no_get_consumption(self):
        token, pin = core.issue('A', self.cfg)
        r = await self.request('GET', '/enter/' + token)
        self.assertEqual(r.status, 200)
        async def login():
            return await self.request('POST', '/api/login', json={'token': token, 'pin': pin})
        responses = await asyncio.gather(login(), login())
        self.assertEqual(sorted(r.status for r in responses), [200, 401])

    async def test_direct_home_and_invalid_links_denied(self):
        r = await self.request('GET', '/')
        self.assertEqual(r.status,403)
        r = await self.request('GET', '/session')
        self.assertEqual(r.status,401)
        r = await self.request('GET', '/enter/'+'x'*43)
        self.assertEqual(r.status,403)
        token,pin=core.issue('A',self.cfg)
        with core.db() as c:
            c.execute('UPDATE invites SET expires=0')
        r=await self.request('GET','/enter/'+token)
        self.assertEqual(r.status,403)
        h,token,pin=await self.sign_in()
        r=await self.request('GET','/enter/'+token,headers=h)
        self.assertEqual(r.status,403)
        r=await self.request('GET','/',headers=h)
        self.assertEqual(r.status,403)
        r=await self.request('GET','/session',headers=h)
        self.assertEqual(r.status,200)

    async def test_pin_lockout_and_expired_invite(self):
        token, pin = core.issue('A', self.cfg)
        bad = '00000000' if pin != '00000000' else '11111111'
        for _ in range(5):
            r = await self.request('POST', '/api/login', json={'token': token, 'pin': bad})
            self.assertEqual(r.status, 401)
        r = await self.request('POST', '/api/login', json={'token': token, 'pin': pin})
        self.assertEqual(r.status, 401)
        token, pin = core.issue('A', self.cfg)
        with core.db() as c:
            c.execute('UPDATE invites SET expires=0')
        r = await self.request('POST', '/api/login', json={'token': token, 'pin': pin})
        self.assertEqual(r.status, 401)

    async def test_shared_files_survive_expiry_and_no_overwrite(self):
        h, _, _ = await self.sign_in()
        ids = []
        for payload in (b'first', b'second'):
            r = await self.request('POST', '/api/upload?name=example.txt', headers=h, data=payload)
            self.assertEqual(r.status, 201, await r.text())
            ids.append((await r.json())['id'])
        self.assertNotEqual(*ids)
        hb, _, _ = await self.sign_in('B')
        r = await self.request('GET', '/api/download/' + ids[0], headers=hb)
        self.assertEqual(await r.read(), b'first')
        with core.db() as c:
            c.execute('UPDATE sessions SET last=0 WHERE user=?', ('A',))
        r = await self.request('GET', '/api/download/' + ids[0], headers=h)
        self.assertEqual(r.status, 401)
        self.assertTrue((core.ROOT / 'files' / ids[0]).exists())
        r = await self.request('GET', '/api/files', headers=hb)
        self.assertEqual(len((await r.json())['files']), 2)
        r = await self.request('GET', '/files/' + ids[0])
        self.assertEqual(r.status, 404)

    async def test_listing_does_not_renew_and_absolute_limit(self):
        h, _, _ = await self.sign_in()
        with core.db() as c:
            original = c.execute('SELECT last FROM sessions').fetchone()[0]
        await self.request('GET', '/api/files', headers=h)
        await self.request('GET', '/api/me', headers=h)
        with core.db() as c:
            self.assertEqual(c.execute('SELECT last FROM sessions').fetchone()[0], original)
            c.execute('UPDATE sessions SET created=0')
        r = await self.request('POST', '/api/upload?name=x', headers=h, data=b'x')
        self.assertEqual(r.status, 401)

    async def test_traversal_size_and_quota(self):
        h, _, _ = await self.sign_in()
        r = await self.request('POST', '/api/upload?name=..%2Fsecret', headers=h, data=b'x')
        self.assertEqual(r.status, 400)
        r = await self.request('POST', '/api/upload?name=x', headers=h, data=b'x'*(1024*1024+1))
        self.assertEqual(r.status, 413)
        self.cfg['quota_bytes'] = 1
        r = await self.request('POST', '/api/upload?name=x', headers=h, data=b'xx')
        self.assertEqual(r.status, 507)

    async def test_revoke_and_single_session(self):
        old, _, _ = await self.sign_in()
        new, _, _ = await self.sign_in()
        r = await self.request('GET', '/api/me', headers=old)
        self.assertEqual(r.status, 401)
        with core.db() as c:
            c.execute('DELETE FROM sessions')
        r = await self.request('GET', '/api/me', headers=new)
        self.assertEqual(r.status, 401)

    async def test_transfer_renews_and_stalled_upload_is_removed(self):
        h, _, _ = await self.sign_in()
        with core.db() as c:
            c.execute('UPDATE sessions SET last=?', (time.time()-100,))
        r = await self.request('POST', '/api/upload?name=x', headers=h, data=b'123')
        self.assertEqual(r.status, 201)
        with core.db() as c:
            self.assertLess(time.time()-c.execute('SELECT last FROM sessions').fetchone()[0], 3)
        self.cfg['stall_seconds'] = .1
        async def slow():
            yield b'x'
            await asyncio.sleep(.5)
            yield b'y'
        r = await self.request('POST', '/api/upload?name=slow', headers=h | {'Content-Length': '2'}, data=slow())
        self.assertEqual(r.status, 408)
        self.assertEqual(list((core.ROOT/'tmp').iterdir()), [])

    async def test_active_transfer_survives_idle_but_not_absolute_limit(self):
        h, _, _ = await self.sign_in()
        self.cfg['idle_seconds'] = .25
        async def streaming():
            for _ in range(8):
                yield b'x'
                await asyncio.sleep(.06)
        r = await self.request('POST', '/api/upload?name=active', headers=h | {'Content-Length': '8'}, data=streaming())
        self.assertEqual(r.status, 201, await r.text())
        self.cfg['lifetime_seconds'] = .15
        with core.db() as c:
            c.execute('UPDATE sessions SET created=?,last=?', (time.time(), time.time()))
        r = await self.request('POST', '/api/upload?name=absolute', headers=h | {'Content-Length': '8'}, data=streaming())
        self.assertIn(r.status, (401, 408))
        self.assertEqual(list((core.ROOT/'tmp').iterdir()), [])

    async def test_revocation_interrupts_upload(self):
        h, _, _ = await self.sign_in()
        async def revoked_stream():
            yield b'x'
            await asyncio.sleep(.05)
            with core.db() as c:
                c.execute('DELETE FROM sessions')
            yield b'y'
        r = await self.request('POST', '/api/upload?name=revoked', headers=h | {'Content-Length': '2'}, data=revoked_stream())
        self.assertEqual(r.status, 401)
        self.assertEqual(list((core.ROOT/'tmp').iterdir()), [])
        self.assertEqual(list((core.ROOT/'files').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
