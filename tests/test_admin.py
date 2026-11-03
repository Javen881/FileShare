import json
import secrets
import time
from aiohttp.test_utils import TestClient, TestServer
from app import core
from app.admin_server import make_app, COOKIE
import unittest
from tests import test_security


class AdminTests(unittest.IsolatedAsyncioTestCase):
    request = test_security.SecurityTests.request
    sign_in = test_security.SecurityTests.sign_in
    async def asyncSetUp(self):
        await test_security.SecurityTests.asyncSetUp(self)
        (core.ROOT/'config.json').write_text(json.dumps(self.cfg))
        salt = secrets.token_hex(16)
        (core.ROOT/'admin-auth.json').write_text(json.dumps({'user':'admin','salt':salt,'hash':core.pin_hash('test-admin-pass',salt)}))
        self.admin = TestClient(TestServer(make_app('https://share.test:8443')))
        await self.admin.start_server()
        self.ah = {'Host':'share.test:8443','Origin':'https://share.test:8443'}

    async def asyncTearDown(self):
        await self.admin.close()
        await test_security.SecurityTests.asyncTearDown(self)

    async def admin_login(self):
        r = await self.admin.post('/api/login',headers=self.ah,json={'user':'admin','password':'test-admin-pass'})
        self.assertEqual(r.status,200)
        self.ah['Cookie'] = COOKIE+'='+r.cookies[COOKIE].value
        r = await self.admin.get('/api/me',headers=self.ah)
        self.ah['X-CSRF-Token'] = (await r.json())['csrf']

    async def test_admin_separate_auth_and_csrf(self):
        guest,_,_=await self.sign_in()
        r=await self.admin.get('/api/files',headers=self.ah|{'Cookie':guest['Cookie']})
        self.assertEqual(r.status,401)
        r=await self.admin.post('/api/login',headers=self.ah,json={'user':'admin','password':'wrong'})
        self.assertEqual(r.status,401)
        await self.admin_login()
        r=await self.admin.post('/api/users/add',headers=self.ah|{'Origin':'https://share.test'},json={'user':'C'})
        self.assertEqual(r.status,403)
        r=await self.admin.post('/api/users/add',headers=self.ah|{'X-CSRF-Token':'wrong'},json={'user':'C'})
        self.assertEqual(r.status,403)
        r=await self.request('GET','/api/overview',headers={'Cookie':self.ah['Cookie']})
        self.assertEqual(r.status,404)
        with core.db() as c:
            c.execute('UPDATE admin_sessions SET last=0')
        r=await self.admin.get('/api/me',headers=self.ah)
        self.assertEqual(r.status,401)

    async def test_admin_trash_restore_search_and_download(self):
        h,_,_=await self.sign_in()
        r=await self.request('POST','/api/upload?name=report.txt',headers=h,data=b'preserve me')
        ident=(await r.json())['id']
        await self.admin_login()
        r=await self.admin.get('/api/files?q=report',headers=self.ah)
        self.assertEqual((await r.json())['files'][0]['id'],ident)
        r=await self.admin.post('/api/files/'+ident+'/trash',headers=self.ah,json={})
        self.assertEqual(r.status,200)
        r=await self.request('GET','/api/download/'+ident,headers=h)
        self.assertEqual(r.status,404)
        r=await self.request('GET','/api/files',headers=h)
        self.assertEqual((await r.json())['files'],[])
        r=await self.admin.get('/api/files?trash=1',headers=self.ah)
        self.assertEqual((await r.json())['files'][0]['id'],ident)
        r=await self.admin.get('/api/download/'+ident,headers=self.ah)
        self.assertEqual(await r.read(),b'preserve me')
        r=await self.admin.post('/api/files/'+ident+'/restore',headers=self.ah,json={})
        self.assertEqual(r.status,200)
        r=await self.request('GET','/api/download/'+ident,headers=h)
        self.assertEqual(await r.read(),b'preserve me')

    async def test_admin_invite_revoke_and_audit(self):
        await self.admin_login()
        r=await self.admin.post('/api/users/add',headers=self.ah,json={'user':'C'})
        self.assertEqual(r.status,200)
        r=await self.admin.post('/api/users/invite',headers=self.ah,json={'user':'C'})
        invite=await r.json()
        r=await self.request('POST','/api/login',json={'token':invite['url'].split('/enter/')[1],'pin':invite['pin']})
        self.assertEqual(r.status,200)
        r=await self.admin.post('/api/users/revoke',headers=self.ah,json={'user':'C'})
        self.assertEqual(r.status,200)
        with core.db() as c:
            self.assertIsNone(c.execute('SELECT * FROM sessions WHERE user=?',('C',)).fetchone())
        r=await self.admin.get('/api/audit',headers=self.ah)
        self.assertTrue(any(a['action']=='admin_revoke' for a in (await r.json())['records']))

    async def test_folders_and_admin_upload_visible_to_guest(self):
        await self.admin_login()
        r=await self.admin.post('/api/folders',headers=self.ah,json={'name':'资料','parent':''})
        self.assertEqual(r.status,201)
        folder=(await r.json())['id']
        r=await self.admin.post('/api/folders',headers=self.ah,json={'name':'资料','parent':''})
        self.assertEqual(r.status,409)
        r=await self.admin.post('/api/folders',headers=self.ah,json={'name':'../bad','parent':''})
        self.assertEqual(r.status,400)
        r=await self.admin.post('/api/upload?name=report.txt&folder='+folder,headers=self.ah,data=b'admin upload')
        self.assertEqual(r.status,201,await r.text())
        ident=(await r.json())['id']
        guest,_,_=await self.sign_in()
        r=await self.request('GET','/api/files',headers=guest)
        root=await r.json()
        self.assertEqual(root['files'],[])
        self.assertEqual(root['folders'][0]['id'],folder)
        r=await self.request('GET','/api/files?folder='+folder,headers=guest)
        self.assertEqual((await r.json())['files'][0]['id'],ident)
        r=await self.request('GET','/api/download/'+ident,headers=guest)
        self.assertEqual(await r.read(),b'admin upload')
        r=await self.request('POST','/api/upload?folder=missing&name=x',headers=guest,data=b'x')
        self.assertEqual(r.status,404)
        with core.db() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM upload_reservations').fetchone()[0],0)

    async def test_public_prefix_and_origin_validation(self):
        await self.admin_login()
        prefix='https://files.example.com:22220'
        r=await self.admin.post('/api/settings',headers=self.ah,json={'public_origin':prefix})
        self.assertEqual(r.status,200)
        r=await self.admin.post('/api/users/invite',headers=self.ah,json={'user':'A'})
        invite=await r.json()
        self.assertTrue(invite['url'].startswith(prefix+'/enter/'))
        external={'Host':'files.example.com:22220','Origin':prefix}
        r=await self.request('POST','/api/login',headers=external,json={'token':invite['url'].split('/enter/')[1],'pin':invite['pin']})
        self.assertEqual(r.status,200)
        r=await self.request('POST','/api/login',headers=external|{'Origin':'https://evil.test'},json={})
        self.assertEqual(r.status,403)
        for bad in ['http://example.com','https://example.com/path','https://name:secret@example.com','javascript:alert(1)']:
            r=await self.admin.post('/api/settings',headers=self.ah,json={'public_origin':bad})
            self.assertEqual(r.status,400)
