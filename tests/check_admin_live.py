import json
import secrets
import ssl
import time
import urllib.request
import urllib.error
from app import core
from app.admin_server import COOKIE


def main():
    origin=core.config()['admin_origin']
    ctx=ssl.create_default_context(cafile=str(core.ROOT/'public-certificate.crt'))
    raw,csrf,ident=secrets.token_urlsafe(32),secrets.token_urlsafe(32),secrets.token_hex(16)
    user='_admin_test_'+secrets.token_hex(4)
    folder=None
    uploaded=None
    def call(path,body=None,authenticated=True):
        h={'Origin':origin,'Content-Type':'application/json'}
        if authenticated:h|={'Cookie':COOKIE+'='+raw,'X-CSRF-Token':csrf}
        req=urllib.request.Request(origin+path,data=None if body is None else json.dumps(body).encode(),headers=h)
        with urllib.request.urlopen(req,context=ctx,timeout=15) as r:return r.status,r.read()
    try:
        with core.db() as c:
            c.execute('INSERT INTO admin_sessions VALUES(?,?,?,?)',(core.digest(raw),csrf,time.time(),time.time()))
            c.execute('INSERT INTO files VALUES(?,?,?,?,?)',(ident,'后台部署验证.txt',4,user,time.time()))
        (core.ROOT/'files'/ident).write_bytes(b'test')
        try:
            call('/api/files',authenticated=False)
            raise AssertionError('unauthorized allowed')
        except urllib.error.HTTPError as e:assert e.code==401
        assert call('/api/me')[0]==200
        assert call('/api/download/'+ident)[1]==b'test'
        assert call('/api/files/'+ident+'/trash',{})[0]==200
        assert any(f['id']==ident for f in json.loads(call('/api/files?trash=1')[1])['files'])
        assert call('/api/files/'+ident+'/restore',{})[0]==200
        assert call('/api/overview')[0]==200
        assert call('/api/audit')[0]==200
        folder=json.loads(call('/api/folders',{'name':'部署测试-'+secrets.token_hex(4),'parent':''})[1])['id']
        req=urllib.request.Request(origin+'/api/upload?folder='+folder+'&name=admin-test.txt',data=b'admin-upload',headers={'Origin':origin,'Cookie':COOKIE+'='+raw,'X-CSRF-Token':csrf,'Content-Type':'application/octet-stream'})
        with urllib.request.urlopen(req,context=ctx,timeout=15) as r:
            assert r.status==201
            uploaded=json.loads(r.read())['id']
        assert call('/api/download/'+uploaded)[1]==b'admin-upload'
        assert any(f['id']==uploaded for f in json.loads(call('/api/files?folder='+folder)[1])['files'])
        assert call('/api/settings')[0]==200
        print('ADMIN_HTTPS_OK: anonymous denied, admin session, download, trash and restore, overview, audit, folder creation, admin upload and settings')
    finally:
        with core.db() as c:
            c.execute('DELETE FROM trash WHERE file_id=?',(ident,))
            c.execute('DELETE FROM files WHERE id=? AND user=?',(ident,user))
            c.execute('DELETE FROM admin_sessions WHERE token=?',(core.digest(raw),))
            if uploaded:
                c.execute('DELETE FROM file_locations WHERE file_id=?',(uploaded,))
                c.execute('DELETE FROM files WHERE id=?',(uploaded,))
                (core.ROOT/'files'/uploaded).unlink(missing_ok=True)
            if folder:
                c.execute('DELETE FROM folders WHERE id=?',(folder,))
        (core.ROOT/'files'/ident).unlink(missing_ok=True)


if __name__=='__main__':main()
