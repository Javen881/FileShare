import json
from pathlib import Path
import tempfile
import unittest
from scripts.render_config import render


class DeploymentConfigTests(unittest.TestCase):
    def test_public_nat_port_and_separate_admin(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)
            render('https://files.example.com:22220','https://192.168.1.10:8443',443,out)
            cfg=json.loads((out/'config.json').read_text())
            self.assertEqual(cfg['admin_origin'],'https://192.168.1.10:8443')
            self.assertIn('listen 443 ssl;', (out/'nginx-public.conf').read_text())
            self.assertIn('listen 8443 ssl;', (out/'nginx-admin.conf').read_text())
            self.assertIn('DNS:files.example.com,IP:192.168.1.10',(out/'certificate-san.txt').read_text())
            self.assertNotIn('__PUBLIC_HOST__',(out/'nginx-public.conf').read_text())

    def test_reject_conflicting_ports_and_injected_hosts(self):
        with tempfile.TemporaryDirectory() as d:
            for public,admin in [('http://files.example.com','https://admin.example.com:8443'),
                                  ('https://files.example.com','https://admin.example.com'),
                                  ('https://files.example.com/path','https://admin.example.com:8443'),
                                  ('https://a;bad.example.com','https://admin.example.com:8443')]:
                with self.assertRaises(ValueError):
                    render(public,admin,443,Path(d))
