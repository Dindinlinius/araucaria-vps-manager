"""Local tests, without a real VPS, systemd, network or Xray installation."""
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlsplit

MODULE_PATH = Path(__file__).resolve().parents[1] / 'araucaria.py'
spec = importlib.util.spec_from_file_location('araucaria', MODULE_PATH)
a = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = a
spec.loader.exec_module(a)


class ConfigTests(unittest.TestCase):
    def test_make_config_matches_current_reality_layout(self):
        with mock.patch.object(a, 'get_x25519_pair', return_value='PRIVATE'):
            cfg = a.make_config(56399, 'www.google.com')
        i = a.find_inbound(cfg)
        user, reality = a.validate_inbound(i)
        self.assertEqual(i['port'], 56399)
        self.assertEqual(i['streamSettings']['security'], 'reality')
        self.assertEqual(user['flow'], 'xtls-rprx-vision')
        self.assertEqual(reality['target'], 'www.google.com:443')
        self.assertEqual(reality['serverNames'], ['www.google.com'])
        self.assertRegex(reality['shortIds'][0], r'^[a-f0-9]{16}$')
        self.assertEqual(reality['privateKey'], 'PRIVATE')

    def test_invalid_target_and_port(self):
        for bad in ['https://www.google.com', 'www.google.com:443', '127.0.0.1', '-bad.com']:
            with self.subTest(bad=bad), self.assertRaises(a.AraucariaError):
                a.validate_target(bad)
        for bad_port in [0, 22, 65536]:
            with self.assertRaises(a.AraucariaError):
                a.validate_port(bad_port)

    def test_vless_link_contains_exact_live_settings(self):
        with mock.patch.object(a, 'get_x25519_pair', return_value='PRIVATE'):
            cfg = a.make_config(56399, 'www.google.com')
        with mock.patch.object(a, 'get_public_key', return_value='PUBLIC_-'):
            link = a.make_link(cfg, '203.0.113.42', 'USAraucaria')
        parsed = urlsplit(link)
        self.assertEqual(parsed.scheme, 'vless')
        self.assertEqual(parsed.port, 56399)
        self.assertEqual(parsed.hostname, '203.0.113.42')
        self.assertEqual(parsed.fragment, 'USAraucaria')
        query = parse_qs(parsed.query)
        self.assertEqual(query['sni'], ['www.google.com'])
        self.assertEqual(query['pbk'], ['PUBLIC_-'])
        self.assertEqual(query['flow'], ['xtls-rprx-vision'])
        self.assertEqual(query['security'], ['reality'])
        self.assertEqual(query['type'], ['tcp'])
        self.assertRegex(query['sid'][0], '^[a-f0-9]{16}$')

    def test_link_rejects_multiple_clients(self):
        with mock.patch.object(a, 'get_x25519_pair', return_value='PRIVATE'):
            cfg = a.make_config(56399, 'www.google.com')
        i = a.find_inbound(cfg)
        i['settings']['clients'].append({'id': 'another'})
        with self.assertRaises(a.AraucariaError):
            a.validate_inbound(i)

    def test_public_ipv4_validation(self):
        self.assertEqual(a.public_ipv4('203.0.113.42'), '203.0.113.42')
        with self.assertRaises(a.AraucariaError):
            a.public_ipv4('not-an-ip')

    def test_public_key_output_compatibility(self):
        for variant in ['PublicKey: abcDEF_123\n', 'Password (PublicKey): abcDEF_123\n', 'Password: abcDEF_123\n']:
            with mock.patch.object(a, 'run', return_value=SimpleNamespace(stdout=variant)):
                self.assertEqual(a.get_public_key('PRIVATE'), 'abcDEF_123')


class ManagerFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.config = base / 'xray' / 'config.json'
        self.config.parent.mkdir()
        self.settings = base / 'etc' / 'settings.json'
        self.backups = base / 'backups'
        self.lock = base / 'lock'
        self.config.write_text('{}\n')
        patchers = [
            mock.patch.object(a, 'CONFIG_FILE', self.config),
            mock.patch.object(a, 'SETTINGS_FILE', self.settings),
            mock.patch.object(a, 'BACKUP_DIR', self.backups),
            mock.patch.object(a, 'LOCK_FILE', self.lock),
            mock.patch.object(a, 'xray_group_id', return_value=os.getgid()),
            mock.patch.object(a.os, 'chown'),
            mock.patch.object(a, 'check_xray_config'),
            mock.patch.object(a, 'service_ok', return_value=True),
            mock.patch.object(a.time, 'sleep'),
            mock.patch.object(a, 'run', return_value=subprocess.CompletedProcess(['systemctl'], 0)),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_first_install_creates_config_metadata_backup(self):
        with mock.patch.object(a, 'get_x25519_pair', return_value='PRIV'):
            with contextlib.redirect_stdout(io.StringIO()):
                a.init(SimpleNamespace(port=56399, target='www.google.com', name='USAraucaria'))
        cfg = json.loads(self.config.read_text())
        self.assertEqual(a.find_inbound(cfg)['port'], 56399)
        self.assertEqual(json.loads(self.settings.read_text())['name'], 'USAraucaria')
        self.assertEqual(len(list(self.backups.glob('*.json'))), 1)
        self.assertEqual(json.loads(next(self.backups.glob('*.json')).read_text()), {})

    def test_refuses_existing_inbounds(self):
        self.config.write_text('{"inbounds":[{"protocol":"trojan"}]}\n')
        with self.assertRaises(a.AraucariaError):
            a.init(SimpleNamespace(port=56399, target='www.google.com', name='USAraucaria'))
        self.assertFalse(self.settings.exists())

    def test_rotation_updates_credentials_but_keeps_server_settings(self):
        with mock.patch.object(a, 'get_x25519_pair', return_value='OLD_PRIV'):
            cfg = a.make_config(56399, 'www.google.com')
        self.config.write_text(json.dumps(cfg))
        self.settings.parent.mkdir(parents=True)
        self.settings.write_text('{"name":"USAraucaria"}')
        before = json.loads(self.config.read_text())
        old = a.find_inbound(before)
        with (mock.patch.object(a, 'get_x25519_pair', return_value='NEW_PRIV'),
              mock.patch.object(a, 'get_public_key', return_value='PUB'),
              contextlib.redirect_stdout(io.StringIO()) as output):
            a.rotate(SimpleNamespace(ip='203.0.113.42'))
        after = json.loads(self.config.read_text())
        i = a.find_inbound(after)
        self.assertEqual(i['port'], old['port'])
        self.assertEqual(i['streamSettings']['realitySettings']['target'], 'www.google.com:443')
        self.assertEqual(i['streamSettings']['realitySettings']['privateKey'], 'NEW_PRIV')
        self.assertNotEqual(i['settings']['clients'][0]['id'], old['settings']['clients'][0]['id'])
        self.assertNotEqual(i['streamSettings']['realitySettings']['shortIds'], old['streamSettings']['realitySettings']['shortIds'])
        self.assertIn('#USAraucaria', output.getvalue())
        self.assertEqual(len(list(self.backups.glob('*.json'))), 1)

    def test_failed_restart_rolls_back_original_json(self):
        with mock.patch.object(a, 'get_x25519_pair', return_value='OLD_PRIV'):
            cfg = a.make_config(56399, 'www.google.com')
        self.config.write_text(json.dumps(cfg))
        updated = json.loads(self.config.read_text())
        a.find_inbound(updated)['settings']['clients'][0]['id'] = 'changed'
        counter = {'restarts': 0}

        def fake_run(*argv, **_kwargs):
            if argv[:2] == ('systemctl', 'restart'):
                counter['restarts'] += 1
                if counter['restarts'] == 1:
                    raise subprocess.CalledProcessError(1, argv)
            return subprocess.CompletedProcess(argv, 0)

        with mock.patch.object(a, 'run', side_effect=fake_run):
            with self.assertRaisesRegex(a.AraucariaError, 'восстановлен'):
                a.apply_config(updated)
        self.assertEqual(json.loads(self.config.read_text()), cfg)
        self.assertEqual(counter['restarts'], 2)
        self.assertEqual(len(list(self.backups.glob('*.json'))), 1)


if __name__ == '__main__':
    unittest.main()
