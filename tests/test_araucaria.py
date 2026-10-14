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
from urllib.parse import parse_qs, unquote, urlsplit

MODULE_PATH = Path(__file__).resolve().parents[1] / 'araucaria.py'
spec = importlib.util.spec_from_file_location('araucaria', MODULE_PATH)
a = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = a
spec.loader.exec_module(a)


class ConfigTests(unittest.TestCase):
    def test_unicode_profile_name_and_safe_url_fragment(self):
        self.assertEqual(a.validate_name('  Мой VPN 🇺🇸  '), 'Мой VPN 🇺🇸')
        with mock.patch.object(a, 'get_x25519_pair', return_value='PRIVATE'):
            cfg = a.make_config(56399, 'www.google.com')
        with mock.patch.object(a, 'get_public_key', return_value='PUBLIC'):
            link = a.make_link(cfg, '203.0.113.42', 'Мой VPN 🇺🇸 #1')
        self.assertEqual(unquote(urlsplit(link).fragment), 'Мой VPN 🇺🇸 #1')
        self.assertIn('%23', link)

    def test_bad_profile_names_are_rejected(self):
        for name in ['', '    ', 'a' * 65, '🌲' * 60, 'foo\nbar',
                     '\x1b[31m', 'hidden\u200btext', 'odd\u202e_name']:
            with self.subTest(name=name), self.assertRaises(a.AraucariaError):
                a.validate_name(name)

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


class PortChangeTests(unittest.TestCase):
    """Safety checks for open-new -> switch-Xray -> close-old operations."""

    def setUp(self):
        ManagerFilesystemTests.setUp(self)
        with mock.patch.object(a, 'get_x25519_pair', return_value='PRIVATE'):
            cfg = a.make_config(56399, 'www.google.com')
        self.config.write_text(json.dumps(cfg) + '\n')
        self.settings.parent.mkdir(parents=True, exist_ok=True)
        self.settings.write_text('{"name":"USAraucaria"}\n')
        self.allowed = {56399}
        self.calls = []
        self.fail_delete_old = False
        self.fail_allow_new = False

    def fake_run(self, *argv, **kwargs):
        self.calls.append(argv)
        if argv[:3] == ('ss', '-H', '-ltn'):
            return subprocess.CompletedProcess(argv, 0, 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 *:2022 *:*\nLISTEN 0 128 *:56399 *:*\n')
        if argv[:2] == ('ufw', 'status'):
            lines = ['Status: active', '', 'To Action From', '-- ------ ----',
                     '22/tcp ALLOW Anywhere # SSH - keep access']
            for p in sorted(self.allowed):
                lines += [f'{p}/tcp ALLOW Anywhere # Araucaria REALITY',
                          f'{p}/tcp (v6) ALLOW Anywhere (v6) # Araucaria REALITY']
            return subprocess.CompletedProcess(argv, 0, '\n'.join(lines))
        if argv[:2] == ('ufw', 'allow'):
            if self.fail_allow_new:
                raise subprocess.CalledProcessError(1, argv)
            self.allowed.add(int(argv[2].split('/')[0]))
        if argv[:4] == ('ufw', '--force', 'delete', 'allow'):
            port = int(argv[4].split('/')[0])
            if self.fail_delete_old and port == 56399:
                raise subprocess.CalledProcessError(1, argv)
            self.allowed.discard(port)
        return subprocess.CompletedProcess(argv, 0, '')

    def call_change(self, port=38421, random=False, with_input=None):
        args = SimpleNamespace(port=port, random=random, ip='203.0.113.42')
        with (mock.patch.object(a, 'require_root'),
              mock.patch.object(a, 'run', side_effect=self.fake_run),
              mock.patch.object(a, 'port_bindable', return_value=True),
              mock.patch.object(a, 'get_public_key', return_value='PUB'),
              contextlib.redirect_stdout(io.StringIO()) as out):
            if with_input is not None:
                with (mock.patch.object(a.sys, 'stdin', new=SimpleNamespace(isatty=lambda: True)),
                      mock.patch('builtins.input', return_value=with_input)):
                    a.switch_vless_port(args)
            else:
                a.switch_vless_port(args)
        return out.getvalue()

    def test_port_change_updates_config_firewall_and_url_without_rotating_keys(self):
        before = json.loads(self.config.read_text())
        printed = self.call_change()
        after = json.loads(self.config.read_text())
        self.assertEqual(a.find_inbound(after)['port'], 38421)
        self.assertEqual(a.find_inbound(before)['settings'], a.find_inbound(after)['settings'])
        self.assertEqual(a.find_inbound(before)['streamSettings'], a.find_inbound(after)['streamSettings'])
        self.assertEqual(self.allowed, {38421})
        self.assertIn('38421', printed)
        self.assertIn('56399/tcp — закрыт', printed)
        self.assertIn(':38421?', printed)
        self.assertEqual(len(list(self.backups.glob('*.json'))), 1)
        # The old port MUST be closed only AFTER the new Xray configuration was applied.
        self.assertIn(('ufw', '--force', 'delete', 'allow', '56399/tcp'), self.calls)

    def test_port_change_rejects_busy_port_without_firewall_mutations(self):
        with self.assertRaisesRegex(a.AraucariaError, 'занят'):
            self.call_change(port=2022)
        self.assertEqual(self.allowed, {56399})
        self.assertEqual(a.find_inbound(json.loads(self.config.read_text()))['port'], 56399)
        self.assertFalse(any(c[:2] == ('ufw', 'allow') for c in self.calls))

    def test_port_change_rejects_current_port(self):
        with self.assertRaisesRegex(a.AraucariaError, 'текущий'):
            self.call_change(port=56399)
        self.assertEqual(self.allowed, {56399})

    def test_port_change_rolls_back_firewall_if_xray_rejected_new_config(self):
        with mock.patch.object(a, 'apply_config', side_effect=a.AraucariaError('Xray error')):
            with self.assertRaisesRegex(a.AraucariaError, 'новый порт закрыт'):
                self.call_change()
        self.assertEqual(self.allowed, {56399})
        self.assertEqual(a.find_inbound(json.loads(self.config.read_text()))['port'], 56399)

    def test_port_change_rolls_back_xray_if_old_port_cannot_close(self):
        self.fail_delete_old = True
        with self.assertRaisesRegex(a.AraucariaError, 'Предыдущее подключение восстановлено'):
            self.call_change()
        self.assertEqual(self.allowed, {56399})
        self.assertEqual(a.find_inbound(json.loads(self.config.read_text()))['port'], 56399)
        self.assertEqual(len(list(self.backups.glob('*.json'))), 2)

    def test_port_change_rejects_ufw_allow_failure(self):
        self.fail_allow_new = True
        with self.assertRaisesRegex(a.AraucariaError, 'Команда UFW'):
            self.call_change()
        self.assertEqual(self.allowed, {56399})

    def test_interactive_yes_selects_random_port_and_prints_busy_ports(self):
        with mock.patch.object(a.secrets, 'randbelow', return_value=13333):
            output = self.call_change(port=None, with_input='yes')
        self.assertEqual(self.allowed, {33333})
        self.assertIn('22, 2022, 56399', output)
        self.assertIn('Допустимый диапазон', output)

    def test_ufw_status_requires_managed_old_port(self):
        self.allowed.clear()
        with self.assertRaisesRegex(a.AraucariaError, 'Нет правила UFW Araucaria'):
            self.call_change()
        self.assertEqual(self.allowed, set())

    def test_port_command_cli_registered(self):
        p = a.create_parser()
        ns = p.parse_args(['port', '43434'])
        self.assertEqual(ns.action, 'port')
        self.assertEqual(ns.port, 43434)
        self.assertFalse(ns.random)
        ns = p.parse_args(['port', '--random'])
        self.assertTrue(ns.random)



if __name__ == '__main__':
    unittest.main()
