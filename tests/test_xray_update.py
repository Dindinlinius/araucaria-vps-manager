"""Safe Xray update tests: no root access, systemd, GitHub or VPS needed."""
import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

PROGRAM = Path(__file__).resolve().parents[1] / 'araucaria.py'
spec = importlib.util.spec_from_file_location('araucaria_xray_update_test', PROGRAM)
a = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = a
spec.loader.exec_module(a)


class XrayUpdateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.xray = self.root / 'bin' / 'xray'
        self.xray.parent.mkdir()
        self.xray.write_bytes(b'OLD')
        self.xray.chmod(0o755)
        self.conf = self.root / 'config.json'
        with mock.patch.object(a, 'get_x25519_pair', return_value='PRIVATE'):
            config = a.make_config(56399, 'www.google.com')
        self.conf.write_text(json.dumps(config))
        self.settings = self.root / 'settings.json'
        self.settings.write_text(json.dumps({'name': 'USAraucaria'}))
        self.backups = self.root / 'backup'
        self.pending = self.backups / 'pending.json'
        self.lock = self.root / 'lock'
        for name, replacement in (
            ('XRAY_BIN', self.xray),
            ('CONFIG_FILE', self.conf),
            ('SETTINGS_FILE', self.settings),
            ('XRAY_UPDATE_DIR', self.backups),
            ('XRAY_PENDING', self.pending),
            ('LOCK_FILE', self.lock),
        ):
            patch = mock.patch.object(a, name, replacement)
            patch.start()
            self.addCleanup(patch.stop)

    def fixture(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(a, 'require_root'))
        stack.enter_context(mock.patch.object(a.sys, 'stdin', SimpleNamespace(isatty=lambda: True)))
        stack.enter_context(mock.patch.object(a, 'service_ok', return_value=True))
        stack.enter_context(mock.patch.object(a, '_xray_wait_for_service', return_value=True))
        stack.enter_context(mock.patch.object(a, 'public_ipv4', return_value='203.0.113.31'))
        stack.enter_context(mock.patch.object(a, 'get_public_key', return_value='PUB'))
        stack.enter_context(mock.patch.object(a, '_xray_release', return_value='v26.9.9'))
        stack.enter_context(mock.patch.object(
            a, '_xray_version',
            side_effect=lambda binary=None: 'v26.9.9' if self.xray.read_bytes() == b'NEW' else 'v26.3.27'
        ))
        stack.enter_context(mock.patch.object(
            a, 'run', return_value=SimpleNamespace(returncode=0)
        ))
        def create_download(tag, folder):
            binary = folder / 'xray'
            binary.write_bytes(b'NEW')
            return binary
        stack.enter_context(mock.patch.object(a, '_download_xray_candidate', side_effect=create_download))

    def call_update(self, answers):
        with (mock.patch('builtins.input', side_effect=answers),
              contextlib.redirect_stdout(io.StringIO()) as output):
            a.xray_update(SimpleNamespace(ip=None))
        return output.getvalue()

    def test_yes_keeps_new_binary_and_preserves_vless_config(self):
        self.fixture()
        before = self.conf.read_bytes()
        with mock.patch('builtins.input', side_effect=['yes', 'yes']) as fake_input:
            with contextlib.redirect_stdout(io.StringIO()) as screen:
                a.xray_update(SimpleNamespace(ip=None))
        stdout = screen.getvalue()
        confirm_prompt = fake_input.call_args_list[1].args[0]
        self.assertIn('\\x1b[1;36myes\\x1b[0m'.encode('utf-8').decode('unicode_escape'), confirm_prompt)
        self.assertIn('\\x1b[1;36mno\\x1b[0m'.encode('utf-8').decode('unicode_escape'), confirm_prompt)
        self.assertEqual(self.xray.read_bytes(), b'NEW')
        self.assertEqual(self.conf.read_bytes(), before)
        self.assertFalse(self.pending.exists())
        self.assertEqual(len(list(self.backups.glob('xray-*.bin'))), 1)
        self.assertIn('Главная vless ссылка не изменилась', stdout)
        self.assertIn('Обновление подтверждено', stdout)

    def test_no_restores_original_binary_and_port(self):
        self.fixture()
        stdout = self.call_update(['yes', 'no'])
        self.assertEqual(self.xray.read_bytes(), b'OLD')
        self.assertFalse(self.pending.exists())
        self.assertIn('Откат выполнен', stdout)
        self.assertIn('Главная vless ссылка не изменилась', stdout)

    def test_lost_input_rolls_back_automatically(self):
        self.fixture()
        with mock.patch('builtins.input', side_effect=['yes', EOFError()]):
            with self.assertRaisesRegex(a.AraucariaError, 'Предыдущий Xray восстановлен'):
                a.xray_update(SimpleNamespace(ip=None))
        self.assertEqual(self.xray.read_bytes(), b'OLD')
        self.assertFalse(self.pending.exists())

    def test_failed_new_service_triggers_rollback(self):
        self.fixture()
        with mock.patch.object(a, '_xray_wait_for_service', side_effect=lambda port: self.xray.read_bytes() == b'OLD'):
            with mock.patch('builtins.input', return_value='yes'):
                with self.assertRaisesRegex(a.AraucariaError, 'Предыдущий Xray восстановлен'):
                    a.xray_update(SimpleNamespace(ip=None))
        self.assertEqual(self.xray.read_bytes(), b'OLD')
        self.assertFalse(self.pending.exists())

    def test_unfinished_update_can_be_rolled_back_manually(self):
        self.backups.mkdir()
        backup = self.backups / 'xray-test.bin'
        backup.write_bytes(b'OLD')
        backup.chmod(0o700)
        self.xray.write_bytes(b'NEW')
        metadata = {
            'previous_version': 'v26.3.27', 'port': 56399,
            'backup_binary': str(backup),
            'backup_sha256': hashlib.sha256(b'OLD').hexdigest(),
        }
        self.pending.write_text(json.dumps(metadata))
        with (mock.patch.object(a, 'require_root'),
              mock.patch.object(a, 'run', return_value=SimpleNamespace(returncode=0)),
              mock.patch.object(a, '_xray_wait_for_service', return_value=True)):
            a.xray_rollback()
        self.assertEqual(self.xray.read_bytes(), b'OLD')
        self.assertFalse(self.pending.exists())

    def test_corrupted_backup_cannot_be_used_for_rollback(self):
        self.backups.mkdir()
        backup = self.backups / 'xray-test.bin'
        backup.write_bytes(b'TAMPERED')
        self.pending.write_text(json.dumps({
            'previous_version': 'v26.3.27', 'port': 56399,
            'backup_binary': str(backup),
            'backup_sha256': hashlib.sha256(b'OLD').hexdigest(),
        }))
        with mock.patch.object(a, 'require_root'):
            with self.assertRaisesRegex(a.AraucariaError, 'повреждена'):
                a.xray_rollback()

    def test_existing_pending_update_blocks_another_update(self):
        self.fixture()
        self.backups.mkdir()
        self.pending.write_text('{}')
        with self.assertRaisesRegex(a.AraucariaError, 'Незавершённое обновление'):
            a.xray_update(SimpleNamespace(ip=None))
        self.assertEqual(self.xray.read_bytes(), b'OLD')

    def test_only_newer_stable_release_can_be_installed(self):
        self.fixture()
        with mock.patch.object(a, '_xray_release', return_value='v26.3.27'):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                a.xray_update(SimpleNamespace(ip=None))
        self.assertIn('более новая стабильная версия не обнаружена', out.getvalue())
        self.assertFalse(self.pending.exists())

    def test_version_check_does_not_update_binary(self):
        self.fixture()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            a.xray_check()
        self.assertIn('v26.3.27', out.getvalue())
        self.assertIn('v26.9.9', out.getvalue())
        self.assertEqual(self.xray.read_bytes(), b'OLD')

    def test_parser_exposes_three_actions(self):
        parser = a.create_parser()
        for action in ('check', 'update', 'rollback'):
            parsed = parser.parse_args(['xray', action])
            self.assertEqual(parsed.action, 'xray')
            self.assertEqual(parsed.xray_action, action)

    def test_sha256_digest_verifies_before_execution(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as zipped:
            zipped.writestr('xray', b'Xray-binary-placeholder')
        zipped_bytes = archive.getvalue()
        good_checksum = 'SHA256= ' + hashlib.sha256(zipped_bytes).hexdigest() + '\n'
        with tempfile.TemporaryDirectory() as directory:
            with (mock.patch.object(a.platform, 'machine', return_value='x86_64'),
                  mock.patch.object(a, '_xray_fetch_bytes', side_effect=[
                      zipped_bytes, good_checksum.encode()]),
                  mock.patch.object(a, '_xray_version', return_value='v26.9.9'),
                  mock.patch.object(a.subprocess, 'run', return_value=SimpleNamespace(returncode=0))):
                output = a._download_xray_candidate('v26.9.9', Path(directory))
                self.assertEqual(output.read_bytes(), b'Xray-binary-placeholder')

    def test_wrong_archive_checksum_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with (mock.patch.object(a.platform, 'machine', return_value='x86_64'),
                  mock.patch.object(a, '_xray_fetch_bytes', side_effect=[
                      b'bad archive', b'SHA256= ' + b'0' * 64])):
                with self.assertRaisesRegex(a.AraucariaError, 'SHA-256'):
                    a._download_xray_candidate('v26.9.9', Path(directory))


if __name__ == '__main__':
    unittest.main()
