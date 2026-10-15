"""Static regression checks for the public release candidate."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReleaseIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installer = (ROOT / 'install.sh').read_text(encoding='utf-8')
        cls.manager = (ROOT / 'araucaria.py').read_text(encoding='utf-8')
        cls.docs = (ROOT / 'README.md').read_text(encoding='utf-8')

    def test_upstream_installer_is_pinned_to_immutable_commit(self):
        self.assertRegex(
            self.installer, r"(?m)^XRAY_INSTALL_REF='[a-f0-9]{40}'$")
        self.assertRegex(
            self.installer, r"(?m)^XRAY_INSTALL_SHA256='[a-f0-9]{64}'$")
        self.assertNotIn('XTLS/Xray-install/main/install-release.sh', self.installer)
        self.assertIn('sha256sum -c -', self.installer)
        self.assertIn('bash -n "$INSTALLER"', self.installer)

    def test_upstream_installer_uses_official_stable_channel(self):
        self.assertIn('bash "$INSTALLER" install', self.installer)
        self.assertNotIn('bash "$INSTALLER" install --beta', self.installer)
        self.assertIn('XRAY_INSTALLED_VERSION=', self.installer)

    def test_test_reinstall_is_not_exposed_in_release_build(self):
        self.assertNotIn('test_reinstall', self.manager)
        self.assertNotIn('--test-reinstall', self.manager)
        self.assertNotIn('--test-reinstall', self.docs)
        self.assertNotIn('--test-reinstall', self.installer)

    def test_mit_license_is_present_and_documented(self):
        license_text = (ROOT / 'LICENSE').read_text(encoding='utf-8')
        self.assertTrue(license_text.startswith('MIT License\\n'.replace('\\n', '\n')))
        self.assertIn('Copyright (c) 2026 Dindinlinius', license_text)
        self.assertIn('The above copyright notice and this permission notice', license_text)
        self.assertIn('MIT License', self.docs)
        self.assertIn('[LICENSE](LICENSE)', self.docs)

    def test_user_facing_console_report_remains_clean(self):
        self.assertNotIn('[ПОДСКАЗКА: ЦВЕТ ТЕРМИНАЛА]', self.installer)
        self.assertNotIn("nprintf '", self.installer)


if __name__ == '__main__':
    unittest.main()
