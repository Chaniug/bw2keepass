"""
测试转换功能
"""

import unittest
import os
import json
import tempfile
import sys

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bw_to_keepass.parser import parse_bitwarden_export, VaultItem, Folder
from bw_to_keepass.converter import (
    get_entry_title,
    get_entry_username,
    get_entry_password,
    get_entry_url,
    get_entry_notes,
    build_custom_fields,
    sanitize_path,
)


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


class TestParser(unittest.TestCase):
    """测试 Bitwarden JSON 解析器"""

    @classmethod
    def setUpClass(cls):
        cls.json_path = os.path.join(FIXTURES_DIR, 'sample_export.json')
        cls.folders, cls.items = parse_bitwarden_export(cls.json_path)

    def test_parse_folders(self):
        """测试文件夹解析"""
        self.assertEqual(len(self.folders), 2)
        folder_names = {f.name for f in self.folders}
        self.assertIn("Work", folder_names)
        self.assertIn("Personal", folder_names)

    def test_parse_items_count(self):
        """测试条目数量（排除已删除的）"""
        self.assertEqual(len(self.items), 5)

    def test_parse_login(self):
        """测试登录类型解析"""
        github = next((i for i in self.items if i.name == "GitHub"), None)
        self.assertIsNotNone(github)
        self.assertEqual(github.type, 1)
        self.assertEqual(github.username, "octocat")
        self.assertEqual(github.password, "super-secret-password")
        self.assertEqual(github.totp, "JBSWY3DPEHPK3PXP")
        self.assertEqual(len(github.uris), 2)
        self.assertEqual(github.uris[0].uri, "https://github.com")
        self.assertEqual(github.folder, "Work")
        self.assertTrue(github.favorite)
        self.assertEqual(len(github.custom_fields), 1)
        self.assertEqual(github.custom_fields[0].name, "2FA Recovery Code")
        self.assertEqual(len(github.password_history), 1)

    def test_parse_secure_note(self):
        """测试安全笔记解析"""
        wifi = next((i for i in self.items if i.name == "WiFi Password"), None)
        self.assertIsNotNone(wifi)
        self.assertEqual(wifi.type, 2)
        self.assertIn("SSID: MyHomeWiFi", wifi.notes)
        self.assertEqual(wifi.folder, "Personal")

    def test_parse_card(self):
        """测试卡片类型解析"""
        card = next((i for i in self.items if i.name == "Visa Card"), None)
        self.assertIsNotNone(card)
        self.assertEqual(card.type, 3)
        self.assertEqual(card.cardholder_name, "John Doe")
        self.assertEqual(card.card_brand, "Visa")
        self.assertEqual(card.card_number, "4111111111111111")
        self.assertEqual(card.card_exp_month, "12")
        self.assertEqual(card.card_exp_year, "2026")
        self.assertEqual(card.card_code, "123")
        self.assertEqual(card.folder, "")

    def test_parse_identity(self):
        """测试身份类型解析"""
        identity = next((i for i in self.items if i.name == "John's Identity"), None)
        self.assertIsNotNone(identity)
        self.assertEqual(identity.type, 4)
        self.assertEqual(identity.identity_first_name, "John")
        self.assertEqual(identity.identity_last_name, "Doe")
        self.assertEqual(identity.identity_email, "john@example.com")
        self.assertEqual(identity.identity_phone, "+1-555-123-4567")
        self.assertEqual(identity.identity_ssn, "123-45-6789")
        self.assertEqual(identity.identity_passport_number, "P12345678")
        self.assertEqual(identity.folder, "Personal")

    def test_parse_ssh_key(self):
        """测试 SSH 密钥解析"""
        ssh = next((i for i in self.items if i.name == "GitHub SSH Key"), None)
        self.assertIsNotNone(ssh)
        self.assertEqual(ssh.type, 5)
        self.assertIn("BEGIN OPENSSH PRIVATE KEY", ssh.ssh_private_key)
        self.assertIn("ssh-ed25519", ssh.ssh_public_key)
        self.assertEqual(ssh.ssh_key_fingerprint, "SHA256:abcdef1234567890")

    def test_deleted_items_skipped(self):
        """测试已删除条目被跳过"""
        deleted = [i for i in self.items if i.name == "Deleted Account"]
        self.assertEqual(len(deleted), 0)


class TestConverter(unittest.TestCase):
    """测试转换器"""

    @classmethod
    def setUpClass(cls):
        cls.json_path = os.path.join(FIXTURES_DIR, 'sample_export.json')
        _, cls.items = parse_bitwarden_export(cls.json_path)

    def test_login_title_username_password(self):
        item = next(i for i in self.items if i.name == "GitHub")
        self.assertEqual(get_entry_title(item), "GitHub")
        self.assertEqual(get_entry_username(item), "octocat")
        self.assertEqual(get_entry_password(item), "super-secret-password")
        self.assertEqual(get_entry_url(item), "https://github.com")

    def test_login_notes(self):
        item = next(i for i in self.items if i.name == "GitHub")
        notes = get_entry_notes(item)
        self.assertIn("My GitHub account", notes)
        self.assertIn("TOTP", notes)
        self.assertIn("otpauth://totp/GitHub", notes)
        self.assertIn("其他 URI", notes)
        self.assertIn("密码历史", notes)

    def test_secure_note_fields(self):
        item = next(i for i in self.items if i.name == "WiFi Password")
        self.assertEqual(get_entry_title(item), "WiFi Password")
        self.assertEqual(get_entry_username(item), "")
        self.assertEqual(get_entry_password(item), "")

    def test_card_title_and_password(self):
        item = next(i for i in self.items if i.name == "Visa Card")
        self.assertEqual(get_entry_username(item), "John Doe")
        self.assertEqual(get_entry_password(item), "123")  # CVV

    def test_custom_fields(self):
        item = next(i for i in self.items if i.name == "GitHub")
        fields = build_custom_fields(item)
        self.assertIn("BitwardenType", fields)
        self.assertEqual(fields["BitwardenType"], "Login")
        self.assertIn("TOTP Seed", fields)
        self.assertIn("2FA Recovery Code", fields)

    def test_sanitize_path(self):
        self.assertEqual(sanitize_path("Work/Project"), "Work_Project")
        self.assertEqual(sanitize_path("A\\B"), "A_B")
        self.assertEqual(sanitize_path("Normal"), "Normal")


if __name__ == "__main__":
    unittest.main()
