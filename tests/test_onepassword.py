"""
测试 1Password 导入（onepassword.py）与反向导出（reverse_to_1password.py）

覆盖：
  - 旧式 overview/details 结构解析（对齐前端 engine.js convert1PUXItem）
  - 官方平铺结构解析（item 顶层 fields/sections/urls）
  - .1pux ZIP 解析
  - 端到端：1Password -> KDBX -> 1Password 往返
"""

import unittest
import os
import json
import zipfile
import tempfile
import sys

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bw_to_keepass.onepassword import (
    parse_1password_export,
    is_1password_data,
)
from bw_to_keepass.writer import write_keepass
from bw_to_keepass.reverse_converter import convert_kdbx_to_bitwarden
from bw_to_keepass.reverse_to_1password import kdbx_to_1password, bitwarden_to_1pux


# 旧式 overview/details 结构（某些 1Password 导出 / 第三方导出器）
LEGACY_1PUX = {
    "accounts": [{"uuid": "acc1", "name": "Test"}],
    "folders": [{"uuid": "folder1", "name": "My Folder"}],
    "items": [
        {
            "uuid": "item1",
            "overview": {
                "title": "GitHub Login",
                "category": "LOGIN",
                "url": "https://github.com",
                "favorite": True,
                "tags": ["web", "dev"],
            },
            "details": {
                "fields": [
                    {"designation": "username", "value": "octocat"},
                    {"designation": "password", "value": "hunter2"},
                    {"designation": "URL", "value": "https://github.com/login"},
                ],
                "notesPlain": "some notes",
                "sections": [
                    {"name": "Security", "fields": [{"n": "TOTP", "k": "TOTP", "v": "JBSWY3DPEHPK3PXP"}]},
                    {"name": "Extra", "fields": [{"n": "api key", "v": "secret-api"}]},
                ],
                "passwordHistory": [{"value": "oldpass", "time": 1600000000}],
            },
            "folderUuid": "folder1",
            "created_at": 1590000000,
            "updated_at": 1610000000,
        },
        {
            "uuid": "item2",
            "overview": {"title": "Visa", "category": "CREDIT_CARD"},
            "details": {"sections": [{"fields": [
                {"n": "cardholder name", "v": "John Doe"},
                {"n": "ccnum", "v": "4111111111111111"},
                {"n": "expiry", "v": "12/2026"},
                {"n": "cvv", "v": "123"},
                {"n": "type", "v": "Visa"},
            ]}]},
        },
        {
            "uuid": "item3",
            "overview": {"title": "My Note", "category": "SECURE_NOTE"},
            "details": {"notesPlain": "secret note content"},
        },
        {
            "uuid": "item4",
            "overview": {"title": "John Identity", "category": "IDENTITY"},
            "details": {"sections": [{"fields": [
                {"n": "first name", "v": "John"},
                {"n": "last name", "v": "Doe"},
                {"n": "email", "v": "john@example.com"},
                {"n": "phone", "v": "+1-555"},
                {"n": "address", "v": "123 Main St"},
                {"n": "city", "v": "NYC"},
                {"n": "zip", "v": "10001"},
                {"n": "country", "v": "US"},
            ]}]},
        },
        # 回收站条目应被跳过
        {
            "uuid": "item5",
            "trashed": True,
            "overview": {"title": "Trashed", "category": "LOGIN"},
            "details": {},
        },
    ],
}


# 官方平铺结构（1Password 8 导出的 1PUX）
FLAT_1PUX = {
    "accounts": [{"uuid": "acc1", "name": "Test"}],
    "folders": [{"uuid": "folder1", "name": "My Folder"}],
    "items": [
        {
            "uuid": "fitem1",
            "category": "LOGIN",
            "name": "GitHub Login",
            "favorite": True,
            "createdAt": 1590000000,
            "updatedAt": 1610000000,
            "folderUuid": "folder1",
            "urls": [{"url": "https://github.com"}],
            "fields": [
                {"id": "x1", "type": "T", "name": "username", "value": "octocat", "designation": "username"},
                {"id": "x2", "type": "P", "name": "password", "value": "hunter2", "designation": "password"},
                {"id": "x3", "type": "T", "name": "TOTP", "value": "JBSWY3DPEHPK3PXP", "k": "TOTP"},
            ],
            "sections": [
                {"id": "s1", "name": "Extra", "fields": [
                    {"id": "x4", "type": "T", "name": "api key", "value": "secret-api"}
                ]}
            ],
            "notesPlain": "some notes",
        },
        {
            "uuid": "fitem2",
            "category": "CREDIT_CARD",
            "name": "Visa",
            "fields": [],
            "sections": [{"id": "s2", "name": "Credit Card", "fields": [
                {"id": "c1", "type": "T", "name": "cardholder name", "value": "John Doe"},
                {"id": "c2", "type": "T", "name": "ccnum", "value": "4111111111111111"},
                {"id": "c3", "type": "T", "name": "expiry", "value": "12/2026"},
                {"id": "c4", "type": "T", "name": "cvv", "value": "123"},
                {"id": "c5", "type": "T", "name": "type", "value": "Visa"},
            ]}],
        },
    ],
}


class TestParse1PasswordLegacy(unittest.TestCase):
    """旧式 overview/details 结构解析"""

    @classmethod
    def setUpClass(cls):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(LEGACY_1PUX, f, ensure_ascii=False)
            cls.path = f.name
        cls.folders, cls.items = parse_1password_export(cls.path)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.path)

    def test_is_1password_data(self):
        self.assertTrue(is_1password_data(LEGACY_1PUX))

    def test_folders(self):
        self.assertEqual(len(self.folders), 1)
        self.assertEqual(self.folders[0].name, "My Folder")

    def test_trashed_skipped(self):
        # 5 条原始，trashed 1 条 -> 4
        self.assertEqual(len(self.items), 4)

    def test_login(self):
        item = next(i for i in self.items if i.name == "GitHub Login")
        self.assertEqual(item.type, 1)
        self.assertEqual(item.username, "octocat")
        self.assertEqual(item.password, "hunter2")
        self.assertEqual(item.totp, "JBSWY3DPEHPK3PXP")
        self.assertEqual(len(item.uris), 2)
        self.assertEqual(item.uris[0].uri, "https://github.com")
        self.assertEqual(item.uris[1].uri, "https://github.com/login")
        self.assertEqual(item.notes, "some notes")
        self.assertTrue(item.favorite)
        self.assertEqual(item.folder, "My Folder")
        cf_names = {c.name: c.value for c in item.custom_fields}
        self.assertIn("api key", cf_names)
        self.assertEqual(cf_names["api key"], "secret-api")
        self.assertIn("_TAGS", cf_names)
        self.assertEqual(cf_names["_TAGS"], "web, dev")
        self.assertEqual(len(item.password_history), 1)
        self.assertTrue(item.creation_date.startswith("2020"))

    def test_card(self):
        item = next(i for i in self.items if i.name == "Visa")
        self.assertEqual(item.type, 3)
        self.assertEqual(item.cardholder_name, "John Doe")
        self.assertEqual(item.card_number, "4111111111111111")
        self.assertEqual(item.card_exp_month, "12")
        self.assertEqual(item.card_exp_year, "2026")
        self.assertEqual(item.card_code, "123")
        self.assertEqual(item.card_brand, "Visa")

    def test_secure_note(self):
        item = next(i for i in self.items if i.name == "My Note")
        self.assertEqual(item.type, 2)
        self.assertEqual(item.notes, "secret note content")

    def test_identity(self):
        item = next(i for i in self.items if i.name == "John Identity")
        self.assertEqual(item.type, 4)
        self.assertEqual(item.identity_first_name, "John")
        self.assertEqual(item.identity_last_name, "Doe")
        self.assertEqual(item.identity_email, "john@example.com")
        self.assertEqual(item.identity_phone, "+1-555")
        self.assertEqual(item.identity_address1, "123 Main St")
        self.assertEqual(item.identity_city, "NYC")
        self.assertEqual(item.identity_postal_code, "10001")
        self.assertEqual(item.identity_country, "US")


class TestParse1PasswordFlat(unittest.TestCase):
    """官方平铺结构解析"""

    @classmethod
    def setUpClass(cls):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(FLAT_1PUX, f, ensure_ascii=False)
            cls.path = f.name
        cls.folders, cls.items = parse_1password_export(cls.path)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.path)

    def test_is_1password_data(self):
        self.assertTrue(is_1password_data(FLAT_1PUX))

    def test_count(self):
        self.assertEqual(len(self.items), 2)

    def test_login(self):
        item = next(i for i in self.items if i.name == "GitHub Login")
        self.assertEqual(item.type, 1)
        self.assertEqual(item.username, "octocat")
        self.assertEqual(item.password, "hunter2")
        self.assertEqual(item.totp, "JBSWY3DPEHPK3PXP")
        self.assertEqual(len(item.uris), 1)
        self.assertEqual(item.uris[0].uri, "https://github.com")
        self.assertEqual(item.notes, "some notes")
        self.assertTrue(item.favorite)
        self.assertEqual(item.folder, "My Folder")
        cf_names = {c.name: c.value for c in item.custom_fields}
        self.assertIn("api key", cf_names)

    def test_card(self):
        item = next(i for i in self.items if i.name == "Visa")
        self.assertEqual(item.type, 3)
        self.assertEqual(item.cardholder_name, "John Doe")
        self.assertEqual(item.card_number, "4111111111111111")
        self.assertEqual(item.card_exp_month, "12")
        self.assertEqual(item.card_exp_year, "2026")
        self.assertEqual(item.card_code, "123")
        self.assertEqual(item.card_brand, "Visa")


class TestParse1PUXZip(unittest.TestCase):
    """1Password 官方 .1pux（ZIP）解析"""

    @classmethod
    def setUpClass(cls):
        with tempfile.NamedTemporaryFile("wb", suffix=".1pux", delete=False) as f:
            cls.path = f.name
        with zipfile.ZipFile(cls.path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data/export.1pif", json.dumps(FLAT_1PUX, ensure_ascii=False))

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.path)

    def test_zip_parse(self):
        folders, items = parse_1password_export(self.path)
        self.assertEqual(len(folders), 1)
        self.assertEqual(len(items), 2)
        self.assertTrue(any(i.name == "GitHub Login" for i in items))


class TestRoundTrip(unittest.TestCase):
    """端到端：1Password -> KDBX -> 1Password 往返"""

    PASSWORD = "test-pass-123"

    @classmethod
    def setUpClass(cls):
        # 1Password -> KDBX
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            cls.json_path = f.name
            json.dump(FLAT_1PUX, f, ensure_ascii=False)
        cls.kdbx_path = cls.json_path + ".kdbx"
        folders, items = parse_1password_export(cls.json_path)
        write_keepass(folders, items, cls.kdbx_path, cls.PASSWORD, db_name="1P Test")

        # KDBX -> 1Password 1PUX
        cls.onepux_path = cls.json_path + ".1pux"
        stats = kdbx_to_1password(cls.kdbx_path, cls.onepux_path, cls.PASSWORD)
        cls.stats = stats

        # 再解析回 1Password
        cls.back_folders, cls.back_items = parse_1password_export(cls.onepux_path)

    @classmethod
    def tearDownClass(cls):
        for p in (cls.json_path, cls.kdbx_path, cls.onepux_path):
            if os.path.exists(p):
                os.unlink(p)

    def test_kdbx_items(self):
        # 反向从 KDBX 读回应仍是 2 个条目
        data = convert_kdbx_to_bitwarden(self.kdbx_path, self.PASSWORD)
        self.assertEqual(len(data["items"]), 2)

    def test_1pux_export_structure(self):
        self.assertEqual(self.stats["items"], 2)
        with zipfile.ZipFile(self.onepux_path, "r") as zf:
            names = zf.namelist()
            self.assertTrue(any(n.endswith(".1pif") for n in names))
            content = json.loads(zf.read([n for n in names if n.endswith(".1pif")][0]).decode("utf-8"))
        self.assertIn("accounts", content)
        self.assertIn("items", content)
        self.assertEqual(len(content["items"]), 2)
        it = content["items"][0]
        self.assertIn("category", it)
        self.assertIn("name", it)
        self.assertIn("fields", it)
        self.assertIn("sections", it)

    def test_login_survives_roundtrip(self):
        # 用户名/密码应能在 1Password -> KDBX -> 1Password 后保留
        github = next(i for i in self.back_items if i.name == "GitHub Login")
        self.assertEqual(github.username, "octocat")
        self.assertEqual(github.password, "hunter2")
        self.assertEqual(github.type, 1)


if __name__ == "__main__":
    unittest.main()
