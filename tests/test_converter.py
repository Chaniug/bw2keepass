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
from bw_to_keepass.encrypted import EncryptedExportError, EncryptedExportRequiresPassword
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
        self.assertEqual(len(github.uris), 3)
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

    def test_parse_fido2_credentials(self):
        """测试 FIDO2 / Passkey 凭据解析"""
        github = next((i for i in self.items if i.name == "GitHub"), None)
        self.assertIsNotNone(github)
        self.assertEqual(len(github.fido2_credentials), 1)
        fc = github.fido2_credentials[0]
        self.assertEqual(fc.credential_id, "e64a25a4-3081-4bc4-baf3-426638381cf6")
        self.assertEqual(fc.key_type, "public-key")
        self.assertEqual(fc.key_algorithm, "ECDSA")
        self.assertEqual(fc.key_curve, "P-256")
        self.assertEqual(fc.rp_id, "github.com")
        self.assertEqual(fc.rp_name, "GitHub")
        self.assertEqual(fc.user_name, "octocat")
        self.assertEqual(fc.user_display_name, "Octocat")
        self.assertEqual(fc.counter, "42")
        self.assertEqual(fc.discoverable, "true")
        self.assertIn("example_key_value", fc.key_value)

    def test_no_fido2_on_other_types(self):
        """测试非登录类型的条目没有 FIDO2 凭据"""
        wifi = next((i for i in self.items if i.name == "WiFi Password"), None)
        self.assertEqual(len(wifi.fido2_credentials), 0)
        card = next((i for i in self.items if i.name == "Visa Card"), None)
        self.assertEqual(len(card.fido2_credentials), 0)

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

    def test_card_custom_fields_names(self):
        """验证卡片字段名正确（Brand/Expiry/CardNumber）"""
        item = next(i for i in self.items if i.name == "Visa Card")
        fields = build_custom_fields(item)
        self.assertEqual(fields["CardNumber"], "4111111111111111")
        self.assertEqual(fields["Expiry"], "12/2026")
        self.assertEqual(fields["Brand"], "Visa")

    def test_ssh_private_key_field(self):
        """验证 SSH 私钥正确写入自定义字段（避免反向转换时丢失）"""
        item = next(i for i in self.items if i.name == "GitHub SSH Key")
        fields = build_custom_fields(item)
        self.assertIn("SSHPrivateKey", fields)
        self.assertTrue(fields["SSHPrivateKey"])
        self.assertIn("SSHFingerprint", fields)
        self.assertIn("SSHPublicKey", fields)

    def test_custom_fields(self):
        item = next(i for i in self.items if i.name == "GitHub")
        fields = build_custom_fields(item)
        self.assertIn("BitwardenType", fields)
        self.assertEqual(fields["BitwardenType"], "Login")
        self.assertIn("TOTP Seed", fields)
        # 注意：不再写 "otp" / "UserName" 自定义字段（pykeepass 保留键，会崩溃）
        self.assertNotIn("otp", fields)
        self.assertNotIn("UserName", fields)
        self.assertIn("2FA Recovery Code", fields)
        # androidapp:// URI 应映射为 AndroidApp 字段
        self.assertEqual(fields.get("AndroidApp"), "com.github.android")

    def test_androidapp_url_skipped(self):
        """验证 androidapp:// 不会成为主 URL"""
        item = next(i for i in self.items if i.name == "GitHub")
        url = get_entry_url(item)
        self.assertTrue(url.startswith("https://"))
        self.assertNotIn("androidapp://", url)

    def test_fido2_custom_fields(self):
        """测试 FIDO2 凭据的自定义字段（对齐 KeePassXC PR #11401 格式）"""
        item = next(i for i in self.items if i.name == "GitHub")
        fields = build_custom_fields(item)
        # 核心字段名对齐 KeePassXC
        self.assertIn("KPEX_PASSKEY_CREDENTIAL_ID", fields)
        # credentialId 应转换为 base64url（不再是原始 UUID）
        self.assertNotEqual(
            fields["KPEX_PASSKEY_CREDENTIAL_ID"],
            "e64a25a4-3081-4bc4-baf3-426638381cf6"  # 原始 UUID
        )
        # 验证是 base64url 格式（不含 +/=）
        cid = fields["KPEX_PASSKEY_CREDENTIAL_ID"]
        self.assertNotIn('+', cid)
        self.assertNotIn('/', cid)
        self.assertNotIn('=', cid)
        self.assertNotIn('-', cid)  # 不再含 UUID 横线
        # relyingParty 字段
        self.assertIn("KPEX_PASSKEY_RELYING_PARTY", fields)
        self.assertEqual(fields["KPEX_PASSKEY_RELYING_PARTY"], "github.com")
        # username 字段
        self.assertIn("KPEX_PASSKEY_USERNAME", fields)
        self.assertEqual(fields["KPEX_PASSKEY_USERNAME"], "octocat")
        # userHandle 字段
        self.assertIn("KPEX_PASSKEY_USER_HANDLE", fields)
        # private key PEM 字段
        self.assertIn("KPEX_PASSKEY_PRIVATE_KEY_PEM", fields)
        pem = fields["KPEX_PASSKEY_PRIVATE_KEY_PEM"]
        self.assertIn("-----BEGIN PRIVATE KEY-----", pem)
        self.assertIn("-----END PRIVATE KEY-----", pem)
        # 以下旧字段不应存在
        self.assertNotIn("KPEX_PASSKEY_RP_ID", fields)
        # KPEX_PASSKEY_RP_NAME / USER_DISPLAY_NAME / CREATION_DATE 是我们补充存储的额外字段
        # 用于 JSON→KDBX→JSON 往返还原（KeePassXC 不存这些）
        self.assertIn("KPEX_PASSKEY_RP_NAME", fields)
        self.assertEqual(fields["KPEX_PASSKEY_RP_NAME"], "GitHub")
        self.assertIn("KPEX_PASSKEY_USER_DISPLAY_NAME", fields)
        self.assertEqual(fields["KPEX_PASSKEY_USER_DISPLAY_NAME"], "Octocat")
        self.assertIn("KPEX_PASSKEY_CREATION_DATE", fields)
        self.assertNotIn("KPEX_PASSKEY_USER_NAME", fields)
        self.assertNotIn("KPEX_PASSKEY_KEY_VALUE", fields)
        self.assertNotIn("KPEX_PASSKEY_ALGORITHM", fields)
        self.assertNotIn("KPEX_PASSKEY_CURVE", fields)
        self.assertNotIn("KPEX_PASSKEY_COUNTER", fields)
        self.assertNotIn("KPEX_PASSKEY_DISCOVERABLE", fields)
        self.assertNotIn("KPEX_PASSKEY_CREATION", fields)

    def test_fido2_in_notes(self):
        """测试 FIDO2 凭据出现在备注中"""
        item = next(i for i in self.items if i.name == "GitHub")
        notes = get_entry_notes(item)
        self.assertIn("Passkey / FIDO2", notes)
        self.assertIn("github.com", notes)
        self.assertIn("ECDSA", notes)
        self.assertIn("e64a25a4-3081-4bc4-baf3-426638381cf6", notes)


    def test_sanitize_path(self):
        self.assertEqual(sanitize_path("Work/Project"), "Work_Project")
        self.assertEqual(sanitize_path("A\\B"), "A_B")
        self.assertEqual(sanitize_path("Normal"), "Normal")


class TestReverseConverter(unittest.TestCase):
    """测试反向转换（KeePass 格式 → Bitwarden 格式）"""

    def test_base64url_to_uuid(self):
        """测试 base64url → UUID 反向转换"""
        from bw_to_keepass.reverse_converter import _base64url_to_uuid
        # KeePassXC 测试数据: o-FfiyfBQq6Qz6YVrYeFTw → a3e15f8b-27c1-42ae-90cf-a615ad87854f
        result = _base64url_to_uuid('o-FfiyfBQq6Qz6YVrYeFTw')
        self.assertEqual(result, 'a3e15f8b-27c1-42ae-90cf-a615ad87854f')

    def test_base64url_to_uuid_already_uuid(self):
        """测试已经是 UUID 格式的不做转换"""
        from bw_to_keepass.reverse_converter import _base64url_to_uuid
        result = _base64url_to_uuid('e64a25a4-3081-4bc4-baf3-426638381cf6')
        self.assertEqual(result, 'e64a25a4-3081-4bc4-baf3-426638381cf6')

    def test_base64url_to_uuid_roundtrip(self):
        """测试 base64url ↔ UUID 往返转换一致性"""
        from bw_to_keepass.reverse_converter import _base64url_to_uuid
        from bw_to_keepass.converter import _uuid_to_base64
        original = 'a3e15f8b-27c1-42ae-90cf-a615ad87854f'
        b64 = _uuid_to_base64(original)
        restored = _base64url_to_uuid(b64)
        self.assertEqual(restored, original)

    def test_pem_to_b64url(self):
        """测试 PEM → URL-safe base64 反向转换"""
        from bw_to_keepass.reverse_converter import _pem_to_b64url
        # 构造一个简单的 PEM
        pem = '-----BEGIN PRIVATE KEY-----\nYWJjZGVm\n-----END PRIVATE KEY-----'
        result = _pem_to_b64url(pem)
        # abcdef 的 base64url 是 YWJjZGVm（无 padding）
        self.assertEqual(result, 'YWJjZGVm')

    def test_pem_to_b64url_already_b64(self):
        """测试已经是 base64 的不过 PEM 处理"""
        from bw_to_keepass.reverse_converter import _pem_to_b64url
        result = _pem_to_b64url('YWJjZGVm')
        self.assertEqual(result, 'YWJjZGVm')

    def test_pem_to_b64url_empty(self):
        """测试空值处理"""
        from bw_to_keepass.reverse_converter import _pem_to_b64url
        self.assertEqual(_pem_to_b64url(''), '')
        self.assertEqual(_pem_to_b64url(None), '')

    def test_base64url_to_uuid_empty(self):
        """测试空值处理"""
        from bw_to_keepass.reverse_converter import _base64url_to_uuid
        self.assertEqual(_base64url_to_uuid(''), '')
        self.assertEqual(_base64url_to_uuid(None), '')

    def test_pem_b64url_roundtrip(self):
        """测试 PEM ↔ URL-safe base64 往返转换"""
        from bw_to_keepass.reverse_converter import _pem_to_b64url
        from bw_to_keepass.converter import _format_private_key_pem
        # 使用 KeePassXC 测试数据中的 keyValue
        original_b64 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmr4GQQjerojFuf0ZouOuUllMvAwxZSZAfB6gwDYcLiehRANCAAT0WR5zVSp6ieusvjkLkzaGc7fjGBmwpiuLPxR_d-ZjqMI9L2DKh-takp6wGt2x0n4jzr1KA352NZg0vjZX9CHh'
        pem = _format_private_key_pem(original_b64)
        restored = _pem_to_b64url(pem)
        self.assertEqual(restored, original_b64)

    def test_detect_entry_type_card_fields(self):
        """验证 _detect_entry_type 能正确识别卡片类型（兼容 Brand/CardBrand）"""
        from bw_to_keepass.reverse_converter import _detect_entry_type

        class MockEntry:
            def __init__(self, fields):
                self._fields = fields
            def get_custom_property(self, k):
                return self._fields.get(k)

        # 用正向转换器写入的 Brand 字段应能识别为 Card (type=3)
        e1 = MockEntry({'Brand': 'Visa', 'CardNumber': '4539147200333257'})
        self.assertEqual(_detect_entry_type(e1, {'Brand': 'Visa', 'CardNumber': '4539147200333257'}), 3)

    def test_build_bitwarden_item_card_fields(self):
        """验证 _build_bitwarden_item 正确读取 Brand/Expiry 字段（修复字段名不匹配）"""
        from bw_to_keepass.reverse_converter import _build_bitwarden_item

        class MockEntry:
            def __init__(self):
                self.title = "Test Card"
                self.username = "John"
                self.password = "123"
                self.url = ""
                self.notes = ""
                self._fields = {
                    'BitwardenType': 'Card',
                    'CardNumber': '4111111111111111',
                    'Expiry': '12/2026',
                    'Brand': 'Visa',
                }
                self.custom_properties = list(self._fields.keys())
            def get_custom_property(self, k):
                return self._fields.get(k)

        item = _build_bitwarden_item(MockEntry(), None, 0)
        self.assertIsNotNone(item)
        self.assertEqual(item['type'], 3)
        self.assertEqual(item['card']['brand'], 'Visa')
        self.assertEqual(item['card']['number'], '4111111111111111')
        self.assertEqual(item['card']['expMonth'], '12')
        self.assertEqual(item['card']['expYear'], '2026')


class TestCSVExporter(unittest.TestCase):
    """测试 CSV 导出功能"""

    def test_import_csv_exporter(self):
        """测试 CSV 导出模块可以导入"""
        from bw_to_keepass.csv_exporter import CSV_COLUMNS, BITWARDEN_CSV_COLUMNS, KEEPASS_CSV_COLUMNS
        self.assertIsInstance(CSV_COLUMNS, list)
        self.assertIsInstance(BITWARDEN_CSV_COLUMNS, list)
        self.assertIsInstance(KEEPASS_CSV_COLUMNS, list)

    def test_csv_columns_have_required(self):
        """测试 CSV 列定义包含必要字段"""
        from bw_to_keepass.csv_exporter import CSV_COLUMNS
        required = ['Title', 'UserName', 'Password', 'URL', 'Notes']
        for col in required:
            self.assertIn(col, CSV_COLUMNS)

    def test_generic_csv_has_passkey_warning(self):
        """测试通用 CSV 有 Passkey 标记列"""
        from bw_to_keepass.csv_exporter import CSV_COLUMNS
        self.assertIn('HasPasskey', CSV_COLUMNS)


class TestEncryptedExport(unittest.TestCase):
    """测试 Bitwarden 加密导出（密码保护 JSON）的解密与解析"""

    EXPORT_PASSWORD = "S3cret-Export-P@ss"

    def _make_encrypted_export(self, plaintext: dict, password: str, enc_type: int = 2) -> dict:
        """构造一个加密导出 dict（解密算法的逆向，供测试自洽验证）

        enc_type: 0=AesCbc256 无 MAC / 1=AesCbc128+HMAC / 2=AesCbc256+HMAC
        """
        import os
        import base64
        import hashlib
        import hmac
        import json
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from bw_to_keepass.encrypted import _hkdf_expand

        salt = base64.b64encode(os.urandom(16)).decode('ascii')  # base64 字符串
        kdf_iterations = 100000
        master_key = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt.encode('utf-8'), kdf_iterations, dklen=32
        )
        enc_key = _hkdf_expand(master_key, 32, b'enc')
        mac_key = _hkdf_expand(master_key, 32, b'mac')

        def enc(obj) -> str:
            iv = os.urandom(16)
            pt = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            pad = 16 - (len(pt) % 16)
            pt += bytes([pad]) * pad
            key = enc_key[:16] if enc_type == 1 else enc_key  # encType 1 用 128 位密钥
            c = Cipher(algorithms.AES(key), modes.CBC(iv))
            e = c.encryptor()
            ct = e.update(pt) + e.finalize()
            if enc_type == 0:
                return f"0.{base64.b64encode(iv).decode()}|{base64.b64encode(ct).decode()}"
            mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
            return f"{enc_type}.{base64.b64encode(iv).decode()}|{base64.b64encode(ct).decode()}|{base64.b64encode(mac).decode()}"

        return {
            "encrypted": True,
            "passwordProtected": True,
            "salt": salt,
            "kdfType": 0,
            "kdfIterations": kdf_iterations,
            "encKeyValidation_DO_NOT_EDIT": enc({"test": "validation"}),
            "data": enc(plaintext),
        }

    def _sample_plaintext(self) -> dict:
        return {
            "folders": [{"id": "f1", "name": "测试文件夹"}],
            "items": [{
                "id": "i1", "type": 1, "name": "示例登录", "folderId": "f1",
                "login": {
                    "username": "user@example.com",
                    "password": "s3cret",
                    "totp": "JBSWY3DPEHPK3PXP",
                    "uris": [{"uri": "https://example.com", "match": None}],
                },
            }],
        }

    def test_decrypt_and_parse_with_correct_password(self):
        """正确密码应能解密并解析出条目"""
        enc = self._make_encrypted_export(self._sample_plaintext(), self.EXPORT_PASSWORD)
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(enc, f, ensure_ascii=False)
            path = f.name
        try:
            folders, items = parse_bitwarden_export(path, export_password=self.EXPORT_PASSWORD)
        finally:
            os.unlink(path)
        self.assertEqual(len(folders), 1)
        self.assertEqual(folders[0].name, "测试文件夹")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].name, "示例登录")
        self.assertEqual(items[0].username, "user@example.com")
        self.assertEqual(items[0].password, "s3cret")
        self.assertEqual(items[0].totp, "JBSWY3DPEHPK3PXP")
        self.assertEqual(items[0].uris[0].uri, "https://example.com")

    def test_wrong_password_raises(self):
        """错误密码应抛出 EncryptedExportError（MAC 验证失败）"""
        enc = self._make_encrypted_export(self._sample_plaintext(), self.EXPORT_PASSWORD)
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(enc, f, ensure_ascii=False)
            path = f.name
        try:
            with self.assertRaises(EncryptedExportError):
                parse_bitwarden_export(path, export_password="wrong-password")
        finally:
            os.unlink(path)

    def test_decrypt_enc_type_1_aes128(self):
        """encType=1 (AesCbc128+HMAC) 导出应能用正确密码解密并解析"""
        enc = self._make_encrypted_export(self._sample_plaintext(), self.EXPORT_PASSWORD, enc_type=1)
        self.assertTrue(enc['data'].startswith('1.'))
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(enc, f, ensure_ascii=False)
            path = f.name
        try:
            folders, items = parse_bitwarden_export(path, export_password=self.EXPORT_PASSWORD)
        finally:
            os.unlink(path)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].password, "s3cret")

    def test_decrypt_enc_type_0_no_mac(self):
        """encType=0 (AesCbc256 无 MAC) 导出应能用正确密码解密并解析"""
        enc = self._make_encrypted_export(self._sample_plaintext(), self.EXPORT_PASSWORD, enc_type=0)
        self.assertTrue(enc['data'].startswith('0.'))
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(enc, f, ensure_ascii=False)
            path = f.name
        try:
            folders, items = parse_bitwarden_export(path, export_password=self.EXPORT_PASSWORD)
        finally:
            os.unlink(path)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].name, "示例登录")

    def test_enc_type_unsupported_raises(self):
        """不支持的加密类型应被透传真实错误（而非伪装成 MAC 失败）"""
        enc = self._make_encrypted_export(self._sample_plaintext(), self.EXPORT_PASSWORD, enc_type=1)
        enc['data'] = '99.' + enc['data'].split('.', 1)[1]  # 篡改 encType 为 99
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(enc, f, ensure_ascii=False)
            path = f.name
        try:
            with self.assertRaisesRegex(EncryptedExportError, '不支持的加密类型'):
                parse_bitwarden_export(path, export_password=self.EXPORT_PASSWORD)
        finally:
            os.unlink(path)

    def test_missing_password_raises_requires_password(self):
        """未提供密码时应抛出 EncryptedExportRequiresPassword，而非静默空库"""
        enc = self._make_encrypted_export(self._sample_plaintext(), self.EXPORT_PASSWORD)
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(enc, f, ensure_ascii=False)
            path = f.name
        try:
            with self.assertRaises(EncryptedExportRequiresPassword):
                parse_bitwarden_export(path)
        finally:
            os.unlink(path)

    def test_plaintext_export_unaffected(self):
        """明文导出不传密码仍应正常解析（向后兼容）"""
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(self._sample_plaintext(), f, ensure_ascii=False)
            path = f.name
        try:
            folders, items = parse_bitwarden_export(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].name, "示例登录")

    def _make_argon2_export(self, plaintext: dict, password: str) -> dict:
        """构造一个 Argon2id 加密导出 dict（官方约定：salt 为 Base64 字符串，KDF 使用其解码后的原始字节）"""
        import os
        import base64
        import hashlib
        import hmac
        import json
        from argon2.low_level import hash_secret_raw, Type
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from bw_to_keepass.encrypted import _hkdf_expand

        salt_str = base64.b64encode(os.urandom(16)).decode('ascii')
        salt = base64.b64decode(salt_str)  # 官方：Base64 解码得到原始字节
        kdf_iterations, kdf_memory, kdf_parallelism = 6, 32, 4
        master_key = hash_secret_raw(
            password.encode('utf-8'), salt,
            time_cost=kdf_iterations, memory_cost=kdf_memory * 1024,
            parallelism=kdf_parallelism, hash_len=32, type=Type.ID, version=19,
        )
        enc_key = _hkdf_expand(master_key, 32, b'enc')
        mac_key = _hkdf_expand(master_key, 32, b'mac')

        def enc(obj) -> str:
            iv = os.urandom(16)
            pt = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            pad = 16 - (len(pt) % 16)
            pt += bytes([pad]) * pad
            c = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
            e = c.encryptor()
            ct = e.update(pt) + e.finalize()
            mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
            return f"2.{base64.b64encode(iv).decode()}|{base64.b64encode(ct).decode()}|{base64.b64encode(mac).decode()}"

        return {
            "encrypted": True,
            "passwordProtected": True,
            "salt": salt_str,
            "kdfType": 1,
            "kdfIterations": kdf_iterations,
            "kdfMemory": kdf_memory,
            "kdfParallelism": kdf_parallelism,
            "encKeyValidation_DO_NOT_EDIT": enc({"test": "validation"}),
            "data": enc(plaintext),
        }

    def test_argon2_decrypt_and_parse_with_correct_password(self):
        """Argon2id 导出（kdfType=1）使用正确密码应能解密并解析出条目"""
        enc = self._make_argon2_export(self._sample_plaintext(), self.EXPORT_PASSWORD)
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(enc, f, ensure_ascii=False)
            path = f.name
        try:
            folders, items = parse_bitwarden_export(path, export_password=self.EXPORT_PASSWORD)
        finally:
            os.unlink(path)
        self.assertEqual(len(folders), 1)
        self.assertEqual(folders[0].name, "测试文件夹")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].name, "示例登录")
        self.assertEqual(items[0].password, "s3cret")

    def test_argon2_wrong_password_raises(self):
        """Argon2id 导出使用错误密码应抛出 EncryptedExportError（MAC 验证失败）"""
        enc = self._make_argon2_export(self._sample_plaintext(), self.EXPORT_PASSWORD)
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(enc, f, ensure_ascii=False)
            path = f.name
        try:
            with self.assertRaises(EncryptedExportError):
                parse_bitwarden_export(path, export_password="wrong-password")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
