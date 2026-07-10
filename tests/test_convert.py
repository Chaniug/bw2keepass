"""
传入 / 传出 统一转换枢纽测试

覆盖：
  - Bitwarden 源 → json / csv / 1pux / encrypted
  - Bitwarden → KDBX（写出）→ KDBX → json 往返
  - vault_items_to_bitwarden / vault_items_to_csv 纯函数
"""

import io
import json
import os
import tempfile
import unittest
import csv
import zipfile

from bw_to_keepass.convert import (
    convert, vault_items_to_bitwarden, vault_items_to_csv,
    parse_source, render_target, TARGET_FORMATS,
)
from bw_to_keepass.parser import parse_bitwarden_dict

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, 'fixtures', 'sample_export.json')
TEST_PWD = 'test-password-1234'


class TestConvertHub(unittest.TestCase):

    def setUp(self):
        with open(FIXTURE, 'r', encoding='utf-8') as f:
            self.data = json.load(f)
        self.n_folders = len(self.data['folders'])
        # 实际可解析条目数（跳过含 deletedDate 的项）
        folders, items = parse_source(FIXTURE, 'bitwarden')
        self.n_items = len(items)
        self.folders = folders
        self.items = items
        self.assertGreater(self.n_items, 0)

    # ---- 源解析 ----
    def test_parse_source_bitwarden(self):
        self.assertEqual(len(self.folders), self.n_folders)
        self.assertEqual(len(self.items), self.n_items)

    # ---- 纯函数：VaultItem → Bitwarden ----
    def test_vault_items_to_bitwarden(self):
        out = vault_items_to_bitwarden(self.folders, self.items)
        self.assertEqual(out['encrypted'], False)
        self.assertEqual(len(out['folders']), self.n_folders)
        self.assertEqual(len(out['items']), self.n_items)
        # 往返稳定：再解析一次数量一致
        f2, i2 = parse_bitwarden_dict(out)
        self.assertEqual(len(i2), self.n_items)

    # ---- 纯函数：VaultItem → CSV ----
    def test_vault_items_to_csv(self):
        csv_text = vault_items_to_csv(self.items, 'generic')
        self.assertIn('Title', csv_text)
        self.assertIn('URL', csv_text)
        # 用 csv.reader 正确计数（字段内换行不应被拆行）
        rows = list(csv.reader(io.StringIO(csv_text)))
        self.assertEqual(len(rows), self.n_items + 1)  # +表头

    def test_vault_items_to_csv_bitwarden_fmt(self):
        csv_text = vault_items_to_csv(self.items, 'bitwarden')
        self.assertIn('login_username', csv_text)

    # ---- 目标渲染：1PUX ----
    def test_render_1pux(self):
        raw = render_target(self.folders, self.items, '1pux')
        self.assertIsInstance(raw, bytes)
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            self.assertTrue(any(n.endswith('1password.1pif') for n in names))

    # ---- 目标渲染：加密 JSON 可解密回 ----
    def test_render_encrypted_roundtrip(self):
        raw = render_target(self.folders, self.items, 'encrypted',
                            export_password=TEST_PWD, salt_mode='utf8')
        env = json.loads(raw.decode('utf-8'))
        self.assertTrue(env.get('encrypted'))
        # 解密回来
        from bw_to_keepass.encrypted import decrypt_bitwarden_export
        plain = decrypt_bitwarden_export(env, TEST_PWD)
        self.assertEqual(len(plain['items']), self.n_items)

    # ---- 统一入口：多目标 ----
    def test_convert_multi_target(self):
        results = convert(FIXTURE, ['json', 'csv', '1pux'],
                          source_format='bitwarden',
                          export_password=TEST_PWD)
        self.assertEqual(set(results.keys()), {'json', 'csv', '1pux'})
        self.assertTrue(results['json'].startswith(b'{'))
        self.assertIn(b'Title', results['csv'])

    # ---- KDBX 往返：Bitwarden → KDBX → json ----
    def test_kdbx_roundtrip(self):
        kdbx_bytes = render_target(self.folders, self.items, 'kdbx',
                                   db_password=TEST_PWD)
        # KDBX 文件头签名
        self.assertTrue(kdbx_bytes[:4] in (b'KDBX', b'\x03\xd9\xa2\x9a'))
        tmp = tempfile.NamedTemporaryFile(suffix='.kdbx', delete=False).name
        try:
            with open(tmp, 'wb') as f:
                f.write(kdbx_bytes)
            f2, i2 = parse_source(tmp, 'kdbx', password=TEST_PWD)
            self.assertEqual(len(i2), self.n_items)
            # 再写出 json，数量应一致
            out = vault_items_to_bitwarden(f2, i2)
            self.assertEqual(len(out['items']), self.n_items)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # ---- 目标格式常量 ----
    def test_target_formats_constant(self):
        self.assertIn('kdbx', TARGET_FORMATS)
        self.assertIn('1pux', TARGET_FORMATS)
        self.assertIn('encrypted', TARGET_FORMATS)


if __name__ == '__main__':
    unittest.main()
