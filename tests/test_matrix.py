"""
转换格式矩阵测试（传入 → 传出 全组合校验）

目标：在推送前确认「任意源格式 → 任意目标格式」没有出现结构性问题。

覆盖：
  1) 每个源格式都能被 parse_source 正确解析（条目数 / 文件夹数保真）
  2) 每个目标格式都能被 render_target 正确写出（产物可打开 / 可再解析）
  3) 4 个「既是源又是目标」的格式两两往返（bitwarden↔encrypted↔kdbx↔1pux），
     往返后条目数保持一致
  4) 全组合 convert() 冒烟：4 源 × 6 目标，无异常且产物 key 正确
  5) CSV 产物结构校验（BOM / 表头 / 行数）

运行：python -m pytest tests/test_matrix.py -v
"""

import csv
import io
import json
import os
import tempfile
import unittest
import zipfile

from bw_to_keepass.convert import (
    convert, parse_source, render_target,
    vault_items_to_bitwarden, vault_items_to_1pux,
    SOURCE_FORMATS, TARGET_FORMATS,
)
from bw_to_keepass.parser import (
    Folder, VaultItem, Uri, CustomField, PasswordHistory, Fido2Credential,
)
from bw_to_keepass.encrypted import encrypt_bitwarden_export, decrypt_bitwarden_export

try:
    from pykeepass import PyKeePass
except ImportError:  # pragma: no cover
    PyKeePass = None

HERE = os.path.dirname(os.path.abspath(__file__))
PWD = 'matrix-test-password-1234'


def _canonical_vault():
    """构造一个覆盖多种类型与字段的代表性密码库"""
    folders = [
        Folder(id='f-work', name='Work'),
        Folder(id='f-personal', name='Personal'),
    ]
    items = [
        VaultItem(
            id='i-github', type=1, name='GitHub', folder='Work', favorite=True,
            username='octocat', password='s3cr3t-pw', totp='otpauth://totp/GitHub',
            uris=[Uri(uri='https://github.com/login'), Uri(uri='https://github.com/settings')],
            custom_fields=[CustomField(name='2FA backup', value='ABCD-EFGH', type=1)],
            password_history=[PasswordHistory(password='old-pw', last_used_date='2024-01-01T00:00:00Z')],
            fido2_credentials=[Fido2Credential(
                credential_id='cred-1', key_type='public-key', key_algorithm='ECDSA',
                key_curve='P-256', rp_id='github.com', rp_name='GitHub',
                user_name='octocat', counter='0', discoverable='true',
            )],
        ),
        VaultItem(
            id='i-wifi', type=2, name='Home WiFi', folder='Personal',
            notes='SSID: MyNet\nPassword: very-long-passphrase\nline3',
        ),
        VaultItem(
            id='i-visa', type=3, name='Visa Card', folder='Work',
            cardholder_name='John Doe', card_brand='Visa', card_number='4111111111111111',
            card_exp_month='12', card_exp_year='2029', card_code='123',
        ),
        VaultItem(
            id='i-identity', type=4, name='John Doe', folder='Personal',
            identity_title='Mr', identity_first_name='John', identity_last_name='Doe',
            identity_address1='123 Main St', identity_city='Springfield',
            identity_postal_code='12345', identity_country='US',
            identity_email='john@example.com', identity_phone='+1-555-0100',
            identity_ssn='123-45-6789',
        ),
        VaultItem(
            id='i-ssh', type=5, name='Server SSH', folder='Work',
            ssh_private_key='-----BEGIN OPENSSH PRIVATE KEY-----', ssh_public_key='ssh-ed25519 AAAA...',
        ),
    ]
    return folders, items


def _write_source(fmt, folders, items, tmpdir):
    """为给定源格式构造一个临时源文件，返回 (path, parse_kwargs)"""
    if fmt == 'bitwarden':
        data = vault_items_to_bitwarden(folders, items)
        p = os.path.join(tmpdir, 'src_bitwarden.json')
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
        return p, {'source_format': 'bitwarden'}

    if fmt == 'encrypted':
        data = vault_items_to_bitwarden(folders, items)
        env = encrypt_bitwarden_export(data, PWD, salt_mode='utf8')
        p = os.path.join(tmpdir, 'src_encrypted.json')
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(env, f, ensure_ascii=False)
        return p, {'source_format': 'encrypted', 'export_password': PWD}

    if fmt == '1password':
        raw = vault_items_to_1pux(folders, items)
        p = os.path.join(tmpdir, 'src_1password.1pux')
        with open(p, 'wb') as f:
            f.write(raw)
        return p, {'source_format': '1password'}

    if fmt == 'kdbx':
        raw = render_target(folders, items, 'kdbx', db_password=PWD)
        p = os.path.join(tmpdir, 'src_kdbx.kdbx')
        with open(p, 'wb') as f:
            f.write(raw)
        return p, {'source_format': 'kdbx', 'password': PWD}

    raise ValueError(fmt)


def _validate_target(fmt, raw, folders, items, tmpdir):
    """校验某目标格式产物是否「可打开 / 结构正确」"""
    if fmt in ('json', 'bitwarden'):
        data = json.loads(raw.decode('utf-8'))
        assert data.get('items'), f'{fmt}: 产物无 items'
        return len(data['items'])
    if fmt == 'encrypted':
        env = json.loads(raw.decode('utf-8'))
        assert env.get('encrypted'), f'encrypted: 标记缺失'
        plain = decrypt_bitwarden_export(env, PWD)
        return len(plain['items'])
    if fmt == 'csv':
        text = raw.decode('utf-8-sig')
        assert text.startswith('﻿') or raw[:3] == b'\xef\xbb\xbf', 'csv: 缺少 UTF-8 BOM'
        rows = list(csv.reader(io.StringIO(text)))
        assert rows[0][0].lower() in ('title', 'name'), f'csv: 表头异常 {rows[0][:3]}'
        return len(rows) - 1  # 去掉表头
    if fmt == '1pux':
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            assert any(n.endswith('1password.1pif') for n in names), '1pux: 缺少 1password.1pif'
        return None  # 1PUX 内部结构由 1Password 解析器校验，数量在往返测试中确认
    if fmt == 'kdbx':
        assert raw[:4] in (b'KDBX', b'\x03\xd9\xa2\x9a'), 'kdbx: 文件头签名异常'
        if PyKeePass is None:
            return None
        p = os.path.join(tmpdir, 'check.kdbx')
        with open(p, 'wb') as f:
            f.write(raw)
        kp = PyKeePass(p, password=PWD)
        return len(kp.entries)
    if fmt == 'zip':
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            assert 'data.json' in names, 'zip: 缺少 data.json'
            data = json.loads(zf.read('data.json').decode('utf-8'))
        assert data.get('items'), 'zip: 产物无 items'
        return len(data['items'])
    raise ValueError(fmt)


class TestFormatMatrix(unittest.TestCase):

    def setUp(self):
        self.folders, self.items = _canonical_vault()
        self.n_items = len(self.items)
        self.n_folders = len(self.folders)

    # ------------------------------------------------------------------
    # 1) 源解析保真
    # ------------------------------------------------------------------
    def test_source_parse_fidelity(self):
        for fmt in SOURCE_FORMATS:
            with self.subTest(source=fmt):
                with tempfile.TemporaryDirectory() as d:
                    p, kw = _write_source(fmt, self.folders, self.items, d)
                    f2, i2 = parse_source(p, **kw)
                    self.assertEqual(len(i2), self.n_items, f'{fmt} 解析条目数不符')
                    self.assertEqual(len(f2), self.n_folders, f'{fmt} 解析文件夹数不符')

    # ------------------------------------------------------------------
    # 2) 目标写出可打开
    # ------------------------------------------------------------------
    def test_target_render_valid(self):
        for fmt in TARGET_FORMATS:
            with self.subTest(target=fmt):
                with tempfile.TemporaryDirectory() as d:
                    raw = render_target(
                        self.folders, self.items, fmt,
                        db_password=PWD, export_password=PWD,
                    )
                    if fmt == 'kdbx':
                        self.assertTrue(raw[:4] in (b'KDBX', b'\x03\xd9\xa2\x9a'))
                    elif fmt == '1pux':
                        _validate_target(fmt, raw, self.folders, self.items, d)
                    else:
                        n = _validate_target(fmt, raw, self.folders, self.items, d)
                        if n is not None:
                            self.assertEqual(n, self.n_items, f'{fmt} 产物条目数不符')

    # ------------------------------------------------------------------
    # 3) 可互转格式两两往返（bitwarden/encrypted/kdbx/1pux）
    # ------------------------------------------------------------------
    def test_roundtrip_matrix(self):
        rt_sources = ['bitwarden', 'encrypted', '1password', 'kdbx']
        rt_targets = ['bitwarden', 'encrypted', '1pux', 'kdbx']
        for src in rt_sources:
            for tgt in rt_targets:
                with self.subTest(src=src, tgt=tgt):
                    with tempfile.TemporaryDirectory() as d:
                        sp, skw = _write_source(src, self.folders, self.items, d)
                        f0, i0 = parse_source(sp, **skw)
                        raw = render_target(
                            f0, i0, tgt, db_password=PWD, export_password=PWD,
                        )
                        # 写回临时文件并再次解析
                        if tgt == 'bitwarden':
                            tp = os.path.join(d, 'tgt.json')
                            with open(tp, 'w', encoding='utf-8') as f:
                                json.dump(json.loads(raw.decode('utf-8')), f, ensure_ascii=False)
                            f1, i1 = parse_source(tp, source_format='bitwarden')
                        elif tgt == 'encrypted':
                            tp = os.path.join(d, 'tgt.json')
                            with open(tp, 'w', encoding='utf-8') as f:
                                json.dump(json.loads(raw.decode('utf-8')), f, ensure_ascii=False)
                            f1, i1 = parse_source(tp, source_format='encrypted', export_password=PWD)
                        elif tgt == 'kdbx':
                            tp = os.path.join(d, 'tgt.kdbx')
                            with open(tp, 'wb') as f:
                                f.write(raw)
                            f1, i1 = parse_source(tp, source_format='kdbx', password=PWD)
                        elif tgt == '1pux':
                            tp = os.path.join(d, 'tgt.1pux')
                            with open(tp, 'wb') as f:
                                f.write(raw)
                            f1, i1 = parse_source(tp, source_format='1password')
                        self.assertEqual(
                            len(i1), self.n_items,
                            f'往返 {src}→{tgt} 后条目数不符 ({len(i1)} != {self.n_items})'
                        )

    # ------------------------------------------------------------------
    # 4) 全组合 convert() 冒烟
    # ------------------------------------------------------------------
    def test_full_convert_smoke(self):
        # 注意：convert() 将 'bitwarden' 归一为 'json'，返回 key 中不含 'bitwarden'
        expected = {'kdbx', 'json', 'encrypted', '1pux', 'csv', 'zip'}
        for fmt in SOURCE_FORMATS:
            with self.subTest(source=fmt):
                with tempfile.TemporaryDirectory() as d:
                    p, kw = _write_source(fmt, self.folders, self.items, d)
                    # 合并密钥：源解析密码 + 目标写出密码（避免重复传参）
                    secrets = {'db_password': PWD, 'export_password': PWD}
                    secrets.update(kw)
                    results = convert(p, list(TARGET_FORMATS), **secrets)
                    self.assertEqual(set(results.keys()), expected,
                                     f'{fmt} 目标产物 key 不完整: {set(results.keys())}')
                    for tgt, raw in results.items():
                        self.assertTrue(raw, f'{fmt}→{tgt} 产物为空')

    # ------------------------------------------------------------------
    # 5) CSV 结构细节
    # ------------------------------------------------------------------
    def test_csv_structure(self):
        raw = render_target(self.folders, self.items, 'csv', csv_format='generic')
        self.assertEqual(raw[:3], b'\xef\xbb\xbf', 'csv: 缺少 UTF-8 BOM')
        text = raw.decode('utf-8-sig')
        rows = list(csv.reader(io.StringIO(text)))
        # 5 条目 + 1 表头
        self.assertEqual(len(rows), self.n_items + 1, 'csv: 行数异常')
        self.assertIn('Title', rows[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
