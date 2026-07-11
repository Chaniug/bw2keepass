"""
数据保真回归测试：密码历史往返 & 附件丢失修复

对应 OPTIMIZATION_PLAN.md 的 P0 项：
  - 密码历史（passwordHistory）在 BW→KDBX→BW 往返后须完整保留
  - 附件（Attachment）从 Bitwarden 未加密 ZIP 解析并写入 KDBX，往返不丢
"""

import io
import json
import os
import tempfile
import unittest
import zipfile

from bw_to_keepass.parser import VaultItem, Folder, Attachment, PasswordHistory
from bw_to_keepass.converter import build_custom_fields
from bw_to_keepass.writer import write_keepass
from bw_to_keepass.reverse_converter import convert_kdbx_to_bitwarden
from pykeepass import PyKeePass


def _make_item(name="Login A", with_history=True, with_attachment=True):
    item = VaultItem(
        id="11111111-1111-1111-1111-111111111111",
        type=1,
        name=name,
        username="user",
        password="pass",
        notes="notes",
    )
    if with_history:
        item.password_history = [
            PasswordHistory(password="old1", last_used_date="2023-01-01T00:00:00.000Z"),
            PasswordHistory(password="old2", last_used_date="2023-06-01T00:00:00.000Z"),
        ]
    if with_attachment:
        item.attachments = [
            Attachment(id="att-1", file_name="readme.txt", data=b"hello-binary", size=12),
        ]
    return item


class TestPasswordHistoryRoundtrip(unittest.TestCase):
    """密码历史：BW→KDBX（结构化字段）→ BW 必须无损"""

    def _kdbx_bytes(self, item):
        tmp = tempfile.mktemp(suffix=".kdbx")
        try:
            write_keepass([], [item], tmp, password="pwd", db_name="Test")
            with open(tmp, "rb") as f:
                return f.read()
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def test_kpex_field_written(self):
        item = _make_item()
        fields = build_custom_fields(item)
        self.assertIn("KPEX_PW_HISTORY", fields)
        parsed = json.loads(fields["KPEX_PW_HISTORY"])
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["password"], "old1")

    def test_roundtrip_preserved(self):
        item = _make_item()
        data = self._kdbx_bytes(item)
        tmp = tempfile.mktemp(suffix=".kdbx")
        try:
            with open(tmp, "wb") as f:
                f.write(data)
            bw = convert_kdbx_to_bitwarden(tmp, "pwd")
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        back = bw["items"][0]
        self.assertEqual(len(back["passwordHistory"]), 2)
        self.assertEqual(back["passwordHistory"][0]["password"], "old1")
        self.assertEqual(back["passwordHistory"][1]["lastUsedDate"], "2023-06-01T00:00:00.000Z")

    def test_empty_history_no_field(self):
        item = _make_item(with_history=False)
        fields = build_custom_fields(item)
        self.assertNotIn("KPEX_PW_HISTORY", fields)


class TestAttachmentFidelity(unittest.TestCase):
    """附件：Bitwarden 未加密 ZIP → 解析 → KDBX → 读回，字节不丢"""

    def _build_zip(self):
        buf = io.BytesIO()
        item = {
            "id": "22222222-2222-2222-2222-222222222222",
            "type": 1,
            "name": "With Attachment",
            "login": {"username": "u", "password": "p"},
            "attachments": [{"id": "att-1", "fileName": "doc.txt", "size": 5}],
        }
        export = {"encrypted": False, "folders": [], "items": [item]}
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.json", json.dumps(export))
            zf.writestr("attachments/att-1/doc.txt", b"hello")
        return buf.getvalue()

    def test_parse_zip_attachment(self):
        from bw_to_keepass.parser import parse_bitwarden_export
        tmp = tempfile.mktemp(suffix=".zip")
        try:
            with open(tmp, "wb") as f:
                f.write(self._build_zip())
            folders, items = parse_bitwarden_export(tmp)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        self.assertEqual(len(items), 1)
        atts = items[0].attachments
        self.assertEqual(len(atts), 1)
        self.assertEqual(atts[0].file_name, "doc.txt")
        self.assertEqual(atts[0].data, b"hello")

    def test_attachment_written_to_kdbx(self):
        from bw_to_keepass.parser import parse_bitwarden_export
        zip_path = tempfile.mktemp(suffix=".zip")
        kdbx_path = tempfile.mktemp(suffix=".kdbx")
        try:
            with open(zip_path, "wb") as f:
                f.write(self._build_zip())
            folders, items = parse_bitwarden_export(zip_path)
            write_keepass(folders, items, kdbx_path, password="pwd", db_name="Test")
            kp = PyKeePass(kdbx_path, password="pwd")
            entry = kp.find_entries(title="With Attachment", first=True)
            self.assertIsNotNone(entry)
            self.assertEqual(len(entry.attachments), 1)
            att = entry.attachments[0]
            self.assertEqual(att.filename, "doc.txt")
            self.assertEqual(att.data, b"hello")
        finally:
            for p in (zip_path, kdbx_path):
                if os.path.exists(p):
                    os.unlink(p)

    def test_attachment_metadata_in_reverse_json(self):
        from bw_to_keepass.parser import parse_bitwarden_export
        zip_path = tempfile.mktemp(suffix=".zip")
        kdbx_path = tempfile.mktemp(suffix=".kdbx")
        try:
            with open(zip_path, "wb") as f:
                f.write(self._build_zip())
            folders, items = parse_bitwarden_export(zip_path)
            write_keepass(folders, items, kdbx_path, password="pwd", db_name="Test")
            bw = convert_kdbx_to_bitwarden(kdbx_path, "pwd")
            back = bw["items"][0]
            self.assertEqual(len(back["attachments"]), 1)
            self.assertEqual(back["attachments"][0]["fileName"], "doc.txt")
            self.assertEqual(back["attachments"][0]["size"], 5)
        finally:
            for p in (zip_path, kdbx_path):
                if os.path.exists(p):
                    os.unlink(p)


if __name__ == "__main__":
    unittest.main()
