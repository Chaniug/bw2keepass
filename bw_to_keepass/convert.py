"""
传入 / 传出 统一转换枢纽

以统一中间模型 (VaultItem / Folder) 为中心，实现「任意源格式 → 任意目标格式」：

    源格式 (parse_source)         →  VaultItem 列表  →  目标格式 (render_target)
    bitwarden / encrypted                                 kdbx / json / encrypted
    1password / kdbx                                      1pux / csv

所有目标统一经「VaultItem → Bitwarden dict」序列化，再由对应写出器落地，
复用充分且无额外字段损耗（与现有 1Password→KDBX 同级）。
"""

import io
import json
import os
import tempfile
import uuid as uuid_mod
import zipfile
from typing import Any

from .parser import (
    VaultItem, Folder, Uri, CustomField, PasswordHistory, Fido2Credential,
    parse_bitwarden_export, parse_bitwarden_dict,
)
from .onepassword import parse_1password_export, is_1password_data
from .encrypted import (
    encrypt_bitwarden_export, EncryptedExportRequiresPassword, EncryptedExportError,
)
from .csv_exporter import vault_items_to_csv
from .reverse_to_1password import bitwarden_to_1pux

try:
    from pykeepass import PyKeePass
except ImportError:  # pragma: no cover
    PyKeePass = None


# ---------------------------------------------------------------------------
# 格式清单（供 CLI / 前端枚举）
# ---------------------------------------------------------------------------
SOURCE_FORMATS = ('bitwarden', 'encrypted', '1password', 'kdbx')
TARGET_FORMATS = ('kdbx', 'json', 'bitwarden', 'encrypted', '1pux', 'csv', 'zip')

# 目标格式默认文件扩展名
TARGET_EXT = {
    'kdbx': '.kdbx',
    'json': '.json',
    'bitwarden': '.json',
    'encrypted': '.json',
    '1pux': '.1pux',
    'csv': '.csv',
    'zip': '.zip',
}


# ---------------------------------------------------------------------------
# 源解析：源格式 → (folders, items)
# ---------------------------------------------------------------------------
def detect_source_format(source: str) -> str:
    """根据扩展名与内容探测源格式"""
    ext = os.path.splitext(source)[1].lower()
    if ext == '.kdbx':
        return 'kdbx'
    if ext == '.1pux':
        return '1password'
    if ext in ('.json', '.zip'):
        if ext == '.json':
            try:
                with open(source, 'r', encoding='utf-8') as f:
                    probe = json.load(f)
                if is_1password_data(probe):
                    return '1password'
            except Exception:
                pass
        return 'bitwarden'
    raise ValueError(f"无法识别的源文件类型: {ext}（支持 {', '.join(SOURCE_FORMATS)}）")


def parse_source(
    source: str,
    source_format: str | None = None,
    *,
    password: str | None = None,
    key_file: str | None = None,
    export_password: str | None = None,
    email: str | None = None,
    master_password: str | None = None,
) -> tuple[list[Folder], list[VaultItem]]:
    """解析任意源文件为统一中间模型

    Args:
        source: 源文件路径
        source_format: 显式指定源格式；为 None 时自动探测
        password: 读取受保护源所需密码（KDBX 主密码 或 Bitwarden 导出密码）
        key_file: KDBX 密钥文件
        export_password: 解密 Bitwarden 加密导出用
        email / master_password: 解密账户限制型加密导出用
    Returns:
        (folders, items)
    """
    fmt = (source_format or detect_source_format(source)).lower()

    if fmt in ('bitwarden', 'encrypted'):
        return parse_bitwarden_export(
            source,
            export_password=export_password,
            master_password=master_password,
            email=email,
        )

    if fmt == '1password':
        return parse_1password_export(source)

    if fmt == 'kdbx':
        if PyKeePass is None:
            raise ImportError("需要安装 pykeepass: pip install pykeepass>=4.1.0")
        from .reverse_converter import convert_kdbx_to_bitwarden
        data = convert_kdbx_to_bitwarden(source, password or '', key_file)
        return parse_bitwarden_dict(data)

    raise ValueError(f"不支持的源格式: {fmt}")


# ---------------------------------------------------------------------------
# 写出：VaultItem → 目标格式字节
# ---------------------------------------------------------------------------
def vault_items_to_bitwarden(folders: list[Folder], items: list[VaultItem]) -> dict:
    """将统一中间模型序列化为 Bitwarden 导出 dict

    结构与 parser._parse_data 的消费格式一致，保证
    VaultItem → Bitwarden → VaultItem 往返稳定。
    """
    folder_list = []
    folder_name_to_id: dict[str, str] = {}
    for f in folders:
        fid = f.id or str(uuid_mod.uuid4())
        folder_name_to_id[f.name] = fid
        folder_list.append({'id': fid, 'name': f.name})

    bw_items = []
    for it in items:
        folder_id = folder_name_to_id.get(it.folder) if it.folder else None

        bw: dict[str, Any] = {
            'id': it.id or str(uuid_mod.uuid4()),
            'organizationId': None,
            'folderId': folder_id,
            'type': it.type,
            'reprompt': 0,
            'name': it.name or '(无标题)',
            'notes': it.notes or None,
            'favorite': bool(it.favorite),
            'login': None,
            'card': None,
            'identity': None,
            'secureNote': None,
            'sshKey': None,
            'collectionIds': [],
            'fields': [],
            'passwordHistory': [],
            'fido2Credentials': [],
            'creationDate': it.creation_date or None,
            'revisionDate': it.revision_date or None,
        }

        if it.type == 1:  # Login
            bw['login'] = {
                'username': it.username or None,
                'password': it.password or None,
                'totp': it.totp or None,
                'uris': [{'uri': u.uri, 'match': u.match} for u in it.uris],
            }
        elif it.type == 2:  # Secure Note
            bw['secureNote'] = {'type': 0}
        elif it.type == 3:  # Card
            bw['card'] = {
                'cardholderName': it.cardholder_name or None,
                'brand': it.card_brand or None,
                'number': it.card_number or None,
                'expMonth': _int_or_none(it.card_exp_month),
                'expYear': _int_or_none(it.card_exp_year),
                'code': it.card_code or None,
            }
        elif it.type == 4:  # Identity
            bw['identity'] = {
                'title': it.identity_title or None,
                'firstName': it.identity_first_name or None,
                'middleName': it.identity_middle_name or None,
                'lastName': it.identity_last_name or None,
                'address1': it.identity_address1 or None,
                'address2': '',
                'address3': '',
                'city': it.identity_city or None,
                'state': it.identity_state or None,
                'postalCode': it.identity_postal_code or None,
                'country': it.identity_country or None,
                'company': '',
                'email': it.identity_email or None,
                'phone': it.identity_phone or None,
                'ssn': it.identity_ssn or None,
                'passportNumber': it.identity_passport_number or None,
                'licenseNumber': it.identity_license_number or None,
            }
        elif it.type == 5:  # SSH Key
            bw['sshKey'] = {
                'privateKey': it.ssh_private_key or None,
                'publicKey': it.ssh_public_key or None,
                'keyFingerprint': it.ssh_key_fingerprint or None,
            }

        bw['fields'] = [
            {'name': cf.name, 'value': cf.value, 'type': cf.type}
            for cf in it.custom_fields
        ]
        bw['passwordHistory'] = [
            {'password': ph.password, 'lastUsedDate': ph.last_used_date}
            for ph in it.password_history
        ]
        bw['fido2Credentials'] = [_fido_to_bw(f) for f in it.fido2_credentials]
        # 附件元数据（纯 JSON 无二进制；KDBX→BW 时携带 id/fileName/size）
        # id 回退规则须与 write_bitwarden_zip 的附件路径一致，保证 ZIP 往返可对齐
        bw['attachments'] = [
            {'id': att.id or att.file_name or 'attachment',
             'fileName': att.file_name, 'size': att.size}
            for att in it.attachments
        ]
        bw_items.append(bw)

    return {'encrypted': False, 'folders': folder_list, 'items': bw_items}


def write_bitwarden_zip(folders: list[Folder], items: list[VaultItem]) -> bytes:
    """将统一中间模型导出为 Bitwarden ZIP 字节（data.json + 附件真实二进制）

    与 Bitwarden 官方未加密 ZIP 导出结构一致：
        data.json
        attachments/<attachmentId>/<fileName>
    仅未加密 ZIP 可携带附件二进制；加密 / 纯 JSON 目标请使用 json / encrypted。
    """
    data = vault_items_to_bitwarden(folders, items)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('data.json', json.dumps(data, ensure_ascii=False, indent=2))
        for it in items:
            for att in (it.attachments or []):
                if att.data:
                    att_id = att.id or att.file_name or 'attachment'
                    zf.writestr(f"attachments/{att_id}/{att.file_name}", att.data)
    return buf.getvalue()


def _fido_to_bw(f: Fido2Credential) -> dict:
    return {
        'credentialId': f.credential_id,
        'keyType': f.key_type,
        'keyAlgorithm': f.key_algorithm,
        'keyCurve': f.key_curve,
        'keyValue': f.key_value,
        'rpId': f.rp_id,
        'rpName': f.rp_name,
        'userHandle': f.user_handle,
        'userName': f.user_name,
        'userDisplayName': f.user_display_name,
        'counter': f.counter,
        'discoverable': f.discoverable,
        'creationDate': f.creation_date,
    }


def _int_or_none(value: str | None) -> int | None:
    if value in (None, ''):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def vault_items_to_1pux(folders: list[Folder], items: list[VaultItem]) -> bytes:
    """将统一中间模型导出为 1Password 1PUX（ZIP 字节）"""
    data = vault_items_to_bitwarden(folders, items)
    onepass = bitwarden_to_1pux(data)
    return _write_1pux_bytes(onepass)


def _write_1pux_bytes(onepass: dict) -> bytes:
    content = json.dumps(onepass, ensure_ascii=False, indent=2)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('data/1password.1pif', content)
    return buf.getvalue()


def render_target(
    folders: list[Folder],
    items: list[VaultItem],
    fmt: str,
    *,
    db_password: str | None = None,
    export_password: str | None = None,
    salt_mode: str = 'utf8',
    csv_format: str = 'generic',
    db_name: str = "Pass2KDBX Import",
) -> bytes:
    """将统一中间模型渲染为指定目标格式的字节内容

    Args:
        fmt: 目标格式（见 TARGET_FORMATS；'bitwarden' 为 'json' 的别名）
        db_password: 写 KDBX 所需主密码（必填）
        export_password: 写加密 JSON 所需密码（必填）
        salt_mode / csv_format: 加密 / CSV 子选项
    """
    fmt = fmt.lower()
    if fmt == 'bitwarden':
        fmt = 'json'

    if fmt == 'zip':
        return write_bitwarden_zip(folders, items)

    if fmt == 'json':
        data = vault_items_to_bitwarden(folders, items)
        return json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')

    if fmt == 'encrypted':
        if not export_password:
            raise EncryptedExportRequiresPassword("写出加密 JSON 需要提供 export_password")
        data = vault_items_to_bitwarden(folders, items)
        env = encrypt_bitwarden_export(data, export_password, salt_mode=salt_mode)
        return json.dumps(env, ensure_ascii=False, indent=2).encode('utf-8')

    if fmt == 'csv':
        text = vault_items_to_csv(items, csv_format)
        return text.encode('utf-8-sig')

    if fmt == '1pux':
        return vault_items_to_1pux(folders, items)

    if fmt == 'kdbx':
        if not db_password:
            raise ValueError("写出 KDBX 需要提供 db_password（数据库主密码）")
        if PyKeePass is None:
            raise ImportError("需要安装 pykeepass: pip install pykeepass>=4.1.0")
        from .writer import write_keepass
        tmp = tempfile.NamedTemporaryFile(suffix='.kdbx', delete=False).name
        try:
            write_keepass(
                folders=folders, items=items, output_path=tmp,
                password=db_password, db_name=db_name,
            )
            with open(tmp, 'rb') as f:
                return f.read()
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    raise ValueError(f"不支持的目标格式: {fmt}")


# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------
def convert(
    source: str,
    targets: list[str],
    *,
    source_format: str | None = None,
    password: str | None = None,
    key_file: str | None = None,
    export_password: str | None = None,
    email: str | None = None,
    master_password: str | None = None,
    db_password: str | None = None,
    salt_mode: str = 'utf8',
    csv_format: str = 'generic',
    db_name: str = "Pass2KDBX Import",
) -> dict[str, bytes]:
    """传入→传出 统一转换入口

    Args:
        source: 源文件路径
        targets: 目标格式列表（可多选，如 ['kdbx', 'json', '1pux']）
        source_format / password / key_file / export_password / email /
        master_password: 源解析参数（见 parse_source）
        db_password: 写 KDBX 目标的主密码（未提供时回退到 password）
        salt_mode / csv_format: 加密 / CSV 子选项
    Returns:
        {fmt: 文件内容 bytes}（fmt 为实际目标格式名，'bitwarden' 归一为 'json'）
    """
    folders, items = parse_source(
        source, source_format,
        password=password, key_file=key_file, export_password=export_password,
        email=email, master_password=master_password,
    )
    out: dict[str, bytes] = {}
    for raw in targets:
        fmt = raw.lower()
        if fmt == 'bitwarden':
            fmt = 'json'
        dp = db_password if fmt == 'kdbx' else None
        out[fmt] = render_target(
            folders, items, fmt,
            db_password=dp, export_password=export_password,
            salt_mode=salt_mode, csv_format=csv_format, db_name=db_name,
        )
    return out
