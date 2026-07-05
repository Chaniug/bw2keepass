"""
CSV 导出器：将 KeePass KDBX 数据库导出为 CSV 格式

注意：CSV 格式无法保留 Passkey/FIDO2 凭据。
Passkey 数据依赖于 KeePass 的自定义字段机制（KPEX_PASSKEY_*），
而通用 CSV 导入不支持这些字段。如果数据库包含 Passkey，
建议同时使用 Bitwarden JSON 格式导出以保留 Passkey。
"""

import csv
import io
from typing import Any

try:
    from pykeepass import PyKeePass
except ImportError:
    PyKeePass = None


# CSV 列定义
CSV_COLUMNS = [
    'Title',
    'UserName',
    'Password',
    'URL',
    'Notes',
    'TOTP',
    'Group',
    'Type',
    'Tags',
    'CustomFields',  # JSON 格式的自定义字段
    'HasPasskey',     # 是否有 passkey（CSV 不支持，仅标记）
]

# Bitwarden CSV 格式兼容列
BITWARDEN_CSV_COLUMNS = [
    'folder',
    'favorite',
    'type',
    'name',
    'notes',
    'fields',
    'reprompt',
    'login_uri',
    'login_username',
    'login_password',
    'login_totp',
]

# KeePass 通用 CSV 列
KEEPASS_CSV_COLUMNS = [
    'Account',
    'Login Name',
    'Password',
    'Web Site',
    'Comments',
    'Group',
    'Expires',
    'Icon',
]


def _get_field_text(entry, attr: str, default: str = '') -> str:
    """安全获取条目字段"""
    try:
        val = getattr(entry, attr, None)
        return str(val) if val else default
    except Exception:
        return default


def _get_custom_fields(entry) -> dict[str, str]:
    """获取所有自定义字段"""
    fields: dict[str, str] = {}
    try:
        for key in entry.custom_properties:
            try:
                val = entry.get_custom_property(key)
                if val:
                    fields[key] = str(val)
            except Exception:
                pass
    except Exception:
        pass
    return fields


def export_kdbx_to_csv(
    kdbx_path: str,
    password: str,
    output_path: str,
    csv_format: str = 'generic',
    key_file: str | None = None,
) -> dict[str, int]:
    """将 KeePass KDBX 数据库导出为 CSV

    Args:
        kdbx_path: KDBX 文件路径
        password: 数据库密码
        output_path: 输出 CSV 文件路径
        csv_format: CSV 格式 ('generic', 'bitwarden', 'keepass')
        key_file: 可选的密钥文件

    Returns:
        统计信息字典
    """
    if PyKeePass is None:
        raise ImportError("需要安装 pykeepass: pip install pykeepass>=4.1.0")

    kp = PyKeePass(kdbx_path, password=password, keyfile=key_file)

    import json as json_mod

    rows = []
    passkey_count = 0
    item_count = 0

    for entry in kp.entries:
        custom_fields = _get_custom_fields(entry)
        title = _get_field_text(entry, 'title')
        username = _get_field_text(entry, 'username')
        password = _get_field_text(entry, 'password')
        url = _get_field_text(entry, 'url')
        notes = _get_field_text(entry, 'notes')

        # 分组路径
        group_path = ''
        g = entry.group
        paths = []
        while g:
            name = g.name or ''
            if name and name.lower() not in ('recycle bin', '回收站'):
                paths.insert(0, name)
            g = g.parentgroup if hasattr(g, 'parentgroup') else None
        group_path = '/'.join(paths)

        # TOTP
        totp = custom_fields.get('TOTP Seed', '') or custom_fields.get('otp', '')

        # 类型
        bw_type = custom_fields.get('BitwardenType', 'Login')

        # Tags
        tags = _get_field_text(entry, 'tags') or ''

        # 检查 passkey
        has_passkey = any(k.startswith('KPEX_PASSKEY_') for k in custom_fields)
        if has_passkey:
            passkey_count += 1

        # 非内部自定义字段（JSON）
        skip_keys = {
            'BitwardenType', 'TOTP Seed', 'TOTP Settings', 'otpauth',
            'CreationDate', 'RevisionDate', 'BitwardenID',
            'CardBrand', 'CardNumber', 'CardExpiry',
            'SSHFingerprint', 'SSHPublicKey', 'SSHPrivateKey',
        }
        extra_fields = {k: v for k, v in custom_fields.items()
                       if k not in skip_keys and not k.startswith('KPEX_PASSKEY_')}

        if csv_format == 'bitwarden':
            row = {
                'folder': group_path,
                'favorite': '',
                'type': 'login',
                'name': title,
                'notes': notes,
                'fields': json_mod.dumps(extra_fields, ensure_ascii=False) if extra_fields else '',
                'reprompt': '0',
                'login_uri': url,
                'login_username': username,
                'login_password': password,
                'login_totp': totp,
            }
            columns = BITWARDEN_CSV_COLUMNS
        elif csv_format == 'keepass':
            row = {
                'Account': title,
                'Login Name': username,
                'Password': password,
                'Web Site': url,
                'Comments': notes,
                'Group': group_path,
                'Expires': '',
                'Icon': '',
            }
            columns = KEEPASS_CSV_COLUMNS
        else:  # generic
            row = {
                'Title': title,
                'UserName': username,
                'Password': password,
                'URL': url,
                'Notes': notes,
                'TOTP': totp,
                'Group': group_path,
                'Type': bw_type,
                'Tags': tags,
                'CustomFields': json_mod.dumps(extra_fields, ensure_ascii=False) if extra_fields else '',
                'HasPasskey': 'YES' if has_passkey else 'NO',
            }
            columns = CSV_COLUMNS

        rows.append(row)
        item_count += 1

    # 写入 CSV
    with open(output_path, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    return {
        'total': item_count,
        'passkey_entries': passkey_count,
    }


def export_kdbx_to_csv_string(
    kdbx_path: str,
    password: str,
    csv_format: str = 'generic',
    key_file: str | None = None,
) -> tuple[str, dict[str, int]]:
    """导出为 CSV 字符串（用于 web 端）

    Returns:
        (csv_string, stats) 元组
    """
    if PyKeePass is None:
        raise ImportError("需要安装 pykeepass: pip install pykeepass>=4.1.0")

    kp = PyKeePass(kdbx_path, password=password, keyfile=key_file)

    import json as json_mod

    rows = []
    passkey_count = 0
    item_count = 0

    for entry in kp.entries:
        custom_fields = _get_custom_fields(entry)
        title = _get_field_text(entry, 'title')
        username = _get_field_text(entry, 'username')
        password = _get_field_text(entry, 'password')
        url = _get_field_text(entry, 'url')
        notes = _get_field_text(entry, 'notes')

        group_path = ''
        g = entry.group
        paths = []
        while g:
            name = g.name or ''
            if name and name.lower() not in ('recycle bin', '回收站'):
                paths.insert(0, name)
            g = g.parentgroup if hasattr(g, 'parentgroup') else None
        group_path = '/'.join(paths)

        totp = custom_fields.get('TOTP Seed', '') or custom_fields.get('otp', '')
        bw_type = custom_fields.get('BitwardenType', 'Login')
        tags = _get_field_text(entry, 'tags') or ''

        has_passkey = any(k.startswith('KPEX_PASSKEY_') for k in custom_fields)
        if has_passkey:
            passkey_count += 1

        skip_keys = {
            'BitwardenType', 'TOTP Seed', 'TOTP Settings', 'otpauth',
            'CreationDate', 'RevisionDate', 'BitwardenID',
            'CardBrand', 'CardNumber', 'CardExpiry',
            'SSHFingerprint', 'SSHPublicKey', 'SSHPrivateKey',
        }
        extra_fields = {k: v for k, v in custom_fields.items()
                       if k not in skip_keys and not k.startswith('KPEX_PASSKEY_')}

        if csv_format == 'bitwarden':
            row = {
                'folder': group_path,
                'favorite': '',
                'type': 'login',
                'name': title,
                'notes': notes,
                'fields': json_mod.dumps(extra_fields, ensure_ascii=False) if extra_fields else '',
                'reprompt': '0',
                'login_uri': url,
                'login_username': username,
                'login_password': password,
                'login_totp': totp,
            }
            columns = BITWARDEN_CSV_COLUMNS
        elif csv_format == 'keepass':
            row = {
                'Account': title,
                'Login Name': username,
                'Password': password,
                'Web Site': url,
                'Comments': notes,
                'Group': group_path,
                'Expires': '',
                'Icon': '',
            }
            columns = KEEPASS_CSV_COLUMNS
        else:
            row = {
                'Title': title,
                'UserName': username,
                'Password': password,
                'URL': url,
                'Notes': notes,
                'TOTP': totp,
                'Group': group_path,
                'Type': bw_type,
                'Tags': tags,
                'CustomFields': json_mod.dumps(extra_fields, ensure_ascii=False) if extra_fields else '',
                'HasPasskey': 'YES' if has_passkey else 'NO',
            }
            columns = CSV_COLUMNS

        rows.append(row)
        item_count += 1

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)

    return output.getvalue(), {
        'total': item_count,
        'passkey_entries': passkey_count,
    }
