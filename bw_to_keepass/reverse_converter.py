"""
反向转换器：将 KeePass KDBX 数据库转换为 Bitwarden JSON 格式

支持 passkey 反向转换：
- KPEX_PASSKEY_CREDENTIAL_ID (base64url) → credentialId (UUID hex)
- KPEX_PASSKEY_PRIVATE_KEY_PEM (PEM) → keyValue (URL-safe base64)
- KPEX_PASSKEY_RELYING_PARTY → rpId
- KPEX_PASSKEY_USERNAME → userName
- KPEX_PASSKEY_USER_HANDLE → userHandle
"""

import base64
import json
import re
import uuid as uuid_mod
from typing import Any

try:
    from pykeepass import PyKeePass
except ImportError:
    PyKeePass = None


def _base64url_to_uuid(b64url: str) -> str:
    """将 KeePassXC 的 base64url credentialId 转换回 Bitwarden UUID 格式

    KeePassXC: QByteArray::fromHex(uuid) → toBase64(Base64UrlEncoding | OmitTrailingEquals)
    反向: base64url decode → hex → UUID (带横线)
    """
    if not b64url:
        return ""
    # 如果已经是 UUID 格式（含横线），直接返回
    if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', b64url):
        return b64url
    try:
        # 补齐 padding
        padding = 4 - len(b64url) % 4
        if padding != 4:
            b64url += '=' * padding
        raw_bytes = base64.urlsafe_b64decode(b64url)
        hex_str = raw_bytes.hex()
        # 格式化为 UUID: 8-4-4-4-12
        if len(hex_str) == 32:
            return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"
        return hex_str
    except Exception:
        return b64url


def _pem_to_b64url(pem: str) -> str:
    """将 KeePassXC 的 PEM 格式 keyValue 转换回 Bitwarden URL-safe base64 格式

    KeePassXC: fromBase64(keyValue, Base64UrlEncoding) → toBase64(Base64Encoding) → 包裹 PEM
    反向: 剥离 PEM 头尾 → 标准 base64 解码 → URL-safe base64 编码（无 padding）
    """
    if not pem:
        return ""
    # 如果已经是纯 base64（不含 PEM 标记），直接返回
    if '-----BEGIN' not in pem:
        return pem
    try:
        # 提取 PEM 中的 base64 内容
        lines = pem.strip().split('\n')
        b64_lines = [l for l in lines if not l.startswith('-----')]
        std_b64 = ''.join(b64_lines).strip()
        # 标准 base64 解码为原始字节
        raw_bytes = base64.standard_b64decode(std_b64)
        # URL-safe base64 编码（去掉 padding）
        return base64.urlsafe_b64encode(raw_bytes).decode('ascii').rstrip('=')
    except Exception:
        # 解码失败，返回原始值
        return pem


def _generate_uuid() -> str:
    """生成 Bitwarden 格式的 UUID"""
    return str(uuid_mod.uuid4())


def _get_field_text(entry, key: str) -> str:
    """从 pykeepass Entry 中安全获取字段文本"""
    try:
        val = entry.get_custom_property(key)
        if val is None:
            val = getattr(entry, key.lower(), None) if hasattr(entry, key.lower()) else None
        return str(val) if val else ""
    except Exception:
        return ""


def _get_all_custom_fields(entry) -> dict[str, str]:
    """获取条目所有自定义字段"""
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


def _extract_passkeys(entry) -> list[dict]:
    """从 KeePass 条目中提取 passkey 凭据（反向转换）

    扫描 KPEX_PASSKEY_CREDENTIAL_ID 开头的自定义字段，
    将 KeePassXC 格式转换回 Bitwarden fido2Credentials 格式。
    """
    custom_fields = _get_all_custom_fields(entry)
    passkeys: list[dict] = []

    # 查找所有 passkey credential IDs
    # 格式: KPEX_PASSKEY_CREDENTIAL_ID, KPEX_PASSKEY_CREDENTIAL_ID_0, KPEX_PASSKEY_CREDENTIAL_ID_1, ...
    credential_keys = sorted(
        [k for k in custom_fields if k.startswith('KPEX_PASSKEY_CREDENTIAL_ID')],
        key=lambda k: (0 if k == 'KPEX_PASSKEY_CREDENTIAL_ID' else
                        int(k.rsplit('_', 1)[-1]) if k.rsplit('_', 1)[-1].isdigit() else 0)
    )

    for ck in credential_keys:
        # 确定后缀
        if ck == 'KPEX_PASSKEY_CREDENTIAL_ID':
            suffix = ''
        else:
            suffix = '_' + ck.rsplit('_', 1)[-1]

        credential_id_b64 = custom_fields.get(ck, '')
        credential_id = _base64url_to_uuid(credential_id_b64)

        key_pem = custom_fields.get(f'KPEX_PASSKEY_PRIVATE_KEY_PEM{suffix}', '')
        key_value = _pem_to_b64url(key_pem)

        rp_id = custom_fields.get(f'KPEX_PASSKEY_RELYING_PARTY{suffix}', '')
        user_handle = custom_fields.get(f'KPEX_PASSKEY_USER_HANDLE{suffix}', '')
        user_name = custom_fields.get(f'KPEX_PASSKEY_USERNAME{suffix}', '')
        rp_name = custom_fields.get(f'KPEX_PASSKEY_RP_NAME{suffix}', '') or rp_id
        user_display_name = custom_fields.get(f'KPEX_PASSKEY_USER_DISPLAY_NAME{suffix}', '') or user_name
        creation_date = custom_fields.get(f'KPEX_PASSKEY_CREATION_DATE{suffix}', '')

        passkeys.append({
            'credentialId': credential_id,
            'keyType': 'public-key',
            'keyAlgorithm': 'ECDSA',
            'keyCurve': 'P-256',
            'keyValue': key_value,
            'rpId': rp_id,
            'rpName': rp_name,
            'userHandle': user_handle,
            'userName': user_name,
            'userDisplayName': user_display_name,
            'counter': '0',
            'discoverable': 'true',
            'creationDate': creation_date,
        })

    return passkeys


def _extract_password_history(entry, custom_fields: dict) -> list[dict]:
    """还原密码历史

    优先使用正向转换写入的结构化字段 KPEX_PW_HISTORY（BW→KDBX→BW 往返无损）；
    否则回退到 KeePass 原生历史（entry.history，KDBX 原生记录的旧密码）。
    """
    raw = custom_fields.get('KPEX_PW_HISTORY', '')
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [{'password': str(h.get('password', '')),
                         'lastUsedDate': h.get('lastUsedDate', '') or ''}
                        for h in parsed]
        except Exception:
            pass
    # 回退：KeePass 原生历史
    history = []
    try:
        for h in (getattr(entry, 'history', None) or []):
            pw = getattr(h, 'password', '') or ''
            if pw:
                history.append({'password': pw, 'lastUsedDate': ''})
    except Exception:
        pass
    return history


def _extract_attachments(entry) -> list[dict]:
    """从 KeePass 条目提取附件元数据（id/fileName/size）

    说明：Bitwarden JSON 无法内嵌二进制，故仅保留元数据。完整"KDBX→Bitwarden 带附件"
    需要额外打包为 Bitwarden ZIP（data.json + attachments/），列为后续增强。
    """
    result = []
    try:
        for att in (getattr(entry, 'attachments', None) or []):
            att_id = str(getattr(att, 'id', '') or '')
            file_name = getattr(att, 'filename', '') or 'attachment'
            data = getattr(att, 'data', b'') or b''
            result.append({
                'id': att_id,
                'fileName': file_name,
                'size': len(data) if isinstance(data, (bytes, bytearray)) else int(data or 0),
            })
    except Exception:
        pass
    return result


def _detect_entry_type(entry, custom_fields: dict) -> int:
    """从 KeePass 条目推断 Bitwarden 类型"""
    bw_type = custom_fields.get('BitwardenType', '')

    # 类型映射
    type_map = {
        'Login': 1, 'login': 1,
        'SecureNote': 2, 'Secure Note': 2, 'securenote': 2,
        'Card': 3, 'card': 3,
        'Identity': 4, 'identity': 4,
        'SSHKey': 5, 'SSH Key': 5, 'sshkey': 5, 'SSH': 5,
    }

    if bw_type in type_map:
        return type_map[bw_type]

    # 通过字段推断
    if custom_fields.get('SSHFingerprint') or custom_fields.get('SSHPublicKey'):
        return 5  # SSH Key
    if custom_fields.get('CardNumber') or custom_fields.get('Brand') or custom_fields.get('CardBrand'):
        return 3  # Card
    if any(k.startswith('Identity') for k in custom_fields):
        return 4  # Identity

    # 默认 Login
    return 1


def _build_bitwarden_item(entry, folder_id: str | None, entry_idx: int) -> dict | None:
    """将单个 KeePass 条目转换为 Bitwarden JSON 格式"""
    title = getattr(entry, 'title', '') or ''
    username = getattr(entry, 'username', '') or ''
    password = getattr(entry, 'password', '') or ''
    url = getattr(entry, 'url', '') or ''
    notes = getattr(entry, 'notes', '') or ''

    if not title and not username and not password and not url and not notes:
        return None

    custom_fields = _get_all_custom_fields(entry)
    item_type = _detect_entry_type(entry, custom_fields)

    # 提取 TOTP（兼容旧版 otpauth 字段名）
    totp = custom_fields.get('TOTP Seed', '') or custom_fields.get('otp', '') or custom_fields.get('otpauth', '')
    if totp.startswith('otpauth://'):
        # 从 otpauth URL 中提取 secret
        from urllib.parse import urlparse, parse_qs
        try:
            parsed = urlparse(totp)
            params = parse_qs(parsed.query)
            totp = params.get('secret', [''])[0]
        except Exception:
            pass

    # 提取 URIs
    uris = []
    if url:
        uris.append({'uri': url, 'match': None})
    # 额外 URI
    for i in range(2, 20):
        extra = custom_fields.get(f'URI_{i}', '')
        if extra:
            uris.append({'uri': extra, 'match': None})
    # KP2A_URL 格式
    for key in sorted(custom_fields.keys()):
        if key.startswith('KP2A_URL'):
            val = custom_fields[key]
            if val and val not in [u['uri'] for u in uris]:
                uris.append({'uri': val, 'match': None})
    # AndroidApp + AndroidApp Signature 字段 → 还原 android URI
    for key in sorted(custom_fields.keys()):
        if key == 'AndroidApp' or (key.startswith('AndroidApp') and key[10:].isdigit()):
            pkg = custom_fields[key]
            if pkg:
                # 查找对应的签名
                sig_key = key.replace('AndroidApp', 'AndroidApp Signature')
                sig = custom_fields.get(sig_key, '')
                if sig:
                    # 还原为 android://fingerprint@package
                    fp_hex = sig.replace(':', '').lower()
                    uri = f"android://{fp_hex}@{pkg}"
                else:
                    uri = f"androidapp://{pkg}"
                if uri not in [u['uri'] for u in uris]:
                    uris.append({'uri': uri, 'match': None})

    # 提取 passkeys
    fido2_credentials = _extract_passkeys(entry)

    # 提取附件（KeePass → Bitwarden 元数据；二进制需 ZIP 重新打包，见下方说明）
    attachments = _extract_attachments(entry)

    # 提取自定义字段（排除内部字段和 passkey 字段）
    # 跳过集合必须与「正向转换器 build_custom_fields 实际写出的字段名」严格对齐，
    # 否则这些内部字段会被当成用户自定义字段泄漏/重复导出。
    # 注意：'otp' 用精确匹配（不用前缀），以免误过滤 'otpauth'、'otp_settings' 等用户自定义字段。
    skip_exact = {
        'BitwardenType', 'BitwardenID', 'TOTP Seed', 'TOTP Settings',
        'otp', 'KPEX_PASSKEY_', 'CreationDate', 'RevisionDate',
        '_TAGS', 'Brand', 'CardBrand', 'CardNumber', 'Expiry', 'CardExpiry',
        'SSHFingerprint', 'SSHPublicKey', 'SSHPrivateKey',
        'IdentityTitle', 'IdentityFirstName', 'IdentityMiddleName', 'IdentityLastName',
        'IdentityAddress1', 'IdentityCity', 'IdentityState', 'IdentityPostalCode',
        'IdentityCountry', 'IdentityEmail', 'IdentityPhone', 'IdentitySSN',
        'IdentityPassport', 'IdentityLicense',
    }
    # 用前缀跳过整组内部字段，避免「精确名 vs 数字后缀」对不上导致泄漏：
    #   - KPEX_PASSKEY_*         Passkey 凭据（单条与多条第 0/1/2… 条）
    #   - KP2A_URL*               KeePassAndroid 额外 URI
    #   - AndroidApp / AndroidApp2..          安卓 URI（多 URI 编号为 2/3…，无 1）
    #   - AndroidApp Signature / AndroidApp Signature2..  安卓签名指纹
    skip_prefixes = ('KPEX_PASSKEY_', 'KP2A_URL', 'AndroidApp')
    skip_full = set()
    for i in range(2, 20):
        skip_full.add(f'URI_{i}')
    for key in custom_fields:
        if key.startswith('KP2A_URL'):
            skip_full.add(key)

    fields = []
    for key, value in custom_fields.items():
        if key in skip_full or key in skip_exact:
            continue
        if any(key.startswith(sp) for sp in skip_prefixes):
            continue
        fields.append({'name': key, 'value': str(value), 'type': 0})

    # 密码历史（优先用正向写入的结构化字段 KPEX_PW_HISTORY；否则回退到 KeePass 原生历史）
    password_history = _extract_password_history(entry, custom_fields)

    # 构建 Bitwarden item
    item: dict[str, Any] = {
        'id': _generate_uuid(),
        'organizationId': None,
        'folderId': folder_id,
        'type': item_type,
        'reprompt': 0,
        'name': title or '(无标题)',
        'notes': notes or None,
        'favorite': False,
        'login': None,
        'card': None,
        'identity': None,
        'secureNote': None,
        'sshKey': None,
        'collectionIds': [],
        'fields': fields,
        'passwordHistory': password_history,
        'fido2Credentials': fido2_credentials,
        'attachments': attachments,
        'creationDate': custom_fields.get('CreationDate', ''),
        'revisionDate': custom_fields.get('RevisionDate', ''),
    }

    if item_type == 1:  # Login
        item['login'] = {
            'username': username or None,
            'password': password or None,
            'totp': totp or None,
            'uris': uris,
        }
    elif item_type == 2:  # Secure Note
        item['secureNote'] = {'type': 0}
    elif item_type == 3:  # Card
        brand = custom_fields.get('Brand', '') or custom_fields.get('CardBrand', '')
        number = custom_fields.get('CardNumber', '')
        expiry = custom_fields.get('Expiry', '') or custom_fields.get('CardExpiry', '')
        exp_month, exp_year = '', ''
        if '/' in expiry:
            parts = expiry.split('/')
            exp_month = parts[0].strip()
            exp_year = parts[1].strip()
        item['card'] = {
            'cardholderName': username or '',
            'brand': brand,
            'number': number,
            'expMonth': exp_month,
            'expYear': exp_year,
            'code': password or '',
        }
    elif item_type == 4:  # Identity
        item['identity'] = {
            'title': custom_fields.get('IdentityTitle', ''),
            'firstName': custom_fields.get('IdentityFirstName', ''),
            'middleName': custom_fields.get('IdentityMiddleName', ''),
            'lastName': custom_fields.get('IdentityLastName', ''),
            'address1': custom_fields.get('IdentityAddress1', ''),
            'address2': '',
            'address3': '',
            'city': custom_fields.get('IdentityCity', ''),
            'state': custom_fields.get('IdentityState', ''),
            'postalCode': custom_fields.get('IdentityPostalCode', ''),
            'country': custom_fields.get('IdentityCountry', ''),
            'company': '',
            'email': custom_fields.get('IdentityEmail', ''),
            'phone': custom_fields.get('IdentityPhone', ''),
            'ssn': custom_fields.get('IdentitySSN', ''),
            'passportNumber': custom_fields.get('IdentityPassport', ''),
            'licenseNumber': custom_fields.get('IdentityLicense', ''),
        }
    elif item_type == 5:  # SSH Key
        item['sshKey'] = {
            'privateKey': custom_fields.get('SSHPrivateKey', ''),
            'publicKey': custom_fields.get('SSHPublicKey', ''),
            'fingerprint': custom_fields.get('SSHFingerprint', ''),
        }

    return item


def convert_kdbx_to_bitwarden(
    kdbx_path: str,
    password: str,
    key_file: str | None = None,
) -> dict:
    """将 KeePass KDBX 数据库转换为 Bitwarden JSON 格式

    Args:
        kdbx_path: KDBX 文件路径
        password: 数据库主密码
        key_file: 可选的密钥文件路径

    Returns:
        Bitwarden JSON 导出格式的字典
    """
    if PyKeePass is None:
        raise ImportError("需要安装 pykeepass: pip install pykeepass>=4.1.0")

    kp = PyKeePass(kdbx_path, password=password, keyfile=key_file)

    # 构建文件夹映射
    folders: list[dict] = []
    group_folder_map: dict[str, str] = {}  # group uuid → folder id

    # 获取所有分组（排除根组和回收站）
    def collect_groups(group, parent_path=''):
        for g in group.subgroups:
            name = g.name or ''
            if name.lower() in ('recycle bin', '回收站'):
                collect_groups(g, parent_path)
                continue
            path = f"{parent_path}/{name}" if parent_path else name
            folder_id = _generate_uuid()
            folders.append({'id': folder_id, 'name': path})
            group_folder_map[g.uuid] = folder_id
            collect_groups(g, path)

    collect_groups(kp.root_group)

    # 转换条目
    items = []
    for entry in kp.entries:
        # 确定文件夹
        folder_id = None
        if entry.group and entry.group.uuid in group_folder_map:
            folder_id = group_folder_map[entry.group.uuid]

        try:
            bw_item = _build_bitwarden_item(entry, folder_id, len(items))
            if bw_item:
                items.append(bw_item)
        except Exception as e:
            # 跳过无法转换的条目
            print(f"警告: 跳过条目 '{getattr(entry, 'title', '?')}': {e}")

    return {
        'encrypted': False,
        'folders': folders,
        'items': items,
    }
