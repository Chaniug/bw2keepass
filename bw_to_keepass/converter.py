"""
转换器：将 Bitwarden VaultItem 转换为 KeePass 条目
"""

import base64
import re
from .parser import VaultItem, Folder

# 类型名称映射
TYPE_NAMES = {
    1: "Login",
    2: "Secure Note",
    3: "Card",
    4: "Identity",
    5: "SSH Key",
}


def sanitize_path(name: str) -> str:
    """清理路径中的非法字符"""
    # 移除或替换 KeePass 路径中不允许的字符
    name = name.replace('/', '_').replace('\\', '_')
    return name.strip()


def get_entry_title(item: VaultItem) -> str:
    """获取 KeePass 条目标题"""
    return sanitize_path(item.name)


def get_entry_username(item: VaultItem) -> str:
    """获取 KeePass 条目用户名"""
    if item.type == 1:
        return item.username
    elif item.type == 3:
        return item.cardholder_name
    return ""


def get_entry_password(item: VaultItem) -> str:
    """获取 KeePass 条目密码"""
    if item.type == 1:
        return item.password
    elif item.type == 3:
        return item.card_code
    return ""


def get_entry_url(item: VaultItem) -> str:
    """获取 KeePass 条目 URL"""
    if item.type == 1 and item.uris:
        return item.uris[0].uri
    return ""


def get_entry_notes(item: VaultItem) -> str:
    """构建 KeePass 条目备注"""
    parts = []

    if item.notes:
        parts.append(item.notes)

    # Card 详细信息
    if item.type == 3:
        card_parts = []
        if item.card_brand:
            card_parts.append(f"品牌: {item.card_brand}")
        if item.card_number:
            card_parts.append(f"卡号: {item.card_number}")
        if item.card_exp_month and item.card_exp_year:
            card_parts.append(f"有效期: {item.card_exp_month}/{item.card_exp_year}")
        if item.card_code:
            card_parts.append(f"安全码: {item.card_code}")
        if card_parts:
            parts.insert(0, "[信用卡信息]\n" + "\n".join(card_parts))

    # Identity 详细信息
    if item.type == 4:
        identity_parts = []
        name_parts = [p for p in [
            item.identity_title,
            item.identity_first_name,
            item.identity_middle_name,
            item.identity_last_name
        ] if p]
        if name_parts:
            identity_parts.append(f"姓名: {' '.join(name_parts)}")
        if item.identity_email:
            identity_parts.append(f"邮箱: {item.identity_email}")
        if item.identity_phone:
            identity_parts.append(f"电话: {item.identity_phone}")
        address_parts = [p for p in [
            item.identity_address1,
            item.identity_city,
            item.identity_state,
            item.identity_postal_code,
            item.identity_country,
        ] if p]
        if address_parts:
            identity_parts.append(f"地址: {', '.join(address_parts)}")
        if item.identity_ssn:
            identity_parts.append(f"SSN: {item.identity_ssn}")
        if item.identity_passport_number:
            identity_parts.append(f"护照号: {item.identity_passport_number}")
        if item.identity_license_number:
            identity_parts.append(f"驾照号: {item.identity_license_number}")
        if identity_parts:
            parts.insert(0, "[身份信息]\n" + "\n".join(identity_parts))

    # SSH Key 信息
    if item.type == 5:
        ssh_parts = []
        if item.ssh_public_key:
            ssh_parts.append(f"公钥:\n{item.ssh_public_key}")
        if item.ssh_private_key:
            ssh_parts.append(f"私钥:\n{item.ssh_private_key}")
        if item.ssh_key_fingerprint:
            ssh_parts.append(f"指纹: {item.ssh_key_fingerprint}")
        if ssh_parts:
            parts.insert(0, "[SSH 密钥]\n" + "\n".join(ssh_parts))

    # 附加 URI（多个 URL 时）
    if item.type == 1 and len(item.uris) > 1:
        uri_lines = ["\n[其他 URI]"]
        for i, u in enumerate(item.uris[1:], start=2):
            uri_lines.append(f"URI {i}: {u.uri}")
        parts.append("\n".join(uri_lines))

    # TOTP
    if item.totp:
        parts.append(f"\n[TOTP]\notpauth://totp/{item.name}?secret={item.totp}")

    # 密码历史
    if item.password_history:
        hist_lines = ["\n[密码历史]"]
        for h in item.password_history[:10]:
            date_str = f" ({h.last_used_date})" if h.last_used_date else ""
            hist_lines.append(f"- {h.password}{date_str}")
        parts.append("\n".join(hist_lines))

    # FIDO2 / Passkey 凭据
    if item.fido2_credentials:
        fido_lines = ["\n[Passkey / FIDO2 凭据]"]
        for i, fc in enumerate(item.fido2_credentials):
            if len(item.fido2_credentials) > 1:
                fido_lines.append(f"\n--- Passkey #{i + 1} ---")
            if fc.rp_name:
                fido_lines.append(f"服务: {fc.rp_name} ({fc.rp_id})")
            else:
                fido_lines.append(f"依赖方: {fc.rp_id}")
            if fc.user_name:
                fido_lines.append(f"用户名: {fc.user_name}")
            if fc.user_display_name:
                fido_lines.append(f"显示名称: {fc.user_display_name}")
            fido_lines.append(f"凭据ID: {fc.credential_id}")
            fido_lines.append(f"算法: {fc.key_algorithm} ({fc.key_curve})")
            fido_lines.append(f"类型: {fc.key_type}")
            fido_lines.append(f"可发现: {fc.discoverable}")
            fido_lines.append(f"计数器: {fc.counter}")
            if fc.user_handle:
                fido_lines.append(f"用户句柄: {fc.user_handle}")
            if fc.key_value:
                fido_lines.append(f"密钥值: {fc.key_value}")
            if fc.creation_date:
                fido_lines.append(f"创建时间: {fc.creation_date}")
        parts.append("\n".join(fido_lines))

    return "\n".join(parts)


def get_entry_tags(item: VaultItem) -> list[str]:
    """获取 KeePass 条目标签"""
    tags = []
    type_name = TYPE_NAMES.get(item.type)
    if type_name:
        tags.append(type_name)
    if item.favorite:
        tags.append("Favorite")
    if item.fido2_credentials:
        tags.append("Passkey")
    return tags


def _uuid_to_base64(uuid_str: str) -> str:
    """将 Bitwarden 的 UUID 格式 credentialId 转换为 KeePassXC 期望的 base64 格式

    Bitwarden: "e64a25a4-3081-4bc4-baf3-426638381cf6" (UUID)
    KeePassXC:  UUID → hex bytes → base64url (no padding)
    """
    if not uuid_str:
        return ""
    # 如果已经像是 base64（包含 +/= 等字符），直接返回
    if any(c in uuid_str for c in ('+', '/', '=')):
        return uuid_str
    # 去除 UUID 横线
    hex_str = uuid_str.replace('-', '')
    # 验证是否为纯十六进制
    if not all(c in '0123456789abcdefABCDEF' for c in hex_str):
        return uuid_str  # 不是 UUID，原样返回
    try:
        raw_bytes = bytes.fromhex(hex_str)
        # KeePassXC 使用 URL-safe base64，去掉尾部 =
        return base64.urlsafe_b64encode(raw_bytes).decode('ascii').rstrip('=')
    except (ValueError, TypeError):
        return uuid_str


def _format_private_key_pem(key_value: str) -> str:
    """将 Bitwarden 的 keyValue 转换为 KeePassXC 期望的 PEM 格式

    KeePassXC 源码 (BitwardenReader.cpp) 中的转换流程：
        1. QByteArray::fromBase64(keyValue, Base64UrlEncoding) → 原始字节
        2. toBase64(Base64Encoding) → 标准 base64
        3. 包裹 PEM 头尾

    Bitwarden 的 keyValue 使用 URL-safe base64 编码（含 - 和 _ 字符），
    不是 URL 编码（%xx 格式）。我们直接按 URL-safe base64 解码。
    """
    if not key_value:
        return ""
    # 如果已经是 PEM 格式，直接返回
    if '-----BEGIN' in key_value:
        return key_value
    try:
        # 1. URL-safe base64 解码为原始字节
        # 补齐 padding（URL-safe base64 通常省略 =）
        padding = 4 - len(key_value) % 4
        if padding != 4:
            key_value += '=' * padding
        raw_bytes = base64.urlsafe_b64decode(key_value)
        # 2. 重新编码为标准 base64
        std_b64 = base64.standard_b64encode(raw_bytes).decode('ascii')
        # 3. 按 64 字符分行，包裹 PEM 头尾
        lines = ['-----BEGIN PRIVATE KEY-----']
        for i in range(0, len(std_b64), 64):
            lines.append(std_b64[i:i+64])
        lines.append('-----END PRIVATE KEY-----')
        return '\n'.join(lines)
    except Exception:
        # 解码失败时，回退尝试 URL decode（兼容旧数据格式）
        import urllib.parse
        try:
            decoded = urllib.parse.unquote(key_value)
            # 再次尝试 URL-safe base64 解码
            padding = 4 - len(decoded) % 4
            if padding != 4:
                decoded += '=' * padding
            raw_bytes = base64.urlsafe_b64decode(decoded)
            std_b64 = base64.standard_b64encode(raw_bytes).decode('ascii')
        except Exception:
            # 最终回退：直接包裹原始值
            std_b64 = key_value
        lines = ['-----BEGIN PRIVATE KEY-----']
        for i in range(0, len(std_b64), 64):
            lines.append(std_b64[i:i+64])
        lines.append('-----END PRIVATE KEY-----')
        return '\n'.join(lines)


def build_custom_fields(item: VaultItem) -> dict[str, str]:
    """
    构建 KeePass 自定义字符串字段

    将 VaultItem 中的各种信息转换为 KeePass 的字符串字段，
    补充备注中没有直接体现的关键信息。
    """
    fields: dict[str, str] = {}

    # 类型标记
    type_name = TYPE_NAMES.get(item.type, f"Type {item.type}")
    fields["BitwardenType"] = type_name

    # 源 ID
    if item.id:
        fields["BitwardenID"] = item.id

    # 登录额外信息
    if item.type == 1:
        if item.username:
            fields["UserName"] = item.username  # KeePass 标准字段
        if item.totp:
            # KeePassXC/OTP 插件格式
            fields["TOTP Seed"] = item.totp
            fields["otp"] = f"otpauth://totp/{item.name}?secret={item.totp}"

    # 卡片额外字段
    if item.type == 3:
        if item.card_number:
            fields["CardNumber"] = item.card_number
        if item.card_exp_month and item.card_exp_year:
            fields["Expiry"] = f"{item.card_exp_month}/{item.card_exp_year}"
        if item.card_brand:
            fields["Brand"] = item.card_brand

    # 身份额外字段
    if item.type == 4:
        identity_map = {
            "IdentityTitle": item.identity_title,
            "IdentityFirstName": item.identity_first_name,
            "IdentityLastName": item.identity_last_name,
            "IdentityEmail": item.identity_email,
            "IdentityPhone": item.identity_phone,
            "IdentitySSN": item.identity_ssn,
            "IdentityPassport": item.identity_passport_number,
            "IdentityLicense": item.identity_license_number,
        }
        for key, value in identity_map.items():
            if value:
                fields[key] = value

    # SSH Key 字段
    if item.type == 5:
        if item.ssh_key_fingerprint:
            fields["SSHFingerprint"] = item.ssh_key_fingerprint
        if item.ssh_public_key:
            fields["SSHPublicKey"] = item.ssh_public_key

    # 用户自定义字段（避免覆盖已有字段）
    for cf in item.custom_fields:
        if cf.name not in fields:
            fields[cf.name] = cf.value

    # FIDO2 / Passkey 凭据自定义字段
    # 字段名和格式完全对齐 KeePassXC PR #11401 的实现
    # 参考: https://github.com/keepassxreboot/keepassxc/pull/11401
    for i, fc in enumerate(item.fido2_credentials):
        idx = f"_{i}" if len(item.fido2_credentials) > 1 else ""
        if fc.credential_id:
            # credentialId: Bitwarden UUID → base64url (KeePassXC 格式)
            fields[f"KPEX_PASSKEY_CREDENTIAL_ID{idx}"] = _uuid_to_base64(fc.credential_id)
        if fc.key_value:
            # keyValue: Bitwarden URL-safe base64 → PEM 格式 (KeePassXC 格式)
            fields[f"KPEX_PASSKEY_PRIVATE_KEY_PEM{idx}"] = _format_private_key_pem(fc.key_value)
        if fc.rp_id:
            fields[f"KPEX_PASSKEY_RELYING_PARTY{idx}"] = fc.rp_id
        if fc.user_handle:
            fields[f"KPEX_PASSKEY_USER_HANDLE{idx}"] = fc.user_handle
        if fc.user_name:
            fields[f"KPEX_PASSKEY_USERNAME{idx}"] = fc.user_name

    # 时间戳
    if item.creation_date:
        fields["CreationDate"] = item.creation_date
    if item.revision_date:
        fields["RevisionDate"] = item.revision_date

    return fields
