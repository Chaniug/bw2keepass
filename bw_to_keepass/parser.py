"""
Bitwarden 导出 JSON 解析器

解析 Bitwarden 导出的 JSON 数据结构，返回标准化的中间数据模型。
"""

import json
import zipfile
import os
from typing import Any
from dataclasses import dataclass, field


@dataclass
class Folder:
    """Bitwarden 文件夹"""
    id: str
    name: str


@dataclass
class Uri:
    """登录项的 URI"""
    uri: str
    match: int | None = None


@dataclass
class CustomField:
    """自定义字段"""
    name: str
    value: str
    type: int = 0  # 0=text, 1=hidden


@dataclass
class PasswordHistory:
    """密码历史记录"""
    password: str
    last_used_date: str | None = None


@dataclass
class VaultItem:
    """标准化后的密码库条目"""
    id: str
    type: int
    name: str
    notes: str = ""
    folder: str = ""  # 文件夹名
    favorite: bool = False

    # Login (type=1)
    username: str = ""
    password: str = ""
    totp: str = ""
    uris: list[Uri] = field(default_factory=list)

    # Card (type=3)
    cardholder_name: str = ""
    card_brand: str = ""
    card_number: str = ""
    card_exp_month: str = ""
    card_exp_year: str = ""
    card_code: str = ""

    # Identity (type=4)
    identity_title: str = ""
    identity_first_name: str = ""
    identity_middle_name: str = ""
    identity_last_name: str = ""
    identity_address1: str = ""
    identity_city: str = ""
    identity_state: str = ""
    identity_postal_code: str = ""
    identity_country: str = ""
    identity_email: str = ""
    identity_phone: str = ""
    identity_ssn: str = ""
    identity_passport_number: str = ""
    identity_license_number: str = ""

    # SSH Key (type=5)
    ssh_private_key: str = ""
    ssh_public_key: str = ""
    ssh_key_fingerprint: str = ""

    # Secure Note (type=2) uses notes field

    # Custom fields
    custom_fields: list[CustomField] = field(default_factory=list)

    # Password history
    password_history: list[PasswordHistory] = field(default_factory=list)

    # Metadata
    creation_date: str = ""
    revision_date: str = ""


def parse_bitwarden_export(file_path: str) -> tuple[list[Folder], list[VaultItem]]:
    """
    解析 Bitwarden 导出文件（支持 .json 和 .zip）

    Returns:
        (folders, items) 元组
    """
    if file_path.lower().endswith('.zip'):
        return _parse_zip(file_path)
    else:
        return _parse_json(file_path)


def _parse_json(file_path: str) -> tuple[list[Folder], list[VaultItem]]:
    """解析 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return _parse_data(data)


def _parse_zip(zip_path: str) -> tuple[list[Folder], list[VaultItem]]:
    """解析 ZIP 文件（含附件）"""
    with zipfile.ZipFile(zip_path, 'r') as zf:
        # 查找 data.json
        json_files = [n for n in zf.namelist() if n.endswith('data.json')]
        if not json_files:
            raise ValueError("ZIP 文件中未找到 data.json")
        data = json.loads(zf.read(json_files[0]).decode('utf-8'))
    return _parse_data(data)


def _parse_data(data: dict) -> tuple[list[Folder], list[VaultItem]]:
    """解析 JSON 数据"""
    # 解析文件夹
    folders: list[Folder] = []
    folder_map: dict[str, str] = {}  # id -> name
    for f_data in data.get('folders', []):
        folder = Folder(id=f_data['id'], name=f_data['name'])
        folders.append(folder)
        folder_map[f_data['id']] = f_data['name']

    # 解析密码项
    items: list[VaultItem] = []
    for item_data in data.get('items', []):
        # 跳过已删除的项
        if item_data.get('deletedDate'):
            continue

        item_type = item_data.get('type', 1)
        folder_name = folder_map.get(item_data.get('folderId', ''), '')

        item = VaultItem(
            id=item_data.get('id', ''),
            type=item_type,
            name=item_data.get('name', ''),
            notes=item_data.get('notes', ''),
            folder=folder_name,
            favorite=item_data.get('favorite', False),
            creation_date=item_data.get('creationDate', ''),
            revision_date=item_data.get('revisionDate', ''),
        )

        # 解析各类型专属字段
        if item_type == 1:
            _parse_login(item, item_data)
        elif item_type == 2:
            _parse_secure_note(item, item_data)
        elif item_type == 3:
            _parse_card(item, item_data)
        elif item_type == 4:
            _parse_identity(item, item_data)
        elif item_type == 5:
            _parse_ssh_key(item, item_data)

        # 自定义字段
        for field_data in item_data.get('fields', []):
            item.custom_fields.append(CustomField(
                name=field_data.get('name', ''),
                value=field_data.get('value', ''),
                type=field_data.get('type', 0),
            ))

        # 密码历史
        for hist_data in item_data.get('passwordHistory', []):
            item.password_history.append(PasswordHistory(
                password=hist_data.get('password', ''),
                last_used_date=hist_data.get('lastUsedDate'),
            ))

        items.append(item)

    return folders, items


def _parse_login(item: VaultItem, data: dict):
    """解析登录类型"""
    login = data.get('login', {})
    item.username = login.get('username', '') or ''
    item.password = login.get('password', '') or ''
    item.totp = login.get('totp', '') or ''

    for uri_data in login.get('uris', []):
        item.uris.append(Uri(
            uri=uri_data.get('uri', '') or '',
            match=uri_data.get('match'),
        ))


def _parse_secure_note(item: VaultItem, data: dict):
    """安全笔记：内容已在 notes 字段中"""
    pass


def _parse_card(item: VaultItem, data: dict):
    """解析卡片类型"""
    card = data.get('card', {})
    item.cardholder_name = card.get('cardholderName', '') or ''
    item.card_brand = card.get('brand', '') or ''
    item.card_number = card.get('number', '') or ''
    item.card_exp_month = str(card.get('expMonth', '')) if card.get('expMonth') else ''
    item.card_exp_year = str(card.get('expYear', '')) if card.get('expYear') else ''
    item.card_code = card.get('code', '') or ''


def _parse_identity(item: VaultItem, data: dict):
    """解析身份类型"""
    identity = data.get('identity', {})
    item.identity_title = identity.get('title', '') or ''
    item.identity_first_name = identity.get('firstName', '') or ''
    item.identity_middle_name = identity.get('middleName', '') or ''
    item.identity_last_name = identity.get('lastName', '') or ''
    item.identity_address1 = identity.get('address1', '') or ''
    item.identity_city = identity.get('city', '') or ''
    item.identity_state = identity.get('state', '') or ''
    item.identity_postal_code = identity.get('postalCode', '') or ''
    item.identity_country = identity.get('country', '') or ''
    item.identity_email = identity.get('email', '') or ''
    item.identity_phone = identity.get('phone', '') or ''
    item.identity_ssn = identity.get('ssn', '') or ''
    item.identity_passport_number = identity.get('passportNumber', '') or ''
    item.identity_license_number = identity.get('licenseNumber', '') or ''


def _parse_ssh_key(item: VaultItem, data: dict):
    """解析 SSH 密钥类型"""
    ssh_key = data.get('sshKey', {})
    item.ssh_private_key = ssh_key.get('privateKey', '') or ''
    item.ssh_public_key = ssh_key.get('publicKey', '') or ''
    item.ssh_key_fingerprint = ssh_key.get('keyFingerprint', '') or ''
