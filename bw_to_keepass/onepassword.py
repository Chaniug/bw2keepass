"""
1Password 导出（1PUX / 1PIF）解析器

将 1Password 导出文件解析为项目统一的中间数据模型（VaultItem / Folder），
以便复用 writer.py 写入 KeePass KDBX。

字段映射严格对齐网页 / App 前端 engine.js 的 convert1PUXItem（旧式 overview/details
结构），并额外兼容 1Password 官方 1PUX 的「平铺结构」（item 顶层直接为
fields / sections / urls），使 CLI 对真实 1Password 导出也能正确解析。

支持的输入：
  - .1pux  文件（ZIP，内含 data/*.json —— 1Password 官方导出格式）
  - .json  文件（根对象含 accounts/items，且 item 采用 overview/details 或平铺结构）
"""

import json
import zipfile
import logging
from typing import Any

from .parser import VaultItem, Folder, CustomField, Uri, PasswordHistory


logger = logging.getLogger(__name__)


# 1Password category -> Bitwarden/VaultItem type
CATEGORY_TO_TYPE = {
    "LOGIN": 1,
    "PASSWORD": 1,
    "SECURE_NOTE": 2,
    "NOTE": 2,
    "CREDIT_CARD": 3,
    "BANK_ACCOUNT": 3,
    "IDENTITY": 4,
    "SSH_KEY": 5,
}


def parse_1password_export(file_path: str) -> tuple[list[Folder], list[VaultItem]]:
    """解析 1Password 导出文件，返回 (folders, items)

    自动识别 .1pux（ZIP）或 .json。根对象需含 accounts/items 才视为 1Password。
    """
    ext = file_path.lower().split(".")[-1]
    if ext == "1pux":
        return _parse_1pux_zip(file_path)
    return _parse_1pux_json_file(file_path)


def is_1password_data(data: dict) -> bool:
    """判断解析后的 dict 是否为 1Password 1PUX 结构（用于自动探测）"""
    if not isinstance(data, dict):
        return False
    if "accounts" in data and "items" in data:
        return True
    items = data.get("items") or []
    if items and isinstance(items[0], dict):
        first = items[0]
        if "overview" in first or "details" in first:
            return True
        # 平铺结构：含 category/name/fields 等
        if "category" in first and ("fields" in first or "sections" in first):
            return True
    return False


def _parse_1pux_zip(zip_path: str) -> tuple[list[Folder], list[VaultItem]]:
    folders: list[Folder] = []
    items: list[VaultItem] = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        # 1Password 官方 1PUX：ZIP 内含 data/<vault>.1pif
        data_files = [
            n
            for n in zf.namelist()
            if n.lower().endswith((".json", ".1pif"))
            and "/data/" in n.lower()
            and "__macosx" not in n.lower()
        ]
        if not data_files:
            # 退化：接受任意顶层 json / 1pif 文件
            data_files = [
                n
                for n in zf.namelist()
                if n.lower().endswith((".json", ".1pif")) and "__macosx" not in n.lower()
            ]
        for name in data_files:
            try:
                data = json.loads(zf.read(name).decode("utf-8"))
            except Exception as e:  # noqa: BLE001
                logger.warning("无法解析 1PUX 内的 JSON %s: %s", name, e)
                continue
            f, it = _parse_1pux_data(data)
            folders.extend(f)
            items.extend(it)
    return folders, items


def _parse_1pux_json_file(json_path: str) -> tuple[list[Folder], list[VaultItem]]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return _parse_1pux_data(data)


def _parse_1pux_data(data: dict) -> tuple[list[Folder], list[VaultItem]]:
    """解析 1PUX 根对象（含 items / accounts / folders）"""
    folders: list[Folder] = []
    folder_map: dict[str, str] = {}
    for f_data in data.get("folders", []) or []:
        f_id = f_data.get("uuid") or f_data.get("id") or ""
        f_name = f_data.get("name") or ""
        if f_id and f_name:
            folders.append(Folder(id=f_id, name=f_name))
            folder_map[f_id] = f_name

    items: list[VaultItem] = []
    for item_data in data.get("items", []) or []:
        item = _convert_1pux_item(item_data, folder_map)
        if item:
            items.append(item)
    return folders, items


def _convert_1pux_item(item: dict, folder_map: dict[str, str]) -> VaultItem | None:
    """将单个 1Password item 转为 VaultItem，自动识别旧式 / 平铺结构"""
    # 跳过回收站
    trashed = item.get("trashed")
    if trashed is True or trashed == "Y":
        return None

    if "overview" in item or "details" in item:
        return _convert_legacy(item, folder_map)
    return _convert_flat(item, folder_map)


# ---------------------------------------------------------------------------
# 旧式 overview/details 结构（对齐前端 engine.js convert1PUXItem）
# ---------------------------------------------------------------------------
def _convert_legacy(item: dict, folder_map: dict[str, str]) -> VaultItem | None:
    overview = item.get("overview") or {}
    details = item.get("details") or {}

    name = overview.get("title") or overview.get("ainfo") or "未命名"
    favorite = bool(overview.get("favorite"))
    category = (overview.get("category") or item.get("category") or "").upper()
    item_type = CATEGORY_TO_TYPE.get(category, 1)

    folder_name = folder_map.get(item.get("folderUuid") or item.get("folder") or "", "")

    vitem = VaultItem(
        id=item.get("uuid") or "",
        type=item_type,
        name=name,
        folder=folder_name,
        favorite=favorite,
        creation_date=_normalize_date(item.get("created_at") or overview.get("created")),
        revision_date=_normalize_date(item.get("updated_at") or overview.get("updated")),
    )

    if item_type == 1:
        _fill_login(vitem, overview, details)
    elif item_type == 2:
        vitem.notes = details.get("notesPlain") or ""
    elif item_type == 3:
        _fill_card(vitem, details)
        vitem.notes = details.get("notesPlain") or ""
    elif item_type == 4:
        _fill_identity(vitem, details)
        vitem.notes = details.get("notesPlain") or ""
    elif item_type == 5:
        _fill_ssh(vitem, details)
        vitem.notes = details.get("notesPlain") or ""
    else:
        _fill_login(vitem, overview, details)

    _fill_custom_fields_from_sections(vitem, details.get("sections") or [])
    _add_tags(vitem, overview)
    return vitem


def _fill_login(vitem: VaultItem, overview: dict, details: dict):
    uris: list[Uri] = []
    if overview.get("url"):
        uris.append(Uri(uri=overview["url"]))
    for u in overview.get("urls") or []:
        if isinstance(u, dict) and u.get("url") and u["url"] != overview.get("url"):
            uris.append(Uri(uri=u["url"]))

    for field in details.get("fields") or []:
        design = field.get("designation") or ""
        val = field.get("value") or ""
        if not val:
            continue
        if design == "username":
            vitem.username = val
        elif design == "password":
            vitem.password = val
        elif design == "URL" and not any(u.uri == val for u in uris):
            uris.append(Uri(uri=val))

    vitem.uris = uris
    if details.get("notesPlain"):
        vitem.notes = details["notesPlain"]

    for section in details.get("sections") or []:
        for field in section.get("fields") or []:
            fn = (field.get("k") or field.get("t") or field.get("n") or "").upper()
            if fn in ("TOTP", "OTP") or (field.get("n") or "").lower() == "one-time password":
                if field.get("v"):
                    vitem.totp = field["v"]

    for ph in details.get("passwordHistory") or []:
        vitem.password_history.append(
            PasswordHistory(password=ph.get("value") or "", last_used_date=_epoch_to_iso(ph.get("time")))
        )


def _fill_card(vitem: VaultItem, details: dict):
    for section in details.get("sections") or []:
        for field in section.get("fields") or []:
            n = (field.get("n") or field.get("t") or "").lower()
            v = field.get("v") or ""
            if not v:
                continue
            if "cardholder" in n or n == "name":
                vitem.cardholder_name = v
            elif "number" in n or "ccnum" in n:
                vitem.card_number = v
            elif "expir" in n or n == "exp":
                exp = str(v).split("/")
                vitem.card_exp_month = exp[0] if len(exp) > 0 else ""
                vitem.card_exp_year = exp[1] if len(exp) > 1 else ""
            elif "cvv" in n or "cvc" in n or "security" in n:
                vitem.card_code = v
            elif "type" in n or "brand" in n:
                vitem.card_brand = v


def _fill_identity(vitem: VaultItem, details: dict):
    for section in details.get("sections") or []:
        for field in section.get("fields") or []:
            n = (field.get("n") or field.get("t") or "").lower()
            v = field.get("v") or ""
            if not v:
                continue
            if "first" in n:
                vitem.identity_first_name = (vitem.identity_first_name + " " + v).strip()
            elif "last" in n:
                vitem.identity_last_name = v
            elif "email" in n:
                vitem.identity_email = v
            elif "phone" in n:
                vitem.identity_phone = v
            elif "address" in n:
                vitem.identity_address1 = v
            elif "city" in n:
                vitem.identity_city = v
            elif "state" in n:
                vitem.identity_state = v
            elif "zip" in n or "postal" in n:
                vitem.identity_postal_code = v
            elif "country" in n:
                vitem.identity_country = v


def _fill_ssh(vitem: VaultItem, details: dict):
    for field in details.get("fields") or []:
        n = (field.get("n") or field.get("t") or field.get("name") or "").lower()
        v = field.get("v") or field.get("value") or ""
        if "private" in n:
            vitem.ssh_private_key = v
        elif "public" in n:
            vitem.ssh_public_key = v
        elif "fingerprint" in n:
            vitem.ssh_key_fingerprint = v


def _fill_custom_fields_from_sections(vitem: VaultItem, sections: list):
    reserved = {"notesplain", "password", "username"}
    for section in sections:
        for field in section.get("fields") or []:
            n = field.get("n") or field.get("t") or field.get("k") or ""
            v = field.get("v") if field.get("v") is not None else field.get("t") or ""
            if not n or not v:
                continue
            if n.lower() in reserved:
                continue
            vitem.custom_fields.append(CustomField(name=n, value=str(v), type=0))


def _add_tags(vitem: VaultItem, overview: dict):
    tags = overview.get("tags") or []
    if tags:
        vitem.custom_fields.append(CustomField(name="_TAGS", value=", ".join(tags), type=0))


# ---------------------------------------------------------------------------
# 官方平铺结构（item 顶层直接 fields / sections / urls）
# ---------------------------------------------------------------------------
def _convert_flat(item: dict, folder_map: dict[str, str]) -> VaultItem | None:
    name = item.get("name") or "未命名"
    favorite = bool(item.get("favorite"))
    category = (item.get("category") or "").upper()
    item_type = CATEGORY_TO_TYPE.get(category, 1)

    folder_name = folder_map.get(item.get("folderUuid") or "", "")

    vitem = VaultItem(
        id=item.get("uuid") or "",
        type=item_type,
        name=name,
        folder=folder_name,
        favorite=favorite,
        creation_date=_epoch_to_iso(item.get("createdAt")),
        revision_date=_epoch_to_iso(item.get("updatedAt")),
    )

    fields = item.get("fields") or []
    sections = item.get("sections") or []
    urls = item.get("urls") or []
    notes = _extract_notes_flat(item, sections, fields)

    if item_type == 1:
        uris = [Uri(uri=u.get("url")) for u in urls if isinstance(u, dict) and u.get("url")]
        for f in fields:
            design = f.get("designation") or ""
            val = f.get("value") or ""
            if not val:
                continue
            if design == "username":
                vitem.username = val
            elif design == "password":
                vitem.password = val
            elif design == "URL" and not any(u.uri == val for u in uris):
                uris.append(Uri(uri=val))
        vitem.uris = uris
        vitem.totp = _find_totp(fields, sections)
        vitem.notes = notes
        for ph in item.get("passwordHistory") or []:
            vitem.password_history.append(
                PasswordHistory(password=ph.get("value") or "", last_used_date=_epoch_to_iso(ph.get("time")))
            )
    elif item_type == 2:
        vitem.notes = notes
    elif item_type == 3:
        _fill_card_flat(vitem, fields, sections)
        vitem.notes = notes
    elif item_type == 4:
        _fill_identity_flat(vitem, fields, sections)
        vitem.notes = notes
    elif item_type == 5:
        _fill_ssh_flat(vitem, fields, sections)
    else:
        vitem.notes = notes

    _fill_custom_fields_flat(vitem, fields, sections)
    _add_tags_flat(vitem, item)
    return vitem


def _extract_notes_flat(item: dict, sections: list, fields: list) -> str:
    if item.get("notesPlain"):
        return item["notesPlain"]
    for f in fields:
        if f.get("name") == "notesPlain" or f.get("k") == "notesPlain" or f.get("type") == "note":
            return f.get("value") or ""
    for sec in sections:
        for f in sec.get("fields") or []:
            if f.get("name") == "notesPlain" or f.get("k") == "notesPlain" or f.get("type") == "note":
                return f.get("value") or ""
    return ""


def _find_totp(fields: list, sections: list) -> str:
    for f in fields:
        n = (f.get("k") or f.get("n") or "").upper()
        if n == "TOTP" or n == "OTP" or (f.get("n") or "").lower() == "one-time password":
            if f.get("value"):
                return f["value"]
    for sec in sections:
        for f in sec.get("fields") or []:
            n = (f.get("k") or f.get("n") or "").upper()
            if n == "TOTP" or n == "OTP" or (f.get("n") or "").lower() == "one-time password":
                if f.get("value"):
                    return f["value"]
    return ""


def _fill_card_flat(vitem: VaultItem, fields: list, sections: list):
    for f in fields + _flatten_section_fields(sections):
        n = (f.get("name") or f.get("n") or f.get("k") or "").lower()
        v = f.get("value") or ""
        if not v:
            continue
        if "cardholder" in n or n == "name":
            vitem.cardholder_name = v
        elif "number" in n or "ccnum" in n:
            vitem.card_number = v
        elif "expir" in n or n == "exp":
            exp = str(v).split("/")
            vitem.card_exp_month = exp[0] if len(exp) > 0 else ""
            vitem.card_exp_year = exp[1] if len(exp) > 1 else ""
        elif "cvv" in n or "cvc" in n or "security" in n:
            vitem.card_code = v
        elif "type" in n or "brand" in n:
            vitem.card_brand = v


def _fill_identity_flat(vitem: VaultItem, fields: list, sections: list):
    for f in fields + _flatten_section_fields(sections):
        n = (f.get("name") or f.get("n") or f.get("k") or "").lower()
        v = f.get("value") or ""
        if not v:
            continue
        if "first" in n:
            vitem.identity_first_name = (vitem.identity_first_name + " " + v).strip()
        elif "last" in n:
            vitem.identity_last_name = v
        elif "email" in n:
            vitem.identity_email = v
        elif "phone" in n:
            vitem.identity_phone = v
        elif "address" in n:
            vitem.identity_address1 = v
        elif "city" in n:
            vitem.identity_city = v
        elif "state" in n:
            vitem.identity_state = v
        elif "zip" in n or "postal" in n:
            vitem.identity_postal_code = v
        elif "country" in n:
            vitem.identity_country = v


def _fill_ssh_flat(vitem: VaultItem, fields: list, sections: list):
    for f in fields + _flatten_section_fields(sections):
        n = (f.get("name") or f.get("n") or f.get("k") or "").lower()
        v = f.get("value") or ""
        if "private" in n:
            vitem.ssh_private_key = v
        elif "public" in n:
            vitem.ssh_public_key = v
        elif "fingerprint" in n:
            vitem.ssh_key_fingerprint = v


def _flatten_section_fields(sections: list) -> list:
    out = []
    for sec in sections:
        out.extend(sec.get("fields") or [])
    return out


def _fill_custom_fields_flat(vitem: VaultItem, fields: list, sections: list):
    reserved = {"notesplain", "password", "username"}
    seen = set()
    for f in fields + _flatten_section_fields(sections):
        n = f.get("name") or f.get("n") or f.get("k") or ""
        v = f.get("value") if f.get("value") is not None else f.get("v") or ""
        if not n or not v:
            continue
        if n.lower() in reserved:
            continue
        key = n.lower()
        if key in seen:
            continue
        seen.add(key)
        vitem.custom_fields.append(CustomField(name=n, value=str(v), type=0))


def _add_tags_flat(vitem: VaultItem, item: dict):
    tags = item.get("tags") or []
    if tags:
        vitem.custom_fields.append(CustomField(name="_TAGS", value=", ".join(tags), type=0))


def _normalize_date(value):
    """将 1Password 日期（epoch 秒 / ISO 字符串）统一为 ISO 字符串或空字符串"""
    if not value:
        return ""
    if isinstance(value, (int, float)):
        return _epoch_to_iso(value)
    if isinstance(value, str):
        s = value.strip()
        if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
            return _epoch_to_iso(s)
        return s  # 已是 ISO 字符串
    return ""


def _epoch_to_iso(epoch) -> str:
    if not epoch:
        return ""
    try:
        import datetime

        return (
            datetime.datetime.fromtimestamp(float(epoch), datetime.timezone.utc).isoformat()
            + "Z"
        )
    except Exception:  # noqa: BLE001
        return ""
