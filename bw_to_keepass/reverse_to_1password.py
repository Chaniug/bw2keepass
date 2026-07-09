"""
KDBX -> 1Password (1PUX) 反向导出

复用 reverse_converter.convert_kdbx_to_bitwarden 得到 Bitwarden 结构，
再映射为 1Password 官方「平铺」1PUX 结构（item 顶层直接 fields/sections/urls），
最后打包为 .1pux ZIP（内含 data/1password.1pif）。

说明：1Password 官方 1PUX 导入不支持 passkey / 附件等扩展字段，这类数据会以
备注形式保留在 notes 中，导入后请核对。
"""

import json
import uuid
import zipfile
import logging
from typing import Any

from .reverse_converter import convert_kdbx_to_bitwarden


logger = logging.getLogger(__name__)


TYPE_TO_CATEGORY = {
    1: "LOGIN",
    2: "SECURE_NOTE",
    3: "CREDIT_CARD",
    4: "IDENTITY",
    5: "SSH_KEY",
}


def kdbx_to_1password(
    kdbx_path: str, output_1pux: str, password: str, key_file: str | None = None
) -> dict:
    """将 KeePass KDBX 反向导出为 1Password 1PUX 文件

    Returns: {"items": int, "folders": int}
    """
    data = convert_kdbx_to_bitwarden(kdbx_path, password, key_file)
    onepass = bitwarden_to_1pux(data)
    _write_1pux(onepass, output_1pux)
    return {
        "items": len(onepass.get("items", [])),
        "folders": len(onepass.get("folders", [])),
    }


def bitwarden_to_1pux(data: dict) -> dict:
    """将 Bitwarden 结构 dict 转为 1Password 1PUX 根对象"""
    # folder 映射：Bitwarden folderId -> 1Password folderUuid
    folder_uuid_map: dict[str, str] = {}
    folders = []
    for f in data.get("folders", []) or []:
        fid = f.get("id") or str(uuid.uuid4())
        folder_uuid_map[fid] = fid
        folders.append({"uuid": fid, "name": f.get("name") or ""})

    items = []
    for bw_item in data.get("items", []) or []:
        items.append(_bw_item_to_1pux(bw_item, folder_uuid_map))

    return {
        "accounts": [{"uuid": str(uuid.uuid4()), "name": "Pass2KDBX", "domain": ""}],
        "folders": folders,
        "items": items,
    }


def _bw_item_to_1pux(bw_item: dict, folder_uuid_map: dict[str, str]) -> dict:
    t = bw_item.get("type", 1)
    category = TYPE_TO_CATEGORY.get(t, "LOGIN")
    name = bw_item.get("name") or "(无标题)"

    fields: list[dict] = []
    sections: list[dict] = []
    urls: list[dict] = []

    # ---- Login ----
    login = bw_item.get("login") or {}
    if login:
        if login.get("username"):
            fields.append(_field("username", login["username"], designation="username"))
        if login.get("password"):
            fields.append(_field("password", login["password"], designation="password"))
        for i, u in enumerate(login.get("uris") or []):
            uri = u.get("uri") if isinstance(u, dict) else u
            if not uri:
                continue
            if i == 0:
                urls.append({"url": uri})
            else:
                fields.append(_field(f"url{i}", uri, designation="URL"))
        if login.get("totp"):
            fields.append(_field("TOTP", login["totp"], kind="TOTP"))

    # ---- Card ----
    card = bw_item.get("card") or {}
    if card:
        card_fields = []
        if card.get("cardholderName"):
            card_fields.append(_field("cardholder name", card["cardholderName"]))
        if card.get("brand"):
            card_fields.append(_field("type", card["brand"]))
        if card.get("number"):
            card_fields.append(_field("ccnum", card["number"]))
        exp = "/".join(
            str(x) for x in [card.get("expMonth"), card.get("expYear")] if x not in (None, "", 0)
        )
        if exp:
            card_fields.append(_field("expiry", exp))
        if card.get("code"):
            card_fields.append(_field("cvv", card["code"]))
        if card_fields:
            sections.append(_section("Credit Card", card_fields))

    # ---- Identity ----
    identity = bw_item.get("identity") or {}
    if identity:
        id_fields = []
        for nm, val in [
            ("first name", identity.get("firstName")),
            ("last name", identity.get("lastName")),
            ("email", identity.get("email")),
            ("phone", identity.get("phone")),
            ("address", identity.get("address1")),
            ("city", identity.get("city")),
            ("state", identity.get("state")),
            ("zip", identity.get("postalCode")),
            ("country", identity.get("country")),
        ]:
            if val:
                id_fields.append(_field(nm, val))
        if id_fields:
            sections.append(_section("Identity", id_fields))

    # ---- SSH Key ----
    ssh = bw_item.get("sshKey") or {}
    if ssh:
        ssh_fields = []
        if ssh.get("privateKey"):
            ssh_fields.append(_field("private key", ssh["privateKey"]))
        if ssh.get("publicKey"):
            ssh_fields.append(_field("public key", ssh["publicKey"]))
        if ssh.get("fingerprint"):
            ssh_fields.append(_field("fingerprint", ssh["fingerprint"]))
        if ssh_fields:
            sections.append(_section("SSH Key", ssh_fields))

    # ---- Notes ----
    notes_parts = []
    if bw_item.get("notes"):
        notes_parts.append(bw_item["notes"])

    # ---- Custom fields ----
    custom_fields = []
    for cf in bw_item.get("fields") or []:
        nm = cf.get("name")
        val = cf.get("value")
        if nm and val not in (None, ""):
            custom_fields.append(_field(nm, str(val)))
    if custom_fields:
        sections.append(_section("Custom Fields", custom_fields))

    # ---- Passkeys (1Password 无标准导入，以备注保留) ----
    fidos = bw_item.get("fido2Credentials") or []
    if fidos:
        pk_lines = ["[Passkey 凭据 - 1Password 暂不支持标准导入，已保留在此]"]
        for f in fidos:
            pk_lines.append(
                f"- RP: {f.get('rpId','')} | 用户: {f.get('userName','')} | "
                f"credentialId: {f.get('credentialId','')}"
            )
        notes_parts.append("\n".join(pk_lines))

    if notes_parts:
        sections.append(
            _section("", [{"id": _fid(), "type": "note", "name": "notesPlain", "value": "\n\n".join(notes_parts)}])
        )

    item: dict[str, Any] = {
        "uuid": bw_item.get("id") or str(uuid.uuid4()),
        "category": category,
        "name": name,
        "urls": urls,
        "favorite": bool(bw_item.get("favorite")),
        "trashed": False,
        "createdAt": _iso_to_epoch(bw_item.get("creationDate")) or 0,
        "updatedAt": _iso_to_epoch(bw_item.get("revisionDate")) or 0,
        "fields": fields,
        "sections": sections,
    }
    folder_uuid = folder_uuid_map.get(bw_item.get("folderId") or "")
    if folder_uuid:
        item["folderUuid"] = folder_uuid
    return item


def _field(name: str, value: str, designation: str | None = None, kind: str | None = None) -> dict:
    n = (name or "").lower()
    ftype = "P" if "password" in n else ("note" if "note" in n else "T")
    if kind == "TOTP":
        ftype = "T"
    f = {"id": _fid(), "type": ftype, "name": name, "value": value}
    if designation:
        f["designation"] = designation
    return f


def _section(name: str, fields: list[dict]) -> dict:
    return {"id": _sid(), "name": name, "fields": fields}


def _fid() -> str:
    return uuid.uuid4().hex


def _sid() -> str:
    return uuid.uuid4().hex


def _iso_to_epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        import datetime

        s = iso.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(s)
        return dt.timestamp()
    except Exception:  # noqa: BLE001
        return None


def _write_1pux(onepass: dict, output_path: str):
    content = json.dumps(onepass, ensure_ascii=False, indent=2)
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("data/1password.1pif", content)
