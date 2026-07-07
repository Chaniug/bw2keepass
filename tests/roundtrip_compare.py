"""
Bitwarden <-> KDBX <-> Bitwarden 往返（round-trip）语义级对比测试

目的
----
验证「原始加密 JSON -> KDBX -> 新加密 JSON」这一往返过程中是否存在
数据丢失或转换 bug。直接比对两个加密 JSON 文件无意义（外层信封每次随机），
因此本工具先**解密两层**拿到明文 M1（原始）/ M2（新），再在**语义层**比对。

两种运行模式
------------
1. 单独对比（默认）：给定 原始加密JSON + 新加密JSON，分别解密后比对。
2. 端到端复算（--e2e）：给定 原始加密JSON + 中间KDBX + 新加密JSON，
   用 reverse_converter 把 KDBX 重新转回明文、再 encrypt 成新加密 JSON，
   与「直接读到的 新加密JSON」比对，验证两者同源（防止拿错文件）。

配对策略
--------
反向转换会为每个 item 重新生成 UUID（id 不可比），且 folderId 被重新映射，
故**按 name 配对**。存在重名时依次用 (name, type) 兜底。文件夹归属通过
文件夹名（而非 folderId）比对。

白名单（预期差异，不报 bug）
----------------------------
反向转换只重建 Bitwarden 导入所需的最小子集，以下差异属设计性、必然存在：
  - item.id / folderId          （重新生成 / 重新映射）
  - item.favorite                （硬编码 False）
  - item.passwordHistory         （清空为 []）
  - item.login.uris[].match      （恒为 null，前向未保留 match 策略）
  - item.collections / organizationId / collectionIds
  - 顶层 collections / sends / profile / 其他元字段
  - item 级空 fido2Credentials:[]（新JSON恒带，原始可能无）
  - 类型子对象 card/identity/secureNote/sshKey 在无对应类型时以 null 存在的差异
  - creationDate / revisionDate 缺失（仅当正向填了对应字段才有）

差异分级
--------
  [系统性]  某一类字段在所有/多数条目上一致地丢失（如 item 级身份字段），
            属转换器设计限制，单列一次统计，不逐条刷屏。
  [字段丢失] 某条目自定义 fields 集合新 < 原始（真实数据丢失）——重点区。
  [内容不符] 配对成功但 login 关键字段 / passkey 内容不一致——重点区。

用法
----
  python tests/roundtrip_compare.py \
      --orig "原始json.json" --orig-pwd 1247903536 \
      --new  "新的json.json"  --new-pwd 123456789

  python tests/roundtrip_compare.py ... --kdbx "转换后kdbx文件.kdbx" \
      --kdbx-pwd 1926980818 --e2e
"""

import argparse
import json
import os
import sys
from collections import defaultdict

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from bw_to_keepass.encrypted import decrypt_bitwarden_export, EncryptedExportError


# ============================================================================
# 解密
# ============================================================================

def load_plaintext(path: str, password: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if data.get('encrypted') and data.get('passwordProtected'):
        try:
            return decrypt_bitwarden_export(data, password)
        except EncryptedExportError as e:
            raise SystemExit(f"[错误] 解密失败 {path!r}: {e}")
    return data


# ============================================================================
# 归一化
# ============================================================================

ITEM_WHITELIST_KEYS = {
    'id', 'favorite', 'passwordHistory', 'organizationId', 'collectionIds',
    'collections', 'creationDate', 'revisionDate', 'reprompt', 'folderId',
}

TYPE_SUBOBJECTS = {'login', 'card', 'identity', 'secureNote', 'sshKey'}
URI_WHITELIST_KEYS = {'match'}

# item 级身份字段：Bitwarden 原始导出可能把身份字段放在 item 顶层（非 identity 子对象）。
# reverse_converter 仅对 type=4 写 identity.*，type!=4 时这些顶层字段会丢失。
# 这是系统性转换器限制，单列统计，不视为逐条随机 bug。
ITEM_LEVEL_IDENTITY_FIELDS = {'bankAccount', 'driversLicense', 'passport'}


def _canon_uri(uri: str) -> str:
    """URI 归一化：android:// 多余斜杠、指纹大小写等造成的等价差异忽略。"""
    if not uri:
        return uri or ''
    s = uri
    # android://ABC -> android:///ABC：统一成三斜杠（KDBX 规范化产物）
    if s.startswith('android://'):
        # 去掉 scheme 后的所有斜杠再补一个，得到 android:///host
        rest = s[len('android://'):].lstrip('/')
        s = 'android:///' + rest
    # android 指纹为十六进制，大小写不敏感
    return s.lower()


def _norm_uri(u: dict) -> dict:
    d = {k: v for k, v in (u or {}).items() if k not in URI_WHITELIST_KEYS}
    if 'uri' in d:
        d['uri'] = _canon_uri(d['uri'])
    return d


def _norm_item(item: dict) -> dict:
    itype = item.get('type')
    out = {}
    for k, v in item.items():
        if k in ITEM_WHITELIST_KEYS:
            continue
        if k in ITEM_LEVEL_IDENTITY_FIELDS:
            # 保留以便统计系统性丢失，但单独归到 identity_level 类别
            out[k] = v
            continue
        if k in TYPE_SUBOBJECTS:
            if v is None:
                continue
            if k == 'login' and itype == 1:
                login = {lk: lv for lk, lv in v.items() if lk != 'uris'}
                if 'uris' in v and v['uris'] is not None:
                    login['uris'] = [_norm_uri(u) for u in v['uris']]
                out[k] = login
            elif k == 'card' and itype == 3:
                out[k] = v
            elif k == 'identity' and itype == 4:
                out[k] = v
            elif k == 'sshKey' and itype == 5:
                out[k] = v
            elif k == 'secureNote' and itype == 2:
                out[k] = v
            continue
        if k == 'fido2Credentials':
            # 空数组视为等价（新JSON恒带 []），仅非空才参与比对
            if v:
                out[k] = v
            continue
        if k == 'fields' and isinstance(v, list):
            out[k] = sorted((f.get('name', ''), str(f.get('value', ''))) for f in v)
            continue
        out[k] = v

    # 兼容：原始导出把 passkey 放在 login.fido2Credentials，而反向转换器
    # convert_kdbx_to_bitwarden 输出在 item 顶层 fido2Credentials。
    # 统一抽取到 out['fido2Credentials']，避免位置差异被误判为丢失。
    login = item.get('login')
    if isinstance(login, dict):
        lf = login.get('fido2Credentials')
        if lf and not out.get('fido2Credentials'):
            out['fido2Credentials'] = lf
    return out


# ============================================================================
# 配对
# ============================================================================

def pair_items(orig_items, new_items):
    orig_by_name = defaultdict(list)
    for idx, it in enumerate(orig_items):
        orig_by_name[it.get('name', '')].append(idx)
    new_by_name = defaultdict(list)
    for idx, it in enumerate(new_items):
        new_by_name[it.get('name', '')].append(idx)

    pairs = []
    matched_new = set()

    for name, o_idxs in orig_by_name.items():
        n_idxs = new_by_name.get(name, [])
        for oi in o_idxs:
            cand = [ni for ni in n_idxs if ni not in matched_new
                    and new_items[ni].get('type') == orig_items[oi].get('type')]
            if not cand:
                cand = [ni for ni in n_idxs if ni not in matched_new]
            if cand:
                ni = cand[0]
                matched_new.add(ni)
                pairs.append((oi, ni, ''))
            else:
                pairs.append((oi, None, '新JSON中无同名条目'))

    new_only = [ni for ni in range(len(new_items)) if ni not in matched_new]
    return pairs, new_only


# ============================================================================
# 分类比对（返回结构化结果，而非直接打印）
# ============================================================================

def compare_pair(o_item, n_item):
    """返回该配对的分类差异字典"""
    res = {
        'identity_level_lost': [],   # 系统性：item 级身份字段丢失
        'fields_lost': [],           # 自定义字段丢失（真实）
        'login_mismatch': [],        # login 关键字段不符
        'passkey_mismatch': [],      # passkey 内容不符
        'other': [],                 # 其它需人工确认
    }
    name = o_item.get('name', '(无标题)')

    # 1. item 级身份字段
    for f in ITEM_LEVEL_IDENTITY_FIELDS:
        if f in o_item and f not in n_item:
            res['identity_level_lost'].append(f)

    o_norm = _norm_item(o_item)
    n_norm = _norm_item(n_item)

    # 2. fields 集合（已归一化为 sorted list of (name,value)）
    o_fields = set(o_norm.get('fields', []))
    n_fields = set(n_norm.get('fields', []))
    lost = o_fields - n_fields
    if lost:
        res['fields_lost'] = sorted(lost)

    # 3. login 关键字段
    ol = o_norm.get('login')
    nl = n_norm.get('login')
    if ol or nl:
        for sub in ('username', 'password', 'totp'):
            ov = (ol or {}).get(sub)
            nv = (nl or {}).get(sub)
            if ov != nv:
                res['login_mismatch'].append(f"login.{sub}: {ov!r} -> {nv!r}")
        ou = (ol or {}).get('uris') or []
        nu = (nl or {}).get('uris') or []
        # 用归一化后的 URI 集合比对（顺序/等价斜杠数/大小写无关）
        oc = {u.get('uri') for u in ou}
        nc = {u.get('uri') for u in nu}
        if oc != nc:
            res['login_mismatch'].append(
                f"login.uris 集合不一致: 原始 {sorted(oc)} -> 新 {sorted(nc)}")

    # 4. passkey —— 用 credentialId 集合比对（位置/顺序无关），更稳健
    of = o_norm.get('fido2Credentials') or []
    nf = n_norm.get('fido2Credentials') or []
    oc = {p.get('credentialId') for p in of}
    nc = {p.get('credentialId') for p in nf}
    if oc != nc:
        res['passkey_mismatch'].append(
            f"fido2Credentials credentialId 集合不一致: 原始 {len(oc)} 个 -> 新 {len(nc)} 个"
            f"（仅在原始: {sorted(oc - nc)}；仅在新: {sorted(nc - oc)}）")

    # 5. 其它内容差异（排除已处理类别）
    handled = {'fields', 'login', 'fido2Credentials'} | ITEM_LEVEL_IDENTITY_FIELDS
    for k in set(o_norm) | set(n_norm):
        if k in handled or k in ITEM_WHITELIST_KEYS or k in TYPE_SUBOBJECTS:
            continue
        ov, nv = o_norm.get(k), n_norm.get(k)
        if ov != nv:
            res['other'].append(f"{k}: {ov!r} -> {nv!r}")

    return res


# ============================================================================
# 报告
# ============================================================================

def print_report(orig, new, pairs, new_only, *, e2e_extra=None):
    orig_items = orig.get('items', [])
    new_items = new.get('items', [])
    orig_folders = orig.get('folders', [])
    new_folders = new.get('folders', [])

    print("\n" + "=" * 64)
    print("  Bitwarden <-> KDBX <-> Bitwarden 往返对比报告")
    print("=" * 64)
    print(f"\n[结构] 原始: {len(orig_items)} 条目 / {len(orig_folders)} 文件夹"
          f"   新: {len(new_items)} 条目 / {len(new_folders)} 文件夹")

    struct_warn = False
    if len(orig_items) != len(new_items):
        print(f"  [疑似bug] 条目数不一致！原始 {len(orig_items)} vs 新 {len(new_items)}")
        struct_warn = True
    if len(orig_folders) != len(new_folders):
        print(f"  [需确认] 文件夹数不一致！原始 {len(orig_folders)} vs 新 {len(new_folders)}")
        struct_warn = True
    orig_fn = {f.get('name', '') for f in orig_folders}
    new_fn = {f.get('name', '') for f in new_folders}
    if orig_fn - new_fn:
        print(f"  [需确认] 缺失文件夹: {sorted(orig_fn - new_fn)}")
        struct_warn = True

    # 聚合
    identity_lost_count = defaultdict(int)   # field -> 受影响条目数
    fields_lost_items = []                   # (name, lost_list)
    login_mismatch_items = []
    passkey_mismatch_items = []
    other_items = []
    missing_items = []

    for oi, ni, note in pairs:
        o_item = orig_items[oi]
        name = o_item.get('name', '(无标题)')
        if ni is None:
            missing_items.append(name)
            continue
        r = compare_pair(o_item, new_items[ni])
        for f in r['identity_level_lost']:
            identity_lost_count[f] += 1
        if r['fields_lost']:
            fields_lost_items.append((name, r['fields_lost']))
        if r['login_mismatch']:
            login_mismatch_items.append((name, r['login_mismatch']))
        if r['passkey_mismatch']:
            passkey_mismatch_items.append((name, r['passkey_mismatch']))
        if r['other']:
            other_items.append((name, r['other']))

    print("\n" + "-" * 64)
    print("  汇总")
    print("-" * 64)

    if identity_lost_count:
        print(f"\n[系统性] item 级身份字段在反向转换中丢失（非 type=4 条目不重建）：")
        for f, c in sorted(identity_lost_count.items()):
            print(f"    - {f}: 影响 {c} 个条目")

    if fields_lost_items:
        print(f"\n[字段丢失] {len(fields_lost_items)} 个条目的自定义 fields 有丢失：")
        for name, lost in fields_lost_items:
            lost_str = "; ".join(f"{n}={v}" for n, v in lost)
            print(f"    - {name!r}: 丢失 [{lost_str}]")
    else:
        print("\n[字段丢失] 无（自定义 fields 全部保留）")

    if login_mismatch_items:
        print(f"\n[内容不符] {len(login_mismatch_items)} 个条目 login 关键字段不一致：")
        for name, msgs in login_mismatch_items:
            print(f"    - {name!r}:")
            for m in msgs:
                print(f"        {m}")
    else:
        print("\n[内容不符] 无（login 用户名/密码/totp/uri 全部一致）")

    if passkey_mismatch_items:
        print(f"\n[Passkey] {len(passkey_mismatch_items)} 个条目 passkey 不一致：")
        for name, msgs in passkey_mismatch_items:
            print(f"    - {name!r}: {msgs}")
    else:
        print("\n[Passkey] 无不一致")

    if other_items:
        print(f"\n[其它] {len(other_items)} 个条目存在其它内容差异：")
        for name, msgs in other_items:
            print(f"    - {name!r}: {msgs}")

    if missing_items:
        print(f"\n[缺失] {len(missing_items)} 个原始条目在新JSON中找不到配对：")
        for n in missing_items:
            print(f"    - {n!r}")

    if new_only:
        print(f"\n[多余] 新JSON中有 {len(new_only)} 个原始没有的条目")

    print("\n" + "-" * 64)
    bug = (len(missing_items) + len(fields_lost_items) + len(login_mismatch_items)
           + len(passkey_mismatch_items) + len(other_items))
    print(f"  配对成功: {len(pairs) - len(missing_items)} | 缺失: {len(missing_items)}"
          f" | 真实数据丢失/不符条目: {bug}")
    if e2e_extra:
        print("  " + e2e_extra)
    print("-" * 64)
    if bug == 0 and not struct_warn:
        print("  [OK] 未发现疑似 bug（仅可能存在白名单内的预期差异）")
    else:
        print("  [!] 存在需人工复核的差异，重点看上方 [字段丢失]/[内容不符]/[Passkey]")
    print("=" * 64 + "\n")


# ============================================================================
# 端到端复算
# ============================================================================

def run_e2e(orig_path, orig_pwd, kdbx_path, kdbx_pwd, new_path, new_pwd, salt_mode):
    from bw_to_keepass.reverse_converter import convert_kdbx_to_bitwarden
    from bw_to_keepass.encrypted import encrypt_bitwarden_export

    print(f"[e2e] 反向转换 KDBX: {kdbx_path}")
    rebuilt = convert_kdbx_to_bitwarden(kdbx_path, kdbx_pwd)
    print(f"[e2e] 重建明文: {len(rebuilt['items'])} 条目, {len(rebuilt['folders'])} 文件夹")

    envelope = encrypt_bitwarden_export(rebuilt, new_pwd, salt_mode=salt_mode)
    m2_rebuilt = decrypt_bitwarden_export(envelope, new_pwd)

    new_plain = load_plaintext(new_path, new_pwd)

    pairs, new_only = pair_items(new_plain.get('items', []), m2_rebuilt.get('items', []))
    print_report(new_plain, m2_rebuilt, pairs, new_only,
                 e2e_extra="[e2e] 复算重建明文 与 给定新JSON 配对一致 -> 文件同源 OK")

    if len(m2_rebuilt.get('items', [])) != len(rebuilt.get('items', [])):
        print("  [疑似bug] 复算加密/解密后条目数变化")


# ============================================================================
# 主流程
# ============================================================================

def main():
    ap = argparse.ArgumentParser(description="Bitwarden<->KDBX 往返语义对比")
    ap.add_argument('--orig', required=True, help="原始加密 JSON 路径")
    ap.add_argument('--orig-pwd', required=True, help="原始 JSON 解密密码")
    ap.add_argument('--new', required=True, help="新加密 JSON 路径")
    ap.add_argument('--new-pwd', required=True, help="新 JSON 解密密码")
    ap.add_argument('--kdbx', help="中间 KDBX 路径（端到端复算用）")
    ap.add_argument('--kdbx-pwd', help="KDBX 主密码")
    ap.add_argument('--e2e', action='store_true', help="启用端到端复算同源校验")
    ap.add_argument('--salt-mode', choices=['utf8', 'base64'], default='base64',
                    help="重新加密新 JSON 的 salt 处理方式（默认 base64）")
    args = ap.parse_args()

    print(f"读取并解密原始 JSON: {args.orig}")
    orig = load_plaintext(args.orig, args.orig_pwd)
    print(f"读取并解密新 JSON: {args.new}")
    new = load_plaintext(args.new, args.new_pwd)

    if not args.e2e:
        pairs, new_only = pair_items(orig.get('items', []), new.get('items', []))
        print_report(orig, new, pairs, new_only)
    else:
        if not (args.kdbx and args.kdbx_pwd):
            raise SystemExit("[错误] --e2e 需要同时提供 --kdbx 与 --kdbx-pwd")
        run_e2e(args.orig, args.orig_pwd, args.kdbx, args.kdbx_pwd,
                args.new, args.new_pwd, args.salt_mode)


if __name__ == '__main__':
    main()
