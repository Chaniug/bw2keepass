"""
bw-to-keepass 命令行入口（传入 / 传出 通用模式）

用法:
    通用转换（任意源 → 任意目标，可多选）:
        python -m bw_to_keepass --from bitwarden --to kdbx,json,1pux in.json out
        python -m bw_to_keepass in.1pux out --to kdbx        # 自动探测源格式
        python -m bw_to_keepass vault.kdbx out --from kdbx --to json,csv

    正向转换 (Bitwarden / 1Password → KDBX):
        python -m bw_to_keepass <input.json|input.zip> <output.kdbx> [--password PWD] [--name NAME]

    反向转换 (KDBX → Bitwarden JSON):
        python -m bw_to_keepass --reverse <input.kdbx> <output.json> [--password PWD]

    CSV 导出 (KDBX → CSV):
        python -m bw_to_keepass --csv <input.kdbx> <output.csv> [--password PWD] [--csv-format generic|bitwarden|keepass]

说明:
    --reverse / --csv 为旧式别名，等价于 --from kdbx --to bitwarden / --to csv。
    多目标时，输出路径作为基名，自动追加对应扩展名（out.kdbx / out.json / out.1pux / out.csv）。
"""

import argparse
import sys
import getpass
import os
import re
import json

from .parser import parse_bitwarden_export, peek_export_kind
from .encrypted import EncryptedExportRequiresPassword, EncryptedExportError
from .writer import write_keepass, print_summary
from .onepassword import parse_1password_export, is_1password_data
from .convert import (
    convert, detect_source_format, TARGET_FORMATS, TARGET_EXT,
)


def main():
    parser = argparse.ArgumentParser(
        description="密码格式通用转换工具（传入 / 传出）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 任意源 → 任意目标（多选）
  python -m bw_to_keepass --from bitwarden --to kdbx,json,1pux in.json out
  python -m bw_to_keepass in.1pux out --to kdbx          # 自动探测源
  python -m bw_to_keepass vault.kdbx out --from kdbx --to json,csv

  # 旧式别名
  python -m bw_to_keepass bitwarden_export.json vault.kdbx        # 正向 → KDBX
  python -m bw_to_keepass --reverse vault.kdbx bitwarden.json     # 反向 → Bitwarden
  python -m bw_to_keepass --csv vault.kdbx vault.csv             # → CSV
        """,
    )
    parser.add_argument("input", nargs='?', help="输入文件路径")
    parser.add_argument("output", nargs='?', help="输出文件路径（多目标时作为基名）")
    parser.add_argument(
        "--from", "-f",
        dest="frm",
        choices=['auto', 'bitwarden', 'encrypted', '1password', 'kdbx'],
        default='auto',
        help="源格式（默认 auto 自动探测）",
    )
    parser.add_argument(
        "--to", "-t",
        help="目标格式，逗号分隔可多选：kdbx,json,bitwarden,encrypted,1pux,csv",
    )
    parser.add_argument(
        "--password", "-p",
        help="源读取密码（KDBX 主密码 或 Bitwarden 导出密码）；不指定则交互式输入",
    )
    parser.add_argument(
        "--db-password",
        help="写出 KDBX 目标时的数据库主密码（不指定则对新建库交互式设置）",
    )
    parser.add_argument(
        "--name", "-n",
        default="Pass2KDBX Import",
        help="数据库名称（默认: Pass2KDBX Import，仅写出 KDBX 时生效）",
    )
    parser.add_argument(
        "--reverse", "-r",
        action="store_true",
        help="别名：--from kdbx --to bitwarden",
    )
    parser.add_argument(
        "--csv", "-c",
        action="store_true",
        help="别名：--from kdbx --to csv",
    )
    parser.add_argument(
        "--csv-format",
        choices=['generic', 'bitwarden', 'keepass'],
        default='generic',
        help="CSV 导出格式（默认: generic）",
    )
    parser.add_argument(
        "--key-file", "-k",
        help="KeePass 密钥文件（可选）",
    )
    parser.add_argument(
        "--export-password", "-e",
        help="写出加密 JSON 目标，或解密 Bitwarden 加密导出时的密码",
    )
    parser.add_argument(
        "--salt-mode",
        choices=['utf8', 'base64'],
        default='utf8',
        help="加密导出的 salt 处理方式（默认 utf8，与 Bitwarden 官方一致）",
    )
    parser.add_argument(
        "--email",
        help="账户限制型加密导出解密用：Bitwarden 账户邮箱",
    )

    args = parser.parse_args()

    # 检查必要参数
    if not args.input or not args.output:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(args.input):
        print(f"错误: 输入文件不存在: {args.input}", file=sys.stderr)
        sys.exit(1)

    # 解析源格式 / 目标格式
    source_format = _resolve_source_format(args)
    targets = _resolve_targets(args)

    # 收集源解析所需的密码（含交互式）
    secrets = _gather_source_secrets(args.input, source_format, args)

    # 解析实际源格式（用于判断是否需要新建 KDBX 密码）
    actual_source = source_format or detect_source_format(args.input)
    source_is_kdbx = (actual_source == 'kdbx')

    # 处理 KDBX 目标密码
    db_password = args.db_password
    if 'kdbx' in targets and not db_password:
        if source_is_kdbx:
            db_password = secrets['password']
        else:
            db_password = _prompt_new_kdbx_password()

    # 输出基名（剥离已知扩展名）
    base = re.sub(r'\.(kdbx|json|csv|1pux)$', '', args.output, flags=re.I) or args.output

    # 统一转换
    try:
        results = convert(
            args.input, targets,
            source_format=source_format,
            password=secrets['password'],
            key_file=secrets['key_file'],
            export_password=secrets['export_password'],
            email=secrets['email'],
            master_password=secrets['master_password'],
            db_password=db_password,
            salt_mode=args.salt_mode,
            csv_format=args.csv_format,
            db_name=args.name,
        )
    except (EncryptedExportError, ValueError, ImportError) as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)

    # 写出各目标
    wrote = 0
    for fmt, content in results.items():
        out_path = base + TARGET_EXT[fmt]
        if os.path.exists(out_path):
            ow = input(f"文件 '{out_path}' 已存在，是否覆盖? [y/N]: ")
            if ow.lower() != 'y':
                print(f"  跳过: {out_path}")
                continue
        with open(out_path, 'wb') as f:
            f.write(content)
        print(f"  已写出: {os.path.abspath(out_path)}")
        wrote += 1

    if wrote == 0:
        print("未写出任何文件。")
    else:
        print(f"\n转换完成，共写出 {wrote} 个文件。")


def _resolve_source_format(args) -> str | None:
    if args.reverse or args.csv:
        return 'kdbx'
    if args.frm and args.frm != 'auto':
        return args.frm
    return None  # auto


def _resolve_targets(args) -> list[str]:
    if args.to:
        targets = [t.strip().lower() for t in args.to.split(',') if t.strip()]
        invalid = [t for t in targets if t not in set(TARGET_FORMATS)]
        if invalid:
            print(f"错误: 不支持的目标格式: {', '.join(invalid)}", file=sys.stderr)
            print(f"  可选: {', '.join(TARGET_FORMATS)}", file=sys.stderr)
            sys.exit(1)
        return targets
    if args.reverse:
        return ['bitwarden']
    if args.csv:
        return ['csv']
    return ['kdbx']


def _gather_source_secrets(input_path: str, source_format: str | None, args) -> dict:
    """收集源解析所需密码（含交互式提示），返回 parse_source 所需参数"""
    secrets = {
        'password': args.password,
        'key_file': args.key_file,
        'export_password': args.export_password,
        'email': args.email,
        'master_password': None,
    }

    fmt = source_format or detect_source_format(input_path)

    if fmt == 'kdbx':
        if not secrets['password']:
            secrets['password'] = getpass.getpass("请输入 KeePass 数据库主密码: ")
            if not secrets['password']:
                print("错误: 密码不能为空", file=sys.stderr)
                sys.exit(1)
        return secrets

    # bitwarden / encrypted：探测加密类型
    try:
        kind = peek_export_kind(input_path)
    except Exception:
        kind = {'encrypted': False, 'account': False}

    if kind.get('account'):
        if not secrets['email']:
            secrets['email'] = input("检测到 Bitwarden 账户限制型加密导出，请输入账户邮箱: ").strip()
        if not secrets['email']:
            print("错误: 邮箱不能为空", file=sys.stderr)
            sys.exit(1)
        if not secrets['master_password']:
            secrets['master_password'] = getpass.getpass("请输入 Bitwarden 账户主密码: ")
            if not secrets['master_password']:
                print("错误: 主密码不能为空", file=sys.stderr)
                sys.exit(1)
    elif kind.get('encrypted'):
        if not secrets['export_password']:
            secrets['export_password'] = getpass.getpass("检测到 Bitwarden 加密导出，请输入导出密码: ")
            if not secrets['export_password']:
                print("错误: 导出密码不能为空", file=sys.stderr)
                sys.exit(1)

    return secrets


def _prompt_new_kdbx_password() -> str:
    """交互式设置新 KDBX 数据库主密码（带确认）"""
    pw = getpass.getpass("请设置输出 KeePass 数据库主密码: ")
    confirm = getpass.getpass("请再次输入确认: ")
    if pw != confirm:
        print("错误: 两次输入的密码不一致", file=sys.stderr)
        sys.exit(1)
    if not pw:
        print("错误: 密码不能为空", file=sys.stderr)
        sys.exit(1)
    return pw


if __name__ == "__main__":
    main()
