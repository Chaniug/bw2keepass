"""
bw-to-keepass 命令行入口

用法:
    正向转换 (Bitwarden → KDBX):
        python -m bw_to_keepass <input.json|input.zip> <output.kdbx> [--password PWD] [--name NAME]

    反向转换 (KDBX → Bitwarden JSON):
        python -m bw_to_keepass --reverse <input.kdbx> <output.json> [--password PWD]

    CSV 导出 (KDBX → CSV):
        python -m bw_to_keepass --csv <input.kdbx> <output.csv> [--password PWD] [--csv-format generic|bitwarden|keepass]
"""

import argparse
import sys
import getpass
import os
import json

from .parser import parse_bitwarden_export
from .encrypted import EncryptedExportRequiresPassword, EncryptedExportError
from .writer import write_keepass, print_summary


def main():
    parser = argparse.ArgumentParser(
        description="Bitwarden <-> KeePass 格式互转工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # Bitwarden → KeePass (正向)
  python -m bw_to_keepass bitwarden_export.json vault.kdbx
  python -m bw_to_keepass bitwarden_export.zip vault.kdbx --name "我的密码库"

  # KeePass → Bitwarden JSON (反向)
  python -m bw_to_keepass --reverse vault.kdbx bitwarden_import.json

  # KeePass → CSV
  python -m bw_to_keepass --csv vault.kdbx vault.csv
  python -m bw_to_keepass --csv vault.kdbx vault.csv --csv-format bitwarden
        """,
    )
    parser.add_argument("input", nargs='?', help="输入文件路径")
    parser.add_argument("output", nargs='?', help="输出文件路径")
    parser.add_argument(
        "--password", "-p",
        help="数据库主密码（如不指定将交互式输入）",
    )
    parser.add_argument(
        "--name", "-n",
        default="Bitwarden Import",
        help="数据库名称（默认: Bitwarden Import，仅正向转换）",
    )
    parser.add_argument(
        "--reverse", "-r",
        action="store_true",
        help="反向转换：KDBX → Bitwarden JSON",
    )
    parser.add_argument(
        "--csv", "-c",
        action="store_true",
        help="导出为 CSV 格式",
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
        help="Bitwarden 加密导出的解密密码（仅当输入为「密码保护加密 JSON」时需要）",
    )

    args = parser.parse_args()

    # 检查必要参数
    if not args.input or not args.output:
        parser.print_help()
        sys.exit(1)

    # 检查输入文件
    if not os.path.exists(args.input):
        print(f"错误: 输入文件不存在: {args.input}", file=sys.stderr)
        sys.exit(1)

    # 获取密码
    password = args.password
    if not password:
        if args.reverse or args.csv:
            password = getpass.getpass("请输入 KeePass 数据库主密码: ")
        else:
            password = getpass.getpass("请输入 KeePass 数据库主密码: ")
            confirm = getpass.getpass("请再次输入确认: ")
            if password != confirm:
                print("错误: 两次输入的密码不一致", file=sys.stderr)
                sys.exit(1)
        if not password:
            print("错误: 密码不能为空", file=sys.stderr)
            sys.exit(1)

    # 检查输出文件
    if os.path.exists(args.output):
        overwrite = input(f"文件 '{args.output}' 已存在，是否覆盖? [y/N]: ")
        if overwrite.lower() != 'y':
            print("已取消")
            sys.exit(0)

    if args.reverse:
        # 反向转换：KDBX → Bitwarden JSON
        _do_reverse_convert(args.input, args.output, password, args.key_file)
    elif args.csv:
        # CSV 导出
        _do_csv_export(args.input, args.output, password, args.csv_format, args.key_file)
    else:
        # 正向转换：Bitwarden → KDBX
        _do_forward_convert(args.input, args.output, password, args.name, args.export_password)


def _do_forward_convert(input_path: str, output_path: str, password: str, db_name: str, export_password: str | None = None):
    """Bitwarden → KeePass 正向转换"""
    ext = os.path.splitext(input_path)[1].lower()
    if ext not in ('.json', '.zip'):
        print(f"错误: 不支持的输入格式 '{ext}'，需要 .json 或 .zip", file=sys.stderr)
        sys.exit(1)

    print(f"\n正在解析: {input_path}")
    try:
        folders, items = parse_bitwarden_export(input_path, export_password=export_password)
    except EncryptedExportRequiresPassword:
        # 检测到加密导出但未提供密码：交互索取（避免静默空库）
        if export_password:
            raise
        export_password = getpass.getpass("检测到 Bitwarden 加密导出，请输入导出密码: ")
        folders, items = parse_bitwarden_export(input_path, export_password=export_password)
    except EncryptedExportError as e:
        print(f"错误: 加密导出解密失败: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"找到 {len(folders)} 个文件夹, {len(items)} 个条目")

    print(f"\n正在生成 KeePass 数据库...")
    type_counts, unknown_count = write_keepass(
        folders=folders,
        items=items,
        output_path=output_path,
        password=password,
        db_name=db_name,
    )

    print_summary(type_counts, unknown_count, len(items))
    print(f"\n数据库已保存至: {os.path.abspath(output_path)}")
    print("可使用 KeePass 2.x 或 KeePassXC 打开此文件。\n")


def _do_reverse_convert(input_path: str, output_path: str, password: str, key_file: str | None):
    """KDBX → Bitwarden JSON 反向转换"""
    ext = os.path.splitext(input_path)[1].lower()
    if ext != '.kdbx':
        print(f"错误: 反向转换需要 .kdbx 文件，不支持 '{ext}'", file=sys.stderr)
        sys.exit(1)

    from .reverse_converter import convert_kdbx_to_bitwarden

    print(f"\n正在加载 KDBX 数据库: {input_path}")
    try:
        data = convert_kdbx_to_bitwarden(input_path, password, key_file)
    except Exception as e:
        print(f"错误: 无法打开 KDBX 文件: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"找到 {len(data['folders'])} 个文件夹, {len(data['items'])} 个条目")

    # 统计类型
    type_names = {1: 'Login', 2: 'Secure Note', 3: 'Card', 4: 'Identity', 5: 'SSH Key'}
    type_counts = {}
    passkey_count = 0
    for item in data['items']:
        tn = type_names.get(item['type'], 'Other')
        type_counts[tn] = type_counts.get(tn, 0) + 1
        if item.get('fido2Credentials'):
            passkey_count += len(item['fido2Credentials'])

    # 写入 JSON
    print(f"\n正在生成 Bitwarden JSON...")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 50)
    print("  反向转换完成！")
    print("=" * 50)
    print(f"  总条目数: {len(data['items'])}")
    for tn, count in sorted(type_counts.items()):
        print(f"  ├─ {tn}: {count}")
    if passkey_count > 0:
        print(f"  ├─ Passkey 凭据: {passkey_count}")
    print("=" * 50)
    print(f"\n文件已保存至: {os.path.abspath(output_path)}")
    print("可在 Bitwarden 中通过 文件 → 导入数据 导入此 JSON 文件。\n")


def _do_csv_export(input_path: str, output_path: str, password: str, csv_format: str, key_file: str | None):
    """KDBX → CSV 导出"""
    ext = os.path.splitext(input_path)[1].lower()
    if ext != '.kdbx':
        print(f"错误: CSV 导出需要 .kdbx 文件，不支持 '{ext}'", file=sys.stderr)
        sys.exit(1)

    from .csv_exporter import export_kdbx_to_csv

    print(f"\n正在加载 KDBX 数据库: {input_path}")
    try:
        stats = export_kdbx_to_csv(input_path, password, output_path, csv_format, key_file)
    except Exception as e:
        print(f"错误: 无法导出 CSV: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "=" * 50)
    print("  CSV 导出完成！")
    print("=" * 50)
    print(f"  总条目数: {stats['total']}")
    if stats['passkey_entries'] > 0:
        print(f"  ⚠ 包含 {stats['passkey_entries']} 个 Passkey 条目")
        print(f"     Passkey 数据无法通过 CSV 保留，请同时使用")
        print(f"     --reverse 导出 Bitwarden JSON 以保留 Passkey")
    print("=" * 50)
    print(f"\n文件已保存至: {os.path.abspath(output_path)}")
    print(f"CSV 格式: {csv_format}\n")


if __name__ == "__main__":
    main()
