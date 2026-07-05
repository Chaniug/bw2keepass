"""
bw-to-keepass 命令行入口

用法:
    python -m bw_to_keepass <input.json|input.zip> <output.kdbx> [--password PWD] [--name NAME]
"""

import argparse
import sys
import getpass
import os

from .parser import parse_bitwarden_export
from .writer import write_keepass, print_summary


def main():
    parser = argparse.ArgumentParser(
        description="将 Bitwarden 导出 JSON 转换为 KeePass KDBX 格式",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python -m bw_to_keepass bitwarden_export.json vault.kdbx
  python -m bw_to_keepass bitwarden_export.zip vault.kdbx --name "我的密码库"
  python -m bw_to_keepass export.json vault.kdbx --password "MyM@sterP@ss"
        """,
    )
    parser.add_argument("input", help="Bitwarden 导出文件路径 (.json 或 .zip)")
    parser.add_argument("output", help="输出 KeePass 数据库路径 (.kdbx)")
    parser.add_argument(
        "--password", "-p",
        help="KeePass 数据库主密码（如不指定将交互式输入）",
    )
    parser.add_argument(
        "--name", "-n",
        default="Bitwarden Import",
        help="数据库名称（默认: Bitwarden Import）",
    )

    args = parser.parse_args()

    # 检查输入文件
    if not os.path.exists(args.input):
        print(f"错误: 输入文件不存在: {args.input}", file=sys.stderr)
        sys.exit(1)

    # 检查输入文件扩展名
    ext = os.path.splitext(args.input)[1].lower()
    if ext not in ('.json', '.zip'):
        print(f"错误: 不支持的输入格式 '{ext}'，需要 .json 或 .zip", file=sys.stderr)
        sys.exit(1)

    # 获取密码
    password = args.password
    if not password:
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

    print(f"\n正在解析: {args.input}")
    folders, items = parse_bitwarden_export(args.input)
    print(f"找到 {len(folders)} 个文件夹, {len(items)} 个条目")

    print(f"\n正在生成 KeePass 数据库...")
    type_counts, unknown_count = write_keepass(
        folders=folders,
        items=items,
        output_path=args.output,
        password=password,
        db_name=args.name,
    )

    print_summary(type_counts, unknown_count, len(items))
    print(f"\n数据库已保存至: {os.path.abspath(args.output)}")
    print("可使用 KeePass 2.x 或 KeePassXC 打开此文件。\n")


if __name__ == "__main__":
    main()
