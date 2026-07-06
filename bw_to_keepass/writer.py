"""
KeePass 数据库写入器

使用 pykeepass 库创建 KDBX 数据库并写入条目。
"""

import os
import logging
from pykeepass import create_database
from .parser import VaultItem, Folder
from .converter import (
    get_entry_title,
    get_entry_username,
    get_entry_password,
    get_entry_url,
    get_entry_notes,
    get_entry_tags,
    build_custom_fields,
    sanitize_path,
)

logger = logging.getLogger(__name__)


def write_keepass(
    folders: list[Folder],
    items: list[VaultItem],
    output_path: str,
    password: str,
    db_name: str = "Bitwarden Import",
):
    """
    将 Bitwarden 数据写入 KeePass KDBX 数据库

    Args:
        folders: 文件夹列表
        items: 密码项列表
        output_path: 输出 KDBX 文件路径
        password: 数据库主密码
        db_name: 数据库名称
    """
    # 创建新的 KDBX 数据库
    # 失败时清理残留文件，避免损坏的部分写入文件误导用户
    try:
        kp = create_database(output_path, password=password)
    except Exception as e:
        # create_database 可能已创建部分文件，清理之
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except OSError:
                pass
        logger.error("创建 KDBX 数据库失败: %s", e)
        raise

    # 设置数据库名称和描述
    try:
        kp.database_name = db_name
        kp.database_description = f"Imported from Bitwarden - {db_name}"
    except AttributeError:
        pass  # 某些版本可能不支持直接设置

    # 建立分组结构（文件夹 → KeePass Group）
    group_map: dict[str, object] = {}  # folder_name -> Group
    root_group = kp.root_group

    for folder in folders:
        folder_name = sanitize_path(folder.name)
        if folder_name:
            group = kp.add_group(root_group, folder_name)
            group_map[folder_name] = group

    # 统计
    type_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    unknown_count = 0

    for item in items:
        # 确定目标分组
        target_group = root_group
        if item.folder and item.folder in group_map:
            target_group = group_map[item.folder]

        # 构建条目属性
        title = get_entry_title(item)
        username = get_entry_username(item)
        password_val = get_entry_password(item)
        url = get_entry_url(item)
        notes = get_entry_notes(item)
        tags = get_entry_tags(item)
        custom_fields = build_custom_fields(item)

        # 创建 KeePass 条目
        entry = kp.add_entry(
            target_group,
            title=title,
            username=username,
            password=password_val,
            url=url,
            notes=notes,
            tags=tags,
        )

        # 添加自定义字符串字段
        for key, value in custom_fields.items():
            if value:  # 只添加非空值
                entry.set_custom_property(key, str(value))

        # 统计
        if item.type in type_counts:
            type_counts[item.type] += 1
        else:
            unknown_count += 1

    # 保存数据库
    try:
        kp.save()
    except Exception as e:
        # 保存失败时清理可能损坏的输出文件
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except OSError:
                pass
        logger.error("保存 KDBX 数据库失败: %s", e)
        raise

    return type_counts, unknown_count


def print_summary(type_counts: dict, unknown_count: int, total: int):
    """打印转换摘要"""
    print("\n" + "=" * 50)
    print("  转换完成！")
    print("=" * 50)
    print(f"  总条目数: {total}")
    print(f"  ├─ 登录 (Login):      {type_counts.get(1, 0)}")
    print(f"  ├─ 安全笔记 (Note):    {type_counts.get(2, 0)}")
    print(f"  ├─ 卡片 (Card):        {type_counts.get(3, 0)}")
    print(f"  ├─ 身份 (Identity):    {type_counts.get(4, 0)}")
    print(f"  └─ SSH 密钥:           {type_counts.get(5, 0)}")
    if unknown_count > 0:
        print(f"  └─ 未知类型:           {unknown_count}")
    print("=" * 50)
