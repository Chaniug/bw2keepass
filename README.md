# bw-to-keepass

将 Bitwarden 导出的 JSON 数据库转换为 KeePass KDBX 格式。

## 功能

- 支持 Bitwarden JSON 明文导出（`.json`）和带附件的 ZIP 导出
- 支持所有 Bitwarden 密码项类型：
  - 登录（用户名/密码/TOTP/URI）
  - 安全笔记
  - 卡片（信用卡）
  - 身份（个人信息）
  - SSH 密钥
- 保留文件夹结构（映射为 KeePass 分组）
- 保留自定义字段
- 保留密码历史
- 输出 KDBX4 格式数据库

## 安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/bw-to-keepass.git
cd bw-to-keepass

# 创建虚拟环境
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/macOS

# 安装依赖
pip install -r requirements.txt
```

## 使用方法

### 1. 从 Bitwarden 导出数据

在 Bitwarden 客户端中：**设置 → 导出保管库 → .json 格式**

### 2. 转换

```bash
# 基本用法：将 bitwarden.json 转换为 keepass.kdbx
python -m bw_to_keepass bitwarden_export.json output.kdbx

# 指定主密码（交互式输入更安全）
python -m bw_to_keepass bitwarden_export.json output.kdbx --password "your_master_password"

# 从 ZIP 文件转换（含附件）
python -m bw_to_keepass bitwarden_export.zip output.kdbx

# 自定义数据库名称
python -m bw_to_keepass bitwarden_export.json output.kdbx --name "My Vault"
```

### 3. 在 KeePass 中打开

使用 KeePass 2.x 或 KeePassXC 打开生成的 `.kdbx` 文件，输入你设置的主密码即可。

## 项目结构

```
bw-to-keepass/
├── bw_to_keepass/       # 主包
│   ├── __init__.py
│   ├── __main__.py      # 入口点
│   ├── parser.py        # Bitwarden JSON 解析器
│   ├── converter.py     # 转换器（JSON → KDBX）
│   └── writer.py        # KeePass 数据库写入器
├── tests/               # 测试
│   └── test_converter.py
├── requirements.txt
└── README.md
```

## 依赖

- [pykeepass](https://github.com/libkeepass/pykeepass) - KeePass 数据库操作
- Python 3.8+

## License

MIT
