# Pass2KDBX 🔐

Bitwarden / KeePass 密码管理器格式互转工具。支持 **Passkey 完整迁移**、双向转换（BW↔KDBX）、CSV 导出。

纯前端处理，**数据不经过任何服务器**。

## 📥 下载安装

### 方式一：安装原生 App（推荐）

| 平台 | 下载 | 说明 |
|------|------|------|
| 🤖 Android | [Pass2KDBX.apk](https://github.com/Chaniug/bw2keepass/releases/latest) | 直接下载安装，无需 Google Play |
| 🍎 iOS | 用 Safari 打开网页版 → 分享 → 添加到主屏幕 | 作为 PWA 使用 |
| 💻 Windows / macOS / Linux | 直接打开网页版 | 无需安装 |

**Android 安装方法**：
1. 点击上方链接下载 `Pass2KDBX.apk`
2. 手机设置 → 安全 → 允许"未知来源"安装
3. 点击下载的 APK 文件安装

**iOS 安装方法**（PWA）：
1. 用 Safari 打开 [key.valk.ccwu.cc](https://key.valk.ccwu.cc)
2. 点击底部分享按钮 → "添加到主屏幕"
3. 桌面会出现独立图标，全屏运行，可离线使用

### 方式二：直接使用网页版

👉 **[打开网页版转换器](https://key.valk.ccwu.cc)**

无需安装，支持所有现代浏览器。手机 Chrome / Edge 可"添加到主屏幕"作为 PWA 使用。

## ✨ 功能特性

- 🔁 **双向转换**：Bitwarden JSON ↔ KeePass KDBX
- 🔑 **Passkey 完整迁移**：支持 FIDO2/WebAuthn 凭据在 Bitwarden 和 KeePassXC 之间无损迁移
- 📊 **CSV 导出**：支持通用 / Bitwarden / KeePass 三种 CSV 格式
- 📁 **保留结构**：文件夹层级、自定义字段、密码历史完整保留
- 🔐 **本地处理**：所有数据在浏览器本地处理，不上传服务器
- 📱 **跨平台**：网页版 + Android APK + iOS PWA

### 支持的密码项类型

| 类型 | Bitwarden → KDBX | KDBX → Bitwarden |
|------|:---:|:---:|
| 登录（用户名/密码/TOTP/URI） | ✅ | ✅ |
| 安全笔记 | ✅ | ✅ |
| 卡片（信用卡） | ✅ | ✅ |
| 身份（个人信息） | ✅ | ✅ |
| SSH 密钥 | ✅ | ✅ |
| Passkey / FIDO2 | ✅ | ✅ |

## 📦 命令行工具（Python）

### 安装

```bash
git clone https://github.com/Chaniug/bw2keepass.git
cd bw2keepass
pip install -r requirements.txt
```

### 使用方法

```bash
# Bitwarden JSON → KeePass KDBX
python -m bw_to_keepass bitwarden_export.json output.kdbx --password "your_password"

# 从 ZIP 文件转换（含附件）
python -m bw_to_keepass bitwarden_export.zip output.kdbx

# KDBX → Bitwarden JSON（反向转换）
python -m bw_to_keepass --reverse input.kdbx output.json --password "your_password"

# KDBX → CSV 导出
python -m bw_to_keepass --csv input.kdbx output.csv --password "your_password"
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `input` | 输入文件路径 |
| `output` | 输出文件路径 |
| `--password` | 数据库密码 |
| `--name` | 自定义数据库名称 |
| `--reverse` | 反向转换（KDBX → Bitwarden JSON） |
| `--csv` | CSV 导出（KDBX → CSV） |

## 🛠 项目结构

```
bw2keepass/
├── bw_to_keepass/       # Python 命令行工具
│   ├── __main__.py      # CLI 入口
│   ├── parser.py        # Bitwarden JSON 解析器
│   ├── converter.py     # 正向转换（BW → KDBX）
│   ├── reverse_converter.py  # 反向转换（KDBX → BW）
│   ├── csv_exporter.py  # CSV 导出
│   └── writer.py        # KeePass 数据库写入器
├── web/                 # 网页版 + PWA
│   ├── index.html       # 纯前端单页应用
│   ├── manifest.json    # PWA 清单
│   ├── sw.js            # Service Worker（离线支持）
│   └── icon-*.png      # PWA 图标
├── tests/               # 测试（33 个用例）
├── .github/workflows/   # GitHub Actions
│   ├── build-apk.yml   # 自动构建 Android APK
│   └── deploy-pages.yml # 部署网页版
├── requirements.txt
└── README.md
```

## 🔒 隐私说明

- **网页版**：所有数据在浏览器本地处理，不发送到任何服务器
- **Android APK**：纯 WebView 包装网页代码，无后端，无数据收集
- **CLI 工具**：本地运行，无网络请求

## 📄 License

MIT
