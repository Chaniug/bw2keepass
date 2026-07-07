# Pass2KDBX 🔐

> Bitwarden / KeePass 密码管理器格式互转工具 · 纯本地处理，数据不经过任何服务器

| | |
|---|---|
| 🔁 **双向互转** | Bitwarden JSON ↔ KeePass KDBX |
| 🔑 **Passkey 迁移** | FIDO2 / WebAuthn 凭据在 Bitwarden 与 KeePassXC 间无损迁移 |
| 🔐 **加密导出** | KDBX → Bitwarden 密码保护加密 JSON（与官方格式兼容） |
| 🛡️ **隐私优先** | 网页 / App / CLI 均本地运行，零上传 |

---

## 📑 目录

- [下载与安装](#下载与安装)
- [功能特性](#功能特性)
- [命令行工具（Python）](#命令行工具python)
  - [加密导出（密码保护）](#加密导出密码保护)
- [Android App 独立工程](#android-app-独立工程)
- [项目结构](#项目结构)
- [隐私说明](#隐私说明)
- [License](#license)

---

## 📥 下载与安装

### 方式一：安装原生 App（推荐）

| 平台 | 获取方式 | 说明 |
|------|----------|------|
| 🤖 Android | [Pass2KDBX.apk](https://github.com/Chaniug/bw2keepass/releases/latest) | 直接下载安装，无需 Google Play |
| 🍎 iOS | Safari 打开网页版 → 分享 → 添加到主屏幕 | 作为 PWA 全屏离线使用 |
| 💻 桌面端 | 直接打开网页版 | 无需安装 |

**Android 安装步骤**

1. 点击上方链接下载 `Pass2KDBX.apk`
2. 系统设置 → 安全 → 允许「未知来源」安装
3. 点击下载的 APK 完成安装

**iOS 安装步骤（PWA）**

1. 用 Safari 打开 [key.valk.ccwu.cc](https://key.valk.ccwu.cc)
2. 点击底部「分享」按钮 →「添加到主屏幕」
3. 主屏出现独立图标，可全屏运行并离线使用

### 方式二：直接使用网页版

👉 **[打开网页版转换器](https://key.valk.ccwu.cc)**

无需安装，支持所有现代浏览器。手机 Chrome / Edge 亦可「添加到主屏幕」作为 PWA 使用。

---

## 🤖 Android App 独立工程

Android APK 已从「CI 内联脚本临时拼装」升级为仓库内**固化、可独立演进**的真实工程，位于 **`app/`** 目录（详见 [`app/README.md`](app/README.md)）。

- **独立发布线**：APK 走专属 tag（前缀 `app-v*`，如 `app-v1.0`）与独立 Release 标题「Pass2KDBX Android App」，**不再与网页版 `apk-latest` 混用**。
- **独立前端副本**：`app/src/main/assets/` 是 `web/` 的固化副本（A 方案），首次由 `web/` 复制而来。网页端 `web/` 原文件保持不动，App 后续单独迭代只改 `assets/` 副本。
- **本地可构建**：提供 [`app/build-apk-local.sh`](app/build-apk-local.sh)，配置好 Android SDK 后可在本机直接复现 CI 构建，无需等待 CI。
- **签名一致**：使用 CI 缓存的固定 keystore，保证每次构建签名一致、可覆盖安装。

> 当前 App 仍处于开发阶段（前端尚未脱离网页版独立成型），但工程结构已独立，可单独维护与发布。

---

## ✨ 功能特性

- 🔁 **双向转换**：Bitwarden JSON ↔ KeePass KDBX，正向反向均支持
- 🔑 **Passkey 完整迁移**：FIDO2 / WebAuthn 凭据在 Bitwarden 与 KeePassXC 间无损迁移
- 🔐 **密码保护导出**：KDBX → Bitwarden 可输出**密码保护加密 JSON**，与 Bitwarden 加密导出格式兼容，可被 Bitwarden 或本工具重新解密导入
- 📊 **CSV 导出**：支持通用 / Bitwarden / KeePass 三种 CSV 格式
- 📁 **保留结构**：文件夹层级、自定义字段、密码历史完整保留
- 🛡️ **本地处理**：所有数据在浏览器本地处理，不上传任何服务器
- 📱 **跨平台**：网页版 + Android APK + iOS PWA

### 支持的密码项类型

| 类型 | Bitwarden → KDBX | KDBX → Bitwarden |
|------|:---:|:---:|
| 登录（用户名 / 密码 / TOTP / URI） | ✅ | ✅ |
| 安全笔记 | ✅ | ✅ |
| 卡片（信用卡） | ✅ | ✅ |
| 身份（个人信息） | ✅ | ✅ |
| SSH 密钥 | ✅ | ✅ |
| Passkey / FIDO2 | ✅ | ✅ |

---

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

# KDBX → Bitwarden JSON（反向转换，明文）
python -m bw_to_keepass --reverse input.kdbx output.json --password "your_password"

# KDBX → Bitwarden 密码保护加密 JSON（见下节）
python -m bw_to_keepass --reverse input.kdbx output.json \
    --password "your_password" --export-password "export_pwd"

# KDBX → CSV 导出
python -m bw_to_keepass --csv input.kdbx output.csv --password "your_password"
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `input` | 输入文件路径 |
| `output` | 输出文件路径 |
| `--password` | 数据库密码（KDBX 主密码） |
| `--name` | 自定义数据库名称（仅正向转换） |
| `--reverse` | 反向转换（KDBX → Bitwarden JSON） |
| `--csv` | CSV 导出（KDBX → CSV） |
| `--export-password` | 反向导出时：将输出加密为密码保护导出（KDBX → 加密 JSON） |
| `--salt-mode` | 加密导出的 salt 处理方式：`utf8`（默认）/ `base64` |

---

## 🔐 加密导出（密码保护）

将 KDBX 反向转换为 Bitwarden JSON 时，可勾选「加密导出」并设定导出密码，输出**密码保护加密 JSON**。该格式与 Bitwarden 官方加密导出完全兼容，采用 **AES-CBC-256 + HMAC-SHA256（encType 2）**，密钥由 PBKDF2 / Argon2 派生后经 HKDF 拉伸得到。

### 命令行

```bash
python -m bw_to_keepass --reverse input.kdbx output.json \
    --password "your_password" --export-password "export_pwd"
```

网页版：在「→ Bitwarden」方向上传 KDBX 后，于选项卡中勾选「加密导出（密码保护）」，填写导出密码即可。

### salt 模式说明

Bitwarden 加密导出对 `salt` 字段的处理在不同版本 / 客户端间存在分歧：

| 模式 | 含义 | 适用场景 |
|------|------|----------|
| `utf8`（默认） | 使用 salt 字符串的 UTF-8 字节参与 KDF | 对齐常见 Bitwarden 导出 |
| `base64` | 使用 salt 的 base64 解码字节（官方文档标准） | 可移植性更好，跨客户端通用 |

> 💡 若导入 Bitwarden 时提示密码错误或无法识别，换用另一种 `--salt-mode` 重试即可；密文算法本身两种模式一致。

### 导入 Bitwarden 步骤

1. 用本工具生成加密 JSON（设好导出密码）
2. 打开 Bitwarden → **工具 → 导入数据**
3. 选择格式 **Bitwarden（密码保护）JSON**，上传文件并输入导出密码
4. 导入完成后即可在原 vault 中查看全部条目

---

## 🛠 项目结构

```
bw2keepass/
├── bw_to_keepass/           # Python 命令行工具
│   ├── __main__.py          # CLI 入口
│   ├── parser.py            # Bitwarden JSON 解析器
│   ├── converter.py         # 正向转换（BW → KDBX）
│   ├── reverse_converter.py # 反向转换（KDBX → BW）
│   ├── encrypted.py         # Bitwarden 密码保护加密导出的加密 / 解密
│   ├── csv_exporter.py      # CSV 导出
│   └── writer.py           # KeePass 数据库写入器
├── web/                     # 网页版 + PWA（原文件保持不动）
│   ├── index.html           # 纯前端单页应用
│   ├── manifest.json        # PWA 清单
│   ├── sw.js               # Service Worker（离线支持）
│   └── icon-*.png          # PWA 图标
├── app/                     # Android App 独立工程（固化）
│   ├── README.md            # App 工程说明
│   ├── build-apk-local.sh   # 本地构建脚本
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/cc/valk/pass2kdbx/MainActivity.java  # WebView 壳 + 下载接口
│       ├── res/             # styles.xml / ic_launcher.xml
│       └── assets/          # 前端固化副本（来自 web/，可独立演进）
├── tests/                   # 测试（47 个用例）
├── .github/workflows/       # GitHub Actions
│   ├── build-apk.yml       # 自动构建 Android APK（独立 app-v* 发布线）
│   └── deploy-pages.yml     # 部署网页版
├── requirements.txt
└── README.md
```

---

## 🔒 隐私说明

- **网页版**：所有数据在浏览器本地处理，不发送到任何服务器
- **Android APK**：纯 WebView 包装网页代码，无后端，无数据收集
- **CLI 工具**：本地运行，无网络请求

---

## 📄 License

MIT
