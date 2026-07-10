# Pass2KDBX Android App（独立子工程）

本目录是 Pass2KDBX 的 Android APK 工程，已从仓库 CI 的「内联脚本临时拼装」升级为**固化、可独立演进**的真实工程。

## 目录结构

```
app/
├── README.md                      # 本说明
├── build-apk-local.sh             # 本地构建脚本（复现 CI 构建）
└── src/main/
    ├── AndroidManifest.xml        # 清单（包名 cc.valk.pass2kdbx）
    ├── java/cc/valk/pass2kdbx/
    │   └── MainActivity.java      # WebView 壳 + AndroidFileSaver 下载接口
    ├── res/
    │   ├── values/styles.xml      # AppTheme（深色）
    │   └── drawable/ic_launcher.xml
    └── assets/                    # 前端（独立 MD3 实现，非 web/ 副本）
        ├── index.html             # Material Design 3 原生风格界面
        ├── engine.js             # 纯转换逻辑（无 DOM，供 WebView 调用）
        └── vendor/               # 本地化依赖（离线可用）
            ├── kdbxweb.min.js
            ├── argon2.umd.min.js
            └── jszip.min.js
```

## 与网页版的关系

- **App 与网页版共用同一套 MD3 实现（单一来源 `web/`）**：`web/index.html` 为唯一前端来源，`assets/index.html` 由构建脚本（`build-apk-local.sh` / CI）在打包前从 `web/` 同步而来，二者保持一致。
- **逻辑层复用**：转换核心抽离为 `assets/engine.js`（无 DOM 的纯函数），通过 `window.Pass2KDBXEngine.run(opts)` 暴露，UI 仅负责交互与渲染，保持与网页版**功能对等**（Bitwarden/KeePass/1Password/CSV 双向转换、Passkey 分离、favicon、加密导出等）。1Password 支持官方 .1pux 平铺结构（fields/sections/urls）与旧式 overview/details 双兼容，反向导出 KDBX → 1Password .1pux 也已支持。
- **依赖本地化**：`kdbxweb` / `hash-wasm(Argon2)` / `JSZip` 已下载至 `assets/vendor/`，WebView 在 `file://` 下**完全离线**运行，不再依赖 CDN。
- **已移除 web 专用产物**：`sw.js`、`CNAME`、`manifest.json`、`debug-test.html` 等与 WebView 无关的文件不再随 App 打包。

## 工程参数

- 包名：`cc.valk.pass2kdbx`
- 应用名：`Pass2KDBX`
- minSdk 21 / targetSdk 34
- versionCode / versionName：`1` / `1.0`（发布时递增，见下方「版本与发布」）

## UI 与设计

- **Material Design 3（MD3）**：大圆角（卡片 28px / 控件胶囊）、surface 分层（surface / surface-1 / surface-2）、柔和 elevation 阴影、主色驱动按钮/开关/分段控件/FAB/Snackbar/Bottom Sheet，整体为现代化安卓 App 观感。
- **深色 / 浅色兼容**：默认跟随系统；App 内部「关于」面板的主题选项可手动选 系统/浅色/深色 并记忆，切换时同步 `meta theme-color`（影响安卓状态栏/导航栏配色）。
- **动态取色（Android 12+）**：`MainActivity` 通过 `WallpaperManager.getWallpaperColors()` 读取壁纸主色，扩展为全套 MD3 变量（primary / onPrimary / primaryContainer / secondary / tertiary …），在 `onPageFinished` 用 `evaluateJavascript` 调用前端 `window.Pass2KDBXDynamic.apply({primary, onPrimary, primaryContainer, ...})`，前端写入 `--md-*` CSS 变量并打 `data-dynamic="true"` 标记。
  - **降级**：Android < 12 不支持壁纸取色，沿用默认 MD3 紫色基线，UI 不受影响。
- 前端**单一来源为 `web/`**（见上文「与网页版的关系」），UI 改动应落在 `web/`，由构建脚本同步到 `app/src/main/assets/`。

## 本地构建

需要：JDK 17、Android SDK（platforms;android-34、build-tools;34.0.0）、`aapt2`/`javac`/`d8`/`zipalign`/`apksigner` 在 PATH，`keytool` 可用。

```bash
cd app
./build-apk-local.sh        # 产出 app/build/Pass2KDBX.apk
```

脚本会：编译资源 → 链接（含 assets）→ 编译 Java → DEX → 对齐 → 用 `app/build/release.keystore` 签名（不存在则自动生成）。

## 版本与发布（CI）

- CI 工作流：`.github/workflows/build-apk.yml`
- 发布采用**独立 tag/Release 线**：tag 前缀 `app-v*`（如 `app-v1.0`），Release 标题「Pass2KDBX Android App」，**不与网页版 `apk-latest` 混用**。
- 提高版本号时，修改 `build-apk.yml` 中 `--version-code` / `--version-name`，并打对应 `app-v*` tag。

## 签名说明

签名 keystore 由 CI cache 固定（`release-keystore-v1`），保证每次构建签名一致、可覆盖安装。本地脚本默认生成独立 keystore，仅用于本地调试。
