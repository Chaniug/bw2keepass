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
    └── assets/                    # 前端固化副本（来源 web/，A 方案）
        └── index.html 等
```

## 与网页版的关系

- `assets/` 是 **`web/` 的固化副本**（A 方案），首次由 `web/` 复制而来。
- **网页版 `web/` 原文件保持不动**；App 后续单独迭代时只改 `app/src/main/assets/` 下的副本。
- 副本中已移除 `serviceWorker` 注册（`file://` 协议不支持 SW，无需 PWA 离线）。
- 若网页版有重大更新需要同步进 App，请手动复制并重新核对差异（后续可加同步脚本）。

## 工程参数

- 包名：`cc.valk.pass2kdbx`
- 应用名：`Pass2KDBX`
- minSdk 21 / targetSdk 34
- versionCode / versionName：`1` / `1.0`（发布时递增，见下方「版本与发布」）

## UI 与设计

- **Material You 风格**：圆润大圆角（24px）、实色分层 surface、柔和长阴影、主色驱动一切元素。
- **深色 / 浅色兼容**：默认跟随系统 `prefers-color-scheme`；右上角按钮可手动切换并 localStorage 记忆；切换时同步 `meta theme-color`（影响安卓状态栏/导航栏配色）。
- **动态取色（Android 12+）**：`MainActivity` 通过 `WallpaperManager.getWallpaperColors()` 读取壁纸主色，在 `onPageFinished` 用 `evaluateJavascript` 调用前端 `window.Pass2KDBXDynamic.apply({accent, accentHover, accentGlow})`，前端把主色写入 CSS 变量 `--accent*`，并据亮度自动算出 `--on-accent`（主色上的文字色），打 `data-dynamic="true"` 标记。
  - **降级**：Android < 12 不支持壁纸取色，自动沿用默认主色（`--accent` 紫色基线），UI 不受影响。
- 前端为 `web/index.html` 的固化副本（见上文「与网页版的关系」），UI 改动只落在 `app/src/main/assets/`。

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
