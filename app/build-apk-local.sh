#!/usr/bin/env bash
# Pass2KDBX Android APK 本地构建脚本
# 复现 .github/workflows/build-apk.yml 的构建链路（手动签名 keystore）
#
# 前置依赖：
#   - JDK 17（javac / keytool）
#   - Android SDK，且设置 ANDROID_HOME / ANDROID_SDK_ROOT
#   - 以下工具在 PATH：aapt2, d8, zipalign, apksigner
#     （通常位于 $ANDROID_HOME/build-tools/<ver>/）
#
# 用法：
#   cd app
#   ./build-apk-local.sh
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$APP_DIR/src/main"
BUILD="$APP_DIR/build"

# ---- 可配置项 ----
BUILD_TOOLS_VER="${BUILD_TOOLS_VER:-34.0.0}"
PLATFORM_VER="${PLATFORM_VER:-android-34}"
MIN_SDK="${MIN_SDK:-21}"
TARGET_SDK="${TARGET_SDK:-34}"
VERSION_CODE="${VERSION_CODE:-1}"
VERSION_NAME="${VERSION_NAME:-1.0}"
KEYSTORE="$BUILD/release.keystore"
KEY_ALIAS="release"
KEY_PASS="pass2kdbx_release"
PKG="cc.valk.pass2kdbx"

# ---- 环境检查 ----
if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ]; then
  echo "ERROR: 请先设置 ANDROID_HOME 或 ANDROID_SDK_ROOT" >&2
  exit 1
fi
SDK_ROOT="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
BUILD_TOOLS="$SDK_ROOT/build-tools/$BUILD_TOOLS_VER"
PLATFORM="$SDK_ROOT/platforms/$PLATFORM_VER"

for tool in aapt2 javac d8 zipalign apksigner keytool; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: 未找到工具 '$tool'" >&2
    exit 1
  fi
done

mkdir -p "$BUILD"

# ---- 1. 生成签名 keystore（仅本地，首次运行）----
if [ ! -f "$KEYSTORE" ]; then
  echo "==> 生成本地签名 keystore: $KEYSTORE"
  keytool -genkey -v -keystore "$KEYSTORE" \
    -alias "$KEY_ALIAS" -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass "$KEY_PASS" -keypass "$KEY_PASS" \
    -dname "CN=Pass2KDBX, OU=App, O=Valk, L=Unknown, S=Unknown, C=US" \
    -noprompt
fi

# ---- 2. 编译资源 ----
echo "==> 编译资源"
aapt2 compile -o "$BUILD/res.zip" --dir "$SRC/res"

# ---- 3. 链接资源（含 assets）----
echo "==> 链接资源"
aapt2 link -o "$BUILD/base.apk" \
  -I "$PLATFORM/android.jar" \
  --manifest "$SRC/AndroidManifest.xml" \
  --java "$BUILD/gen" \
  -A "$SRC/assets" \
  --min-sdk-version "$MIN_SDK" \
  --target-sdk-version "$TARGET_SDK" \
  --version-code "$VERSION_CODE" \
  --version-name "$VERSION_NAME" \
  --package-id 0x7f \
  "$BUILD/res.zip"

# ---- 4. 编译 Java ----
echo "==> 编译 Java"
mkdir -p "$BUILD/obj"
javac -source 17 -target 17 \
  -cp "$PLATFORM/android.jar" \
  -d "$BUILD/obj" \
  "$SRC/java/$PKG/MainActivity.java" \
  "$BUILD/gen/$PKG/R.java"

# ---- 5. DEX ----
echo "==> DEX 编译"
mkdir -p "$BUILD/dex"
d8 --lib "$PLATFORM/android.jar" \
  --output "$BUILD/dex" \
  "$BUILD/obj/$PKG"/*.class

# ---- 6. 注入 classes.dex ----
cp "$BUILD/base.apk" "$BUILD/unsigned.apk"
( cd "$BUILD/dex" && zip -0 -j ../unsigned.apk classes.dex )

# ---- 7. 对齐 ----
zipalign -p -f 4 "$BUILD/unsigned.apk" "$BUILD/aligned.apk"

# ---- 8. 签名 ----
apksigner sign \
  --ks "$KEYSTORE" \
  --ks-pass "pass:$KEY_PASS" \
  --key-pass "pass:$KEY_PASS" \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out "$BUILD/Pass2KDBX.apk" \
  "$BUILD/aligned.apk"

echo "==> 验证签名"
apksigner verify --verbose "$BUILD/Pass2KDBX.apk" || true

echo "==> 构建完成: $BUILD/Pass2KDBX.apk"
ls -lh "$BUILD/Pass2KDBX.apk"
