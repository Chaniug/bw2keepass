package cc.valk.pass2kdbx;

import android.app.Activity;
import android.app.WallpaperManager;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.os.Build;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.util.Base64;
import android.util.Log;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.ValueCallback;
import android.webkit.ConsoleMessage;
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.content.ActivityNotFoundException;
import android.provider.MediaStore;
import android.content.ContentResolver;
import android.content.ContentValues;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

public class MainActivity extends Activity {
    private WebView webView;
    private ValueCallback<Uri[]> filePathCallback;
    private static final int FILE_CHOOSER_REQUEST = 100;
    private static final String TAG = "Pass2KDBX";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // 沉浸式：WebView 全屏延伸到系统栏下方，由前端用注入的 CSS 变量
        // var(--app-inset-*) 自行避让状态栏/导航栏；主题表面色通过 JS 同步到系统栏背景，融为一体
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            Window window = getWindow();
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS);
            // 状态栏/导航栏透明，让页面背景（渐变/纯色）沉浸式延伸到系统栏下方；
            // 系统栏图标的深浅由 setDark() 同步，避免透明背景下图标不可见
            window.setStatusBarColor(Color.TRANSPARENT);
            window.setNavigationBarColor(Color.TRANSPARENT);
            int uiFlags = View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                    | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                    | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION;
            window.getDecorView().setSystemUiVisibility(uiFlags);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            getWindow().setDecorFitsSystemWindows(false);
            getWindow().setNavigationBarContrastEnforced(false);
        }

        webView = new WebView(this);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            webView.setFitsSystemWindows(false);
        }
        webView.setBackgroundColor(Color.TRANSPARENT);
        setContentView(webView);

        // 页面加载后由 injectWindowInsets() 把系统栏高度注入 CSS 变量，前端据此避让
        injectWindowInsets();

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        settings.setJavaScriptCanOpenWindowsAutomatically(true);
        settings.setSupportMultipleWindows(false);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                // 页面加载完成后注入系统动态取色（Android 12+ 壁纸主色）
                applyDynamicColor();
                // 通知前端当前系统深浅模式，便于同步 theme-color / 状态栏
                applySystemDarkMode(view);
                // 注入系统栏高度，供前端用 var(--app-inset-*) 避让状态栏/导航栏
                injectWindowInsets();
            }
        });
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView wv, ValueCallback<Uri[]> fpc, FileChooserParams params) {
                if (filePathCallback != null) {
                    filePathCallback.onReceiveValue(null);
                    filePathCallback = null;
                }
                filePathCallback = fpc;
                try {
                    Intent intent = params.createIntent();
                    intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    startActivityForResult(intent, FILE_CHOOSER_REQUEST);
                } catch (ActivityNotFoundException e) {
                    Log.e(TAG, "No file chooser available", e);
                    filePathCallback.onReceiveValue(null);
                    filePathCallback = null;
                    return false;
                }
                return true;
            }

            @Override
            public void onPermissionRequest(PermissionRequest request) {
                request.grant(request.getResources());
            }

            @Override
            public boolean onConsoleMessage(ConsoleMessage cm) {
                Log.d(TAG, "JS: " + cm.message() + " (" + cm.sourceId() + ":" + cm.lineNumber() + ")");
                return true;
            }
        });

        // 注入文件下载接口
        webView.addJavascriptInterface(new FileSaver(this), "AndroidFileSaver");
        // 注入主题接口：前端选择主题后同步状态栏 / 导航栏图标深浅
        webView.addJavascriptInterface(new ThemeBridge(), "AndroidTheme");

        webView.loadUrl("file:///android_asset/index.html");
    }

    // ============ Material You 动态取色（Android 12+）============
    // 读取壁纸主色，扩展成 Material 风格的 primary / onPrimary / container 等，
    // 通过 evaluateJavascript 注入到前端 CSS 变量。Android < 12 不支持时降级默认紫。
    private void applyDynamicColor() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            Log.i(TAG, "Dynamic color not supported (< Android 12), using default purple");
            return;
        }
        try {
            WallpaperManager wm = WallpaperManager.getInstance(this);
            if (wm == null) return;
            android.app.WallpaperColors colors = wm.getWallpaperColors(WallpaperManager.FLAG_SYSTEM);
            if (colors == null) return;
            Color primary = colors.getPrimaryColor();
            if (primary == null) return;
            int argb = primary.toArgb();
            injectColor(argb);
        } catch (Exception e) {
            Log.e(TAG, "applyDynamicColor error", e);
        }
    }

    // 将取到的壁纸主色扩展为一组 MD3 变量并注入前端
    private void injectColor(int argb) {
        int r = Color.red(argb), g = Color.green(argb), b = Color.blue(argb);
        // onPrimary：在深色 surface 上，主色足够亮时可用近黑文字；这里统一取深紫底文字
        int onPrimary = mix(argb, 0x141318, 0.78f);
        // primaryContainer：主色混入深色背景（深色表面上的低对比容器）
        int primaryContainer = mix(argb, 0x141318, 0.55f);
        int onPrimaryContainer = mix(argb, 0xffffff, 0.82f);
        // secondary / tertiary：由主色色相派生（略偏移 + 降饱和），用于丰富界面层次
        int secondary = desaturate(shiftHue(argb, 28), 0.18f);
        int onSecondaryContainer = mix(secondary, 0xffffff, 0.82f);
        int secondaryContainer = mix(secondary, 0x141318, 0.55f);
        int tertiary = desaturate(shiftHue(argb, -42), 0.22f);
        // 统一注入 MD3 变量（与前端 Pass2KDBXDynamic.apply 的键对应）
        String js = String.format(
            "if (window.Pass2KDBXDynamic && window.Pass2KDBXDynamic.apply) {"
            + " window.Pass2KDBXDynamic.apply({"
            + "primary:'%s', onPrimary:'%s', primaryContainer:'%s', onPrimaryContainer:'%s',"
            + "secondary:'%s', secondaryContainer:'%s', onSecondaryContainer:'%s',"
            + "tertiary:'%s'}); }",
            hex(argb), hex(onPrimary), hex(primaryContainer), hex(onPrimaryContainer),
            hex(secondary), hex(secondaryContainer), hex(onSecondaryContainer), hex(tertiary));
        webView.evaluateJavascript(js, null);
        Log.i(TAG, "Dynamic color injected (MD3): " + hex(argb));
    }

    // 向目标色混合（factor=0 取 color，1 取 target）
    private static int mix(int color, int target, float factor) {
        int r = (int) (Color.red(color) + (Color.red(target) - Color.red(color)) * factor);
        int g = (int) (Color.green(color) + (Color.green(target) - Color.green(color)) * factor);
        int b = (int) (Color.blue(color) + (Color.blue(target) - Color.blue(color)) * factor);
        return Color.argb(255, clamp(r), clamp(g), clamp(b));
    }

    // 向白色混合（提亮）
    private static int lighten(int color, float factor) {
        return mix(color, 0xffffff, factor);
    }

    // 降低饱和度
    private static int desaturate(int color, float factor) {
        float[] hsl = new float[3];
        Color.colorToHSV(color, hsl);
        hsl[1] = hsl[1] * (1f - factor);
        return Color.HSVToColor(hsl);
    }

    // 色相偏移（degree）
    private static int shiftHue(int color, int degree) {
        float[] hsl = new float[3];
        Color.colorToHSV(color, hsl);
        hsl[0] = (hsl[0] + degree + 360) % 360;
        return Color.HSVToColor(hsl);
    }

    private static int clamp(int v) { return Math.max(0, Math.min(255, v)); }
    private static String hex(int argb) {
        return String.format("#%02x%02x%02x", Color.red(argb), Color.green(argb), Color.blue(argb));
    }

    // 同步系统深浅模式给前端（仅提示，前端自行决定是否跟随）
    private void applySystemDarkMode(WebView view) {
        boolean isDark = isSystemDark();
        syncStatusBarIcon(isDark);
        String js = "if (window.Pass2KDBXDynamic && window.Pass2KDBXDynamic.setSystemDark) {"
                + " window.Pass2KDBXDynamic.setSystemDark(" + (isDark ? "true" : "false") + "); }";
        view.evaluateJavascript(js, null);
    }

    // 读取当前系统是否为深色模式
    private boolean isSystemDark() {
        int nightMode = getResources().getConfiguration().uiMode
                & android.content.res.Configuration.UI_MODE_NIGHT_MASK;
        return nightMode == android.content.res.Configuration.UI_MODE_NIGHT_YES;
    }

    // 根据当前是否为深色背景，调整状态栏图标/文字的颜色（浅色背景→深色图标，深色背景→浅色图标）
    private void syncStatusBarIcon(boolean isDark) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return; // 早版本无法控制图标色
        Window window = getWindow();
        View decor = window.getDecorView();
        int flags = decor.getSystemUiVisibility();
        if (isDark) {
            // 深色背景：移除 LIGHT_STATUS_BAR，使状态栏图标为浅色
            flags &= ~View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
        } else {
            // 浅色背景：加 LIGHT_STATUS_BAR，使状态栏图标为深色
            flags |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
        }
        decor.setSystemUiVisibility(flags);
    }

    // JavaScript 接口：前端选择主题后，同步状态栏 / 导航栏图标深浅与背景色
    // （深色背景 → 浅色图标；浅色背景 → 深色图标），避免浅色主题下图标不可见
    public class ThemeBridge {
        @JavascriptInterface
        public void setDark(final boolean isDark) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    try {
                        syncStatusBarIcon(isDark);
                        syncNavBarIcon(isDark);
                    } catch (Exception e) {
                        Log.e(TAG, "ThemeBridge.setDark error", e);
                    }
                }
            });
        }

        // 状态栏/导航栏保持透明，让页面背景沉浸式延伸到系统栏下方；
        // 这里的 color 仅用作 WebView 兜底底色。系统栏图标深浅由 setDark() 同步。
        @JavascriptInterface
        public void setStatusBarColor(final String color) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    try {
                        int c = Color.parseColor(color);
                        Window window = getWindow();
                        window.setStatusBarColor(Color.TRANSPARENT);
                        window.setNavigationBarColor(Color.TRANSPARENT);
                        // 同步 WebView 背景色，作为透明系统栏下的兜底底色，避免露黑
                        if (webView != null) webView.setBackgroundColor(c);
                    } catch (Exception e) {
                        Log.e(TAG, "ThemeBridge.setStatusBarColor error", e);
                    }
                }
            });
        }
    }

    // 根据背景深浅调整导航栏图标颜色（Android 8.0+ 支持浅色导航栏图标）
    private void syncNavBarIcon(boolean isDark) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        Window window = getWindow();
        View decor = window.getDecorView();
        int flags = decor.getSystemUiVisibility();
        if (isDark) {
            flags &= ~View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        } else {
            flags |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        }
        decor.setSystemUiVisibility(flags);
    }

    // 把测量到的系统栏高度注入为 CSS 变量，供前端用 var(--app-inset-*) 避让状态栏/导航栏。
    // 关键：Android WebView 的 env(safe-area-inset-*) 默认返回 0，必须用原生测量值注入，
    // 否则顶部文案会顶到状态栏下被截断。
    private void injectWindowInsets() {
        if (webView == null) return;
        int top = getStatusBarHeight();
        int bottom = getNavigationBarHeight();
        final String js = "try{var s=document.documentElement.style;"
                + "s.setProperty('--app-inset-top','" + top + "px');"
                + "s.setProperty('--app-inset-bottom','" + bottom + "px');"
                + "s.setProperty('--app-inset-left','0px');"
                + "s.setProperty('--app-inset-right','0px');}catch(e){}";
        webView.evaluateJavascript(js, null);
    }

    // 读取系统状态栏高度（像素）
    private int getStatusBarHeight() {
        int resId = getResources().getIdentifier("status_bar_height", "dimen", "android");
        return resId > 0 ? getResources().getDimensionPixelSize(resId) : 0;
    }

    // 读取系统导航栏高度（像素）
    private int getNavigationBarHeight() {
        int resId = getResources().getIdentifier("navigation_bar_height", "dimen", "android");
        return resId > 0 ? getResources().getDimensionPixelSize(resId) : 0;
    }

    // JavaScript 接口：处理文件下载
    public static class FileSaver {
        private Context context;
        FileSaver(Context ctx) { context = ctx; }

        @JavascriptInterface
        public void saveFile(String base64Data, String fileName, String mimeType) {
            try {
                byte[] data = Base64.decode(base64Data, Base64.NO_WRAP);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    // Android 10+ 用 MediaStore
                    ContentResolver resolver = context.getContentResolver();
                    ContentValues values = new ContentValues();
                    values.put(MediaStore.MediaColumns.DISPLAY_NAME, fileName);
                    values.put(MediaStore.MediaColumns.MIME_TYPE, mimeType);
                    values.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
                    Uri uri = resolver.insert(MediaStore.Files.getContentUri("external"), values);
                    if (uri != null) {
                        OutputStream os = resolver.openOutputStream(uri);
                        if (os != null) {
                            os.write(data);
                            os.close();
                            Log.i(TAG, "File saved to Downloads: " + fileName);
                        }
                    }
                } else {
                    // Android 9 及以下，写到 Downloads 目录
                    File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                    if (!downloads.exists()) downloads.mkdirs();
                    File file = new File(downloads, fileName);
                    FileOutputStream fos = new FileOutputStream(file);
                    fos.write(data);
                    fos.close();
                    Log.i(TAG, "File saved: " + file.getAbsolutePath());
                }
            } catch (Exception e) {
                Log.e(TAG, "saveFile error", e);
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != FILE_CHOOSER_REQUEST || filePathCallback == null) {
            return;
        }
        Uri[] results = null;
        try {
            if (resultCode == RESULT_OK) {
                if (data != null && data.getData() != null) {
                    results = new Uri[]{data.getData()};
                } else if (data != null && data.getClipData() != null) {
                    int count = data.getClipData().getItemCount();
                    results = new Uri[count];
                    for (int i = 0; i < count; i++) {
                        results[i] = data.getClipData().getItemAt(i).getUri();
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "onActivityResult error", e);
            results = null;
        }
        try {
            filePathCallback.onReceiveValue(results);
        } catch (Exception e) {
            Log.e(TAG, "callback error", e);
        }
        filePathCallback = null;
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    // 实时跟随系统深浅模式切换（需在 Manifest 声明 android:configChanges="uiMode"）
    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        if (webView != null) {
            applySystemDarkMode(webView);
            injectWindowInsets();
        }
    }

    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }
}
