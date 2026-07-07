package cc.valk.pass2kdbx;

import android.app.Activity;
import android.app.WallpaperManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.os.Build;
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
        webView = new WebView(this);
        setContentView(webView);

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

    // 将取到的主色扩展为一组 Material 变量并注入前端
    private void injectColor(int argb) {
        int r = Color.red(argb), g = Color.green(argb), b = Color.blue(argb);
        // 提亮/降暗派生 hover 与 glow
        int hover = lighten(argb, 0.12f);
        int glowR = r, glowG = g, glowB = b;
        // container：主色 + 透明度混合到深色背景（前端用 rgba，这里给出带 alpha 的 hex）
        String accent = String.format("#%02x%02x%02x", r, g, b);
        String accentHover = String.format("#%02x%02x%02x", Color.red(hover), Color.green(hover), Color.blue(hover));
        String glow = String.format("rgba(%d, %d, %d, 0.32)", r, g, b);
        String js = String.format(
            "if (window.Pass2KDBXDynamic && window.Pass2KDBXDynamic.apply) {"
            + " window.Pass2KDBXDynamic.apply({accent:'%s', accentHover:'%s', accentGlow:'%s'}); }",
            accent, accentHover, glow);
        webView.evaluateJavascript(js, null);
        Log.i(TAG, "Dynamic color injected: " + accent);
    }

    // 提亮颜色（向白色混合）
    private static int lighten(int color, float factor) {
        int r = Color.red(color), g = Color.green(color), b = Color.blue(color);
        r = (int) (r + (255 - r) * factor);
        g = (int) (g + (255 - g) * factor);
        b = (int) (b + (255 - b) * factor);
        return Color.argb(255, r, g, b);
    }

    // 同步系统深浅模式给前端（仅提示，前端自行决定是否跟随）
    private void applySystemDarkMode(WebView view) {
        int nightMode = getResources().getConfiguration().uiMode
                & android.content.res.Configuration.UI_MODE_NIGHT_MASK;
        boolean isDark = nightMode == android.content.res.Configuration.UI_MODE_NIGHT_YES;
        String js = "if (window.Pass2KDBXDynamic && window.Pass2KDBXDynamic.setSystemDark) {"
                + " window.Pass2KDBXDynamic.setSystemDark(" + (isDark ? "true" : "false") + "); }";
        view.evaluateJavascript(js, null);
    }
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

    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }
}
