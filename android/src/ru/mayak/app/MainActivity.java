package ru.mayak.app;

import android.Manifest;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import java.io.File;
import java.io.RandomAccessFile;

/** Экран: настройка ссылки и запуск; затем — веб-панель клиента. */
public class MainActivity extends Activity {
    private WebView web;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        web = new WebView(this);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        web.setWebViewClient(new WebViewClient() {
            // панель ещё не поднялась / ядро упало — возвращаемся на главный экран
            @Override public void onReceivedError(WebView v, int code, String desc, String url) {
                if (url != null && url.startsWith("http://127.0.0.1")) {
                    Toast.makeText(MainActivity.this, "Панель недоступна: " + desc, Toast.LENGTH_SHORT).show();
                    v.loadUrl("file:///android_asset/home.html");
                }
            }
        });
        web.setWebChromeClient(new WebChromeClient());
        web.addJavascriptInterface(new Bridge(), "Mayak");
        setContentView(web);
        handleIntent(getIntent());
        web.loadUrl("file:///android_asset/home.html");
    }

    @Override protected void onNewIntent(Intent i) { super.onNewIntent(i); handleIntent(i); web.loadUrl("file:///android_asset/home.html"); }

    private void handleIntent(Intent i) {
        Uri u = i == null ? null : i.getData();
        if (u != null && "mayak".equals(u.getScheme())) {
            Prefs.setLink(this, u.toString());
            Toast.makeText(this, "Ссылка сохранена", Toast.LENGTH_SHORT).show();
        }
    }

    private static final int REQ_VPN = 7;

    /** Запуск по выбранному режиму; для VPN сначала спрашиваем разрешение системы. */
    void startSelected() {
        if ("vpn".equals(Prefs.mode(this))) {
            Intent ask = VpnService.prepare(this);
            if (ask != null) { startActivityForResult(ask, REQ_VPN); return; }
            launch(MayakVpn.class);
        } else {
            launch(MayakService.class);
        }
    }

    private void launch(Class<?> cls) {
        Intent it = new Intent(this, cls);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(it); else startService(it);
    }

    @Override protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == REQ_VPN) {
            if (res == RESULT_OK) launch(MayakVpn.class);
            else Toast.makeText(this, "Без разрешения VPN не включить", Toast.LENGTH_LONG).show();
        }
    }

    static String tail(File f, int max) {
        try (RandomAccessFile r = new RandomAccessFile(f, "r")) {
            long len = r.length(), from = Math.max(0, len - max);
            byte[] b = new byte[(int) (len - from)];
            r.seek(from);
            r.readFully(b);
            String s = new String(b, "UTF-8");
            // секрет ссылки в журнал не попадает, но на всякий случай маскируем
            return s.replaceAll("mayak://[^@\\s]+@", "mayak://***@").replaceAll("(?i)(secret|password|pass|key|token)=[^&\\s]+", "$1=***")
                    .replaceAll("(vless|vmess|trojan|ss|hysteria2|hy2)://[^@\\s]{6,}@", "$1://***@");
        } catch (Exception e) { return ""; }
    }

    @Override public void onBackPressed() { if (web.canGoBack()) web.goBack(); else super.onBackPressed(); }

    final class Bridge {
        @JavascriptInterface public String version() { return BuildConfigInfo.version(MainActivity.this); }
        /** Проверка обновления; ответ — в JS onUpdate(json, manual). Автопроверка — не чаще раза в 6 ч. */
        @JavascriptInterface public void checkUpdate(final boolean manual) {
            new Thread(new Runnable() { public void run() {
                String j = manual ? null : Updater.cached(MainActivity.this);
                if (j == null) j = Updater.run(MainActivity.this, false);
                js("onUpdate(" + org.json.JSONObject.quote(j) + "," + manual + ")");
            } }).start();
        }
        /** Скачать, проверить и отдать системе на установку. Состояние — в JS onUpdState(text). */
        @JavascriptInterface public void installUpdate() {
            if (Build.VERSION.SDK_INT >= 26 && !getPackageManager().canRequestPackageInstalls()) {
                runOnUiThread(new Runnable() { public void run() {
                    Toast.makeText(MainActivity.this, "Разрешите МАЯКу установку приложений и нажмите «Обновить» ещё раз", Toast.LENGTH_LONG).show();
                    try {
                        startActivity(new Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + getPackageName())));
                    } catch (Exception e) {
                        startActivity(new Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS));
                    }
                } });
                return;
            }
            js("onUpdState('Скачиваю и проверяю…')");
            new Thread(new Runnable() { public void run() {
                String j = Updater.run(MainActivity.this, true);
                String err = null;
                try {
                    org.json.JSONObject o = new org.json.JSONObject(j);
                    if (o.has("error")) err = o.getString("error");
                    else if (!o.optBoolean("newer")) err = "новее нет";
                } catch (Exception e) { err = "ответ не разобран"; }
                File f = Updater.apk(MainActivity.this);
                if (err == null) {
                    android.content.pm.PackageInfo pi = getPackageManager().getPackageArchiveInfo(f.getAbsolutePath(), 0);
                    if (pi == null || !getPackageName().equals(pi.packageName)) err = "скачанный файл — не МАЯК";
                }
                if (err != null) {
                    f.delete();
                    js("onUpdState(" + org.json.JSONObject.quote("Не удалось обновить: " + err) + ")");
                    return;
                }
                js("onUpdState('Скачано и проверено — подтвердите установку')");
                runOnUiThread(new Runnable() { public void run() {
                    Intent i = new Intent(Intent.ACTION_VIEW).setDataAndType(ApkProvider.URI, "application/vnd.android.package-archive")
                            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
                    try { startActivity(i); } catch (Exception e) { Toast.makeText(MainActivity.this, "Нет системного установщика: " + e.getMessage(), Toast.LENGTH_LONG).show(); }
                } });
            } }).start();
        }
        private void js(final String code) { runOnUiThread(new Runnable() { public void run() { web.evaluateJavascript(code, null); } }); }
        @JavascriptInterface public String link() { return Prefs.link(MainActivity.this); }
        @JavascriptInterface public boolean running() { return MayakService.running || MayakVpn.running; }
        @JavascriptInterface public boolean vpnRunning() { return MayakVpn.running; }
        @JavascriptInterface public String state() { return MayakVpn.running ? MayakVpn.state : (MayakService.running ? "прокси работает" : "остановлен"); }
        @JavascriptInterface public String mode() { return Prefs.mode(MainActivity.this); }
        @JavascriptInterface public void setMode(String m) { Prefs.setMode(MainActivity.this, m); }
        @JavascriptInterface public String route() { return Prefs.route(MainActivity.this); }
        @JavascriptInterface public void setRoute(String r) { Prefs.setRoute(MainActivity.this, r); }
        @JavascriptInterface public String desync() { return Prefs.desync(MainActivity.this); }
        @JavascriptInterface public void setDesync(String d) {
            Prefs.setDesync(MainActivity.this, d);
            // на лету, без переподключения
            String list = d.trim().isEmpty() ? "tlsrec+split,tlsrec+disorder,tlsrec+fake,oob" : d.trim();
            try { post("/api/desync?list=" + java.net.URLEncoder.encode(list, "UTF-8")); } catch (Exception ignored) {}
        }
        @JavascriptInterface public String subsMode() { return Prefs.subsMode(MainActivity.this); }
        @JavascriptInterface public void setSubsMode(String m) { Prefs.setSubsMode(MainActivity.this, m); post("/api/subs/mode?m=" + Prefs.subsMode(MainActivity.this)); }
        @JavascriptInterface public String subsCfg() { return Prefs.subsCfg(MainActivity.this); }
        @JavascriptInterface public void setSubsCfg(String json) { Prefs.setSubsCfg(MainActivity.this, json); post("/api/subs/reload"); }
        /** Короткое сообщение внизу экрана (вместо окна alert с заголовком file://). */
        @JavascriptInterface public void toast(final String msg) {
            runOnUiThread(new Runnable() { public void run() { Toast.makeText(MainActivity.this, msg, Toast.LENGTH_SHORT).show(); } });
        }
        /** POST к ядру в фоне; ответ отдаётся в JS-функцию cb(text). */
        @JavascriptInterface public void apiPost(final String path, final String cb) {
            new Thread(new Runnable() { public void run() {
                String body = "";
                try {
                    java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL("http://127.0.0.1:9090" + path).openConnection();
                    c.setRequestMethod("POST"); c.setConnectTimeout(1000); c.setReadTimeout(30000);
                    java.io.InputStream in = c.getInputStream();
                    java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
                    byte[] b = new byte[8192]; int n;
                    while ((n = in.read(b)) > 0) o.write(b, 0, n);
                    in.close(); c.disconnect();
                    body = o.toString("UTF-8");
                } catch (Exception e) { body = ""; }
                final String js = cb + "(" + org.json.JSONObject.quote(body) + ")";
                runOnUiThread(new Runnable() { public void run() { web.evaluateJavascript(js, null); } });
            } }).start();
        }
        @JavascriptInterface public String bypass() { return Prefs.bypass(MainActivity.this); }
        @JavascriptInterface public void setBypass(String d) { Prefs.setBypass(MainActivity.this, d); }
        private void post(String path) {
            try {
                java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL("http://127.0.0.1:9090" + path).openConnection();
                c.setRequestMethod("POST"); c.setConnectTimeout(700); c.setReadTimeout(1500);
                c.getResponseCode(); c.disconnect();
            } catch (Exception ignored) {}
        }
        /** GET к локальной панели ядра (без CORS и без доступа сайтов из браузера). */
        @JavascriptInterface public String api(String path) {
            try {
                java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL("http://127.0.0.1:9090" + path).openConnection();
                c.setConnectTimeout(700); c.setReadTimeout(3000);
                java.io.InputStream in = c.getInputStream();
                java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
                byte[] b = new byte[8192]; int n;
                while ((n = in.read(b)) > 0) o.write(b, 0, n);
                in.close(); c.disconnect();
                return o.toString("UTF-8");
            } catch (Exception e) { return ""; }
        }
        @JavascriptInterface public String log() { Core.trimLog(MainActivity.this); return tail(Core.log(MainActivity.this), 20000); }
        @JavascriptInterface public boolean debug() { return Prefs.debug(MainActivity.this); }
        @JavascriptInterface public void setDebug(boolean on) {
            Prefs.setDebug(MainActivity.this, on);
            post("/api/debug?on=" + (on ? "1" : "0")); // на лету, без переподключения
        }
        @JavascriptInterface public void clearLog() {
            try (RandomAccessFile r = new RandomAccessFile(Core.log(MainActivity.this), "rw")) { r.setLength(0); } catch (Exception ignored) {}
        }
        @JavascriptInterface public void shareLog() {
            final String text = "МАЯК " + BuildConfigInfo.version(MainActivity.this) + ", Android " + Build.VERSION.RELEASE + " (" + Build.MODEL + ")\n"
                    + "режим " + Prefs.mode(MainActivity.this) + ", маршрут " + Prefs.route(MainActivity.this) + ", подписки " + Prefs.subsMode(MainActivity.this)
                    + ", приёмы " + (Prefs.desync(MainActivity.this).isEmpty() ? "по умолчанию" : Prefs.desync(MainActivity.this)) + "\n\n"
                    + tail(Core.log(MainActivity.this), 150000);
            runOnUiThread(new Runnable() { public void run() {
                Intent i = new Intent(Intent.ACTION_SEND).setType("text/plain")
                        .putExtra(Intent.EXTRA_SUBJECT, "Журнал МАЯК")
                        .putExtra(Intent.EXTRA_TEXT, text);
                startActivity(Intent.createChooser(i, "Отправить журнал"));
            } });
        }
        @JavascriptInterface public void copyLog() { copy(tail(Core.log(MainActivity.this), 150000)); }
        @JavascriptInterface public String apps() { return AppList.json(MainActivity.this); }
        @JavascriptInterface public String icon(String pkg) { return AppList.icon(MainActivity.this, pkg); }
        @JavascriptInterface public void home() { runOnUiThread(new Runnable() { public void run() { web.loadUrl("file:///android_asset/home.html"); } }); }
        @JavascriptInterface public boolean lan() { return Prefs.lan(MainActivity.this); }
        @JavascriptInterface public void setLan(boolean v) { Prefs.setLan(MainActivity.this, v); }
        @JavascriptInterface public void save(String l) { Prefs.setLink(MainActivity.this, l.trim()); }
        @JavascriptInterface public void start() { runOnUiThread(new Runnable() { public void run() { startSelected(); } }); }
        @JavascriptInterface public void stop() {
            if (MayakVpn.running) startService(new Intent(MainActivity.this, MayakVpn.class).setAction("stop"));
            if (MayakService.running) startService(new Intent(MainActivity.this, MayakService.class).setAction("stop"));
        }
        @JavascriptInterface public void copy(String t) {
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("mayak", t));
            runOnUiThread(new Runnable() { public void run() { Toast.makeText(MainActivity.this, "Скопировано", Toast.LENGTH_SHORT).show(); } });
        }
        @JavascriptInterface public String paste() {
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            ClipData d = cm.getPrimaryClip();
            return d != null && d.getItemCount() > 0 && d.getItemAt(0).getText() != null ? d.getItemAt(0).getText().toString() : "";
        }
        @JavascriptInterface public void dashboard() {
            if (!(MayakService.running || MayakVpn.running)) {
                runOnUiThread(new Runnable() { public void run() { Toast.makeText(MainActivity.this, "Панель доступна, когда МАЯК подключён", Toast.LENGTH_SHORT).show(); } });
                return;
            }
            runOnUiThread(new Runnable() { public void run() { web.loadUrl("http://127.0.0.1:9090/"); } });
        }
    }
}
