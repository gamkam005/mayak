package ru.mayak.app;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Обновление приложения из GitHub: проверку, скачивание и проверку подписи
 * SHA256SUMS (ed25519) и SHA-256 делает Go-ядро (libmayak.so update …);
 * ставит APK системный установщик — подтверждает пользователь.
 */
final class Updater {
    static final String ASSET = "MAYAK-vpn-*.apk";
    static final long EVERY = 6L * 3600 * 1000;

    static File apk(Context c) {
        File d = new File(c.getCacheDir(), "update");
        d.mkdirs();
        return new File(d, "MAYAK-update.apk");
    }

    private static SharedPreferences sp(Context c) { return c.getSharedPreferences("update", 0); }

    /** Кэш последней проверки, если она была недавно; иначе null. */
    static String cached(Context c) {
        SharedPreferences p = sp(c);
        if (System.currentTimeMillis() - p.getLong("at", 0) > EVERY) return null;
        String j = p.getString("json", null);
        return j != null && j.contains("\"current\":\"" + BuildConfigInfo.version(c) + "\"") ? j : null;
    }

    /** Проверить (download=false) или скачать (download=true). Возвращает JSON ядра. */
    static String run(Context c, boolean download) {
        List<String> a = new ArrayList<>();
        a.add(new File(c.getApplicationInfo().nativeLibraryDir, "libmayak.so").getAbsolutePath());
        a.add("update"); a.add("-json");
        a.add("-asset"); a.add(ASSET);
        a.add("-current"); a.add(BuildConfigInfo.version(c));
        if (MayakService.running || MayakVpn.running) {
            // GitHub напрямую не открывается — пусть идёт через сам МАЯК
            String l = Prefs.listen(c);
            a.add("-proxy"); a.add("http://127.0.0.1:" + l.substring(l.lastIndexOf(':') + 1));
        }
        if (download) { File f = apk(c); f.delete(); a.add("-out"); a.add(f.getAbsolutePath()); } else a.add("-check");
        String out;
        try {
            ProcessBuilder pb = new ProcessBuilder(a);
            pb.redirectErrorStream(false);
            pb.redirectError(ProcessBuilder.Redirect.appendTo(Core.log(c)));
            pb.environment().put("HOME", c.getFilesDir().getAbsolutePath());
            Process p = pb.start();
            InputStream in = p.getInputStream();
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            byte[] b = new byte[4096]; int n;
            while ((n = in.read(b)) > 0) o.write(b, 0, n);
            p.waitFor();
            out = o.toString("UTF-8").trim();
            int i = out.lastIndexOf('\n');
            if (i >= 0) out = out.substring(i + 1);
            if (!out.startsWith("{")) out = "{\"error\":\"нет ответа от ядра\"}";
        } catch (Exception e) {
            out = "{\"error\":" + org.json.JSONObject.quote(String.valueOf(e.getMessage())) + "}";
        }
        if (!download && !out.contains("\"error\"")) sp(c).edit().putLong("at", System.currentTimeMillis()).putString("json", out).apply();
        return out;
    }
}
