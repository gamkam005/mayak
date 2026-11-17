package ru.mayak.app;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.List;

final class Prefs {
    private static SharedPreferences p(Context c) { return c.getSharedPreferences("mayak", Context.MODE_PRIVATE); }
    static String link(Context c) { return p(c).getString("link", ""); }
    static void setLink(Context c, String l) { p(c).edit().putString("link", l).apply(); }
    static boolean lan(Context c) { return p(c).getBoolean("lan", false); }
    static void setLan(Context c, boolean v) { p(c).edit().putBoolean("lan", v).apply(); }
    static String listen(Context c) { return lan(c) ? "0.0.0.0:1080" : "127.0.0.1:1080"; }
    /** vpn | proxy */
    static String mode(Context c) { return p(c).getString("mode", "vpn"); }
    static void setMode(Context c, String m) { p(c).edit().putString("mode", "proxy".equals(m) ? "proxy" : "vpn").apply(); }
    /** auto | direct | tunnel */
    static String route(Context c) { return p(c).getString("route", "auto"); }
    static void setRoute(Context c, String r) {
        if (!"direct".equals(r) && !"tunnel".equals(r)) r = "auto";
        p(c).edit().putString("route", r).apply();
    }
    static String routeLabel(Context c) {
        String r = route(c);
        return "direct".equals(r) ? "только напрямую" : "tunnel".equals(r) ? "только туннель" : "авто";
    }
    /** Диагностический журнал (подробно: решения маршрутизатора, приёмы, тайминги). */
    static boolean debug(Context c) { return p(c).getBoolean("debug", false); }
    static void setDebug(Context c, boolean v) { p(c).edit().putBoolean("debug", v).apply(); }
    static String desync(Context c) { return p(c).getString("desync", ""); }
    static void setDesync(Context c, String d) { p(c).edit().putString("desync", d.trim()).apply(); }
    /** Запасной вход из подписок: off | reserve (если сервер МАЯК недоступен) | always. */
    static String subsMode(Context c) { return p(c).getString("subsMode", "reserve"); }
    static void setSubsMode(Context c, String m) {
        if (!"off".equals(m) && !"always".equals(m)) m = "reserve";
        p(c).edit().putString("subsMode", m).apply();
        writeSubs(c);
    }
    /** JSON {"disabled":[id…],"urls":[…],"links":"…"} — хранится только на телефоне. */
    static String subsCfg(Context c) { return p(c).getString("subsCfg", "{}"); }
    static void setSubsCfg(Context c, String json) { p(c).edit().putString("subsCfg", json).apply(); writeSubs(c); }
    static java.io.File subsFile(Context c) { return new java.io.File(c.getFilesDir(), "subs.json"); }
    static java.io.File subsState(Context c) { return new java.io.File(c.getFilesDir(), "subs"); }
    /** Файл для ядра (оно перечитывает его по /api/subs/reload). */
    static void writeSubs(Context c) {
        try {
            org.json.JSONObject o = new org.json.JSONObject(subsCfg(c));
            o.put("mode", subsMode(c));
            java.io.File f = subsFile(c), t = new java.io.File(f.getPath() + ".tmp");
            try (java.io.FileOutputStream w = new java.io.FileOutputStream(t)) { w.write(o.toString().getBytes("UTF-8")); }
            t.renameTo(f);
        } catch (Exception ignored) {}
    }
    /** Приложения мимо VPN, через запятую (имена пакетов). */
    static String bypass(Context c) { return p(c).getString("bypass", ""); }
    static void setBypass(Context c, String s) { p(c).edit().putString("bypass", s.trim()).apply(); }
    static List<String> bypassApps(Context c) {
        List<String> out = new ArrayList<>();
        for (String s : bypass(c).split("[,\\s]+")) if (!s.isEmpty()) out.add(s);
        return out;
    }
}
