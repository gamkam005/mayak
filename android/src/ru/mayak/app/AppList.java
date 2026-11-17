package ru.mayak.app;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Список установленных приложений для выбора «мимо VPN» (иконки — data:URL). */
final class AppList {
    private static final Map<String, String> icons = new HashMap<>();

    static String json(Context c) {
        PackageManager pm = c.getPackageManager();
        Set<String> launchable = new HashSet<>();
        Intent main = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        for (android.content.pm.ResolveInfo ri : pm.queryIntentActivities(main, 0)) launchable.add(ri.activityInfo.packageName);
        List<ApplicationInfo> list = new ArrayList<>(pm.getInstalledApplications(0));
        final Map<String, String> labels = new HashMap<>();
        for (ApplicationInfo a : list) labels.put(a.packageName, String.valueOf(pm.getApplicationLabel(a)));
        Collections.sort(list, new Comparator<ApplicationInfo>() {
            public int compare(ApplicationInfo x, ApplicationInfo y) { return labels.get(x.packageName).compareToIgnoreCase(labels.get(y.packageName)); }
        });
        JSONArray out = new JSONArray();
        try {
            for (ApplicationInfo a : list) {
                if (a.packageName.equals(c.getPackageName())) continue;
                boolean sys = (a.flags & ApplicationInfo.FLAG_SYSTEM) != 0 && (a.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0;
                JSONObject o = new JSONObject();
                o.put("pkg", a.packageName);
                o.put("name", labels.get(a.packageName));
                o.put("sys", sys && !launchable.contains(a.packageName));
                o.put("net", pm.checkPermission(android.Manifest.permission.INTERNET, a.packageName) == PackageManager.PERMISSION_GRANTED);
                out.put(o);
            }
        } catch (Exception ignored) {}
        return out.toString();
    }

    static synchronized String icon(Context c, String pkg) {
        String s = icons.get(pkg);
        if (s != null) return s;
        try {
            Drawable d = c.getPackageManager().getApplicationIcon(pkg);
            int n = 72;
            Bitmap b = Bitmap.createBitmap(n, n, Bitmap.Config.ARGB_8888);
            Canvas cv = new Canvas(b);
            d.setBounds(0, 0, n, n);
            d.draw(cv);
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            b.compress(Bitmap.CompressFormat.PNG, 100, o);
            s = "data:image/png;base64," + Base64.encodeToString(o.toByteArray(), Base64.NO_WRAP);
        } catch (Exception e) { s = ""; }
        icons.put(pkg, s);
        return s;
    }
}
