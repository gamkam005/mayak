package ru.mayak.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;

import java.io.File;
import java.io.FileOutputStream;

/**
 * VPN-режим: весь трафик телефона → tun → hev-socks5-tunnel → SOCKS5 ядра
 * (127.0.0.1:1080) → маршрутизатор ядра: напрямую с обманом DPI или туннель.
 * Само приложение (и ядро, у него тот же UID) исключено из VPN — без петли.
 */
public class MayakVpn extends VpnService {
    static final String CH = "mayak";
    static volatile boolean running = false;
    static volatile String state = "остановлен";
    static final String MAPDNS = "198.18.0.2";

    private Core core;
    private ParcelFileDescriptor tun;
    private Thread starter;
    private PowerManager.WakeLock wl;

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "stop".equals(intent.getAction())) { stopAll(); stopSelf(); return START_NOT_STICKY; }
        startFg();
        if (!running) {
            running = true;
            state = "запускается…";
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "mayak:vpn");
            wl.acquire();
            starter = new Thread(new Runnable() { public void run() { bringUp(); } }, "mayak-vpn");
            starter.start();
        }
        return START_STICKY;
    }

    private void bringUp() {
        core = new Core(this);
        core.start();
        if (!core.waitReady(10000)) { state = "ядро не запустилось — см. журнал"; return; }
        try {
            Builder b = new Builder()
                    .setSession("МАЯК")
                    .setMtu(8500)
                    .addAddress("10.111.0.1", 32)
                    .addRoute("0.0.0.0", 0)
                    .addAddress("fd00:6d61:796b::1", 128)
                    .addRoute("::", 0)
                    .addDnsServer(MAPDNS);
            b.addDisallowedApplication(getPackageName());
            for (String pkg : Prefs.bypassApps(this)) {
                try { b.addDisallowedApplication(pkg); } catch (Exception ignored) {}
            }
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
            int fl = Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0;
            b.setConfigureIntent(PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), fl));
            tun = b.establish();
            if (tun == null) { state = "нет разрешения на VPN"; return; }
            File cfg = new File(getFilesDir(), "tun2socks.yml");
            String port = Prefs.listen(this).split(":")[1];
            String y = "tunnel:\n  mtu: 8500\n"
                    + "socks5:\n  address: 127.0.0.1\n  port: " + port + "\n  udp: 'udp'\n"
                    + "mapdns:\n  address: " + MAPDNS + "\n  port: 53\n  network: 100.64.0.0\n  netmask: 255.192.0.0\n  cache-size: 10000\n"
                    + "misc:\n  task-stack-size: 81920\n  connect-timeout: 15000\n  log-level: warn\n"
                    + "  log-file: " + new File(getFilesDir(), "tun2socks.log").getAbsolutePath() + "\n";
            try (FileOutputStream o = new FileOutputStream(cfg)) { o.write(y.getBytes("UTF-8")); }
            TProxy.TProxyStartService(cfg.getAbsolutePath(), tun.getFd());
            state = "VPN работает · маршрут " + Prefs.route(this);
        } catch (Throwable e) {
            state = "ошибка VPN: " + e;
        }
    }

    private void startFg() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26) nm.createNotificationChannel(new NotificationChannel(CH, "Туннель", NotificationManager.IMPORTANCE_LOW));
        int fl = Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0;
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), fl);
        PendingIntent stop = PendingIntent.getService(this, 2, new Intent(this, MayakVpn.class).setAction("stop"), fl);
        Notification.Builder b = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CH) : new Notification.Builder(this);
        Notification n = b.setContentTitle("МАЯК: VPN включён")
                .setContentText("Маршрут: " + Prefs.routeLabel(this))
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(open)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Отключить", stop)
                .setOngoing(true).build();
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(1, n);
    }

    private synchronized void stopAll() {
        if (!running) return;
        running = false;
        state = "остановлен";
        try { TProxy.TProxyStopService(); } catch (Throwable ignored) {}
        if (tun != null) { try { tun.close(); } catch (Exception ignored) {} tun = null; }
        if (core != null) core.stop();
        if (starter != null) starter.interrupt();
        if (wl != null && wl.isHeld()) wl.release();
    }

    @Override public void onRevoke() { stopAll(); stopSelf(); }
    @Override public void onDestroy() { stopAll(); super.onDestroy(); }
}
