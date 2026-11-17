package ru.mayak.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

/** Режим «только прокси»: ядро поднимает SOCKS5/HTTP 127.0.0.1:1080 (как в 0.1, для v2rayNG/NekoBox). */
public class MayakService extends Service {
    static final String CH = "mayak";
    static volatile boolean running = false;
    private Core core;
    private PowerManager.WakeLock wl;

    @Override public IBinder onBind(Intent i) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "stop".equals(intent.getAction())) { stopAll(); stopSelf(); return START_NOT_STICKY; }
        startFg();
        if (!running) {
            running = true;
            core = new Core(this);
            core.start();
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "mayak:tunnel");
            wl.acquire();
        }
        return START_STICKY;
    }

    private void startFg() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26) nm.createNotificationChannel(new NotificationChannel(CH, "Туннель", NotificationManager.IMPORTANCE_LOW));
        int fl = Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0;
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), fl);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, MayakService.class).setAction("stop"), fl);
        Notification.Builder b = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CH) : new Notification.Builder(this);
        Notification n = b.setContentTitle("МАЯК работает")
                .setContentText("Прокси SOCKS5/HTTP " + Prefs.listen(this) + " · " + Prefs.routeLabel(this))
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(open)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Остановить", stop)
                .setOngoing(true).build();
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(1, n);
    }

    private void stopAll() {
        running = false;
        if (core != null) core.stop();
        if (wl != null && wl.isHeld()) wl.release();
    }

    @Override public void onDestroy() { stopAll(); super.onDestroy(); }
}
