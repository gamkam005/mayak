package ru.mayak.app;

import android.content.Context;

import java.io.File;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/** Запускает и сторожит Go-ядро МАЯКа (libmayak.so — исполняемый файл). */
final class Core {
    private final Context ctx;
    private volatile boolean running;
    private volatile Process proc;
    private Thread thread;

    Core(Context c) { ctx = c.getApplicationContext(); }

    static File log(Context c) { return new File(c.getFilesDir(), "mayak.log"); }

    List<String> args() {
        String route = Prefs.route(ctx);
        String link = Prefs.link(ctx);
        List<String> a = new ArrayList<>();
        a.add(new File(ctx.getApplicationInfo().nativeLibraryDir, "libmayak.so").getAbsolutePath());
        a.add("client");
        // «только напрямую» — сервер не нужен и не трогается вообще
        if (!"direct".equals(route) && link != null && !link.isEmpty()) { a.add("-link"); a.add(link); }
        a.add("-route"); a.add(route);
        String ds = Prefs.desync(ctx);
        if (!ds.isEmpty()) { a.add("-desync"); a.add(ds); }
        a.add("-listen"); a.add(Prefs.listen(ctx));
        a.add("-ui"); a.add("127.0.0.1:9090");
        a.add("-open=false");
        if (Prefs.debug(ctx)) { a.add("-debug"); a.add("-v"); }
        // запасной вход из бесплатных подписок (свой сервер остаётся основным)
        if (!Prefs.subsFile(ctx).exists()) Prefs.writeSubs(ctx);
        a.add("-subs"); a.add(Prefs.subsMode(ctx));
        a.add("-sub-file"); a.add(Prefs.subsFile(ctx).getAbsolutePath());
        a.add("-sub-state"); a.add(Prefs.subsState(ctx).getAbsolutePath());
        return a;
    }

    boolean canStart() {
        return "direct".equals(Prefs.route(ctx)) || !Prefs.link(ctx).isEmpty() || !"off".equals(Prefs.subsMode(ctx));
    }

    synchronized void start() {
        if (running) return;
        running = true;
        thread = new Thread(new Runnable() { public void run() { loop(); } }, "mayak-core");
        thread.start();
    }

    private void loop() {
        File log = log(ctx);
        while (running) {
            if (!canStart()) { sleep(2000); continue; }
            try {
                ProcessBuilder pb = new ProcessBuilder(args());
                pb.redirectErrorStream(true);
                pb.redirectOutput(ProcessBuilder.Redirect.appendTo(log));
                pb.environment().put("HOME", ctx.getFilesDir().getAbsolutePath());
                proc = pb.start();
                proc.waitFor();
            } catch (Exception e) {
                // упало — перезапуск ниже
            }
            trimLog(ctx);
            if (running) sleep(1500);
        }
    }

    /** Журнал не растёт бесконечно: больше 3 МБ — обнуляем (ядро пишет с O_APPEND). */
    static void trimLog(Context c) {
        File f = log(c);
        if (f.length() > 3L * 1024 * 1024) {
            try (java.io.RandomAccessFile r = new java.io.RandomAccessFile(f, "rw")) { r.setLength(0); } catch (Exception ignored) {}
        }
    }

    /** Ждём, пока SOCKS ядра начнёт принимать соединения. */
    boolean waitReady(long ms) {
        long end = System.currentTimeMillis() + ms;
        String[] hp = Prefs.listen(ctx).split(":");
        int port = Integer.parseInt(hp[1]);
        while (System.currentTimeMillis() < end && running) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", port), 300);
                return true;
            } catch (Exception e) { sleep(150); }
        }
        return false;
    }

    synchronized void stop() {
        running = false;
        Process p = proc;
        if (p != null) p.destroy();
        if (thread != null) thread.interrupt();
        thread = null;
    }

    private static void sleep(long ms) { try { Thread.sleep(ms); } catch (InterruptedException ignored) {} }
}
