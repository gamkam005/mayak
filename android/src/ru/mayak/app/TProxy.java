package ru.mayak.app;

/** JNI к hev-socks5-tunnel (MIT, github.com/heiher/hev-socks5-tunnel): tun → SOCKS5. */
final class TProxy {
    static { System.loadLibrary("hev-socks5-tunnel"); }
    static native boolean TProxyStartService(String configPath, int fd);
    static native boolean TProxyStopService();
    static native boolean TProxyIsRunning();
    static native long[] TProxyGetStats();
}
