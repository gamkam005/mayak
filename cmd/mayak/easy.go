package main

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"mayak/internal/route"
)

// defaultDesync — на Windows без прав администратора работают только
// перекройка TLS-записей и TCP-разрез (TTL/OOB/MD5 там не выставить).
func defaultDesync() string {
	if runtime.GOOS == "windows" {
		return "tlsrec+split,tlsrec:at=sniext+split,multirec+split,split:at=mid"
	}
	return route.DefaultStrategies
}

// besideExe — путь к файлу рядом с программой.
func besideExe(name string) string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), name)
	}
	return name
}

// proxyHostPort — адрес для системного прокси: слушаем «на всех» — подставим 127.0.0.1.
func proxyHostPort(a net.Addr) string {
	if t, ok := a.(*net.TCPAddr); ok && (t.IP == nil || t.IP.IsUnspecified()) {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(t.Port))
	}
	return a.String()
}
