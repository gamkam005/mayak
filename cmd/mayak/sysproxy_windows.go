//go:build windows

package main

import (
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const inetKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// consoleUTF8 — чтобы русские сообщения в окне не превращались в кракозябры.
func consoleUTF8() {
	k := syscall.NewLazyDLL("kernel32.dll")
	_, _, _ = k.NewProc("SetConsoleOutputCP").Call(65001)
	_, _, _ = k.NewProc("SetConsoleCP").Call(65001)
}

// refreshProxy — сообщить WinINet (Chrome, Edge, системе), что настройки сменились.
func refreshProxy() {
	w := syscall.NewLazyDLL("wininet.dll").NewProc("InternetSetOptionW")
	_, _, _ = w.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	_, _, _ = w.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
}

// setSystemProxy включает системный прокси на addr и возвращает функцию,
// которая вернёт прежние настройки.
func setSystemProxy(addr string) (func(), error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	prevEnable, _, errE := k.GetIntegerValue("ProxyEnable")
	prevServer, _, errS := k.GetStringValue("ProxyServer")
	prevOverride, _, errO := k.GetStringValue("ProxyOverride")
	if prevServer == addr { // остался от прошлого запуска, который не успел убрать за собой
		prevEnable = 0
	}
	if err := k.SetStringValue("ProxyServer", addr); err != nil {
		k.Close()
		return nil, err
	}
	_ = k.SetStringValue("ProxyOverride", "localhost;127.*;10.*;172.16.*;192.168.*;<local>")
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		k.Close()
		return nil, err
	}
	refreshProxy()
	return func() {
		defer k.Close()
		if errE == nil {
			_ = k.SetDWordValue("ProxyEnable", uint32(prevEnable))
		} else {
			_ = k.SetDWordValue("ProxyEnable", 0)
		}
		if errS == nil && prevServer != addr {
			_ = k.SetStringValue("ProxyServer", prevServer)
		}
		if errO == nil {
			_ = k.SetStringValue("ProxyOverride", prevOverride)
		}
		refreshProxy()
	}, nil
}
