package main

import (
	"net"
	"testing"

	"mayak/internal/desync"
)

func TestDefaultDesyncParses(t *testing.T) {
	if _, err := desync.ParseList(defaultDesync()); err != nil {
		t.Fatal(err)
	}
	if _, err := desync.ParseList("tlsrec+split,tlsrec:at=sniext+split,multirec+split,split:at=mid"); err != nil {
		t.Fatal(err)
	}
}

func TestProxyHostPort(t *testing.T) {
	for in, want := range map[string]string{"0.0.0.0:1080": "127.0.0.1:1080", "[::]:1081": "127.0.0.1:1081", "127.0.0.1:1080": "127.0.0.1:1080"} {
		a, _ := net.ResolveTCPAddr("tcp", in)
		if got := proxyHostPort(a); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestPlaceholderLinkIgnored(t *testing.T) {
	if l := firstLink("Вставьте сюда одной строкой ссылку mayak://... от сервера\r\n"); l != "" {
		t.Fatalf("placeholder taken as link: %q", l)
	}
	if l := firstLink("\ufeffmayak://k@h:443?x=1 \r\n"); l != "mayak://k@h:443?x=1" {
		t.Fatalf("got %q", l)
	}
}
