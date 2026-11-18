package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSniffTLS(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		_ = tls.Client(a, &tls.Config{ServerName: "example.org"}).Handshake()
	}()
	br := bufio.NewReaderSize(b, 16*1024+5)
	got, err := sniffTarget(br)
	if err != nil || got != "example.org:443" {
		t.Fatalf("got %q %v", got, err)
	}
	if first, _ := br.Peek(1); first[0] != 0x16 {
		t.Fatal("stream consumed")
	}
	_ = a.Close()
	_ = b.Close()
}

func TestSniffHTTP(t *testing.T) {
	for in, want := range map[string]string{
		"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nAccept: */*\r\n\r\n": "api.ipify.org:80",
		"GET /x HTTP/1.1\r\nhost: a.b:8080\r\n\r\n":                    "a.b:8080",
		"POST / HTTP/1.0\r\nX: y\r\n\r\n":                              "",
		"garbage\r\n\r\n":                                              "",
	} {
		got, _ := sniffTarget(bufio.NewReader(strings.NewReader(in)))
		if got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestServeRedirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 1)
	go func() {
		_ = ServeRedirect(ctx, ln, func(c net.Conn, target string) {
			b, _ := io.ReadAll(io.LimitReader(c, 3))
			got <- target + "|" + string(b)
			_ = c.Close()
		})
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x.test\r\n\r\n"))
	select {
	case s := <-got:
		if s != "x.test:80|GET" {
			t.Fatalf("got %q", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}
