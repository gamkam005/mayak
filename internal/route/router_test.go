package route

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"mayak/internal/desync"
)

// recordLog — прослойка перед TLS-сервером: пишет размеры входящих TLS-записей.
type recordLog struct {
	mu      sync.Mutex
	records []int
}

func (rl *recordLog) add(n int) { rl.mu.Lock(); rl.records = append(rl.records, n); rl.mu.Unlock() }

// dpi — простейший «ТСПУ»: собирает ПЕРВУЮ TLS-запись и, если в ней
// целиком видно запрещённое имя, перестаёт пересылать ответ (как глушение).
func dpi(t *testing.T, to string, banned string, rl *recordLog) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				s, err := net.Dial("tcp", to)
				if err != nil {
					return
				}
				defer s.Close()
				var hdr [5]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				if rl != nil {
					rl.add(len(body))
				}
				blocked := false
				if h, err := desync.ParseHello(append(hdr[:], body...)); err == nil && h.SNI == banned {
					blocked = true
				}
				s.Write(hdr[:])
				s.Write(body)
				go io.Copy(s, c)
				if blocked {
					io.Copy(io.Discard, s) // ответ сервера «теряется»
					return
				}
				// остальные записи тоже залогируем
				io.Copy(c, s)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func tlsServer(t *testing.T) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from "+r.Host)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// socksPair — «приложение» ↔ Router: отдаём роутеру серверный конец пайпа.
func runThrough(t *testing.T, r *Router, target, sni string) (string, error) {
	a, b := net.Pipe()
	go r.Handle(b, target)
	cl := tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	defer cl.Close()
	_ = cl.SetDeadline(time.Now().Add(15 * time.Second))
	if err := cl.Handshake(); err != nil {
		return "", err
	}
	io.WriteString(cl, "GET / HTTP/1.1\r\nHost: "+sni+"\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufioReader(cl), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func lookupTo(addr string) func(context.Context, string) ([]net.IP, error) {
	h, _, _ := net.SplitHostPort(addr)
	return func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP(h)}, nil }
}

func TestDirectTLSRecSplitBypassesDPI(t *testing.T) {
	srv := tlsServer(t)
	rl := &recordLog{}
	front := dpi(t, srv.Listener.Addr().String(), "blocked.example", rl)
	_, port, _ := net.SplitHostPort(front)
	sts, _ := desync.ParseList("tlsrec+split")
	r := New(Config{Mode: ModeDirect, Strategies: sts, Lookup: lookupTo(front), Timeout: 2 * time.Second})
	body, err := runThrough(t, r, "blocked.example:"+port, "blocked.example")
	if err != nil {
		t.Fatalf("direct with tlsrec failed: %v", err)
	}
	if !strings.Contains(body, "hello from blocked.example") {
		t.Fatalf("body %q", body)
	}
	if len(rl.records) == 0 || rl.records[0] > 300 {
		t.Fatalf("first record not split: %v", rl.records)
	}
	t.Logf("first TLS record seen by DPI: %d bytes (split inside SNI)", rl.records[0])
}

func TestNoDesyncIsBlockedAndAutoFallsBackToTunnel(t *testing.T) {
	srv := tlsServer(t)
	front := dpi(t, srv.Listener.Addr().String(), "blocked.example", nil)
	_, port, _ := net.SplitHostPort(front)
	sts, _ := desync.ParseList("none")
	var tunnelled []byte
	var mu sync.Mutex
	tunnel := func(c net.Conn, target string) {
		// «туннель» = прямое соединение мимо DPI к настоящему серверу
		s, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			c.Close()
			return
		}
		pre := make([]byte, 5)
		io.ReadFull(c, pre)
		mu.Lock()
		tunnelled = append([]byte(nil), pre...)
		mu.Unlock()
		s.Write(pre)
		go io.Copy(s, c)
		io.Copy(c, s)
		c.Close()
	}
	r := New(Config{Mode: ModeAuto, Strategies: sts, Lookup: lookupTo(front), Timeout: 1 * time.Second, Tunnel: tunnel})
	t0 := time.Now()
	body, err := runThrough(t, r, "blocked.example:"+port, "blocked.example")
	if err != nil {
		t.Fatalf("auto fallback failed: %v", err)
	}
	if !strings.Contains(body, "hello") || len(tunnelled) == 0 || tunnelled[0] != 0x16 {
		t.Fatalf("not via tunnel: body=%q pre=%x", body, tunnelled)
	}
	t.Logf("fallback to tunnel took %s", time.Since(t0).Round(time.Millisecond))
	// второй раз — сразу туннель из кэша
	t1 := time.Now()
	if _, err := runThrough(t, r, "blocked.example:"+port, "blocked.example"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t1); d > 800*time.Millisecond {
		t.Fatalf("cache not used: %s", d)
	}
	s := r.Snapshot()
	if s.Fallback != 1 || s.Tunnel != 2 {
		t.Fatalf("stats %+v", s)
	}
}

func TestStrategiesAllHandshake(t *testing.T) {
	srv := tlsServer(t)
	// fake на loopback не проверить: TTL не истекает, фейк доходит до сервера (см. tests/desync-netns.sh)
	for _, name := range []string{"none", "split", "tlsrec", "tlsrec+split", "tlsrec+disorder", "oob", "disorder", "multirec+split", "split:at=mid", "split:at=sniext", "tlsrec:at=sniext+split", "multirec+disorder"} {
		sts, err := desync.ParseList(name)
		if err != nil {
			t.Fatal(err)
		}
		r := New(Config{Mode: ModeDirect, Strategies: sts, Lookup: lookupTo(srv.Listener.Addr().String()), Timeout: 3 * time.Second})
		_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
		t0 := time.Now()
		body, err := runThrough(t, r, "www.example.com:"+port, "www.example.com")
		if err != nil || !strings.Contains(body, "hello") {
			t.Fatalf("%s: %v %q", name, err, body)
		}
		t.Logf("%-16s ok in %s", name, time.Since(t0).Round(time.Millisecond))
	}
}

func TestHTTPHostSplit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "plain "+r.Host) }))
	defer srv.Close()
	sts, _ := desync.ParseList("hmod+split")
	r := New(Config{Mode: ModeDirect, Strategies: sts, Lookup: lookupTo(srv.Listener.Addr().String())})
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	a, b := net.Pipe()
	go r.Handle(b, "site.example:"+port)
	a.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(a, "GET / HTTP/1.1\r\nHost: site.example\r\nConnection: close\r\n\r\n")
	got, _ := io.ReadAll(a)
	if !bytes.Contains(bytes.ToLower(got), []byte("plain site.example")) {
		t.Fatalf("%q", got)
	}
}

func TestFreezeWatch(t *testing.T) {
	f := &freezeWatch{}
	rec := append([]byte{0x17, 3, 3, 0x40, 0}, make([]byte, 100)...) // запись 16 КБ, пришло 100 байт
	f.feed(rec)
	f.last.Store(time.Now().Add(-time.Minute).UnixNano())
	if !f.frozen(time.Second) {
		t.Fatal("mid-record stall not detected")
	}
	g := &freezeWatch{}
	g.feed(append([]byte{0x17, 3, 3, 0, 3}, 1, 2, 3))
	g.last.Store(time.Now().Add(-time.Minute).UnixNano())
	if g.frozen(time.Second) {
		t.Fatal("idle between records is not a freeze")
	}
}

func TestMatchers(t *testing.T) {
	ms := parseMatchers(DefaultTunnelHosts)
	for _, h := range []string{"www.instagram.com", "x.com", "149.154.167.51"} {
		if !match(ms, h) {
			t.Fatal(h)
		}
	}
	for _, h := range []string{"box.com", "example.org", "8.8.8.8"} {
		if match(ms, h) {
			t.Fatal(h)
		}
	}
}

func TestDNSParse(t *testing.T) {
	q := buildQuery("example.com", 1)
	resp := append([]byte(nil), q...)
	resp[2], resp[3] = 0x81, 0x80
	binary.BigEndian.PutUint16(resp[6:], 1)
	resp = append(resp, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 216, 34)
	ips, ttl, err := parseAnswer(resp, 1)
	if err != nil || len(ips) != 1 || ips[0].String() != "93.184.216.34" || ttl != 3600 {
		t.Fatal(ips, ttl, err)
	}
}
