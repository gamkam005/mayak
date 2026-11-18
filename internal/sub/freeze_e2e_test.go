//go:build !lite

package sub

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// freezeRelay — как cmd/tspusim -freeze N: после N байт от сервера к клиенту
// данные молча перестают идти, соединение не рвётся.
func freezeRelay(t *testing.T, to string, limit int64) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
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
				go func() { _, _ = io.Copy(s, c) }()
				var sent atomic.Int64
				buf := make([]byte, 4096)
				for {
					n, err := s.Read(buf)
					if n > 0 {
						left := limit - sent.Load()
						if left <= 0 {
							continue // заморожено: читаем и выбрасываем
						}
						if int64(n) > left {
							n = int(left)
						}
						sent.Add(int64(n))
						if _, err := c.Write(buf[:n]); err != nil {
							return
						}
					}
					if err != nil {
						time.Sleep(30 * time.Second) // не закрываем: «висит»
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func webForFreeze() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generate_204":
			w.WriteHeader(204)
		case "/dl":
			n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
			w.Header().Set("Content-Length", strconv.Itoa(n))
			chunk := make([]byte, 16<<10)
			for n > 0 {
				k := min(n, len(chunk))
				if _, err := w.Write(chunk[:k]); err != nil {
					return
				}
				n -= k
			}
		default:
			io.WriteString(w, "ok")
		}
	}))
}

// Узел за «ТСПУ» отвечает на generate_204, но заморожен на загрузке; рабочий
// узел идёт первым в автовыборе, даже если у замороженного задержка меньше.
func TestFreezeClassificationE2E(t *testing.T) {
	uuid := "a3090000-1bf0-4be5-8000-000000000002"
	srv := xrayServer(t, uuid)
	frozen := freezeRelay(t, fmt.Sprintf("127.0.0.1:%d", srv), 16384)
	web := webForFreeze()
	defer web.Close()
	links := []string{
		fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#good", uuid, srv),
		fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#frozen", uuid, frozen),
	}
	p := New(Options{StateDir: t.TempDir(), Links: strings.Join(links, "\n"), TestURL: web.URL + "/generate_204",
		OpenURL: "-", FreezeURL: web.URL + "/dl?bytes={bytes}"})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := p.Check(ctx, true); err != nil {
		t.Fatal(err)
	}
	s := p.SnapshotAll()
	st := map[string]NodeView{}
	for _, n := range s.Nodes {
		st[n.Name] = n
	}
	g, f := st["good"], st["frozen"]
	if !g.OK || g.Status != StatusWorking || g.DL == nil || g.DL.Bytes < FreezeSmall {
		t.Fatalf("good: %+v dl=%+v", g.Result, g.DL)
	}
	if !f.OK || f.Status != StatusFrozen || f.DL == nil || !f.DL.Stalled || f.DL.Bytes >= frozenBelow {
		t.Fatalf("frozen: %+v dl=%+v", f.Result, f.DL)
	}
	if s.Nodes[0].Name != "good" || s.Working != 1 || s.Frozen != 1 {
		t.Fatalf("порядок/счётчики: first=%s working=%d frozen=%d", s.Nodes[0].Name, s.Working, s.Frozen)
	}
	if f.DL.StallMs <= 0 || f.IP != "127.0.0.1" {
		t.Errorf("stall_ms=%d ip=%q", f.DL.StallMs, f.IP)
	}
	if h := p.History(10); len(h) < 2 {
		t.Errorf("история: %d записей", len(h))
	}
	t.Logf("good: %d байт, %.1f Мбит/с; frozen: встал на %d байтах через %d мс", g.DL.Bytes, g.DL.Mbps, f.DL.Bytes, f.DL.StallMs)
	// кнопка 3 МБ по замороженному — тоже «заморожен»
	d, err := p.SpeedTest(ctx, f.Node.ID, "", FreezeLarge)
	if err != nil || d.Class != StatusFrozen {
		t.Errorf("3 МБ через замороженный: %+v %v", d, err)
	}
	p.closeAll()
}
