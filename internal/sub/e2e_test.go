//go:build !lite

package sub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
)

// xrayServer — настоящий VLESS-сервер на Xray в этом же процессе.
func xrayServer(t *testing.T, uuid string) int {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg := fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[{"id":"%s"}],"decryption":"none"}}],"outbounds":[{"protocol":"freedom"}]}`, port, uuid)
	var c conf.Config
	if err := json.Unmarshal([]byte(cfg), &c); err != nil {
		t.Fatal(err)
	}
	pb, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	inst, err := core.New(pb)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	return port
}

func TestPoolEndToEnd(t *testing.T) {
	uuid := "a3090000-1bf0-4be5-8000-000000000001"
	good := xrayServer(t, uuid)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/generate_204" {
			w.WriteHeader(204)
			return
		}
		io.WriteString(w, "hello via vless")
	}))
	defer web.Close()
	dead, _ := net.Listen("tcp", "127.0.0.1:0") // принимает TCP, но не VLESS
	go func() {
		for {
			c, err := dead.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	defer dead.Close()
	deadPort := dead.Addr().(*net.TCPAddr).Port
	links := []string{
		fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#good", uuid, good),
		fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#dead", uuid, deadPort),
		"vless://" + uuid + "@127.0.0.1:1?security=none#closed",
	}
	subSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Join(links, "\n"))
	}))
	defer subSrv.Close()
	dir := t.TempDir()
	p := New(Options{StateDir: dir, Sources: []Source{{URL: subSrv.URL + "/?key=SECRET", Enabled: true}}, TestURL: web.URL + "/generate_204", OpenURL: web.URL + "/x"})
	if err := p.Check(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	s := p.Snapshot()
	if s.Total != 3 || s.Alive != 1 || s.Nodes[0].Name != "good" {
		b, _ := json.MarshalIndent(s, "", " ")
		t.Fatalf("snapshot: %s", b)
	}
	if strings.Contains(s.Sources[0].URL, "SECRET") {
		t.Error("key not masked")
	}
	// трафик через пул
	a, b := net.Pipe()
	go p.Handle(b, strings.TrimPrefix(web.URL, "http://"))
	fmt.Fprintf(a, "GET /x HTTP/1.0\r\nHost: x\r\n\r\n")
	out, _ := io.ReadAll(a)
	if !strings.Contains(string(out), "hello via vless") {
		t.Fatalf("через пул: %q", out)
	}
	// состояние переживает перезапуск
	p.closeAll()
	p2 := New(Options{StateDir: dir, Sources: []Source{{URL: subSrv.URL + "/?key=SECRET", Enabled: true}}, TestURL: web.URL + "/generate_204", OpenURL: web.URL + "/x"})
	p2.rebuild(context.Background(), false)
	p2.mu.Lock()
	p2.rankLocked()
	p2.mu.Unlock()
	if !p2.Ready() {
		t.Fatal("после перезапуска нет живых")
	}
	c, err := p2.Dial(context.Background(), strings.TrimPrefix(web.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "GET / HTTP/1.0\r\n\r\n")
	out, _ = io.ReadAll(c)
	if !strings.Contains(string(out), "hello") {
		t.Fatalf("p2: %q", out)
	}
	_ = strconv.Itoa
	p2.closeAll()
}

func TestCandidatesCapAndBalance(t *testing.T) {
	p := New(Options{MaxCandidates: 30})
	p.nodes = map[string]*Node{}
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("big%d", i)
		p.nodes[id] = &Node{ID: id, Source: "big"}
		p.order = append(p.order, id)
	}
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("small%d", i)
		p.nodes[id] = &Node{ID: id, Source: "small"}
		p.order = append(p.order, id)
	}
	c := p.candidates(30)
	small := 0
	for _, n := range c {
		if n.Source == "small" {
			small++
		}
	}
	if len(c) != 30 || small != 5 {
		t.Errorf("got %d candidates, %d from small list", len(c), small)
	}
}
