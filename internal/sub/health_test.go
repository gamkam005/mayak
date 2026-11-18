package sub

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ssLink(host, name string) string {
	return "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw")) + "@" + host + ":8388#" + name
}

func vlessLink(sni, name string) string {
	return "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=tls&type=tcp&sni=" + sni + "#" + name
}

// testPool — пул из своих ссылок; probe решает, отвечает ли сервер.
func testPool(t *testing.T, links string, probe func(n *Node) error) (*Pool, *sync.Map) {
	t.Helper()
	calls := &sync.Map{}
	p := New(Options{Links: links, OpenURL: "-", Logf: func(f string, a ...any) { t.Logf(f, a...) }})
	p.probeFn = func(_ context.Context, n *Node, _ string, _ time.Duration) (time.Duration, error) {
		v, _ := calls.LoadOrStore(n.Name, new(atomic.Int32))
		v.(*atomic.Int32).Add(1)
		if err := probe(n); err != nil {
			return 0, err
		}
		return 50 * time.Millisecond, nil
	}
	p.rebuild(context.Background(), false)
	return p, calls
}

func idByName(t *testing.T, p *Pool, name string) string {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, n := range p.nodes {
		if n.Name == name {
			return id
		}
	}
	t.Fatalf("нет узла %s", name)
	return ""
}

func markAlive(p *Pool, ids ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, id := range ids {
		p.res[id] = &Result{ID: id, OK: true, Delay: 100 + i, Checked: time.Now()}
	}
	p.rankLocked()
}

func count(calls *sync.Map, name string) int {
	if v, ok := calls.Load(name); ok {
		return int(v.(*atomic.Int32).Load())
	}
	return 0
}

func waitVerify(t *testing.T, p *Pool, id string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		p.mu.Lock()
		busy := p.verifying[id]
		done := !p.verified[id].IsZero()
		p.mu.Unlock()
		if !busy && done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("проверка вне очереди не закончилась")
}

func TestFailRetestDemotes(t *testing.T) {
	p, calls := testPool(t, ssLink("a.example", "A")+"\n"+ssLink("b.example", "B"), func(n *Node) error {
		if n.Name == "A" {
			return errors.New("timeout")
		}
		return nil
	})
	a, b := idByName(t, p, "A"), idByName(t, p, "B")
	markAlive(p, a, b)
	p.mu.Lock()
	p.active, p.selected = a, a
	p.mu.Unlock()
	p.fail(a, errors.New("EOF"))
	waitVerify(t, p, a)
	if c := count(calls, "A"); c != 2 {
		t.Errorf("проверок вне очереди: %d, нужно 2", c)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.res[a].OK || p.active == a {
		t.Error("сервер A должен выпасть")
	}
	if len(p.alive) != 1 || p.alive[0] != b {
		t.Errorf("живые: %v, нужен только B", p.alive)
	}
	if p.selected != "" || !strings.Contains(p.notice, "автовыбор") {
		t.Errorf("ручной выбор не сброшен: selected=%q notice=%q", p.selected, p.notice)
	}
}

func TestFailRetestKeeps(t *testing.T) {
	var n atomic.Int32
	p, calls := testPool(t, ssLink("a.example", "A"), func(*Node) error {
		if n.Add(1) == 1 {
			return errors.New("timeout")
		}
		return nil
	})
	a := idByName(t, p, "A")
	markAlive(p, a)
	p.mu.Lock()
	p.active, p.selected = a, a
	p.res[a].Fails = 1
	p.mu.Unlock()
	p.fail(a, errors.New("EOF"))
	waitVerify(t, p, a)
	if c := count(calls, "A"); c != 2 {
		t.Errorf("проверок: %d, нужно 2 (первая не прошла, вторая прошла)", c)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.res[a].OK || p.res[a].Fails != 0 || p.active != a || p.selected != a {
		t.Errorf("сервер A должен остаться: %+v active=%q selected=%q", *p.res[a], p.active, p.selected)
	}
	// повторный сбой сразу после проверки — без новой проверки (cooldown)
	p.mu.Unlock()
	p.fail(a, errors.New("EOF"))
	p.mu.Lock()
	if p.verifying[a] {
		t.Error("сразу после проверки переспрашивать не нужно")
	}
}

func TestRecheckRetriesAliveTwice(t *testing.T) {
	p, calls := testPool(t, ssLink("a.example", "A"), func(*Node) error { return errors.New("timeout") })
	a := idByName(t, p, "A")
	markAlive(p, a)
	p.Recheck(context.Background())
	if c := count(calls, "A"); c != 3 {
		t.Errorf("перепроверка живого: %d запросов, нужно 1+2", c)
	}
	if p.res[a].OK {
		t.Error("должен выпасть")
	}
}

func TestRemapAfterRefresh(t *testing.T) {
	p, _ := testPool(t, vlessLink("old.example", "A")+"\n"+ssLink("b.example", "B"), func(*Node) error { return nil })
	a, b := idByName(t, p, "A"), idByName(t, p, "B")
	markAlive(p, a, b)
	p.mu.Lock()
	p.active, p.selected, p.pinned[a] = a, a, true
	p.mu.Unlock()

	// у сервера A поменялся SNI — новый id, всё переходит на него
	p.opt.Links = vlessLink("new.example", "A") + "\n" + ssLink("b.example", "B")
	p.rebuild(context.Background(), false)
	na := idByName(t, p, "A")
	if na == a {
		t.Fatal("id должен смениться вместе с настройками")
	}
	p.mu.Lock()
	if p.active != na || p.selected != na || !p.pinned[na] || p.pinned[a] {
		t.Errorf("не перешли на новые настройки: active=%q selected=%q pinned=%v", p.active, p.selected, p.pinned)
	}
	if r := p.res[na]; r == nil || !r.OK {
		t.Error("результат должен перейти на новый id")
	}
	if len(p.alive) != 2 || p.alive[0] != na {
		t.Errorf("живые: %v", p.alive)
	}
	sni := get(p.nodes[na].ob, "streamSettings", "tlsSettings", "serverName")
	p.mu.Unlock()
	if sni != "new.example" {
		t.Errorf("SNI %v", sni)
	}

	// A пропал совсем — активный на следующего живого, ручной выбор на автовыбор
	p.opt.Links = ssLink("b.example", "B")
	p.rebuild(context.Background(), false)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active != "" || p.selected != "" || !strings.Contains(p.notice, "пропал") {
		t.Errorf("active=%q selected=%q notice=%q", p.active, p.selected, p.notice)
	}
	if len(p.alive) != 1 || p.alive[0] != b {
		t.Errorf("живые: %v", p.alive)
	}
}

func TestSelectedDeadFallsBack(t *testing.T) {
	p, _ := testPool(t, ssLink("a.example", "A")+"\n"+ssLink("b.example", "B"), func(*Node) error { return nil })
	a, b := idByName(t, p, "A"), idByName(t, p, "B")
	markAlive(p, a, b)
	p.Select(a)
	p.mu.Lock()
	p.res[a] = &Result{ID: a, OK: false, Err: "TCP: нет ответа", Checked: time.Now()}
	p.rankLocked()
	defer p.mu.Unlock()
	if p.selected != "" || p.notice == "" {
		t.Errorf("selected=%q notice=%q", p.selected, p.notice)
	}
}

func TestEffectiveRefresh(t *testing.T) {
	for _, c := range []struct {
		cfg   Config
		asked time.Duration
		want  time.Duration
	}{
		{Config{Refresh: 6 * time.Hour, HonorInterval: true}, time.Hour, time.Hour},
		{Config{Refresh: 6 * time.Hour, HonorInterval: false}, time.Hour, 6 * time.Hour},
		{Config{Refresh: 6 * time.Hour, HonorInterval: true}, 5 * time.Minute, MinRefresh},
		{Config{Refresh: 30 * time.Minute, HonorInterval: true}, time.Hour, 30 * time.Minute},
		{Config{Refresh: 6 * time.Hour, HonorInterval: true}, 0, 6 * time.Hour},
	} {
		if got := EffectiveRefresh(c.cfg, c.asked); got != c.want {
			t.Errorf("%+v asked %s: %s, want %s", c.cfg, c.asked, got, c.want)
		}
	}
	for in, want := range map[string]time.Duration{"1": time.Hour, "0.5": 30 * time.Minute, " 12 ": 12 * time.Hour, "": 0, "x": 0, "-1": 0} {
		if got := parseUpdateInterval(in); got != want {
			t.Errorf("parseUpdateInterval(%q) = %s", in, got)
		}
	}
}

func TestUpdateIntervalHeader(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Profile-Update-Interval", "1")
		fmt.Fprintln(w, ssLink("a.example", "A"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	mk := func(honor bool) *Pool {
		p := New(Options{StateDir: dir, Sources: []Source{{URL: srv.URL, Enabled: true}}, HonorInterval: honor, Refresh: 6 * time.Hour, OpenURL: "-"})
		p.probeFn = func(context.Context, *Node, string, time.Duration) (time.Duration, error) {
			return time.Millisecond, nil
		}
		return p
	}
	p := mk(true)
	p.rebuild(context.Background(), false)
	if hits.Load() != 1 {
		t.Fatalf("скачиваний %d", hits.Load())
	}
	id := p.srcs[0].ID
	if got := p.srcRefresh(id); got != time.Hour {
		t.Fatalf("период %s, нужен 1h из заголовка", got)
	}
	p.mu.Lock()
	p.saveLocked()
	p.mu.Unlock()
	snap := p.Snapshot()
	if snap.Sources[0].UpdateHours != 1 || snap.Sources[0].Refresh != "1h0m0s" {
		t.Errorf("в панели: %+v", snap.Sources[0])
	}
	// кэш двухчасовой давности: после перезапуска (период из state.json) — перекачать
	cache := filepath.Join(dir, "src-"+id+".txt")
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(cache, old, old); err != nil {
		t.Fatal(err)
	}
	p2 := mk(true)
	if got := p2.srcRefresh(id); got != time.Hour {
		t.Fatalf("после перезапуска период %s", got)
	}
	p2.rebuild(context.Background(), false)
	if hits.Load() != 2 {
		t.Errorf("устаревший по заголовку кэш должен перекачаться: скачиваний %d", hits.Load())
	}
	// без учёта заголовка тот же кэш (2 ч < 6 ч) свежий
	_ = os.Chtimes(cache, old, old)
	p3 := mk(false)
	p3.rebuild(context.Background(), false)
	if hits.Load() != 2 {
		t.Errorf("без учёта заголовка кэш свежий: скачиваний %d", hits.Load())
	}
	// фоновый цикл видит, что подписка просрочена
	p3.SetConfig(Config{Refresh: 6 * time.Hour, HonorInterval: true})
	p3.mu.Lock()
	p3.srcs[0].Fetched = old
	p3.mu.Unlock()
	if !p3.sourcesDue() {
		t.Error("подписка с периодом 1 ч, скачанная 2 ч назад, должна быть к обновлению")
	}
}

func TestSnapshotAllIncludesDead(t *testing.T) {
	p, _ := testPool(t, ssLink("a.example", "A")+"\n"+ssLink("b.example", "B")+"\n"+ssLink("c.example", "C"), func(*Node) error { return nil })
	a, b := idByName(t, p, "A"), idByName(t, p, "B")
	markAlive(p, a)
	p.mu.Lock()
	p.res[b] = &Result{ID: b, Err: "TCP: нет ответа", Checked: time.Now()}
	p.mu.Unlock()
	if n := len(p.Snapshot().Nodes); n != 1 {
		t.Errorf("обычный снимок: %d", n)
	}
	all := p.SnapshotAll()
	if len(all.Nodes) != 3 || all.Nodes[0].Node.ID != a || all.Nodes[1].Node.ID != b || all.Nodes[1].Err == "" {
		t.Errorf("полный снимок: %+v", all.Nodes)
	}
}

func TestMaskLink(t *testing.T) {
	for in, want := range map[string]string{
		"vless://11111111-1111-1111-1111-111111111111@a.example:443?security=reality&pbk=x#Имя": "vless://***@a.example:443?security=reality&pbk=x#Имя",
		ssLink("b.example", "B"):                                 "ss://***@b.example:8388#B",
		"vmess://eyJhZGQiOiJ4In0=":                               "vmess://***",
		"hysteria2://secret@c.example:443?obfs-password=p&sni=c": "hysteria2://***@c.example:443?obfs-password=***&sni=c",
		"https://x.example/sub?token=abc":                        "https://x.example/sub?token=***",
	} {
		if got := MaskLink(in); got != want {
			t.Errorf("MaskLink(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSelectAutoResetsActive(t *testing.T) {
	p, _ := testPool(t, ssLink("a.example", "A")+"\n"+ssLink("b.example", "B"), func(*Node) error { return nil })
	a, b := idByName(t, p, "A"), idByName(t, p, "B")
	markAlive(p, a, b) // A лучше
	p.Select(b)
	p.mu.Lock()
	p.active = b
	p.mu.Unlock()
	p.Select("")
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active != "" || p.selected != "" {
		t.Errorf("автовыбор должен сразу взять лучший: active=%q", p.active)
	}
}
