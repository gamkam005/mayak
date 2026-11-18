package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mayak/internal/asn"
	"mayak/internal/client"
	"mayak/internal/desync"
	"mayak/internal/route"
	"mayak/internal/sub"
)

// subsFile — настройки подписок, которые пишет приложение (или руками):
// {"disabled":["barryfar-vless"],"urls":["https://…"],"links":"vless://…"}
// Периоды и проверка (панель пишет их сюда же): "refresh":"6h", "recheck":"30m",
// "test_url":"http://…", "honor_update_interval":true — слушать просьбу подписки.
type subsFile struct {
	Disabled []string `json:"disabled"`
	URLs     []string `json:"urls"`
	Links    string   `json:"links"`
	Mode     string   `json:"mode,omitempty"`
	Refresh  string   `json:"refresh,omitempty"`
	Recheck  string   `json:"recheck,omitempty"`
	TestURL  string   `json:"test_url,omitempty"`
	Honor    *bool    `json:"honor_update_interval,omitempty"`
	// Budget — размер плитки mosaic своего сервера, байт (0 = из -budget/ссылки, 14000).
	Budget int `json:"budget,omitempty"`
}

// poolConfig — настройки из файла поверх флагов/переменных (def).
func poolConfig(f subsFile, def sub.Config) sub.Config {
	c := def
	if d, err := time.ParseDuration(f.Refresh); err == nil && d > 0 {
		c.Refresh = d
	}
	if d, err := time.ParseDuration(f.Recheck); err == nil && d > 0 {
		c.Recheck = d
	}
	if f.TestURL != "" {
		c.TestURL = f.TestURL
	}
	if f.Honor != nil {
		c.HonorInterval = *f.Honor
	}
	return c
}

func readSubsFile(path string, extra []string) (srcs []sub.Source, links string, f subsFile) {
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(b, &f)
		}
	}
	off := map[string]bool{}
	for _, id := range f.Disabled {
		off[id] = true
	}
	for _, p := range sub.Presets {
		p.Enabled = !off[p.ID]
		srcs = append(srcs, p)
	}
	seen := map[string]bool{}
	for _, u := range append(f.URLs, extra...) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		if strings.Contains(u, "://") && !strings.HasPrefix(u, "http") {
			links += u + "\n" // ссылка на сервер, а не на подписку
			continue
		}
		srcs = append(srcs, sub.Source{URL: u, Enabled: true})
	}
	return srcs, links + f.Links, f
}

// chain — куда отправлять «туннельный» трафик: свой сервер МАЯК, сервер из
// подписки или их сочетание (основной + запасной).
type chain struct {
	c       *client.Client // nil = своего сервера нет
	pool    *sub.Pool
	mode    atomic.Value // off|reserve|always
	health  atomic.Int32 // 0 неизвестно, 1 сервер МАЯК отвечает, 2 не отвечает
	via     atomic.Value // mayak|subs|none — куда ушло последнее соединение
	started sync.Once
	ctx     context.Context
	logf    func(string, ...any)
	// defBudget — размер плитки из -budget / MAYAK_BUDGET / ссылки (без subs.json)
	defBudget int
	lookup    func(ctx context.Context, host string) ([]net.IP, error)
}

// applyBudget — размер плитки: subs.json важнее флага/переменной/ссылки.
func (ch *chain) applyBudget(f subsFile) {
	if ch.c == nil {
		return
	}
	if f.Budget > 0 {
		ch.c.SetBudget(f.Budget, "настройки панели")
	} else if ch.defBudget > 0 {
		ch.c.SetBudget(ch.defBudget, "по умолчанию")
	}
}

// ownIP — фактический адрес своего сервера.
func (ch *chain) ownIP(ctx context.Context) string {
	if ch.c == nil {
		return ""
	}
	h, _, err := net.SplitHostPort(ch.c.ServerAddr())
	if err != nil {
		return ""
	}
	if net.ParseIP(h) != nil || ch.lookup == nil {
		return h
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := ch.lookup(ctx, h)
	if err != nil || len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String()
		}
	}
	return ips[0].String()
}

// ownView — свой сервер для панели: адрес, AS, последняя проба «заморозки».
func (ch *chain) ownView(ctx context.Context) map[string]any {
	if ch.c == nil {
		return map[string]any{"present": false}
	}
	ip := ch.ownIP(ctx)
	p := ch.c.Profile()
	return map[string]any{"present": true, "ip": ip, "as": asn.LookupString(ip), "health": ch.health2s(),
		"probe": ch.c.LastProbe(), "profile": p.Name, "tile": p.Budget, "budget": ch.c.Budget(), "budget_default": ch.defBudget}
}

// recordOwnProbe — проба своего сервера → история тестов (отдельно от узлов подписок).
func (ch *chain) recordOwnProbe(r client.FreezeResult) {
	ip := ch.ownIP(context.Background())
	in := asn.LookupString(ip)
	class := sub.StatusWorking
	switch {
	case r.Frozen:
		class = sub.StatusFrozen
	case r.Err != "":
		class = sub.StatusDead
	case r.Body < r.Target:
		class = sub.StatusSlow
	}
	ch.pool.AddHistory(sub.HistEntry{DL: sub.DL{At: r.At, Target: r.Target, Bytes: r.Body, StallMs: int(r.StallMs), TotalMs: int(r.Duration.Milliseconds()), Mbps: r.Mbps,
		Stalled: r.Frozen, Err: r.Err, Class: class}, Node: "own", Name: "свой сервер МАЯК", IP: ip, ASN: in.ASN, Kind: "own"})
}

func (ch *chain) Mode() string { return ch.mode.Load().(string) }

func (ch *chain) SetMode(m string) {
	switch m {
	case "off", "reserve", "always":
	default:
		m = "off"
	}
	if !sub.Available && m != "off" {
		if old, _ := ch.mode.Load().(string); old == "" {
			ch.logf("подписки: в этой сборке (lite) нет ядра Xray — запасной вход из подписок выключен")
		}
		m = "off"
	}
	if old, _ := ch.mode.Load().(string); old != m {
		ch.mode.Store(m)
		if old != "" {
			ch.logf("подписки: режим %s", m)
		}
	}
	if m != "off" {
		ch.started.Do(func() {
			delay := 20 * time.Second // в резерве не мешаем старту основного сервера
			if m == "always" || ch.c == nil {
				delay = 0
			}
			go ch.pool.Run(ch.ctx, delay)
			if ch.c != nil {
				go ch.watch()
			}
		})
		if m == "always" || ch.c == nil {
			ch.pool.Kick()
		}
	}
}

func (ch *chain) Handle(conn net.Conn, target string) {
	mode := ch.Mode()
	usePool := false
	switch {
	case mode == "off":
	case ch.c == nil, mode == "always":
		usePool = ch.pool.Ready() || ch.c == nil
	case mode == "reserve":
		usePool = ch.health.Load() == 2 && ch.pool.Ready()
	}
	if usePool {
		ch.via.Store("subs")
		ch.pool.Handle(conn, target)
		return
	}
	if ch.c == nil {
		ch.via.Store("none")
		_ = conn.Close()
		return
	}
	ch.via.Store("mayak")
	ch.c.Open(conn, target)
}

// watch — проверка своего сервера: TLS-рукопожатие раз в минуту
// (раз в 30 с, пока он недоступен). Два провала подряд — переход на запасной.
func (ch *chain) watch() {
	fails := 0
	for {
		wait := time.Minute
		if ch.Mode() == "reserve" {
			ctx, cancel := context.WithTimeout(ch.ctx, 8*time.Second)
			err := ch.c.Ping(ctx)
			cancel()
			if err == nil {
				if ch.health.Swap(1) == 2 {
					ch.logf("сервер МАЯК снова доступен — трафик возвращается на него")
				}
				fails = 0
			} else {
				fails++
				if fails >= 2 && ch.health.Swap(2) != 2 {
					ch.logf("сервер МАЯК недоступен (%v) — запасной вход из подписок", err)
					if !ch.pool.Ready() {
						ch.pool.Kick()
					}
				}
				wait = 30 * time.Second
				if fails == 1 {
					wait = 5 * time.Second // быстро подтвердить
				}
			}
		}
		select {
		case <-ch.ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (ch *chain) health2s() string {
	switch ch.health.Load() {
	case 1:
		return "ok"
	case 2:
		return "down"
	}
	if ch.c == nil {
		return "none"
	}
	return "unknown"
}

// subsAPI — ручки панели/приложения для подписок и живых настроек.
func subsAPI(ch *chain, rt *route.Router, subsPath string, extra []string, speedURL string, def sub.Config, logger *log.Logger) map[string]http.HandlerFunc {
	js := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	post := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST", http.StatusMethodNotAllowed)
				return
			}
			h(w, r)
		}
	}
	via, _ := ch.via.Load().(string)
	_ = via
	return map[string]http.HandlerFunc{
		"/api/subs": func(w http.ResponseWriter, r *http.Request) {
			v, _ := ch.via.Load().(string)
			snap := ch.pool.Snapshot()
			if r.URL.Query().Get("all") == "1" {
				snap = ch.pool.SnapshotAll()
			}
			js(w, map[string]any{"mode": ch.Mode(), "available": sub.Available, "mayak": ch.health2s(), "via": v, "pool": snap})
		},
		"/api/subs/check": post(func(w http.ResponseWriter, r *http.Request) {
			go func() { _ = ch.pool.Check(context.Background(), r.URL.Query().Get("refetch") == "1") }()
			js(w, map[string]any{"ok": true})
		}),
		"/api/subs/select": post(func(w http.ResponseWriter, r *http.Request) {
			ch.pool.Select(r.URL.Query().Get("id"))
			js(w, map[string]any{"ok": true})
		}),
		"/api/subs/pin": post(func(w http.ResponseWriter, r *http.Request) {
			ch.pool.Pin(r.URL.Query().Get("id"), r.URL.Query().Get("on") == "1")
			js(w, map[string]any{"ok": true})
		}),
		"/api/subs/speed": post(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
			defer cancel()
			d, err := ch.pool.SpeedTest(ctx, r.URL.Query().Get("id"), speedURL, sub.FreezeLarge)
			if err != nil {
				js(w, map[string]any{"ok": false, "err": err.Error()})
				return
			}
			if d.Bytes == 0 {
				js(w, map[string]any{"ok": false, "err": d.Err, "dl": d})
				return
			}
			js(w, map[string]any{"ok": true, "mbps": d.Mbps, "dl": d})
		}),
		// история тестов загрузки (узлы подписок и свой сервер): GET ?n=200
		"/api/subs/history": func(w http.ResponseWriter, r *http.Request) {
			n := 200
			_, _ = fmt.Sscan(r.URL.Query().Get("n"), &n)
			js(w, map[string]any{"history": ch.pool.History(n)})
		},
		// свой сервер МАЯК: адрес, AS, последняя проба «заморозки», плитка
		"/api/own": func(w http.ResponseWriter, r *http.Request) {
			js(w, ch.ownView(r.Context()))
		},
		// проба «заморозки» своего сервера по кнопке: 256 КБ одним соединением
		"/api/own/probe": post(func(w http.ResponseWriter, r *http.Request) {
			if ch.c == nil {
				js(w, map[string]any{"ok": false, "err": "своего сервера нет (только подписки)"})
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
			defer cancel()
			res := ch.c.ProbeFreeze(ctx, 256<<10)
			js(w, map[string]any{"ok": res.Err == "" || res.Frozen, "probe": res})
		}),
		"/api/subs/reload": post(func(w http.ResponseWriter, r *http.Request) {
			applySubsFile(ch, subsPath, extra, def)
			js(w, map[string]any{"ok": true})
		}),
		"/api/subs/mode": post(func(w http.ResponseWriter, r *http.Request) {
			ch.SetMode(r.URL.Query().Get("m"))
			js(w, map[string]any{"ok": true, "mode": ch.Mode()})
		}),
		// приёмы обмана DPI на лету: POST /api/desync?list=tlsrec+split,oob
		"/api/desync": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && rt != nil {
				sts, err := desync.ParseList(r.URL.Query().Get("list"))
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					js(w, map[string]any{"ok": false, "err": err.Error()})
					return
				}
				rt.SetStrategies(sts)
				logger.Printf("приёмы: %s (применены без переподключения)", r.URL.Query().Get("list"))
			}
			var list []string
			if rt != nil {
				for _, s := range rt.Strategies() {
					list = append(list, s.String())
				}
			}
			js(w, map[string]any{"ok": true, "strategies": list})
		},
	}
}

// applySubsFile — перечитать subs.json: подписки, режим, периоды.
func applySubsFile(ch *chain, subsPath string, extra []string, def sub.Config) {
	srcs, links, f := readSubsFile(subsPath, extra)
	ch.pool.SetConfig(poolConfig(f, def))
	ch.applyBudget(f)
	ch.pool.Reload(srcs, links)
	if f.Mode != "" {
		ch.SetMode(f.Mode)
	}
}

func defaultSubsState() string {
	if exe, err := os.Executable(); err == nil {
		d := filepath.Join(filepath.Dir(exe), "mayak-subs")
		if err := os.MkdirAll(d, 0o700); err == nil {
			return d
		}
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "mayak", "subs")
	}
	return ""
}

func newPool(state, freezeURL string, srcs []sub.Source, links string, maxC int, lookup func(context.Context, string) ([]net.IP, error), fetchDial func(ctx context.Context, network, addr string) (net.Conn, error), logf func(string, ...any)) *sub.Pool {
	tr := &http.Transport{DialContext: fetchDial, TLSHandshakeTimeout: 15 * time.Second, ForceAttemptHTTP2: true}
	return sub.New(sub.Options{StateDir: state, FreezeURL: freezeURL, Sources: srcs, Links: links, Lookup: lookup, MaxCandidates: maxC,
		Fetch: &http.Client{Transport: tr, Timeout: 45 * time.Second}, Logf: func(f string, a ...any) { logf(sub.Mask(fmt.Sprintf(f, a...))) }})
}
