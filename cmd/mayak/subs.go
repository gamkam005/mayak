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

	"mayak/internal/client"
	"mayak/internal/desync"
	"mayak/internal/route"
	"mayak/internal/sub"
)

// subsFile — настройки подписок, которые пишет приложение (или руками):
// {"disabled":["barryfar-vless"],"urls":["https://…"],"links":"vless://…"}
type subsFile struct {
	Disabled []string `json:"disabled"`
	URLs     []string `json:"urls"`
	Links    string   `json:"links"`
	Mode     string   `json:"mode,omitempty"`
}

func readSubsFile(path string, extra []string) (srcs []sub.Source, links, mode string) {
	var f subsFile
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
	return srcs, links + f.Links, f.Mode
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
}

func (ch *chain) Mode() string { return ch.mode.Load().(string) }

func (ch *chain) SetMode(m string) {
	switch m {
	case "off", "reserve", "always":
	default:
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
func subsAPI(ch *chain, rt *route.Router, subsPath string, extra []string, speedURL string, logger *log.Logger) map[string]http.HandlerFunc {
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
			js(w, map[string]any{"mode": ch.Mode(), "mayak": ch.health2s(), "via": v, "pool": ch.pool.Snapshot()})
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
			ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
			defer cancel()
			mbps, err := ch.pool.Speed(ctx, r.URL.Query().Get("id"), speedURL)
			if err != nil {
				js(w, map[string]any{"ok": false, "err": err.Error()})
				return
			}
			js(w, map[string]any{"ok": true, "mbps": mbps})
		}),
		"/api/subs/reload": post(func(w http.ResponseWriter, r *http.Request) {
			srcs, links, mode := readSubsFile(subsPath, extra)
			ch.pool.Reload(srcs, links)
			if mode != "" {
				ch.SetMode(mode)
			}
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

func newPool(state string, srcs []sub.Source, links string, maxC int, lookup func(context.Context, string) ([]net.IP, error), fetchDial func(ctx context.Context, network, addr string) (net.Conn, error), logf func(string, ...any)) *sub.Pool {
	tr := &http.Transport{DialContext: fetchDial, TLSHandshakeTimeout: 15 * time.Second, ForceAttemptHTTP2: true}
	return sub.New(sub.Options{StateDir: state, Sources: srcs, Links: links, Lookup: lookup, MaxCandidates: maxC,
		Fetch: &http.Client{Transport: tr, Timeout: 45 * time.Second}, Logf: func(f string, a ...any) { logf(sub.Mask(fmt.Sprintf(f, a...))) }})
}
