package client

import (
	"context"
	_ "embed"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

//go:embed web/index.html
var indexHTML []byte

// Middleware — обёртка панели (вход по паролю, CSRF); nil = без неё.
type Middleware func(http.Handler) http.Handler

func wrapMux(mux *http.ServeMux, mw Middleware) http.Handler {
	if mw == nil {
		return mux
	}
	return mw(mux)
}

// ServeDashboard — локальная панель: статус, скорость, режим, диагностика.
func (c *Client) ServeDashboard(ctx context.Context, ln net.Listener, speedURL string, mw Middleware) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, c.Snapshot())
	})
	for p, h := range c.handlers {
		mux.HandleFunc(p, h)
	}
	mux.HandleFunc("/api/route", func(w http.ResponseWriter, r *http.Request) {
		if c.routeSnap == nil {
			writeJSON(w, map[string]string{"mode": "tunnel"})
			return
		}
		writeJSON(w, c.routeSnap())
	})
	var dmu sync.Mutex
	var last *DiagReport
	running := false
	mux.HandleFunc("/api/diag", func(w http.ResponseWriter, r *http.Request) {
		dmu.Lock()
		if r.Method == http.MethodPost && !running {
			running = true
			go func() {
				ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
				defer cancel()
				rep := c.RunDiag(ctx, speedURL)
				dmu.Lock()
				last, running = &rep, false
				dmu.Unlock()
				c.events.add("diag", "диагностика завершена")
			}()
		}
		out := map[string]any{"running": running, "report": last}
		dmu.Unlock()
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/mode", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Query().Get("m") {
		case "fast":
			c.setProfile(fastProfile, "выбрано вручную")
		case "mosaic":
			c.setProfile(mosaicProfile(c.Budget()), "выбрано вручную")
		case "auto":
			go func() {
				r := c.ProbeFreeze(ctx, 256<<10)
				if r.Frozen {
					c.setProfile(mosaicProfile(c.Budget()), "проба по кнопке: заморозка")
				} else if r.Err == "" {
					c.setProfile(fastProfile, "проба по кнопке: заморозки нет")
				}
			}()
		}
		writeJSON(w, c.Profile())
	})
	srv := &http.Server{Handler: wrapMux(mux, mw), ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	return srv.Serve(ln)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// ServeMini — панель для режима «только напрямую» (без сервера и туннеля):
// /api/stats в том же виде, что у полной панели, и /api/route.
func ServeMini(ctx context.Context, ln net.Listener, snap func() any, extra map[string]http.HandlerFunc, mw Middleware) error {
	mux := http.NewServeMux()
	for p, h := range extra {
		mux.HandleFunc(p, h)
	}
	_, hasPanel := extra["/panel"]
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if hasPanel {
			http.Redirect(w, r, "/panel", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(miniHTML))
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"profile": map[string]any{"name": "direct"}, "streams": 0, "route": snap()})
	})
	mux.HandleFunc("/api/route", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, snap()) })
	srv := &http.Server{Handler: wrapMux(mux, mw), ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	return srv.Serve(ln)
}

const miniHTML = `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>МАЯК</title>
<body style="font:15px system-ui;background:#0b1020;color:#e6ebf7;padding:16px;margin:0">
<script>if(window.Mayak)document.write('<button onclick="Mayak.home()" style="background:#24304f;color:#e6ebf7;border:0;border-radius:10px;padding:10px 14px;font:inherit;font-weight:700">← В приложение</button>')</script>
<h2>МАЯК — без своего сервера</h2>
<div id=s style="background:#141d36;border:1px solid #24304f;border-radius:12px;padding:12px;margin-bottom:12px"></div>
<pre id=o style="white-space:pre-wrap;font:12px ui-monospace,monospace;color:#9fb0d6"></pre>
<script>
const e=x=>String(x).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
setInterval(()=>{fetch('/api/route').then(r=>r.json()).then(j=>o.textContent=JSON.stringify(j,null,1)).catch(()=>{});
fetch('/api/subs').then(r=>r.ok?r.json():null).then(j=>{if(!j){s.style.display='none';return}const p=j.pool,a=p.active;
s.innerHTML='<b>Подписки: '+e(j.mode)+'</b> · живых '+p.alive+' из '+p.total+(p.checking?' · проверка…':'')+(a?'<br>активный: '+e(a.name||a.host)+' · '+a.proto+' '+(a.delay_ms||'?')+' мс':'')+
(p.nodes||[]).slice(0,10).map(n=>'<div style="font-size:13px;color:#8a96b3">'+(n.active?'▶ ':'')+e(n.name||n.host)+' · '+n.proto+'·'+n.net+' · '+(n.ok?n.delay_ms+' мс':'✕')+'</div>').join('')}).catch(()=>{})},2000)
</script>`
