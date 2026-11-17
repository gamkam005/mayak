package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mayak/internal/sub"
)

// runPicker — «mayak picker»: на VPS качает подписки, отбрасывает мёртвые
// (TCP + реальный запрос через Xray) и отдаёт готовую подписку из живых.
// Финальную проверку из РФ всё равно делает клиент: из-за границы «живыми»
// окажутся и серверы, которые ТСПУ режет.
func runPicker(args []string) int {
	fs := flag.NewFlagSet("picker", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8090", "адрес HTTP(S)")
	path := fs.String("path", "", "секретный путь (/<path>/sub); пусто = случайный")
	subs := fs.String("sub", "", "доп. подписки через запятую")
	presets := fs.Bool("presets", true, "брать встроенные подписки")
	interval := fs.Duration("interval", time.Hour, "как часто перепроверять")
	maxC := fs.Int("max", 400, "серверов за прогон")
	keep := fs.Int("keep", 60, "сколько живых отдавать")
	state := fs.String("state", "/var/lib/mayak-picker", "кэш")
	cert := fs.String("cert", "", "TLS-сертификат (пусто = HTTP, ставьте за свой nginx/МАЯК)")
	key := fs.String("key", "", "TLS-ключ")
	_ = fs.Parse(args)
	logger := log.New(os.Stderr, "picker ", log.LstdFlags)
	if *path == "" {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		*path = hex.EncodeToString(b)
	}
	var srcs []sub.Source
	if *presets {
		srcs = append(srcs, sub.Presets...)
	}
	for _, u := range strings.Split(*subs, ",") {
		if u = strings.TrimSpace(u); u != "" {
			srcs = append(srcs, sub.Source{URL: u, Enabled: true})
		}
	}
	p := sub.New(sub.Options{StateDir: *state, Sources: srcs, MaxCandidates: *maxC, ProbeMax: *maxC, ProbeWorkers: 16,
		Keep: (*keep + 2) / 3, Logf: func(f string, a ...any) { logger.Print(sub.Mask(fmt.Sprintf(f, a...))) }})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		for {
			_ = p.Check(ctx, true)
			select {
			case <-ctx.Done():
				return
			case <-time.After(*interval):
			}
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+*path+"/sub", func(w http.ResponseWriter, r *http.Request) {
		links := p.Links()
		if len(links) > *keep {
			links = links[:*keep]
		}
		body := strings.Join(links, "\n")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("МАЯК picker")))
		w.Header().Set("Profile-Update-Interval", "1")
		if r.URL.Query().Get("plain") == "1" {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(body))))
	})
	mux.HandleFunc("/"+*path+"/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s := p.Snapshot()
		s.Nodes = nil
		_ = json.NewEncoder(w).Encode(s)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	scheme := "http"
	if *cert != "" {
		scheme = "https"
	}
	logger.Printf("подписка: %s://%s/%s/sub (добавьте её в приложение как свою)", scheme, *listen, *path)
	var err error
	if *cert != "" {
		err = srv.ListenAndServeTLS(*cert, *key)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		logger.Print(err)
		return 1
	}
	return 0
}
