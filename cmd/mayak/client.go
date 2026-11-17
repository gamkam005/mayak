package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"mayak/internal/client"
	"net/http"
	"sync/atomic"

	"mayak/internal/desync"
	"mayak/internal/protocol"
	"mayak/internal/route"
)

// debugHandler — GET: состояние, POST ?on=1|0: переключить диагностический журнал.
func debugHandler(dbg *atomic.Bool, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			on := r.URL.Query().Get("on") == "1"
			if dbg.Swap(on) != on {
				logger.Printf("диагностический журнал: %v", map[bool]string{true: "включён", false: "выключен"}[on])
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"debug":%v}`, dbg.Load())
	}
}

func buildRouter(mode, strat string, timeout, freeze time.Duration, tun, dir, doh string, tunnel func(net.Conn, string), logf func(string, ...any), dbg *atomic.Bool) (*route.Router, error) {
	switch mode {
	case route.ModeAuto, route.ModeDirect, route.ModeTunnel:
	default:
		return nil, fmt.Errorf("-route: %q (нужно tunnel, direct или auto)", mode)
	}
	sts, err := desync.ParseList(strat)
	if err != nil {
		return nil, fmt.Errorf("-desync: %w", err)
	}
	cfg := route.Config{
		Mode: mode, Strategies: sts, Timeout: timeout, Freeze: freeze,
		TunnelHosts: append(append([]string{}, route.DefaultTunnelHosts...), route.ReadList(tun, os.ReadFile)...),
		DirectHosts: route.ReadList(dir, os.ReadFile),
		Tunnel:      tunnel, Logf: logf, Debug: dbg,
	}
	if doh != "" && doh != "off" {
		cfg.Lookup = route.NewDoH(route.ReadList(doh, os.ReadFile)).Lookup
	}
	return route.New(cfg), nil
}

func runClient(args []string, auto bool) int {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	linkS := fs.String("link", "", "ссылка mayak://… (или файл с ней)")
	listen := fs.String("listen", "127.0.0.1:1080", "локальный SOCKS5/HTTP-прокси")
	ui := fs.String("ui", "127.0.0.1:9090", "адрес панели (пусто = без панели)")
	mode := fs.String("mode", "", "auto | mosaic | fast (перекрывает ссылку)")
	budget := fs.Int("budget", 0, "байт на одно TLS-соединение в режиме mosaic (по умолчанию 14000)")
	fp := fs.String("fp", "", "TLS-отпечаток: chrome|firefox|safari|edge|random|go")
	sni := fs.String("sni", "", "перекрыть SNI из ссылки")
	speed := fs.String("speed-url", "https://speed.cloudflare.com/__down?bytes=5000000", "что качать в тесте скорости")
	down := fs.Int("down-workers", 0, "параллельных запросов вниз (по умолчанию 16)")
	open := fs.Bool("open", auto, "открыть панель в браузере")
	verbose := fs.Bool("v", false, "подробный журнал")
	routeMode := fs.String("route", "tunnel", "маршрут: tunnel (всё через сервер) | direct (напрямую с обманом DPI, сервер не нужен) | auto (сначала напрямую, не вышло — туннель)")
	strat := fs.String("desync", defaultDesync(), "приёмы обмана DPI по очереди: tlsrec, split, disorder, fake[:ttl=N], oob, none; через «+» сочетаются (на лету: POST /api/desync?list=…)")
	dTimeout := fs.Duration("direct-timeout", 4*time.Second, "сколько ждать ответ сервера напрямую до отката на туннель")
	freeze := fs.Duration("freeze", 8*time.Second, "auto: поток напрямую замер посреди TLS-записи дольше этого — сайт уходит в туннель (0 = выкл)")
	tunHosts := fs.String("tunnel-hosts", "", "доп. сайты только через туннель: a.com,b.org,1.2.3.0/24 или @файл")
	dirHosts := fs.String("direct-hosts", "", "сайты всегда напрямую: a.com,b.org или @файл")
	debug := fs.Bool("debug", false, "диагностический журнал маршрутизатора: каждое решение, приёмы, тайминги (вкл/выкл на лету: POST /api/debug?on=1|0)")
	doh := fs.String("doh", "1.1.1.1,8.8.8.8,9.9.9.9", "DNS для прямого пути: DoH-серверы по IP; off = системный DNS")
	subsMode := fs.String("subs", "off", "запасной вход из бесплатных подписок: off | reserve (если сервер МАЯК недоступен) | always (всегда через подписки)")
	subFile := fs.String("sub-file", "", "JSON с настройками подписок: {\"disabled\":[…],\"urls\":[…],\"links\":\"…\"}")
	subURLs := fs.String("sub", "", "доп. подписки или ссылки vless://… через запятую")
	subState := fs.String("sub-state", "", "папка для кэша подписок и результатов проверок (по умолчанию mayak-subs рядом с программой)")
	subMax := fs.Int("sub-max", 150, "сколько серверов проверять за один прогон (выборка поровну из подписок)")
	easy := fs.Bool("easy", false, "как двойной щелчок: маршрут auto, подписки reserve, на Windows — системный прокси, subs.json рядом с программой (явно заданные флаги важнее)")
	sysproxy := fs.Bool("sysproxy", false, "Windows: включить системный прокси на время работы (при выходе вернуть как было)")
	if args != nil {
		_ = fs.Parse(args)
	}
	if args == nil || *easy {
		// двойной щелчок: всё, что нужно обычному человеку, без флагов
		if !flagSet(fs, "route") {
			*routeMode = route.ModeAuto
		}
		if !flagSet(fs, "subs") {
			*subsMode = "reserve"
		}
		if !flagSet(fs, "sysproxy") {
			*sysproxy = runtime.GOOS == "windows"
		}
		if *subFile == "" {
			*subFile = besideExe("subs.json")
		}
	}
	consoleUTF8()
	logger := log.New(os.Stderr, "mayak ", log.LstdFlags)

	raw := *linkS
	if raw == "" {
		raw = findLinkFile()
	} else if !strings.HasPrefix(raw, "mayak://") {
		if b, err := os.ReadFile(raw); err == nil {
			raw = firstLink(string(b))
		}
	}
	srcs, links, fileMode := readSubsFile(*subFile, strings.Split(*subURLs, ","))
	if fileMode != "" && !flagSet(fs, "subs") {
		*subsMode = fileMode
	}
	switch *subsMode {
	case "off", "reserve", "always":
	default:
		fmt.Fprintf(os.Stderr, "-subs: %q (нужно off, reserve или always)\n", *subsMode)
		return 2
	}
	if raw == "" && *subsMode == "off" && *routeMode != route.ModeDirect {
		fmt.Fprintln(os.Stderr, "Нет ссылки. Положите файл link.txt со ссылкой mayak://… рядом с программой, укажите -link, или включите -subs always / -route direct.")
		pause(auto)
		return 2
	}
	var c *client.Client
	var opt client.Options
	if raw != "" {
		l, err := protocol.ParseLink(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Ошибка в ссылке:", err)
			pause(auto)
			return 2
		}
		opt = client.Options{Server: l.Server, SNI: l.SNI, Pin: l.Pin, Secret: l.Secret, Fingerprint: l.FP, Mode: l.Mode, Budget: l.Budget, DownWorkers: *down}
		if *mode != "" {
			opt.Mode = *mode
		}
		if *budget > 0 {
			opt.Budget = *budget
		}
		if *fp != "" {
			opt.Fingerprint = *fp
		}
		if *sni != "" {
			opt.SNI = *sni
		}
		if opt.Fingerprint == "" {
			opt.Fingerprint = "chrome"
		}
		if *verbose {
			opt.Log = logger
		}
		if c, err = client.New(opt); err != nil {
			fmt.Fprintln(os.Stderr, err)
			pause(auto)
			return 2
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pl, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Не удалось занять порт прокси:", err)
		pause(auto)
		return 1
	}
	dbg := &atomic.Bool{}
	dbg.Store(*debug)
	logf := func(f string, a ...any) {
		msg := fmt.Sprintf(f, a...)
		if c != nil && !strings.HasPrefix(msg, "[diag]") {
			c.Event("route", msg)
		}
		if *verbose || dbg.Load() {
			logger.Print(msg)
		}
	}
	// события подписок и переключений пишем всегда
	infof := func(f string, a ...any) {
		msg := fmt.Sprintf(f, a...)
		if c != nil {
			c.Event("subs", msg)
		}
		logger.Print(msg)
	}
	ch := &chain{c: c, ctx: ctx, logf: infof}
	ch.via.Store("")
	var tunnel func(net.Conn, string)
	if c != nil || *subsMode != "off" {
		tunnel = ch.Handle
	}
	var rt *route.Router
	if *routeMode != route.ModeTunnel {
		if rt, err = buildRouter(*routeMode, *strat, *dTimeout, *freeze, *tunHosts, *dirHosts, *doh, tunnel, logf, dbg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			pause(auto)
			return 2
		}
		logger.Printf("маршрут: %s, приёмы: %s", rt.Mode(), *strat)
	}
	// служебный «прямой» маршрутизатор: качать подписки с обманом DPI
	helper := rt
	if helper == nil {
		if helper, err = buildRouter(route.ModeDirect, *strat, *dTimeout, 0, "", "", *doh, nil, nil, nil); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	lookup := func(ctx context.Context, h string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, "ip", h)
	}
	if *doh != "" && *doh != "off" {
		lookup = route.NewDoH(route.ReadList(*doh, os.ReadFile)).Lookup
	}
	state := *subState
	if state == "" {
		state = defaultSubsState()
	}
	ch.pool = newPool(state, srcs, links, *subMax, lookup, helper.DialDesync, infof)
	ch.SetMode(*subsMode)
	if *sysproxy {
		if restore, err := setSystemProxy(proxyHostPort(pl.Addr())); err != nil {
			logger.Printf("системный прокси: %v", err)
		} else {
			logger.Printf("системный прокси Windows включён на %s (вернётся как было при закрытии окна)", proxyHostPort(pl.Addr()))
			defer restore()
		}
	}
	handlers := subsAPI(ch, rt, *subFile, strings.Split(*subURLs, ","), *speed, logger)
	handlers["/api/debug"] = debugHandler(dbg, logger)

	if c != nil {
		go c.Run(ctx)
		if rt != nil {
			c.SetRouter(rt.Handle, func() any { return rt.Snapshot() })
		} else {
			c.SetRouter(ch.Handle, nil)
		}
		for p, h := range handlers {
			c.Handle(p, h)
		}
		go func() { _ = c.ServeProxy(ctx, pl) }()
		logger.Printf("МАЯК %s: прокси SOCKS5/HTTP на %s → %s (SNI %s, режим %s, подписки %s)", version, pl.Addr(), opt.Server, c.Snapshot().SNI, opt.Mode, ch.Mode())
	} else {
		h := ch.Handle
		if rt != nil {
			h = rt.Handle
		}
		go func() { _ = client.ServeProxyFunc(ctx, pl, h) }()
		logger.Printf("МАЯК %s: без своего сервера, прокси SOCKS5/HTTP на %s, маршрут %s, подписки %s, приёмы: %s", version, pl.Addr(), *routeMode, ch.Mode(), *strat)
	}
	if *ui != "" {
		ul, err := net.Listen("tcp", *ui)
		if err != nil {
			logger.Printf("панель: %v", err)
		} else {
			if c != nil {
				go func() { _ = c.ServeDashboard(ctx, ul, *speed) }()
			} else {
				snap := func() any { return map[string]string{"mode": route.ModeTunnel} }
				if rt != nil {
					snap = func() any { return rt.Snapshot() }
				}
				go func() { _ = client.ServeMini(ctx, ul, snap, handlers) }()
			}
			url := "http://" + ul.Addr().String() + "/"
			logger.Printf("панель: %s", url)
			if *open {
				go func() { time.Sleep(500 * time.Millisecond); openBrowser(url) }()
			}
		}
	}
	<-ctx.Done()
	return 0
}

func flagSet(fs *flag.FlagSet, name string) (set bool) {
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return
}

func firstLink(s string) string {
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if t := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff")); strings.HasPrefix(t, "mayak://") {
			return t
		}
	}
	return ""
}

func findLinkFile() string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}
	dirs = append(dirs, "/etc/mayak")
	for _, d := range dirs {
		if b, err := os.ReadFile(filepath.Join(d, "link.txt")); err == nil {
			if l := firstLink(string(b)); l != "" {
				return l
			}
		}
	}
	return ""
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}

func pause(auto bool) {
	if auto && runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, "\nНажмите Enter, чтобы закрыть окно.")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
