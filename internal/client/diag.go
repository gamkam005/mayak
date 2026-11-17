package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DialTunnel открывает TCP-поток к addr через туннель (для тестов и
// встроенного замера скорости).
func (c *Client) DialTunnel(_ context.Context, _ string, addr string) (net.Conn, error) {
	a, b := net.Pipe()
	c.Open(b, addr)
	return a, nil
}

// Check — одна строка отчёта диагностики.
type Check struct {
	Group  string `json:"group"`
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail | info
	Detail string `json:"detail"`
	Ms     int64  `json:"ms"`
}

type DiagReport struct {
	Started  int64    `json:"started"`
	Checks   []Check  `json:"checks"`
	Verdict  []string `json:"verdict"`
	Advice   string   `json:"advice"`
	Duration int64    `json:"duration_ms"`
}

// siteProbe — прямое (мимо туннеля) скачивание начала страницы по TLS.
// Возвращает: ok, frozen, blocked (рукопожатие не прошло), err.
func siteProbe(ctx context.Context, host string, want int64) (string, int64, time.Duration, string) {
	t0 := time.Now()
	d := net.Dialer{Timeout: 6 * time.Second}
	tc, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return "ip", 0, time.Since(t0), err.Error()
	}
	cc := &countConn{Conn: tc}
	defer tc.Close()
	// для эталонных сайтов отпечаток не важен, важен объём: просим http/1.1
	uc := tls.Client(cc, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
	_ = tc.SetDeadline(time.Now().Add(7 * time.Second))
	if err := uc.HandshakeContext(ctx); err != nil {
		return "tls", cc.rd.Load(), time.Since(t0), err.Error()
	}
	_ = tc.SetDeadline(time.Time{})
	fmt.Fprintf(uc, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", host, uas[0])
	cc.stall = 5 * time.Second
	n, err := io.CopyN(io.Discard, uc, want)
	if err != nil && !errors.Is(err, io.EOF) {
		if errors.Is(wrapStall(err), errStall) {
			return "frozen", cc.rd.Load(), time.Since(t0), "поток замер"
		}
		if n > 0 {
			return "ok", cc.rd.Load(), time.Since(t0), ""
		}
		return "err", cc.rd.Load(), time.Since(t0), err.Error()
	}
	return "ok", cc.rd.Load(), time.Since(t0), ""
}

// RunDiag выполняет весь набор проверок.
func (c *Client) RunDiag(ctx context.Context, speedURL string) DiagReport {
	t0 := time.Now()
	rep := DiagReport{Started: t0.Unix()}
	add := func(ch Check) { rep.Checks = append(rep.Checks, ch) }

	// 1. IP сервера
	ts := time.Now()
	tc, err := net.DialTimeout("tcp", c.opt.Server, 6*time.Second)
	ipOK := err == nil
	if ipOK {
		_ = tc.Close()
		add(Check{"Сервер", "TCP до " + c.opt.Server, "ok", "порт открыт", time.Since(ts).Milliseconds()})
	} else {
		add(Check{"Сервер", "TCP до " + c.opt.Server, "fail", "нет ответа — похоже на блокировку IP: " + err.Error(), time.Since(ts).Milliseconds()})
	}

	// 2. SNI-перебор к нашему серверу
	sniOK := map[string]bool{}
	if ipOK {
		snis := uniq([]string{c.opt.SNI, "ya.ru", "vk.com", "max.ru", "www.google.com", "telegram.org", randomName()})
		var wg sync.WaitGroup
		var mu sync.Mutex
		res := make([]Check, len(snis))
		for i, sni := range snis {
			wg.Add(1)
			go func(i int, sni string) {
				defer wg.Done()
				ts := time.Now()
				l, err := c.dialSNI(ctx, sni)
				ch := Check{"SNI", "рукопожатие с SNI " + sni, "ok", "проходит", time.Since(ts).Milliseconds()}
				if err != nil {
					ch.Status, ch.Detail = "fail", "режется: "+short(err)
				} else {
					l.Close()
				}
				if sni == c.opt.SNI {
					ch.Name += " (ваш)"
				}
				mu.Lock()
				sniOK[sni] = err == nil
				res[i] = ch
				mu.Unlock()
			}(i, sni)
		}
		wg.Wait()
		for _, r := range res {
			add(r)
		}
	}

	// 3. Заморозка по объёму
	var fr FreezeResult
	if ipOK && sniOK[c.opt.SNI] {
		fr = c.ProbeFreeze(ctx, 512<<10)
		switch {
		case fr.Frozen:
			add(Check{"Заморозка", "512 КБ по одному соединению", "fail", fmt.Sprintf("поток замер после %d байт — нужна мозаика", fr.Bytes), fr.Duration.Milliseconds()})
		case fr.Err == "":
			add(Check{"Заморозка", "512 КБ по одному соединению", "ok", fmt.Sprintf("прошло целиком (%.1f Мбит/с)", mbps(fr.Body, fr.Duration)), fr.Duration.Milliseconds()})
		default:
			add(Check{"Заморозка", "512 КБ по одному соединению", "warn", fr.Err, fr.Duration.Milliseconds()})
		}
	}

	// 4. Эталонные сайты напрямую (мимо туннеля)
	refs := []struct{ host, kind string }{
		{"ya.ru", "ru"}, {"vk.com", "ru"}, {"www.gosuslugi.ru", "ru"},
		{"www.google.com", "foreign"}, {"github.com", "foreign"}, {"www.wikipedia.org", "foreign"},
	}
	type rr struct {
		kind, st string
	}
	var refRes []rr
	var wg sync.WaitGroup
	var mu sync.Mutex
	rc := make([]Check, len(refs))
	for i, r := range refs {
		wg.Add(1)
		go func(i int, host, kind string) {
			defer wg.Done()
			st, n, d, e := siteProbe(ctx, host, 96<<10)
			ch := Check{Group: "Сайты напрямую", Name: host, Ms: d.Milliseconds()}
			switch st {
			case "ok":
				ch.Status, ch.Detail = "ok", fmt.Sprintf("открывается (%d КБ)", n/1024)
			case "frozen":
				ch.Status, ch.Detail = "fail", fmt.Sprintf("замер после %d байт", n)
			case "tls":
				ch.Status, ch.Detail = "fail", "TLS-рукопожатие сорвано: "+short(errors.New(e))
			case "ip":
				ch.Status, ch.Detail = "fail", "нет TCP: "+short(errors.New(e))
			default:
				ch.Status, ch.Detail = "warn", e
			}
			mu.Lock()
			rc[i] = ch
			refRes = append(refRes, rr{kind, st})
			mu.Unlock()
		}(i, r.host, r.kind)
	}
	wg.Wait()
	for _, r := range rc {
		add(r)
	}

	// 5. UDP (DNS-запрос) — косвенно про QUIC/WireGuard/Hysteria
	for _, ns := range []string{"77.88.8.8:53", "1.1.1.1:53"} {
		ts := time.Now()
		ok, e := udpDNS(ns)
		ch := Check{"UDP", "DNS по UDP к " + ns, "ok", "UDP ходит", time.Since(ts).Milliseconds()}
		if !ok {
			ch.Status, ch.Detail = "warn", "нет ответа: "+e
		}
		add(ch)
	}

	// 6. Сквозной тест через туннель
	if ipOK && sniOK[c.opt.SNI] && speedURL != "" {
		ts := time.Now()
		n, err := c.tunnelSpeed(ctx, speedURL)
		d := time.Since(ts)
		if err != nil && n == 0 {
			add(Check{"Туннель", "скачивание через МАЯК", "fail", short(err), d.Milliseconds()})
		} else {
			add(Check{"Туннель", "скачивание через МАЯК", "ok", fmt.Sprintf("%.1f МБ за %.1f с = %.1f Мбит/с (режим %s)", float64(n)/1e6, d.Seconds(), mbps(n, d), c.Profile().Name), d.Milliseconds()})
		}
	}

	// Вердикт
	ruOK, foreignBad, foreignN := 0, 0, 0
	for _, r := range refRes {
		if r.kind == "ru" && r.st == "ok" {
			ruOK++
		}
		if r.kind == "foreign" {
			foreignN++
			if r.st != "ok" {
				foreignBad++
			}
		}
	}
	switch {
	case !ipOK:
		rep.Verdict = append(rep.Verdict, "IP сервера недоступен — нужен другой VPS/подсеть (смена протокола не поможет).")
	case !sniOK[c.opt.SNI]:
		rep.Verdict = append(rep.Verdict, "Ваш SNI режется. Возьмите из таблицы тот, что проходит, и пропишите в ссылке (sni=...).")
	}
	if fr.Frozen {
		rep.Verdict = append(rep.Verdict, fmt.Sprintf("Работает «заморозка» длинных соединений (~%d КБ). Режим mosaic её обходит.", fr.Bytes/1024))
	} else if fr.Err == "" && fr.Body > 0 {
		rep.Verdict = append(rep.Verdict, "Заморозки на этом сервере нет — можно быстрый режим (fast).")
	}
	if ruOK >= 2 && foreignN > 0 && foreignBad == foreignN {
		rep.Verdict = append(rep.Verdict, "Российские сайты открываются, все зарубежные — нет. Похоже на режим «белых списков».")
	}
	if len(rep.Verdict) == 0 {
		rep.Verdict = append(rep.Verdict, "Явных ограничений не найдено.")
	}
	switch {
	case !ipOK:
		rep.Advice = "Смените IP сервера."
	case fr.Frozen:
		rep.Advice = "Оставьте режим auto или mosaic."
	default:
		rep.Advice = "Режим auto сам выберет fast."
	}
	rep.Duration = time.Since(t0).Milliseconds()
	return rep
}

func (c *Client) tunnelSpeed(ctx context.Context, url string) (int64, error) {
	tr := &http.Transport{
		DialContext:       c.DialTunnel,
		TLSClientConfig:   &tls.Config{},
		ForceAttemptHTTP2: false,
	}
	hc := &http.Client{Transport: tr, Timeout: 40 * time.Second}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return io.Copy(io.Discard, resp.Body)
}

func udpDNS(ns string) (bool, string) {
	conn, err := net.DialTimeout("udp", ns, 3*time.Second)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()
	// запрос A ya.ru
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, 'y', 'a', 2, 'r', 'u', 0, 0, 1, 0, 1}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(q); err != nil {
		return false, err.Error()
	}
	b := make([]byte, 512)
	n, err := conn.Read(b)
	if err != nil {
		return false, short(err)
	}
	return n > 12 && b[0] == 0x12 && b[1] == 0x34, ""
}

func mbps(n int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) * 8 / d.Seconds() / 1e6
}

func short(err error) string {
	s := err.Error()
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "reset"):
		return "сброс соединения (RST)"
	case strings.Contains(l, "refused"):
		return "отказ в подключении"
	case strings.Contains(l, "timeout") || strings.Contains(l, "deadline"):
		return "таймаут — ответа нет"
	case strings.Contains(l, "eof"):
		return "соединение закрыли посреди обмена"
	case strings.Contains(l, "no such host"):
		return "домен не найден (DNS)"
	case strings.Contains(l, "certificate"):
		return "сертификат не тот (подмена?)"
	}
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 80 {
		s = s[i+2:]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func randomName() string {
	return fmt.Sprintf("x%d.example-test.net", time.Now().UnixNano()%100000)
}
