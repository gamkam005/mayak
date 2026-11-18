package sub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Тест «заморозки» узла: после короткой проверки (generate_204) качаем через
// узел 256 КБ по ОДНОМУ соединению. ТСПУ замораживает соединения с сетями
// многих хостингов примерно после 16 КБ (~25 пакетов дома, ~8 в мобильной
// сети): короткий запрос проходит, а настоящая загрузка встаёт. Поэтому
// «отвечает» (probe ok) и «реально качает» — разные состояния.

// DefaultFreezeURL — откуда качать; {bytes} заменяется размером.
const DefaultFreezeURL = "https://speed.cloudflare.com/__down?bytes={bytes}"

const (
	FreezeSmall  = 256 << 10 // плановый тест
	FreezeLarge  = 3 << 20   // по кнопке в панели
	frozenBelow  = 64 << 10  // встал раньше — «заморожен»
	slowMbps     = 0.2       // докачал, но медленнее — «медленный»
	stallTimeout = 5 * time.Second
)

// Статусы узла (Result.Status).
const (
	StatusDead      = "dead"      // generate_204 не прошёл
	StatusReachable = "reachable" // отвечает, но загрузку проверить не вышло (или не проверяли)
	StatusWorking   = "working"   // загрузка прошла
	StatusSlow      = "slow"      // больше 64 КБ, но не до конца / очень медленно
	StatusFrozen    = "frozen"    // поток встал раньше 64 КБ — похоже на ТСПУ
)

// DL — итог одной загрузки через узел.
type DL struct {
	At      time.Time `json:"at"`
	Target  int64     `json:"target"`        // сколько хотели
	Bytes   int64     `json:"bytes"`         // сколько пришло (тело)
	TTFB    int       `json:"ttfb_ms"`       // до первого байта тела
	StallMs int       `json:"stall_ms"`      // время до последнего пришедшего байта (если встал)
	TotalMs int       `json:"total_ms"`      // сколько длился тест
	Mbps    float64   `json:"mbps"`          // средняя скорость
	Stalled bool      `json:"stalled"`       // поток замер (не оборвался, а встал)
	Err     string    `json:"err,omitempty"` // ошибка, если была
	Class   string    `json:"class"`         // working | slow | frozen | reachable
}

func freezeURL(tpl string, n int64) string {
	if strings.Contains(tpl, "{bytes}") {
		return strings.ReplaceAll(tpl, "{bytes}", fmt.Sprint(n))
	}
	return tpl
}

// firstWait — сколько ждать первый байт: соединение через медленный узел и
// TLS до сайта занимают несколько его «задержек».
func firstWait(delay time.Duration) time.Duration {
	return min(max(3*delay+stallTimeout, 10*time.Second), 20*time.Second)
}

// dlTest — скачать target байт через dial одним соединением. Поток, который
// после первого байта stall не приносит ни байта (или не дал первого байта
// за first), считается замершим.
func dlTest(ctx context.Context, dial func(ctx context.Context, addr string) (net.Conn, error), url string, target int64, stall, first, timeout time.Duration) DL {
	res := DL{At: time.Now(), Target: target}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last atomic.Int64 // UnixNano последнего прогресса
	t0 := time.Now()
	last.Store(t0.UnixNano())
	var stalled, got atomic.Bool
	done := make(chan struct{})
	defer close(done)
	go func() {
		tk := time.NewTicker(200 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-tk.C:
				lim := stall
				if !got.Load() {
					lim = first
				}
				if time.Since(time.Unix(0, last.Load())) > lim {
					stalled.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	tr := &http.Transport{
		DialContext:       func(ctx context.Context, _, addr string) (net.Conn, error) { return dial(ctx, addr) },
		DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSHandshakeTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Err, res.Class = err.Error(), StatusReachable
		return res
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	var firstAt time.Time
	if err == nil {
		if resp.StatusCode >= 400 {
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		} else {
			buf := make([]byte, 32<<10)
			for res.Bytes < target {
				n, e := resp.Body.Read(buf)
				if n > 0 {
					if firstAt.IsZero() {
						firstAt = time.Now()
						got.Store(true)
					}
					res.Bytes += int64(n)
					last.Store(time.Now().UnixNano())
				}
				if e != nil {
					if !errors.Is(e, io.EOF) {
						err = e
					}
					break
				}
			}
		}
		_ = resp.Body.Close()
	}
	end := time.Unix(0, last.Load())
	if !firstAt.IsZero() {
		res.TTFB = ms(firstAt.Sub(t0))
	}
	res.TotalMs = ms(time.Since(t0))
	el := end.Sub(t0).Seconds()
	if el > 0 && res.Bytes > 0 {
		res.Mbps = float64(res.Bytes) * 8 / 1e6 / el
	}
	res.Stalled = stalled.Load() || (err != nil && errors.Is(err, context.DeadlineExceeded) && res.Bytes < target)
	if res.Stalled {
		res.StallMs = max(1, ms(end.Sub(t0)))
	}
	if err != nil {
		res.Err = shortErr(err)
	}
	if res.Stalled {
		if res.Bytes == 0 {
			res.Err = fmt.Sprintf("ни байта за %.0f с", time.Since(t0).Seconds())
		} else {
			res.Err = fmt.Sprintf("поток встал на %d байтах", res.Bytes)
		}
	}
	res.Class = classify(res)
	return res
}

func classify(d DL) string {
	switch {
	case d.Bytes >= d.Target && d.Mbps >= slowMbps:
		return StatusWorking
	case d.Bytes >= d.Target:
		return StatusSlow
	case d.Bytes < frozenBelow && d.Stalled:
		return StatusFrozen
	case d.Bytes >= frozenBelow:
		return StatusSlow
	}
	return StatusReachable // оборвалось без «заморозки» (HTTP-ошибка, сброс) — не судим
}

// better — какой из двух результатов теста лучше (для повторных попыток).
func better(a, b DL) DL {
	rank := map[string]int{StatusWorking: 3, StatusSlow: 2, StatusReachable: 1, StatusFrozen: 0}
	if rank[b.Class] > rank[a.Class] || (rank[b.Class] == rank[a.Class] && b.Bytes > a.Bytes) {
		return b
	}
	return a
}

// statusOf — итоговый статус узла по результату проверки.
func statusOf(r *Result) string {
	switch {
	case (r.Checked.IsZero() || r.Err == errQueue) && !r.OK:
		return ""
	case !r.OK:
		return StatusDead
	case r.DL == nil:
		return StatusReachable
	}
	return r.DL.Class
}

// HistEntry — запись истории тестов (freeze-history.json).
type HistEntry struct {
	DL
	Node string `json:"node"`           // id узла или "own"
	Name string `json:"name,omitempty"` // имя узла
	IP   string `json:"ip,omitempty"`
	ASN  uint32 `json:"asn,omitempty"`
	Kind string `json:"kind"` // auto | button | own
}

const histMax = 1000
