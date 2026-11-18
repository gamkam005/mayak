package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// FreezeResult — итог проверки «заморозки» на одном TLS-соединении.
type FreezeResult struct {
	Bytes    int64         `json:"bytes"`     // сколько байт TCP пришло
	Body     int64         `json:"body"`      // сколько байт тела
	Target   int64         `json:"target"`    // сколько хотели получить
	Frozen   bool          `json:"frozen"`    // поток замер
	Duration time.Duration `json:"duration_ns"`
	Err      string        `json:"err,omitempty"`
	At       time.Time     `json:"at"`
	StallMs  int64         `json:"stall_ms,omitempty"` // когда пришёл последний байт (если замер)
	Mbps     float64       `json:"mbps,omitempty"`
}

// LastProbe — последняя проба «заморозки» своего сервера (nil — не было).
func (c *Client) LastProbe() *FreezeResult {
	c.probeMu.Lock()
	defer c.probeMu.Unlock()
	if c.lastProbe == nil {
		return nil
	}
	r := *c.lastProbe
	return &r
}

// SetProbeHook — кому сообщать итог каждой пробы (история тестов).
func (c *Client) SetProbeHook(f func(FreezeResult)) {
	c.probeMu.Lock()
	c.probeHook = f
	c.probeMu.Unlock()
}

// ServerAddr — host:port своего сервера.
func (c *Client) ServerAddr() string { return c.opt.Server }

// ProbeFreeze скачивает начало «бандла» сайта-заглушки по ОДНОМУ
// TLS-соединению. Если поток замирает — у провайдера работает
// ограничение по объёму на соединение, и нужна «мозаика».
// Это проба СВОЕГО сервера: она выбирает fast/mosaic для туннеля МАЯК и не
// влияет на оценку узлов из подписок (у тех свой тест загрузки, sub.dlTest).
func (c *Client) ProbeFreeze(ctx context.Context, want int64) FreezeResult {
	res := c.probeFreeze(ctx, want)
	if res.Frozen && res.Duration > 5*time.Second {
		res.StallMs = (res.Duration - 5*time.Second).Milliseconds()
	}
	if s := res.Duration.Seconds(); s > 0 && res.Body > 0 {
		end := s
		if res.StallMs > 0 {
			end = float64(res.StallMs) / 1000
		}
		if end > 0 {
			res.Mbps = float64(res.Body) * 8 / 1e6 / end
		}
	}
	c.probeMu.Lock()
	r := res
	c.lastProbe = &r
	hook := c.probeHook
	c.probeMu.Unlock()
	if hook != nil {
		hook(res)
	}
	return res
}

func (c *Client) probeFreeze(ctx context.Context, want int64) FreezeResult {
	t0 := time.Now()
	res := FreezeResult{Target: want, At: t0}
	l, err := c.dial(ctx)
	if err != nil {
		res.Err = err.Error()
		res.Duration = time.Since(t0)
		return res
	}
	defer l.Close()
	req := fmt.Sprintf("GET /static/app.js HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Language: ru-RU,ru;q=0.9\r\nConnection: close\r\n\r\n", c.opt.Host, uas[0])
	if _, err := l.tls.Write([]byte(req)); err != nil {
		res.Err = err.Error()
		return res
	}
	l.raw.stall = 5 * time.Second
	resp, err := http.ReadResponse(l.br, nil)
	if err == nil {
		res.Body, err = io.CopyN(io.Discard, resp.Body, want)
		_ = resp.Body.Close()
	}
	res.Bytes = l.raw.rd.Load()
	res.Duration = time.Since(t0)
	if err != nil && !errors.Is(err, io.EOF) {
		if errors.Is(wrapStall(err), errStall) {
			res.Frozen = true
		}
		res.Err = err.Error()
	}
	return res
}

// autoLoop — режим auto: периодически проверяет, режет ли сеть длинные
// соединения, и выбирает fast или mosaic.
func (c *Client) autoLoop(ctx context.Context) {
	sleepCtx(ctx, 800*time.Millisecond)
	for ctx.Err() == nil {
		r := c.ProbeFreeze(ctx, 256<<10)
		switch {
		case r.Frozen:
			budget := c.Budget()
			// подстраиваемся под реальный порог: 75% от того, что успело пройти
			if b := int(float64(r.Bytes) * 0.75); b < budget {
				budget = b
			}
			c.setProfile(mosaicProfile(budget), fmt.Sprintf("проба: поток замер после %d байт", r.Bytes))
			c.events.add("probe", fmt.Sprintf("заморозка обнаружена: прошло %d байт за %s", r.Bytes, r.Duration.Round(time.Millisecond)))
		case r.Err == "" && r.Body >= r.Target:
			c.setProfile(fastProfile, "проба: 256 КБ по одному соединению прошли без задержек")
			c.events.add("probe", fmt.Sprintf("заморозки нет: 256 КБ за %s", r.Duration.Round(time.Millisecond)))
		default:
			c.events.add("probe", "проба не удалась: "+r.Err)
		}
		sleepCtx(ctx, 10*time.Minute)
	}
}
