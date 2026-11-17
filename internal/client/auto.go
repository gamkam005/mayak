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
}

// ProbeFreeze скачивает начало «бандла» сайта-заглушки по ОДНОМУ
// TLS-соединению. Если поток замирает — у провайдера работает
// ограничение по объёму на соединение, и нужна «мозаика».
func (c *Client) ProbeFreeze(ctx context.Context, want int64) FreezeResult {
	t0 := time.Now()
	res := FreezeResult{Target: want}
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
			budget := c.opt.Budget
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
