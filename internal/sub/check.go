package sub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// DefaultTestURL — «реальная задержка» как в v2rayN: HTTP 204 через сервер.
const DefaultTestURL = "http://www.gstatic.com/generate_204"

// DefaultOpenURL — второй тест: открывает ли сервер то, что заблокировано
// в РФ (выходы в Иране, Китае или «белых» подсетях РФ это не умеют).
const DefaultOpenURL = "https://www.instagram.com/favicon.ico"

// tcpPing — время TCP-рукопожатия до сервера.
func tcpPing(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	d := net.Dialer{Timeout: timeout}
	t := time.Now()
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	_ = c.Close()
	return time.Since(t), nil
}

// probe — запрос testURL через движок; возвращает время до ответа.
func probe(ctx context.Context, e *Engine, testURL string, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tr := &http.Transport{
		DialContext:       func(ctx context.Context, _, addr string) (net.Conn, error) { return e.Dial(ctx, addr) },
		DisableKeepAlives: true, ResponseHeaderTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	t := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return time.Since(t), nil
}

// SpeedTest — скачать до limit байт через движок, Мбит/с.
func SpeedTest(ctx context.Context, e *Engine, url string, limit int64, timeout time.Duration) (float64, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return e.Dial(ctx, addr) }}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	t := time.Now()
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	n, err := io.CopyN(io.Discard, resp.Body, limit)
	el := time.Since(t).Seconds()
	if n == 0 {
		if err == nil {
			err = errors.New("пусто")
		}
		return 0, 0, err
	}
	return float64(n) * 8 / 1e6 / el, n, nil
}

// parallel — f(i) для i<n не больше k одновременно; стоп по ctx.
func parallel(ctx context.Context, n, k int, f func(i int)) {
	sem := make(chan struct{}, k)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			f(i)
		}(i)
	}
	wg.Wait()
}
