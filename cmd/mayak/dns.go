package main

import (
	"context"
	"net"
	"os"
	"time"
)

// На Android (и в некоторых урезанных системах) нет /etc/resolv.conf, и
// встроенный в Go резолвер обращается к 127.0.0.1:53, где никого нет.
// Тогда используем публичные DNS напрямую (Яндекс в приоритете — он
// доступен и в режиме «белых списков»).
func init() {
	if _, err := os.Stat("/etc/resolv.conf"); err == nil {
		return
	}
	servers := []string{"77.88.8.8:53", "1.1.1.1:53", "8.8.8.8:53"}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			var last error
			for _, s := range servers {
				c, err := d.DialContext(ctx, network, s)
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
}
