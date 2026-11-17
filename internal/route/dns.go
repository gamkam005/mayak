package route

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DoH — DNS-over-HTTPS к публичным резолверам по IP (без SNI-имени, которое
// можно заблокировать). Провайдерский DNS для заблокированных сайтов часто
// отдаёт адрес заглушки — тогда «прямой» путь шёл бы не туда.
type DoH struct {
	Servers []string // IP: "1.1.1.1"
	client  *http.Client
	mu      sync.Mutex
	cache   map[string]dnsEntry
}

type dnsEntry struct {
	ips []net.IP
	exp time.Time
}

func NewDoH(servers []string) *DoH {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
	}
	return &DoH{Servers: servers, client: &http.Client{Transport: tr, Timeout: 4 * time.Second}, cache: map[string]dnsEntry{}}
}

// Lookup: сначала DoH (по очереди серверов), при неудаче — системный DNS.
func (d *DoH) Lookup(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	d.mu.Lock()
	if e, ok := d.cache[host]; ok && time.Now().Before(e.exp) {
		d.mu.Unlock()
		return e.ips, nil
	}
	d.mu.Unlock()
	var last error
	for _, s := range d.Servers {
		ips, ttl, err := d.query(ctx, s, host, 1)
		if err == nil && len(ips) == 0 {
			ips, ttl, err = d.query(ctx, s, host, 28)
		}
		if err == nil && len(ips) > 0 {
			if ttl < 60 {
				ttl = 60
			}
			d.mu.Lock()
			d.cache[host] = dnsEntry{ips, time.Now().Add(time.Duration(ttl) * time.Second)}
			d.mu.Unlock()
			return ips, nil
		}
		if err == nil {
			err = errors.New("no addresses")
		}
		last = err
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		if last != nil {
			return nil, last
		}
		return nil, err
	}
	var ips []net.IP
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

func (d *DoH) query(ctx context.Context, server, host string, qtype uint16) ([]net.IP, uint32, error) {
	q := buildQuery(host, qtype)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+server+"/dns-query", bytes.NewReader(q))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, 0, errors.New("doh: " + resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, 0, err
	}
	return parseAnswer(b, qtype)
}

func buildQuery(host string, qtype uint16) []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], 0) // id=0 рекомендуется для DoH
	binary.BigEndian.PutUint16(b[2:], 0x0100)
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, l := range strings.Split(host, ".") {
		if l == "" {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1)
	return b
}

func skipName(b []byte, p int) (int, error) {
	for p < len(b) {
		l := int(b[p])
		switch {
		case l == 0:
			return p + 1, nil
		case l&0xC0 == 0xC0:
			return p + 2, nil
		default:
			p += 1 + l
		}
	}
	return 0, errors.New("dns: bad name")
}

func parseAnswer(b []byte, qtype uint16) ([]net.IP, uint32, error) {
	if len(b) < 12 {
		return nil, 0, errors.New("dns: short")
	}
	if rc := b[3] & 0x0F; rc != 0 {
		return nil, 0, errors.New("dns: rcode " + string(rune('0'+rc)))
	}
	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	p := 12
	var err error
	for i := 0; i < qd; i++ {
		if p, err = skipName(b, p); err != nil {
			return nil, 0, err
		}
		p += 4
	}
	var ips []net.IP
	var ttl uint32 = 3600
	for i := 0; i < an; i++ {
		if p, err = skipName(b, p); err != nil {
			return nil, 0, err
		}
		if p+10 > len(b) {
			break
		}
		t := binary.BigEndian.Uint16(b[p:])
		tl := binary.BigEndian.Uint32(b[p+4:])
		rl := int(binary.BigEndian.Uint16(b[p+8:]))
		p += 10
		if p+rl > len(b) {
			break
		}
		if t == qtype && (rl == 4 || rl == 16) {
			ips = append(ips, net.IP(append([]byte(nil), b[p:p+rl]...)))
			if tl < ttl {
				ttl = tl
			}
		}
		p += rl
	}
	return ips, ttl, nil
}
