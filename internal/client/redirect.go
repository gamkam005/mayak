package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

// ServeRedirect принимает соединения, которые роутер перенаправил сюда через dst-nat
// (MikroTik, OpenWrt), когда исходный адрес назначения уже потерян. Цель берётся из
// самого потока: для TLS — имя из SNI в ClientHello (порт 443), для HTTP — заголовок Host
// (порт 80). Ничего не нужно настраивать внутри контейнера: ни iptables, ни TUN.
func ServeRedirect(ctx context.Context, ln net.Listener, open OpenFunc) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go handleRedirect(conn, open)
	}
}

func handleRedirect(conn net.Conn, open OpenFunc) {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReaderSize(conn, 16*1024+5)
	target, err := sniffTarget(br)
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	open(&bufConn{Conn: conn, r: br}, target)
}

var errNoTarget = errors.New("нет SNI/Host")

// sniffTarget смотрит начало потока, ничего из него не забирая.
func sniffTarget(br *bufio.Reader) (string, error) {
	first, err := br.Peek(1)
	if err != nil {
		return "", err
	}
	if first[0] == 0x16 {
		h, err := br.Peek(5)
		if err != nil {
			return "", err
		}
		n := int(binary.BigEndian.Uint16(h[3:5]))
		if n == 0 || n > 16*1024 {
			return "", errNoTarget
		}
		rec, err := br.Peek(5 + n)
		if err != nil {
			return "", err
		}
		name := ParseSNI(rec[5:])
		if name == "" {
			return "", errNoTarget
		}
		return net.JoinHostPort(name, "443"), nil
	}
	// HTTP: заголовки до пустой строки, не больше буфера; ждём байты по мере прихода
	for n := 1; ; n = br.Buffered() + 1 {
		if n > br.Size() {
			return "", errNoTarget
		}
		if _, err := br.Peek(n); err != nil {
			return "", err
		}
		b, _ := br.Peek(br.Buffered())
		if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
			return hostHeader(b[:i])
		}
	}
}

func hostHeader(hdr []byte) (string, error) {
	lines := strings.Split(string(hdr), "\r\n")
	if len(lines) < 2 || !strings.Contains(lines[0], " HTTP/1.") {
		return "", errNoTarget
	}
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "host") {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" {
			break
		}
		if _, _, err := net.SplitHostPort(v); err == nil {
			return v, nil
		}
		return net.JoinHostPort(strings.Trim(v, "[]"), "80"), nil
	}
	return "", errNoTarget
}

// ParseSNI достаёт server_name из тела TLS-записи с ClientHello ("" — если его нет).
func ParseSNI(b []byte) string {
	// handshake: type(1)=1, len(3), version(2), random(32)
	if len(b) < 38 || b[0] != 1 {
		return ""
	}
	p := 38
	skip := func(lenBytes int) bool {
		if p+lenBytes > len(b) {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(b[p+i])
		}
		p += lenBytes + n
		return p <= len(b)
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return ""
	}
	if p+2 > len(b) {
		return ""
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(b[p:])
		n := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if p+n > end {
			return ""
		}
		if typ == 0 { // server_name
			e := b[p : p+n]
			if len(e) < 5 || e[2] != 0 {
				return ""
			}
			l := int(binary.BigEndian.Uint16(e[3:]))
			if 5+l > len(e) {
				return ""
			}
			name := string(e[5 : 5+l])
			if strings.ContainsAny(name, " /\\:\x00") {
				return ""
			}
			return strings.TrimSuffix(name, ".")
		}
		p += n
	}
	return ""
}
