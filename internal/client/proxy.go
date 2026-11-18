package client

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ServeProxy принимает на одном порту и SOCKS5, и HTTP-прокси
// (CONNECT и обычные запросы).
func (c *Client) ServeProxy(ctx context.Context, ln net.Listener) error {
	return ServeProxyFunc(ctx, ln, c.openRouted)
}

// ServeRedirect — приём перенаправленных роутером соединений (см. ServeRedirect).
func (c *Client) ServeRedirect(ctx context.Context, ln net.Listener) error {
	return ServeRedirect(ctx, ln, c.openRouted)
}

// OpenFunc связывает принятое соединение приложения с целью "host:port".
type OpenFunc func(conn net.Conn, target string)

// ServeProxyFunc — тот же SOCKS5/HTTP-прокси, но с произвольным обработчиком
// (нужно для режима «только напрямую», где туннеля нет).
func ServeProxyFunc(ctx context.Context, ln net.Listener, open OpenFunc) error {
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
		go handleLocal(conn, open)
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return b.Conn.Close()
}

func handleLocal(conn net.Conn, open OpenFunc) {
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReaderSize(conn, 16*1024)
	first, err := br.Peek(1)
	if err != nil {
		_ = conn.Close()
		return
	}
	if first[0] == 0x05 {
		handleSOCKS(conn, br, open)
		return
	}
	handleHTTP(conn, br, open)
}

func handleSOCKS(conn net.Conn, br *bufio.Reader, open OpenFunc) {
	fail := func() { _ = conn.Close() }
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		fail()
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		fail()
		return
	}
	_, _ = conn.Write([]byte{5, 0}) // без пароля: слушаем по умолчанию только локально
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil || req[0] != 5 {
		fail()
		return
	}
	if req[1] != 1 { // только CONNECT
		_, _ = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		fail()
		return
	}
	var host string
	switch req[3] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			fail()
			return
		}
		host = net.IP(a[:]).String()
	case 3:
		l, err := br.ReadByte()
		if err != nil {
			fail()
			return
		}
		d := make([]byte, l)
		if _, err := io.ReadFull(br, d); err != nil {
			fail()
			return
		}
		host = string(d)
	case 4:
		var a [16]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			fail()
			return
		}
		host = net.IP(a[:]).String()
	default:
		fail()
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		fail()
		return
	}
	port := binary.BigEndian.Uint16(pb[:])
	// Отвечаем «успех» сразу: реальное подключение произойдёт на сервере.
	// Это экономит целый круг туда-обратно (как «fast open» в Xray).
	_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	_ = conn.SetReadDeadline(time.Time{})
	open(&bufConn{Conn: conn, r: br}, net.JoinHostPort(host, strconv.Itoa(int(port))))
}

func handleHTTP(conn net.Conn, br *bufio.Reader, open OpenFunc) {
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if req.Method == http.MethodConnect {
		target := req.Host
		if !strings.Contains(target, ":") {
			target += ":443"
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		open(&bufConn{Conn: conn, r: br}, target)
		return
	}
	if req.URL.Host == "" {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		_ = conn.Close()
		return
	}
	target := req.URL.Host
	if !strings.Contains(target, ":") {
		target += ":80"
	}
	// обычный HTTP: переписываем первую строку в origin-form и отправляем
	// дальше как есть. Следующие запросы в этом же соединении уйдут к тому же хосту.
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.RequestURI = ""
	pr, pw := io.Pipe()
	go func() {
		_ = req.Write(pw) // req.Write пишет origin-form, Host берёт из URL
		_, err := io.Copy(pw, br)
		pw.CloseWithError(err)
	}()
	open(&pipeConn{Conn: conn, r: pr}, target)
}

type pipeConn struct {
	net.Conn
	r *io.PipeReader
}

func (p *pipeConn) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p *pipeConn) Close() error               { _ = p.r.Close(); return p.Conn.Close() }
func (p *pipeConn) CloseWrite() error {
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return p.Conn.Close()
}
