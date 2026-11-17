package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// countConn считает сырые байты TCP (вместе с TLS-заголовками) —
// именно их видит ТСПУ, когда решает «заморозить» соединение.
type countConn struct {
	net.Conn
	rd, wr atomic.Int64
	stall  time.Duration
}

func (c *countConn) Read(p []byte) (int, error) {
	if c.stall > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.stall))
	}
	n, err := c.Conn.Read(p)
	c.rd.Add(int64(n))
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.wr.Add(int64(n))
	return n, err
}

// legConn — одно TLS-соединение до сервера.
type legConn struct {
	raw  *countConn
	tls  net.Conn
	br   *bufio.Reader
	born time.Time
	legs int
}

func (l *legConn) Close() { _ = l.tls.Close() }

var errStall = errors.New("stall: data stopped flowing (freeze?)")

func helloID(name string) utls.ClientHelloID {
	switch strings.ToLower(name) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "random":
		return utls.HelloRandomized
	case "go", "golang":
		return utls.HelloGolang
	default:
		return utls.HelloChrome_Auto
	}
}

func (c *Client) dial(ctx context.Context) (*legConn, error) { return c.dialSNI(ctx, c.opt.SNI) }

func (c *Client) dialSNI(ctx context.Context, sni string) (*legConn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tc, err := d.DialContext(ctx, "tcp", c.opt.Server)
	if err != nil {
		return nil, err
	}
	cc := &countConn{Conn: tc}
	cfg := &utls.Config{ServerName: sni, NextProtos: []string{"http/1.1"}}
	if c.pin != nil {
		cfg.InsecureSkipVerify = true
		pin := c.pin
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			h := sha256.Sum256(raw[0])
			if !bytes.Equal(h[:], pin) {
				return fmt.Errorf("certificate pin mismatch: %s", hex.EncodeToString(h[:]))
			}
			return nil
		}
	}
	uc := newUClient(cc, cfg, c.opt.Fingerprint)
	// ClientHello оставляем как у настоящего браузера (в т.ч. ALPN h2,http/1.1);
	// сервер предлагает только http/1.1, на нём и договариваемся.
	_ = tc.SetDeadline(time.Now().Add(12 * time.Second))
	if err := uc.HandshakeContext(ctx); err != nil {
		_ = tc.Close()
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	c.st.dials.Add(1)
	return &legConn{raw: cc, tls: uc, br: bufio.NewReaderSize(uc, 32*1024), born: time.Now()}, nil
}

var uas = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
}

const padAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randPad(r *rand.Rand, min, max int) string {
	n := min + r.Intn(max-min+1)
	b := make([]byte, n)
	for i := range b {
		b[i] = padAlphabet[r.Intn(len(padAlphabet))]
	}
	return string(b)
}

// roundTrip отправляет один HTTP/1.1-запрос по соединению и читает ответ.
func (c *Client) roundTrip(l *legConn, method, path, token string, extra map[string]string, body []byte, keep bool, wait time.Duration) (*http.Response, []byte, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Language: ru-RU,ru;q=0.9,en;q=0.8\r\n",
		method, path, c.opt.Host, uas[0])
	fmt.Fprintf(&b, "Cookie: sid=%s; _ym_uid=%s\r\n", token, randPad(r, 8, 120))
	for k, v := range extra {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	if method == http.MethodPost {
		fmt.Fprintf(&b, "Content-Type: application/octet-stream\r\nContent-Length: %d\r\n", len(body))
	}
	if keep {
		b.WriteString("Connection: keep-alive\r\n\r\n")
	} else {
		b.WriteString("Connection: close\r\n\r\n")
	}
	_ = l.raw.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	req := append([]byte(b.String()), body...)
	if _, err := l.tls.Write(req); err != nil {
		return nil, nil, err
	}
	// заголовок ответа может задержаться на время long-poll
	l.raw.stall = wait + c.stall()
	resp, err := http.ReadResponse(l.br, nil)
	if err != nil {
		return nil, nil, wrapStall(err)
	}
	l.raw.stall = c.stall()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	_ = resp.Body.Close()
	l.raw.stall = 0
	_ = l.raw.Conn.SetReadDeadline(time.Time{})
	if err != nil {
		return resp, nil, wrapStall(err)
	}
	if resp.ContentLength >= 0 && int64(len(data)) != resp.ContentLength {
		return resp, nil, io.ErrUnexpectedEOF
	}
	l.legs++
	return resp, data, nil
}

func wrapStall(err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errStall
	}
	return err
}

func hdrOff(resp *http.Response) (uint64, bool) {
	h := resp.Header.Get("X-Off")
	if h == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(h, 10, 64)
	return v, err == nil
}

// Ping — проверка, что сервер МАЯК отвечает (TLS-рукопожатие с ним).
func (c *Client) Ping(ctx context.Context) error {
	l, err := c.dial(ctx)
	if err != nil {
		return err
	}
	l.Close()
	return nil
}
