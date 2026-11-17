// Package route решает, как пустить каждое соединение: напрямую с
// обманом DPI (быстро, без сервера) или через туннель МАЯКа.
package route

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mayak/internal/desync"
)

const (
	ModeTunnel = "tunnel" // всё через туннель (как раньше)
	ModeDirect = "direct" // всё напрямую с обманом DPI, без сервера
	ModeAuto   = "auto"   // сначала напрямую, не вышло — туннель
)

type Config struct {
	Mode           string
	Strategies     []desync.Strategy // по очереди для каждого сайта
	ConnectTimeout time.Duration     // TCP connect напрямую
	Timeout        time.Duration     // ждать первый ответ сервера
	FirstWait      time.Duration     // ждать первый пакет от приложения
	OKTTL          time.Duration     // помнить «напрямую работает»
	FailTTL        time.Duration     // помнить «только туннель»
	Freeze         time.Duration     // 0 = не ловить заморозку посреди TLS-записи
	TunnelHosts    []string          // всегда туннель (суффиксы доменов, IP, CIDR)
	DirectHosts    []string          // всегда напрямую
	Lookup         func(ctx context.Context, host string) ([]net.IP, error)
	Tunnel         func(conn net.Conn, target string) // nil = туннеля нет
	Logf           func(format string, args ...any)
	Debug          *atomic.Bool // подробный журнал каждого решения (вкл/выкл на лету)
}

// Встроенный список: сервисы, заблокированные в РФ по IP — обман DPI не поможет.
var DefaultTunnelHosts = []string{
	"instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "fb.com", "messenger.com",
	"twitter.com", "x.com", "twimg.com", "t.co",
	"linkedin.com", "licdn.com",
	"telegram.org", "t.me", "telegra.ph", "telesco.pe", "cdn-telegram.org",
	"149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22",
	"91.108.20.0/22", "91.108.56.0/22", "95.161.64.0/20", "185.76.151.0/24",
	"2001:67c:4e8::/48", "2001:b28:f23d::/48", "2001:b28:f23f::/48",
}

// Российские зоны: напрямую и без хитростей (им туннель только вредит).
var plainSuffixes = []string{"ru", "su", "xn--p1ai", "yandex.net", "yandex.com", "vk.com", "userapi.com", "mail.ru", "max.ru"}

type entry struct {
	strat    int       // какую стратегию пробовать
	tunnel   time.Time // до этого момента — только туннель
	okUntil  time.Time
	ok, fail int
	last     string
}

type Router struct {
	cfg    Config
	mu     sync.Mutex
	cache  map[string]*entry
	tun    []matcher
	dir    []matcher
	strats atomic.Pointer[[]desync.Strategy]

	nDirect, nFallback, nTunnel, nFail, nFreeze atomic.Int64
}

func New(cfg Config) *Router {
	if cfg.Mode == "" {
		cfg.Mode = ModeTunnel
	}
	if len(cfg.Strategies) == 0 {
		cfg.Strategies, _ = desync.ParseList(DefaultStrategies)
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 4 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 4 * time.Second
	}
	if cfg.FirstWait == 0 {
		cfg.FirstWait = 400 * time.Millisecond
	}
	if cfg.OKTTL == 0 {
		cfg.OKTTL = 30 * time.Minute
	}
	if cfg.FailTTL == 0 {
		cfg.FailTTL = 15 * time.Minute
	}
	if cfg.Lookup == nil {
		cfg.Lookup = func(ctx context.Context, h string) ([]net.IP, error) {
			a, err := net.DefaultResolver.LookupIP(ctx, "ip", h)
			return a, err
		}
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Debug == nil {
		cfg.Debug = &atomic.Bool{}
	}
	if cfg.Tunnel == nil && cfg.Mode == ModeAuto {
		cfg.Mode = ModeDirect
	}
	r := &Router{cfg: cfg, cache: map[string]*entry{}}
	r.SetStrategies(cfg.Strategies)
	r.tun = parseMatchers(cfg.TunnelHosts)
	r.dir = parseMatchers(cfg.DirectHosts)
	return r
}

// Strategies — текущий список приёмов.
func (r *Router) Strategies() []desync.Strategy { return *r.strats.Load() }

// SetStrategies — сменить приёмы на лету (без переподключения). Запомненные
// для сайтов индексы сбрасываются: порядок мог поменяться.
func (r *Router) SetStrategies(sts []desync.Strategy) {
	if len(sts) == 0 {
		sts, _ = desync.ParseList(DefaultStrategies)
	}
	cp := append([]desync.Strategy{}, sts...)
	r.strats.Store(&cp)
	r.mu.Lock()
	for _, e := range r.cache {
		e.strat = 0
	}
	r.mu.Unlock()
}

// DialDesync — TCP-соединение «напрямую», где первая запись (ClientHello)
// уходит первым приёмом обмана DPI. Для своих служебных запросов (подписки).
func (r *Router) DialDesync(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	c, err := r.dial(host, port)
	if err != nil {
		return nil, err
	}
	st := r.Strategies()[0]
	if isPlain(host) || isLocal(host) {
		st, _ = desync.ParseStrategy("none")
	}
	return &desyncConn{TCPConn: c, st: st}, nil
}

type desyncConn struct {
	*net.TCPConn
	st   desync.Strategy
	sent bool
}

func (d *desyncConn) Write(b []byte) (int, error) {
	if d.sent {
		return d.TCPConn.Write(b)
	}
	d.sent = true
	if _, err := d.st.Send(d.TCPConn, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// DefaultStrategies — от самой мягкой к самой хитрой.
const DefaultStrategies = "tlsrec+split,tlsrec+disorder,tlsrec+fake,oob"

func (r *Router) Mode() string { return r.cfg.Mode }

// SetDebug включает/выключает подробный журнал.
func (r *Router) SetDebug(on bool) { r.cfg.Debug.Store(on) }
func (r *Router) DebugOn() bool    { return r.cfg.Debug.Load() }

func (r *Router) dbg(format string, a ...any) {
	if r.cfg.Debug.Load() {
		r.cfg.Logf("[diag] "+format, a...)
	}
}

type matcher struct {
	suffix string
	ipnet  *net.IPNet
}

func parseMatchers(list []string) []matcher {
	var out []matcher
	for _, s := range list {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, matcher{ipnet: n})
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, matcher{ipnet: &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}})
			continue
		}
		out = append(out, matcher{suffix: strings.TrimPrefix(s, ".")})
	}
	return out
}

func match(ms []matcher, names ...string) bool {
	for _, n := range names {
		if n == "" {
			continue
		}
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		ip := net.ParseIP(n)
		for _, m := range ms {
			if m.ipnet != nil {
				if ip != nil && m.ipnet.Contains(ip) {
					return true
				}
			} else if ip == nil && (n == m.suffix || strings.HasSuffix(n, "."+m.suffix)) {
				return true
			}
		}
	}
	return false
}

func isPlain(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, s := range plainSuffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

func isLocal(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return host == "localhost"
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || cgnat.Contains(ip) || bench.Contains(ip)
}

// 100.64/10 (CGNAT, фейковые адреса mapdns) и 198.18/15 (адреса VPN-интерфейса)
var _, cgnat, _ = net.ParseCIDR("100.64.0.0/10")
var _, bench, _ = net.ParseCIDR("198.18.0.0/15")

func (r *Router) entry(key string) *entry {
	e := r.cache[key]
	if e == nil {
		e = &entry{}
		r.cache[key] = e
	}
	return e
}

// prefixConn — сначала отдаёт уже прочитанные байты, потом читает из сокета.
type prefixConn struct {
	net.Conn
	pre []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.pre) > 0 {
		n := copy(b, p.pre)
		p.pre = p.pre[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func (p *prefixConn) CloseWrite() error {
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return p.Conn.Close()
}

// Handle обслуживает одно соединение приложения до target ("host:port").
// Ответ «успех» приложению уже отправлен, поэтому выбор пути (и откат на
// туннель) для него незаметен: пока сервер не ответил, приложению ничего
// не передаётся, и первый пакет можно повторить в туннеле.
func (r *Router) Handle(conn net.Conn, target string) {
	sts := r.Strategies()
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		_ = conn.Close()
		return
	}
	if r.cfg.Mode == ModeTunnel || (r.cfg.Mode == ModeAuto && match(r.tun, host)) {
		r.dbg("%s → туннель (%s)", target, map[bool]string{true: "режим tunnel", false: "в списке блокировок по IP"}[r.cfg.Mode == ModeTunnel])
		r.tunnel(conn, target, nil, "")
		return
	}
	if isLocal(host) {
		r.dbg("%s → напрямую без хитростей (локальный адрес)", target)
		r.direct(conn, host, port, nil, desync.Strategy{Method: "none"}, false)
		return
	}
	r.mu.Lock()
	if e := r.cache[host]; e != nil && r.cfg.Mode == ModeAuto && time.Now().Before(e.tunnel) {
		left := time.Until(e.tunnel).Round(time.Second)
		r.mu.Unlock()
		r.dbg("%s → туннель (запомнено, ещё %s)", target, left)
		r.tunnel(conn, target, nil, "")
		return
	}
	r.mu.Unlock()

	first := readFirst(conn, r.cfg.FirstWait)
	name := host
	if desync.IsTLSHello(first) {
		if h, err := desync.ParseHello(first); err == nil && h.SNI != "" {
			name = h.SNI
		}
	}
	r.dbg("%s: первый пакет %d Б, имя %q", target, len(first), name)
	if r.cfg.Mode == ModeAuto && match(r.tun, name, host) {
		r.dbg("%s → туннель (%s в списке блокировок по IP)", target, name)
		r.tunnel(conn, target, first, name)
		return
	}
	forced := match(r.dir, name, host)
	if isPlain(name) {
		r.dbg("%s → напрямую без хитростей (российская зона)", name)
		r.direct(conn, host, port, first, desync.Strategy{Method: "none"}, false)
		return
	}
	r.mu.Lock()
	e := r.entry(name)
	idx := e.strat % len(sts)
	r.mu.Unlock()

	tries := 1
	if r.cfg.Mode == ModeDirect || forced || r.cfg.Tunnel == nil {
		tries = len(sts)
	}
	for i := 0; i < tries; i++ {
		st := sts[(idx+i)%len(sts)]
		t0 := time.Now()
		up, resp, rep, err := r.try(host, port, first, st)
		if err == nil {
			r.dbg("%s: напрямую OK приёмом %s за %d мс; сегменты %v, ответ %d Б%s", name, st, time.Since(t0).Milliseconds(), rep.Segments, len(resp), noteStr(rep.Note))
			r.mu.Lock()
			e.strat = (idx + i) % len(sts)
			e.ok++
			e.okUntil = time.Now().Add(r.cfg.OKTTL)
			e.last = "direct " + st.String()
			r.mu.Unlock()
			r.nDirect.Add(1)
			if rep.Note != "" {
				r.cfg.Logf("route %s: %s (%s)", name, st, rep.Note)
			}
			r.pipe(conn, up, resp, name, rep.Plan.Proto == "tls")
			return
		}
		r.cfg.Logf("route %s: напрямую (%s) не вышло за %d мс: %v", name, st, time.Since(t0).Milliseconds(), err)
		r.dbg("%s: сегменты %v%s", name, rep.Segments, noteStr(rep.Note))
		r.mu.Lock()
		e.fail++
		e.last = "fail " + st.String() + ": " + err.Error()
		var ce *connectErr
		if errors.As(err, &ce) || i+1 >= len(sts) || (idx+i+1)%len(sts) == 0 {
			// IP недоступен или все приёмы перепробованы — сайту нужен туннель
			e.tunnel = time.Now().Add(r.cfg.FailTTL)
		}
		e.strat = (idx + i + 1) % len(sts)
		r.mu.Unlock()
		if errors.As(err, &ce) && r.cfg.Tunnel == nil {
			break
		}
	}
	if r.cfg.Tunnel != nil && r.cfg.Mode == ModeAuto && !forced {
		r.dbg("%s → откат в туннель", name)
		r.nFallback.Add(1)
		r.tunnel(conn, target, first, name)
		return
	}
	r.dbg("%s: не открылся ни одним приёмом, соединение закрыто", name)
	r.nFail.Add(1)
	_ = conn.Close()
}

func noteStr(n string) string {
	if n == "" {
		return ""
	}
	return " (" + n + ")"
}

func (r *Router) tunnel(conn net.Conn, target string, first []byte, name string) {
	r.nTunnel.Add(1)
	if r.cfg.Tunnel == nil {
		_ = conn.Close()
		return
	}
	if len(first) > 0 {
		conn = &prefixConn{Conn: conn, pre: first}
	}
	r.cfg.Tunnel(conn, target)
}

// readFirst читает первый пакет приложения. Для TLS дочитывает всю запись
// с ClientHello (с постквантовыми ключами она бывает ~1.8 КБ и приходит частями).
func readFirst(conn net.Conn, wait time.Duration) []byte {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 16384)
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	defer conn.SetReadDeadline(time.Time{})
	for {
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf
		}
		if len(buf) >= 5 && buf[0] == 0x16 {
			if rl := desync.TLSRecordLen(buf); rl > len(buf) && rl < 20000 {
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				continue
			}
		}
		return buf
	}
}

type connectErr struct{ err error }

func (c *connectErr) Error() string { return "connect: " + c.err.Error() }
func (c *connectErr) Unwrap() error { return c.err }

func (r *Router) dial(host, port string) (*net.TCPConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.ConnectTimeout)
	defer cancel()
	ips, err := r.cfg.Lookup(ctx, host)
	if err != nil {
		return nil, &connectErr{err}
	}
	if len(ips) == 0 {
		return nil, &connectErr{errors.New("нет адресов")}
	}
	// IPv4 вперёд: IPv6 у мобильных операторов работает не везде
	sort.SliceStable(ips, func(i, j int) bool { return ips[i].To4() != nil && ips[j].To4() == nil })
	if len(ips) > 2 {
		ips = ips[:2]
	}
	var last error
	d := net.Dialer{KeepAlive: 30 * time.Second}
	for _, ip := range ips {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c.(*net.TCPConn), nil
		}
		last = err
	}
	return nil, &connectErr{last}
}

func (r *Router) try(host, port string, first []byte, st desync.Strategy) (*net.TCPConn, []byte, desync.Report, error) {
	up, err := r.dial(host, port)
	if err != nil {
		return nil, nil, desync.Report{}, err
	}
	if len(first) == 0 {
		return up, nil, desync.Report{}, nil // протокол, где сервер говорит первым
	}
	rep, err := st.Send(up, first)
	if err != nil {
		_ = up.Close()
		return nil, nil, rep, err
	}
	_ = up.SetReadDeadline(time.Now().Add(r.cfg.Timeout))
	buf := make([]byte, 32<<10)
	n, err := up.Read(buf)
	_ = up.SetReadDeadline(time.Time{})
	if n == 0 {
		_ = up.Close()
		if err == nil {
			err = io.EOF
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			err = errors.New("сервер молчит (DPI?)")
		}
		return nil, nil, rep, err
	}
	resp := buf[:n]
	switch rep.Plan.Proto {
	case "tls":
		if resp[0] != 0x16 { // вместо ServerHello — alert или мусор: вмешательство
			_ = up.Close()
			return nil, nil, rep, fmt.Errorf("ответ не ServerHello (0x%02x)", resp[0])
		}
	case "http":
		if isBlockPage(resp) {
			_ = up.Close()
			return nil, nil, rep, errors.New("страница-заглушка провайдера")
		}
	}
	return up, resp, rep, nil
}

func isBlockPage(b []byte) bool {
	s := strings.ToLower(string(b))
	if !strings.HasPrefix(s, "http/1.") {
		return false
	}
	for _, m := range []string{"warning.rt.ru", "blocked", "zapret", "rkn.gov.ru", "eais.rkn", "fz139", "block.mts", "blacklist"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func (r *Router) direct(conn net.Conn, host, port string, first []byte, st desync.Strategy, _ bool) {
	if first == nil {
		first = readFirst(conn, r.cfg.FirstWait)
	}
	up, err := r.dial(host, port)
	if err != nil {
		if r.cfg.Tunnel != nil && r.cfg.Mode == ModeAuto && !isLocal(host) {
			r.nFallback.Add(1)
			r.tunnel(conn, net.JoinHostPort(host, port), first, host)
			return
		}
		r.nFail.Add(1)
		_ = conn.Close()
		return
	}
	if len(first) > 0 {
		if _, err := st.Send(up, first); err != nil {
			_ = up.Close()
			_ = conn.Close()
			return
		}
	}
	r.nDirect.Add(1)
	r.pipe(conn, up, nil, host, false)
}

// pipe связывает приложение и сервер. Если включено Freeze, следит за
// TLS-записями вниз: поток, замерший посреди записи, — признак «заморозки»
// ТСПУ; тогда сайт уходит в туннель (новые соединения), а это — рвётся,
// чтобы приложение быстро переподключилось.
func (r *Router) pipe(conn net.Conn, up *net.TCPConn, resp []byte, name string, tlsProto bool) {
	var fr *freezeWatch
	if tlsProto && r.cfg.Freeze > 0 && r.cfg.Tunnel != nil && r.cfg.Mode == ModeAuto {
		fr = &freezeWatch{}
		fr.last.Store(time.Now().UnixNano())
	}
	if len(resp) > 0 {
		if fr != nil {
			fr.feed(resp)
		}
		if _, err := conn.Write(resp); err != nil {
			_ = up.Close()
			_ = conn.Close()
			return
		}
	}
	done := make(chan struct{})
	if fr != nil {
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					if fr.frozen(r.cfg.Freeze) {
						r.nFreeze.Add(1)
						r.mu.Lock()
						e := r.entry(name)
						e.tunnel = time.Now().Add(r.cfg.FailTTL)
						e.last = fmt.Sprintf("заморозка после %d байт — туннель", fr.total.Load())
						r.mu.Unlock()
						r.cfg.Logf("route %s: поток замер посреди TLS-записи после %d байт — дальше через туннель", name, fr.total.Load())
						_ = up.Close()
						_ = conn.Close()
						return
					}
				}
			}
		}()
	}
	go func() {
		_, _ = io.Copy(up, conn)
		_ = up.CloseWrite()
	}()
	buf := make([]byte, 32<<10)
	for {
		n, err := up.Read(buf)
		if n > 0 {
			if fr != nil {
				fr.feed(buf[:n])
			}
			if _, werr := conn.Write(buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	close(done)
	if fr != nil || r.cfg.Debug.Load() {
		r.dbg("%s: соединение закрыто", name)
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	time.Sleep(50 * time.Millisecond)
	_ = conn.Close()
	_ = up.Close()
}

// freezeWatch разбирает поток TLS-записей и знает, остановился ли он посреди записи.
type freezeWatch struct {
	mu    sync.Mutex
	hdr   []byte
	left  int // сколько байт текущей записи ещё не пришло
	last  atomic.Int64
	total atomic.Int64
}

func (f *freezeWatch) feed(b []byte) {
	f.last.Store(time.Now().UnixNano())
	f.total.Add(int64(len(b)))
	f.mu.Lock()
	defer f.mu.Unlock()
	for len(b) > 0 {
		if f.left > 0 {
			n := min(f.left, len(b))
			f.left -= n
			b = b[n:]
			continue
		}
		need := 5 - len(f.hdr)
		n := min(need, len(b))
		f.hdr = append(f.hdr, b[:n]...)
		b = b[n:]
		if len(f.hdr) == 5 {
			f.left = int(binary.BigEndian.Uint16(f.hdr[3:5]))
			f.hdr = f.hdr[:0]
		}
	}
}

func (f *freezeWatch) frozen(d time.Duration) bool {
	f.mu.Lock()
	mid := f.left > 0 || len(f.hdr) > 0
	f.mu.Unlock()
	return mid && time.Since(time.Unix(0, f.last.Load())) > d
}

// ---------- статистика ----------

type HostInfo struct {
	Host  string `json:"host"`
	Path  string `json:"path"` // direct|tunnel|?
	OK    int    `json:"ok"`
	Fail  int    `json:"fail"`
	Last  string `json:"last"`
	Strat string `json:"strategy"`
}

type Snapshot struct {
	Mode       string     `json:"mode"`
	Strategies []string   `json:"strategies"`
	Direct     int64      `json:"direct"`
	Fallback   int64      `json:"fallback"`
	Tunnel     int64      `json:"tunnel"`
	Failed     int64      `json:"failed"`
	Freezes    int64      `json:"freezes"`
	Hosts      []HostInfo `json:"hosts"`
}

func (r *Router) Snapshot() Snapshot {
	sts := r.Strategies()
	s := Snapshot{Mode: r.cfg.Mode, Direct: r.nDirect.Load(), Fallback: r.nFallback.Load(), Tunnel: r.nTunnel.Load(), Failed: r.nFail.Load(), Freezes: r.nFreeze.Load()}
	for _, st := range sts {
		s.Strategies = append(s.Strategies, st.String())
	}
	r.mu.Lock()
	now := time.Now()
	for h, e := range r.cache {
		p := "?"
		switch {
		case now.Before(e.tunnel):
			p = "tunnel"
		case now.Before(e.okUntil):
			p = "direct"
		}
		s.Hosts = append(s.Hosts, HostInfo{Host: h, Path: p, OK: e.ok, Fail: e.fail, Last: e.last, Strat: sts[e.strat%len(sts)].String()})
	}
	r.mu.Unlock()
	sort.Slice(s.Hosts, func(i, j int) bool { return s.Hosts[i].OK+s.Hosts[i].Fail > s.Hosts[j].OK+s.Hosts[j].Fail })
	if len(s.Hosts) > 100 {
		s.Hosts = s.Hosts[:100]
	}
	return s
}

// ReadList — список из строки "a,b,c" или из файла "@путь".
func ReadList(s string, read func(string) ([]byte, error)) []string {
	if strings.HasPrefix(s, "@") {
		b, err := read(s[1:])
		if err != nil {
			return nil
		}
		s = string(b)
	}
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' })
}
