// Package server реализует серверную часть МАЯКа.
//
// Снаружи это обычный HTTPS-сайт (TLS 1.3, crypto/tls). Неавторизованным
// запросам и активному зондированию отдаётся правдоподобная статическая
// страница. Авторизованный клиент (куки с HMAC-токеном) переносит туннель
// короткими запросами POST /api/v1/up и GET /api/v1/down. Клиент сам
// решает, сколько байт можно передать по одному TLS-соединению, и меняет
// соединения раньше, чем сработает «заморозка после ~16 КБ».
//
// Надёжность: запросы вверх нумеруются (X-Seq) и применяются строго по
// порядку; ответы вниз тоже нумеруются, клиент подтверждает их (X-Ack),
// неподтверждённые через RTO отправляются повторно.
package server

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"mayak/internal/protocol"
)

type Config struct {
	DialTimeout time.Duration
	IdleTimeout time.Duration
	RTO         time.Duration // повтор неподтверждённого ответа вниз
	MaxBuffered int           // максимум байт вниз на сессию (backpressure)
	SiteName    string
	Log         *log.Logger
}

func (c *Config) def() {
	if c.DialTimeout == 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 120 * time.Second
	}
	if c.RTO == 0 {
		c.RTO = 4 * time.Second
	}
	if c.MaxBuffered == 0 {
		c.MaxBuffered = 8 << 20
	}
	if c.SiteName == "" {
		c.SiteName = "Statika CDN"
	}
	if c.Log == nil {
		c.Log = log.New(io.Discard, "", 0)
	}
}

type upMsg struct {
	kind byte
	data []byte
}

type stream struct {
	ch   chan upMsg
	done chan struct{}
	mu   sync.Mutex
	conn net.Conn
	once sync.Once
}

func (st *stream) close() {
	st.once.Do(func() {
		close(st.done)
		st.mu.Lock()
		if st.conn != nil {
			_ = st.conn.Close()
		}
		st.mu.Unlock()
	})
}

type seg struct {
	off uint64
	n   int
	at  time.Time
}

type session struct {
	id protocol.SessionID
	mu sync.Mutex

	strm map[uint32]*stream

	// вверх: сборка байтового потока по смещениям X-Off
	upR   *protocol.Reasm
	upFP  protocol.FrameParser
	upMu  sync.Mutex // сериализует применение

	// вниз
	downQ    []protocol.Frame // ещё не отправленные кадры
	downSize int
	downBase uint64 // смещение первого неподтверждённого байта
	dbuf     []byte // отправленные, но не подтверждённые байты
	segs     []seg  // как именно они отправлялись (для повторов)

	signal chan struct{}
	last   time.Time
	closed bool
}

// wake будит всех ждущих /down (широковещательно: закрываем канал).
func (se *session) wake() {
	se.mu.Lock()
	close(se.signal)
	se.signal = make(chan struct{})
	se.mu.Unlock()
}

// Server — HTTPS-сервер МАЯКа.
type Server struct {
	cfg   Config
	ver   *protocol.Verifier
	mu    sync.Mutex
	sess  map[protocol.SessionID]*session
	site  []byte
	asset []byte
}

func New(secret string, cfg Config) *Server {
	cfg.def()
	s := &Server{
		cfg:   cfg,
		ver:   protocol.NewVerifier(protocol.DeriveKey(secret)),
		sess:  map[protocol.SessionID]*session{},
		site:  buildSite(cfg.SiteName),
		asset: buildAsset(),
	}
	go s.reaper()
	return s
}

func (s *Server) reaper() {
	t := time.NewTicker(15 * time.Second)
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for id, se := range s.sess {
			se.mu.Lock()
			dead := now.Sub(se.last) > s.cfg.IdleTimeout
			se.mu.Unlock()
			if dead {
				s.cfg.Log.Printf("session %s: idle, closing", id.String()[:8])
				s.dropLocked(id)
			}
		}
		s.mu.Unlock()
	}
}

func (s *Server) dropLocked(id protocol.SessionID) {
	se := s.sess[id]
	if se == nil {
		return
	}
	delete(s.sess, id)
	se.mu.Lock()
	se.closed = true
	streams := se.strm
	se.strm = map[uint32]*stream{}
	se.mu.Unlock()
	for _, st := range streams {
		st.close()
	}
	se.wake()
}

// getSession возвращает сессию; fresh=true, если её создали только что.
func (s *Server) getSession(id protocol.SessionID, create bool) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	se := s.sess[id]
	if se != nil {
		return se, false
	}
	if !create {
		return nil, false
	}
	se = &session{
		id: id, strm: map[uint32]*stream{}, upR: protocol.NewReasm(),
		signal: make(chan struct{}), last: time.Now(),
	}
	s.sess[id] = se
	s.cfg.Log.Printf("session %s: new", id.String()[:8])
	return se, true
}

func (s *Server) auth(r *http.Request) (protocol.SessionID, bool) {
	c, err := r.Cookie("sid")
	if err != nil {
		return protocol.SessionID{}, false
	}
	id, err := s.ver.Verify(c.Value)
	return id, err == nil
}

func hdrU(r *http.Request, k string) uint64 {
	v, _ := strconv.ParseUint(r.Header.Get(k), 10, 64)
	return v
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/up":
		if id, ok := s.auth(r); ok && r.Method == http.MethodPost {
			s.handleUp(w, r, id)
			return
		}
	case "/api/v1/down":
		if id, ok := s.auth(r); ok && r.Method == http.MethodGet {
			s.handleDown(w, r, id)
			return
		}
	}
	s.handleSite(w, r)
}

func writeOK(w http.ResponseWriter, off int64, body []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Server", "nginx")
	if off >= 0 {
		h.Set("X-Off", strconv.FormatInt(off, 10))
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// sessionGone — сервер не знает сессию (например, перезапускался).
func sessionGone(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusConflict)
}

func (s *Server) handleUp(w http.ResponseWriter, r *http.Request, id protocol.SessionID) {
	offS := r.Header.Get("X-Off")
	off, perr := strconv.ParseUint(offS, 10, 64)
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil || perr != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	// Куски вверх могут прийти в любом порядке (параллельные запросы), поэтому
	// неизвестная сессия просто создаётся. Перезапуск сервера клиент узнает
	// по /down: там он подтверждает уже полученные байты, которых у нас нет.
	se, _ := s.getSession(id, true)
	se.mu.Lock()
	se.last = time.Now()
	se.mu.Unlock()
	se.upMu.Lock()
	out, _ := se.upR.Put(off, body)
	se.upFP.Feed(out, func(f protocol.Frame) { s.applyUp(se, f) })
	se.upMu.Unlock()
	writeOK(w, -1, nil)
}

func (s *Server) applyUp(se *session, f protocol.Frame) {
	if f.Type == protocol.TypeSYN {
		st := &stream{ch: make(chan upMsg, 1024), done: make(chan struct{})}
		se.mu.Lock()
		if se.closed {
			se.mu.Unlock()
			return
		}
		se.strm[f.Stream] = st
		se.mu.Unlock()
		go s.runStream(se, f.Stream, st, string(f.Payload))
		return
	}
	se.mu.Lock()
	st := se.strm[f.Stream]
	se.mu.Unlock()
	if st == nil {
		return
	}
	switch f.Type {
	case protocol.TypeData, protocol.TypeFIN, protocol.TypeRST:
		select {
		case st.ch <- upMsg{kind: f.Type, data: f.Payload}:
		case <-st.done:
		case <-time.After(30 * time.Second):
			s.resetStream(se, f.Stream)
		}
	}
}

func (s *Server) runStream(se *session, id uint32, st *stream, addr string) {
	conn, err := net.DialTimeout("tcp", addr, s.cfg.DialTimeout)
	if err != nil {
		s.cfg.Log.Printf("dial %s: %v", addr, err)
		s.resetStream(se, id)
		return
	}
	st.mu.Lock()
	st.conn = conn
	st.mu.Unlock()
	select {
	case <-st.done:
		_ = conn.Close()
		return
	default:
	}
	go s.pumpDown(se, id, st, conn)
	for {
		var m upMsg
		select {
		case m = <-st.ch:
		case <-st.done:
			return
		}
		switch m.kind {
		case protocol.TypeData:
			_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := conn.Write(m.data); err != nil {
				s.resetStream(se, id)
				return
			}
		case protocol.TypeFIN:
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
		case protocol.TypeRST:
			s.removeStream(se, id)
			return
		}
	}
}

func (s *Server) pumpDown(se *session, id uint32, st *stream, conn net.Conn) {
	buf := make([]byte, 16*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			p := make([]byte, n)
			copy(p, buf[:n])
			se.enqueue(protocol.Frame{Stream: id, Type: protocol.TypeData, Payload: p})
			se.waitRoom(s.cfg.MaxBuffered, st.done)
		}
		if err != nil {
			break
		}
	}
	select {
	case <-st.done: // закрыт с нашей стороны (RST) — FIN не нужен
	default:
		se.enqueue(protocol.Frame{Stream: id, Type: protocol.TypeFIN})
	}
	s.removeStream(se, id)
}

func (s *Server) resetStream(se *session, id uint32) {
	if s.removeStream(se, id) {
		se.enqueue(protocol.Frame{Stream: id, Type: protocol.TypeRST})
	}
}

func (s *Server) removeStream(se *session, id uint32) bool {
	se.mu.Lock()
	st := se.strm[id]
	delete(se.strm, id)
	se.mu.Unlock()
	if st != nil {
		st.close()
		return true
	}
	return false
}

func (se *session) enqueue(f protocol.Frame) {
	se.mu.Lock()
	if !se.closed {
		se.downQ = append(se.downQ, f)
		se.downSize += f.Size()
	}
	close(se.signal)
	se.signal = make(chan struct{})
	se.mu.Unlock()
}

func (se *session) waitRoom(max int, done chan struct{}) {
	for {
		se.mu.Lock()
		size, closed := se.downSize+len(se.dbuf), se.closed
		se.mu.Unlock()
		if size < max || closed {
			return
		}
		select {
		case <-done:
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// drainLocked собирает кадры в тело ответа не больше limit байт.
// Большие кадры DATA режутся, чтобы заполнить ответ под завязку.
func (se *session) drainLocked(limit int) []byte {
	var out []byte
	for len(se.downQ) > 0 {
		room := limit - len(out)
		f := se.downQ[0]
		if f.Size() <= room {
			out = protocol.AppendFrame(out, f)
			se.downSize -= f.Size()
			se.downQ = se.downQ[1:]
			continue
		}
		if f.Type == protocol.TypeData && room >= protocol.HeaderLen+512 {
			n := room - protocol.HeaderLen
			out = protocol.AppendFrame(out, protocol.Frame{Stream: f.Stream, Type: f.Type, Payload: f.Payload[:n]})
			se.downQ[0].Payload = f.Payload[n:]
			se.downSize -= n
		}
		if len(out) == 0 { // кадр не влезает даже один (крошечный лимит)
			out = protocol.AppendFrame(out, f)
			se.downSize -= f.Size()
			se.downQ = se.downQ[1:]
		}
		break
	}
	return out
}

func (s *Server) handleDown(w http.ResponseWriter, r *http.Request, id protocol.SessionID) {
	ack := hdrU(r, "X-Ack")
	limit := int(hdrU(r, "X-Max"))
	if limit < 1024 {
		limit = 1024
	}
	if limit > 4<<20 {
		limit = 4 << 20
	}
	wait := time.Duration(hdrU(r, "X-Wait")) * time.Millisecond
	if wait > 20*time.Second {
		wait = 20 * time.Second
	}
	// /down может прийти раньше первого /up — тогда создаём сессию;
	// если же клиент уже что-то подтверждал, а сессии нет — сервер перезапускался.
	se, _ := s.getSession(id, ack == 0)
	if se == nil {
		sessionGone(w)
		return
	}
	deadline := time.Now().Add(wait)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		se.mu.Lock()
		if se.closed {
			se.mu.Unlock()
			sessionGone(w)
			return
		}
		se.last = time.Now()
		// подтверждение: клиент получил всё до смещения ack
		if ack > se.downBase {
			drop := ack - se.downBase
			if drop > uint64(len(se.dbuf)) {
				drop = uint64(len(se.dbuf))
			}
			se.dbuf = se.dbuf[drop:]
			se.downBase += drop
			k := 0
			for _, g := range se.segs {
				end := g.off + uint64(g.n)
				if end <= se.downBase {
					continue
				}
				if g.off < se.downBase {
					g.n = int(end - se.downBase)
					g.off = se.downBase
				}
				se.segs[k] = g
				k++
			}
			se.segs = se.segs[:k]
		}
		now := time.Now()
		// повтор самого старого неподтверждённого куска, если истёк RTO;
		// кусок режется под текущий лимит клиента (после смены режима он меньше)
		for i := range se.segs {
			g := se.segs[i]
			rto := s.cfg.RTO + time.Duration(g.n/100)*time.Millisecond // +1 с на 100 КБ
			if now.Sub(g.at) <= rto {
				continue
			}
			n := g.n
			if n > limit {
				n = limit
				rest := seg{off: g.off + uint64(n), n: g.n - n, at: g.at}
				se.segs = append(se.segs[:i+1], append([]seg{rest}, se.segs[i+1:]...)...)
			}
			se.segs[i] = seg{off: g.off, n: n, at: now}
			st := g.off - se.downBase
			body := append([]byte(nil), se.dbuf[st:st+uint64(n)]...)
			se.mu.Unlock()
			s.cfg.Log.Printf("session %s: retransmit off %d len %d", id.String()[:8], g.off, n)
			writeOK(w, int64(g.off), body)
			return
		}
		if out := se.drainLocked(limit); len(out) > 0 {
			off := se.downBase + uint64(len(se.dbuf))
			se.dbuf = append(se.dbuf, out...)
			se.segs = append(se.segs, seg{off: off, n: len(out), at: now})
			se.mu.Unlock()
			writeOK(w, int64(off), out)
			return
		}
		sig := se.signal
		se.mu.Unlock()
		if !time.Now().Before(deadline) {
			writeOK(w, -1, nil)
			return
		}
		select {
		case <-sig:
		case <-tick.C:
		case <-time.After(time.Until(deadline)):
		case <-r.Context().Done():
			return
		}
	}
}

// Serve запускает HTTP-обработчик на TLS-слушателе.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	return srv.Serve(ln)
}
