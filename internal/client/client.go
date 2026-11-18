// Package client — клиентская часть МАЯКа.
//
// Логический поток (несколько TCP-потоков пользователя, мультиплексированных
// в одну сессию) режется на «плитки» — HTTP-запросы внутри TLS. Каждое
// TLS-соединение живёт, пока через него не прошло Budget байт, затем
// заменяется заранее открытым свежим соединением. Так ни одно соединение не
// доходит до порога «заморозки» ТСПУ (~16 КБ к зарубежным хостингам).
package client

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"mayak/internal/protocol"
)

type Options struct {
	Server      string // host:port VPS
	SNI         string // имя в ClientHello (маскировка)
	Host        string // заголовок Host (по умолчанию = SNI)
	Pin         string // sha256 сертификата сервера (hex); пусто = обычная проверка
	Secret      string
	Fingerprint string // chrome|firefox|safari|edge|random|go
	Mode        string // auto|mosaic|fast
	Budget      int    // байт на одно TLS-соединение в режиме mosaic
	DownWorkers int
	UpWorkers   int
	Log         *log.Logger
}

// Profile — текущие параметры нарезки.
type Profile struct {
	Name    string `json:"name"`
	Budget  int    `json:"budget"`   // 0 = без ограничения на соединение
	DownMax int    `json:"down_max"` // макс. тело ответа
	UpMax   int    `json:"up_max"`   // макс. тело запроса
}

func mosaicProfile(budget int) Profile {
	if budget < 4000 {
		budget = 4000
	}
	// запас на TLS-рукопожатие (~2 КБ с сертификатом) и HTTP-заголовки
	m := budget - 2600
	return Profile{Name: "mosaic", Budget: budget, DownMax: m, UpMax: m}
}

var fastProfile = Profile{Name: "fast", Budget: 0, DownMax: 512 << 10, UpMax: 256 << 10}

type cstream struct {
	id       uint32
	conn     net.Conn
	target   string
	wq       chan []byte // данные к пользователю
	finOnce  sync.Once
	closed   atomic.Bool
	upDone   atomic.Bool
	downDone atomic.Bool
	opened   time.Time
}

type Client struct {
	opt  Options
	key  []byte
	pin  []byte
	prof atomic.Pointer[Profile]
	// budget — размер плитки mosaic; меняется на лету из панели (0.3.5)
	budget atomic.Int64
	// последняя проба «заморозки» своего сервера и кому о ней сообщить
	probeMu   sync.Mutex
	lastProbe *FreezeResult
	probeHook func(FreezeResult)

	mu      sync.Mutex
	cond    *sync.Cond
	gen     uint64
	sid     protocol.SessionID
	streams map[uint32]*cstream
	nextID  uint32
	upQ     []protocol.Frame
	upSize  int
	upOff   uint64 // смещение следующего байта вверх
	lastUse time.Time

	// приём вниз
	dmu    sync.Mutex
	downR  *protocol.Reasm
	downFP protocol.FrameParser

	st     stats
	events *eventLog

	opener    OpenFunc   // маршрутизатор (напрямую/туннель); nil = всё в туннель
	routeSnap func() any // для панели
	handlers  map[string]http.HandlerFunc
	ctx       context.Context
}

func New(opt Options) (*Client, error) {
	if opt.Server == "" || opt.Secret == "" {
		return nil, errors.New("server and secret are required")
	}
	if _, _, err := net.SplitHostPort(opt.Server); err != nil {
		return nil, fmt.Errorf("server must be host:port: %w", err)
	}
	if opt.SNI == "" {
		h, _, _ := net.SplitHostPort(opt.Server)
		opt.SNI = h
	}
	if opt.Host == "" {
		opt.Host = opt.SNI
	}
	if opt.Budget == 0 {
		opt.Budget = 14000
	}
	if opt.DownWorkers == 0 {
		opt.DownWorkers = 16
	}
	if opt.UpWorkers == 0 {
		opt.UpWorkers = 3
	}
	if opt.Mode == "" {
		opt.Mode = "auto"
	}
	if opt.Log == nil {
		opt.Log = log.New(io.Discard, "", 0)
	}
	c := &Client{opt: opt, key: protocol.DeriveKey(opt.Secret), streams: map[uint32]*cstream{}, downR: protocol.NewReasm()}
	if opt.Pin != "" {
		p, err := hex.DecodeString(opt.Pin)
		if err != nil || len(p) != 32 {
			return nil, errors.New("pin must be 64 hex chars (sha256)")
		}
		c.pin = p
	}
	c.budget.Store(int64(opt.Budget))
	c.cond = sync.NewCond(&c.mu)
	c.sid = protocol.NewSessionID()
	c.events = newEventLog(80)
	switch opt.Mode {
	case "fast":
		p := fastProfile
		c.prof.Store(&p)
	default:
		p := mosaicProfile(opt.Budget)
		c.prof.Store(&p)
	}
	return c, nil
}

func (c *Client) Profile() Profile { return *c.prof.Load() }

// Budget — текущий размер плитки mosaic (байт на одно TLS-соединение).
func (c *Client) Budget() int { return int(c.budget.Load()) }

// SetBudget — новый размер плитки без перезапуска (из панели/subs.json).
// Если сейчас mosaic — сразу переходит на новый размер.
func (c *Client) SetBudget(n int, why string) {
	if n < 4000 {
		n = 4000
	}
	if int(c.budget.Swap(int64(n))) == n {
		return
	}
	c.events.add("mode", fmt.Sprintf("размер плитки по умолчанию: %d байт (%s)", n, why))
	if p := c.Profile(); p.Name == "mosaic" {
		c.setProfile(mosaicProfile(n), why)
	}
}

func (c *Client) setProfile(p Profile, why string) {
	old := c.prof.Load()
	if old.Name == p.Name && old.Budget == p.Budget {
		return
	}
	c.prof.Store(&p)
	if old.Name == p.Name {
		c.events.add("mode", fmt.Sprintf("размер плитки %.1f → %.1f КБ (%s)", float64(old.Budget)/1000, float64(p.Budget)/1000, why))
	} else {
		c.events.add("mode", fmt.Sprintf("режим %s → %s (%s)", old.Name, p.Name, why))
	}
	c.opt.Log.Printf("profile %s -> %s: %s", old.Name, p.Name, why)
}

func (c *Client) stall() time.Duration {
	if c.Profile().Budget == 0 {
		return 6 * time.Second // быстрый режим: дольше 6 с тишины — подозрение на заморозку
	}
	return 10 * time.Second
}

// Run запускает рабочие горутины. Блокируется до отмены ctx.
func (c *Client) Run(ctx context.Context) {
	c.ctx = ctx
	for i := 0; i < c.opt.UpWorkers; i++ {
		go c.upWorker(ctx)
	}
	for i := 0; i < c.opt.DownWorkers; i++ {
		go c.downWorker(ctx, i)
	}
	go c.sampler(ctx)
	go c.idleReset(ctx)
	if c.opt.Mode == "auto" {
		go c.autoLoop(ctx)
	}
	c.events.add("start", fmt.Sprintf("старт: сервер %s, SNI %s, отпечаток %s, режим %s", c.opt.Server, c.opt.SNI, c.opt.Fingerprint, c.opt.Mode))
	<-ctx.Done()
	c.mu.Lock()
	c.cond.Broadcast()
	c.mu.Unlock()
}

// ---------- потоки ----------

// Open открывает поток до target ("host:port") и связывает его с conn.
// Возвращается сразу; данные начинают течь асинхронно.
func (c *Client) Open(conn net.Conn, target string) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	st := &cstream{id: id, conn: conn, target: target, wq: make(chan []byte, 256), opened: time.Now()}
	c.streams[id] = st
	c.lastUse = time.Now()
	c.pushLocked(protocol.Frame{Stream: id, Type: protocol.TypeSYN, Payload: []byte(target)})
	gen := c.gen
	c.mu.Unlock()
	c.st.streamsTotal.Add(1)
	go c.writer(st)
	go c.reader(st, gen)
}

// SetRouter ставит маршрутизатор перед туннелем: open решает, пустить ли
// соединение напрямую или вызвать c.Open.
func (c *Client) SetRouter(open OpenFunc, snap func() any) {
	c.opener, c.routeSnap = open, snap
}

func (c *Client) openRouted(conn net.Conn, target string) {
	if c.opener != nil {
		c.opener(conn, target)
		return
	}
	c.Open(conn, target)
}

// Handle добавляет обработчик в панель (до ServeDashboard).
func (c *Client) Handle(path string, h http.HandlerFunc) {
	if c.handlers == nil {
		c.handlers = map[string]http.HandlerFunc{}
	}
	c.handlers[path] = h
}

// Event пишет событие в журнал панели.
func (c *Client) Event(kind, text string) { c.events.add(kind, text) }

func (c *Client) pushLocked(f protocol.Frame) {
	c.upQ = append(c.upQ, f)
	c.upSize += f.Size()
	c.cond.Broadcast()
}

// reader: пользователь → туннель.
func (c *Client) reader(st *cstream, gen uint64) {
	buf := make([]byte, 16*1024)
	for {
		n, err := st.conn.Read(buf)
		if n > 0 {
			p := make([]byte, n)
			copy(p, buf[:n])
			c.mu.Lock()
			for c.upSize > 2<<20 && c.gen == gen && !st.closed.Load() {
				c.cond.Wait()
			}
			if c.gen != gen || st.closed.Load() {
				c.mu.Unlock()
				return
			}
			c.pushLocked(protocol.Frame{Stream: st.id, Type: protocol.TypeData, Payload: p})
			c.lastUse = time.Now()
			c.mu.Unlock()
			c.st.upBytes.Add(int64(n))
		}
		if err != nil {
			c.mu.Lock()
			if c.gen == gen && !st.closed.Load() {
				c.pushLocked(protocol.Frame{Stream: st.id, Type: protocol.TypeFIN})
			}
			c.mu.Unlock()
			st.upDone.Store(true)
			c.maybeFinish(st)
			return
		}
	}
}

// writer: туннель → пользователь.
func (c *Client) writer(st *cstream) {
	for p := range st.wq {
		if p == nil { // FIN от сервера
			if tc, ok := st.conn.(interface{ CloseWrite() error }); ok {
				_ = tc.CloseWrite()
			} else {
				_ = st.conn.Close()
			}
			st.downDone.Store(true)
			c.maybeFinish(st)
			continue
		}
		_ = st.conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if _, err := st.conn.Write(p); err != nil {
			c.reset(st, true)
			return
		}
	}
}

func (c *Client) maybeFinish(st *cstream) {
	if st.upDone.Load() && st.downDone.Load() {
		c.reset(st, false)
	}
}

// reset закрывает поток; notify=true — сообщить серверу (RST).
func (c *Client) reset(st *cstream, notify bool) {
	if !st.closed.CompareAndSwap(false, true) {
		return
	}
	_ = st.conn.Close()
	c.mu.Lock()
	if c.streams[st.id] == st {
		delete(c.streams, st.id)
		if notify {
			c.pushLocked(protocol.Frame{Stream: st.id, Type: protocol.TypeRST})
		}
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	st.finOnce.Do(func() { close(st.wq) })
}

// ---------- вверх ----------

func (c *Client) cutLocked(limit int) []byte {
	var out []byte
	for len(c.upQ) > 0 {
		room := limit - len(out)
		f := c.upQ[0]
		if f.Size() <= room {
			out = protocol.AppendFrame(out, f)
			c.upSize -= f.Size()
			c.upQ = c.upQ[1:]
			continue
		}
		if f.Type == protocol.TypeData && room >= protocol.HeaderLen+256 {
			n := room - protocol.HeaderLen
			out = protocol.AppendFrame(out, protocol.Frame{Stream: f.Stream, Type: f.Type, Payload: f.Payload[:n]})
			c.upQ[0].Payload = f.Payload[n:]
			c.upSize -= n
		} else if len(out) == 0 {
			out = protocol.AppendFrame(out, f)
			c.upSize -= f.Size()
			c.upQ = c.upQ[1:]
		}
		break
	}
	c.cond.Broadcast()
	return out
}

type worker struct {
	c     *Client
	cur   *legConn
	spare chan *legConn
}

// conn выдаёт соединение для очередного запроса: текущее (если бюджет
// позволяет) или заранее открытое запасное.
func (w *worker) conn(ctx context.Context, need int) (*legConn, error) {
	p := w.c.Profile()
	if w.cur != nil {
		fresh := time.Since(w.cur.born) < 25*time.Second
		fits := p.Budget == 0 || int(w.cur.raw.rd.Load())+need <= p.Budget
		if fresh && fits {
			return w.cur, nil
		}
		w.retire()
	}
	select {
	case l := <-w.spare:
		if l != nil && time.Since(l.born) < 15*time.Second {
			w.cur = l
			return l, nil
		}
		if l != nil {
			l.Close()
		}
	default:
	}
	l, err := w.c.dial(ctx)
	if err != nil {
		return nil, err
	}
	w.cur = l
	return l, nil
}

// prefetch заранее открывает следующее соединение, если текущее скоро
// исчерпает бюджет — рукопожатие прячется за передачей данных.
func (w *worker) prefetch(ctx context.Context, need int) {
	p := w.c.Profile()
	if p.Budget == 0 || w.cur == nil || len(w.spare) > 0 {
		return
	}
	if int(w.cur.raw.rd.Load())+2*need <= p.Budget {
		return
	}
	go func() {
		l, err := w.c.dial(ctx)
		if err != nil {
			return
		}
		select {
		case w.spare <- l:
		default:
			l.Close()
		}
	}()
}

func (w *worker) retire() {
	if w.cur == nil {
		return
	}
	rd := w.cur.raw.rd.Load()
	w.c.st.noteConn(rd, w.cur.raw.wr.Load(), w.cur.legs)
	w.cur.Close()
	w.cur = nil
}

func (c *Client) token() (string, uint64) {
	c.mu.Lock()
	sid, gen := c.sid, c.gen
	c.mu.Unlock()
	return protocol.MakeToken(c.key, sid), gen
}

func (c *Client) upWorker(ctx context.Context) {
	w := &worker{c: c, spare: make(chan *legConn, 1)}
	for ctx.Err() == nil {
		c.mu.Lock()
		for len(c.upQ) == 0 && ctx.Err() == nil {
			c.cond.Wait()
		}
		if ctx.Err() != nil {
			c.mu.Unlock()
			return
		}
		p := c.Profile()
		body := c.cutLocked(p.UpMax)
		off, gen, sid := c.upOff, c.gen, c.sid
		c.upOff += uint64(len(body))
		c.mu.Unlock()
		c.sendUp(ctx, w, body, off, gen, sid)
	}
}

func (c *Client) sendUp(ctx context.Context, w *worker, body []byte, off, gen uint64, sid protocol.SessionID) {
	for attempt := 0; ctx.Err() == nil; attempt++ {
		c.mu.Lock()
		stale := c.gen != gen
		c.mu.Unlock()
		if stale {
			return
		}
		// режим сменился на более мелкую нарезку — повторяем кусок частями
		if attempt > 0 {
			if m := c.Profile().UpMax; len(body) > m {
				for i := 0; i < len(body); i += m {
					c.sendUp(ctx, w, body[i:min(i+m, len(body))], off+uint64(i), gen, sid)
				}
				return
			}
		}
		need := len(body) + 1200
		l, err := w.conn(ctx, need)
		if err == nil {
			p := c.Profile()
			keep := p.Budget == 0 || int(l.raw.rd.Load())+need+1200 <= p.Budget
			t0 := time.Now()
			resp, _, err2 := c.roundTrip(l, http.MethodPost, "/api/v1/up", protocol.MakeToken(c.key, sid),
				map[string]string{"X-Off": strconv.FormatUint(off, 10)}, body, keep, 0)
			err = err2
			if err == nil {
				c.st.legs.Add(1)
				c.st.legRTT(time.Since(t0))
				if resp.StatusCode == http.StatusConflict {
					c.resetSession("сервер не знает сессию (перезапуск?)")
					return
				}
				if !keep || resp.Close {
					w.retire()
				}
				if resp.StatusCode == http.StatusOK {
					return
				}
				err = fmt.Errorf("http %d", resp.StatusCode)
			}
		}
		w.retire()
		c.legError(err)
		if attempt > 0 {
			c.st.retries.Add(1)
		}
		if attempt >= 30 {
			c.resetSession("не удаётся отправить данные: " + err.Error())
			return
		}
		sleepCtx(ctx, backoff(attempt))
	}
}

// ---------- вниз ----------

func (c *Client) active() bool {
	return len(c.streams) > 0 || len(c.upQ) > 0
}

func (c *Client) downWorker(ctx context.Context, idx int) {
	w := &worker{c: c, spare: make(chan *legConn, 1)}
	fails := 0
	for ctx.Err() == nil {
		c.mu.Lock()
		// первые 2 воркера держат long-poll, остальные подключаются при нагрузке
		for !c.active() && ctx.Err() == nil {
			c.cond.Wait()
		}
		sid, gen := c.sid, c.gen
		c.mu.Unlock()
		if idx >= 2 && !c.busy() {
			sleepCtx(ctx, 50*time.Millisecond)
			if !c.busy() {
				continue
			}
		}
		p := c.Profile()
		need := p.DownMax + 1500
		l, err := w.conn(ctx, need)
		if err != nil {
			c.legError(err)
			fails++
			sleepCtx(ctx, backoff(fails))
			continue
		}
		w.prefetch(ctx, need)
		keep := p.Budget == 0 || int(l.raw.rd.Load())+2*need <= p.Budget
		c.dmu.Lock()
		ack := c.downR.Next
		c.dmu.Unlock()
		wait := 8 * time.Second
		t0 := time.Now()
		resp, body, err := c.roundTrip(l, http.MethodGet, "/api/v1/down", protocol.MakeToken(c.key, sid), map[string]string{
			"X-Ack":  strconv.FormatUint(ack, 10),
			"X-Max":  strconv.Itoa(p.DownMax),
			"X-Wait": strconv.Itoa(int(wait / time.Millisecond)),
		}, nil, keep, wait)
		if err != nil {
			w.retire()
			c.legError(err)
			if errors.Is(err, errStall) && p.Budget == 0 {
				c.setProfile(mosaicProfile(c.Budget()), "поток замер посреди ответа — похоже на «заморозку 16 КБ»")
			}
			fails++
			sleepCtx(ctx, backoff(fails))
			continue
		}
		fails = 0
		c.st.legs.Add(1)
		if len(body) > 0 {
			c.st.legRTT(time.Since(t0))
		}
		if !keep || resp.Close {
			w.retire()
		}
		if resp.StatusCode == http.StatusConflict {
			c.resetSession("сервер не знает сессию")
			continue
		}
		if resp.StatusCode != http.StatusOK {
			c.legError(fmt.Errorf("http %d", resp.StatusCode))
			continue
		}
		if off, ok := hdrOff(resp); ok && len(body) > 0 {
			c.deliver(gen, off, body)
		}
	}
}

// busy — есть ли смысл держать дополнительные параллельные запросы вниз.
func (c *Client) busy() bool {
	return c.st.recentDown() > 32*1024
}

func (c *Client) deliver(gen, off uint64, body []byte) {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	c.mu.Lock()
	stale := c.gen != gen
	c.mu.Unlock()
	if stale {
		return
	}
	out, dup := c.downR.Put(off, body)
	if dup {
		c.st.dups.Add(1)
	}
	c.downFP.Feed(out, c.dispatch)
}

func (c *Client) dispatch(f protocol.Frame) {
	c.mu.Lock()
	st := c.streams[f.Stream]
	c.mu.Unlock()
	if st == nil || st.closed.Load() {
		return
	}
	switch f.Type {
	case protocol.TypeData:
		c.st.downBytes.Add(int64(len(f.Payload)))
		func() {
			defer func() { _ = recover() }() // канал мог закрыться
			st.wq <- f.Payload
		}()
	case protocol.TypeFIN:
		func() {
			defer func() { _ = recover() }()
			st.wq <- nil
		}()
	case protocol.TypeRST:
		c.reset(st, false)
	}
}

// resetSession — начать новую сессию (все текущие потоки рвутся).
func (c *Client) resetSession(why string) {
	c.mu.Lock()
	old := c.streams
	c.streams = map[uint32]*cstream{}
	c.gen++
	c.sid = protocol.NewSessionID()
	c.upQ = nil
	c.upSize = 0
	c.upOff = 0
	c.cond.Broadcast()
	c.mu.Unlock()
	c.dmu.Lock()
	c.downR = protocol.NewReasm()
	c.downFP = protocol.FrameParser{}
	c.dmu.Unlock()
	for _, st := range old {
		c.reset(st, false)
	}
	c.st.resets.Add(1)
	c.events.add("reset", "новая сессия: "+why)
}

// idleReset — после минуты простоя начинаем с чистой сессии, чтобы не
// упереться в истёкшую на сервере.
func (c *Client) idleReset(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	var lastGot uint64
	lastMove := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.mu.Lock()
		idle := len(c.streams) == 0 && len(c.upQ) == 0 && c.upOff > 0 && time.Since(c.lastUse) > 60*time.Second
		busy := len(c.streams) > 0
		c.mu.Unlock()
		if idle {
			c.resetSession("простой больше минуты")
			continue
		}
		// сторож: потоки открыты, а вниз ничего не приходит 30 с — сессия сломалась
		c.dmu.Lock()
		got := c.downR.Next
		c.dmu.Unlock()
		if busy && got == lastGot && c.downR.Buffered() > 0 && time.Since(lastMove) > 30*time.Second {
			c.resetSession("30 с без продвижения потока вниз")
		}
		if got != lastGot || !busy {
			lastGot, lastMove = got, time.Now()
		}
	}
}

func (c *Client) legError(err error) {
	if err == nil {
		return
	}
	c.st.errors.Add(1)
	c.st.setLastErr(err.Error())
}

func backoff(n int) time.Duration {
	if n > 6 {
		n = 6
	}
	return time.Duration(100<<n) * time.Millisecond
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
