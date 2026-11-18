package sub

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Options — настройки пула.
type Options struct {
	StateDir      string   // кэш подписок и результаты проверок ("" = в памяти)
	Sources       []Source // подписки (встроенные + свои)
	Links         string   // свои ссылки vless://… построчно
	Lookup        func(ctx context.Context, host string) ([]net.IP, error)
	Fetch         *http.Client  // чем качать подписки (nil = обычный)
	MaxCandidates int           // сколько серверов проверять за прогон (150)
	Concurrency   int           // параллельных TCP-проб (32)
	ProbeWorkers  int           // параллельных проверок через ядро (8)
	ProbeMax      int           // сколько лучших по TCP проверять через ядро (48)
	Keep          int           // сколько живых держать (10)
	TCPTimeout    time.Duration // 2.5 с
	ProbeTimeout  time.Duration // 6 с
	TestURL       string
	OpenURL       string        // "-" = не проверять
	Refresh       time.Duration // перекачивать подписки (6 ч)
	Recheck       time.Duration // перепроверять живых (30 мин)
	HonorInterval bool          // слушать заголовок подписки profile-update-interval (не чаще MinRefresh)
	Lazy          bool          // резервный режим: фоновые проверки, только если пулом пользовались за последний час
	Logf          func(string, ...any)
}

// Result — итог проверки сервера.
type Result struct {
	ID      string    `json:"-"`
	TCP     int       `json:"tcp_ms"`
	Delay   int       `json:"delay_ms"` // 0 = не проверен/мёртв
	OK      bool      `json:"ok"`
	Err     string    `json:"err,omitempty"`
	Checked time.Time `json:"checked"`
	Fails   int       `json:"fails"`
	Speed   float64   `json:"mbps,omitempty"`
	Limited bool      `json:"limited,omitempty"` // жив, но заблокированное в РФ через него не открывается
}

type sourceState struct {
	Source
	Count   int            `json:"count"`
	Bad     int            `json:"bad"`
	Mix     map[string]int `json:"mix"`
	Fetched time.Time      `json:"fetched"`
	Err     string         `json:"err,omitempty"`
	// UpdateHours — что просит сама подписка (profile-update-interval), Refresh — с каким периодом реально перекачиваем.
	UpdateHours float64 `json:"update_hours,omitempty"`
	Refresh     string  `json:"refresh,omitempty"`
}

// Pool — набор серверов из подписок с проверкой и автопереключением.
type Pool struct {
	opt Options

	mu       sync.Mutex
	srcs     []*sourceState
	nodes    map[string]*Node
	order    []string // порядок узлов (для выборки)
	res      map[string]*Result
	alive    []string // живые, по задержке
	pinned   map[string]bool
	selected string // ручной выбор ("" = авто)
	active   string
	engines  map[string]*Engine
	checking atomic.Bool
	lastRun  time.Time
	lastFull time.Time
	lastUse  atomic.Int64
	kick     chan struct{}
	progress atomic.Value // string

	cfgMu     sync.RWMutex             // Refresh/Recheck/TestURL/HonorInterval меняются на лету
	ivl       map[string]time.Duration // srcID → период из заголовка подписки
	tried     map[string]time.Time     // srcID → последняя попытка скачать
	verifying map[string]bool          // идёт внеочередная проверка сервера
	verified  map[string]time.Time     // когда она закончилась
	notice    string                   // заметка для панели (сброс ручного выбора и т. п.)
	noticeAt  time.Time
	probeFn   func(ctx context.Context, n *Node, testURL string, timeout time.Duration) (time.Duration, error)
}

type persisted struct {
	Selected string             `json:"selected"`
	Pinned   []string           `json:"pinned"`
	Results  map[string]*Result `json:"results"`
	Alive    []string           `json:"alive"`
	LastFull time.Time          `json:"last_full"`
	// Intervals — profile-update-interval подписок (часы), чтобы и после
	// перезапуска кэш считался свежим по нужному периоду.
	Intervals map[string]float64 `json:"intervals,omitempty"`
}

func New(opt Options) *Pool {
	if opt.MaxCandidates <= 0 {
		opt.MaxCandidates = 150
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 32
	}
	if opt.ProbeWorkers <= 0 {
		opt.ProbeWorkers = 8
	}
	if opt.ProbeMax <= 0 {
		opt.ProbeMax = 48
	}
	if opt.Keep <= 0 {
		opt.Keep = 10
	}
	if opt.TCPTimeout <= 0 {
		opt.TCPTimeout = 2500 * time.Millisecond
	}
	if opt.ProbeTimeout <= 0 {
		opt.ProbeTimeout = 6 * time.Second
	}
	if opt.TestURL == "" {
		opt.TestURL = DefaultTestURL
	}
	if opt.OpenURL == "" {
		opt.OpenURL = DefaultOpenURL
	}
	if opt.Refresh <= 0 {
		opt.Refresh = 6 * time.Hour
	}
	if opt.Recheck <= 0 {
		opt.Recheck = 30 * time.Minute
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.Fetch == nil {
		opt.Fetch = &http.Client{Timeout: 30 * time.Second}
	}
	if opt.Refresh < MinRefresh {
		opt.Refresh = MinRefresh
	}
	p := &Pool{opt: opt, nodes: map[string]*Node{}, res: map[string]*Result{}, pinned: map[string]bool{},
		engines: map[string]*Engine{}, kick: make(chan struct{}, 1),
		ivl: map[string]time.Duration{}, tried: map[string]time.Time{}, verifying: map[string]bool{}, verified: map[string]time.Time{}}
	p.progress.Store("")
	p.setSources(opt.Sources)
	p.load()
	return p
}

var keyRe = regexp.MustCompile(`(?i)([?&](key|token|uuid|pass|password|auth|secret|obfs-password)=)[^&#\s]+`)

// Mask — спрятать ключи в адресе подписки для журнала.
// pathKeyRe — секрет в пути (/subs/<uuid>, /sub/<token>): длинный кусок пути, где цифр от 4.
var pathKeyRe = regexp.MustCompile(`/[A-Za-z0-9_=-]{16,}`)

func digits(s string) (n int) {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n++
		}
	}
	return n
}

// Mask прячет ключи подписки — и в параметрах, и в пути.
func Mask(u string) string {
	u = keyRe.ReplaceAllString(u, "${1}***")
	return pathKeyRe.ReplaceAllStringFunc(u, func(m string) string {
		if digits(m) < 4 {
			return m
		}
		return "/***"
	})
}

func srcID(u string) string {
	h := sha1.Sum([]byte(u))
	return "u" + hex.EncodeToString(h[:4])
}

func (p *Pool) setSources(list []Source) {
	p.srcs = nil
	for _, s := range list {
		if s.ID == "" {
			s.ID = srcID(s.URL)
		}
		if s.Name == "" {
			s.Name = Mask(s.URL)
		}
		p.srcs = append(p.srcs, &sourceState{Source: s})
	}
}

// Reload — новые подписки/ссылки (из настроек приложения) без перезапуска.
func (p *Pool) Reload(list []Source, links string) {
	p.mu.Lock()
	old := map[string]*sourceState{}
	for _, s := range p.srcs {
		old[s.URL] = s
	}
	p.setSources(list)
	for _, s := range p.srcs {
		if o := old[s.URL]; o != nil {
			s.Count, s.Bad, s.Mix, s.Fetched, s.Err = o.Count, o.Bad, o.Mix, o.Fetched, o.Err
		}
	}
	p.opt.Links = links
	p.mu.Unlock()
	p.rebuild(context.Background(), false)
	p.Kick()
}

func (p *Pool) path(name string) string {
	if p.opt.StateDir == "" {
		return ""
	}
	return filepath.Join(p.opt.StateDir, name)
}

func (p *Pool) load() {
	f := p.path("state.json")
	if f == "" {
		return
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return
	}
	var st persisted
	if json.Unmarshal(b, &st) != nil {
		return
	}
	p.selected, p.lastFull, p.lastRun = st.Selected, st.LastFull, st.LastFull
	for _, id := range st.Pinned {
		p.pinned[id] = true
	}
	if st.Results != nil {
		p.res = st.Results
	}
	p.alive = st.Alive
	for id, h := range st.Intervals {
		if h > 0 {
			p.ivl[id] = time.Duration(h * float64(time.Hour))
		}
	}
}

func (p *Pool) saveLocked() {
	f := p.path("state.json")
	if f == "" {
		return
	}
	st := persisted{Selected: p.selected, Results: map[string]*Result{}, Alive: p.alive, LastFull: p.lastFull, Intervals: map[string]float64{}}
	for id, d := range p.ivl {
		st.Intervals[id] = d.Hours()
	}
	for id := range p.pinned {
		st.Pinned = append(st.Pinned, id)
	}
	for id, r := range p.res {
		if r.OK || p.pinned[id] || time.Since(r.Checked) < 12*time.Hour {
			st.Results[id] = r
		}
	}
	b, _ := json.Marshal(st)
	_ = os.MkdirAll(p.opt.StateDir, 0o700)
	_ = os.WriteFile(f+".tmp", b, 0o600)
	_ = os.Rename(f+".tmp", f)
}

// fetchOne — скачать подписку (или взять кэш, если свежий/сеть недоступна).
func (p *Pool) fetchOne(ctx context.Context, s *sourceState, force bool) string {
	cache := p.path("src-" + srcID(s.URL) + ".txt")
	if cache != "" && !force {
		if fi, err := os.Stat(cache); err == nil && (time.Since(fi.ModTime()) < p.srcRefresh(s.ID) || p.triedRecently(s.ID)) {
			if b, err := os.ReadFile(cache); err == nil {
				p.mu.Lock()
				s.Fetched = fi.ModTime()
				p.mu.Unlock()
				return string(b)
			}
		}
	}
	p.mu.Lock()
	p.tried[s.ID] = time.Now()
	p.mu.Unlock()
	body, every, err := p.download(ctx, s.URL)
	if every > 0 {
		p.mu.Lock()
		p.ivl[s.ID] = every
		p.mu.Unlock()
	}
	if err != nil {
		p.mu.Lock()
		s.Err = err.Error()
		p.mu.Unlock()
		p.opt.Logf("подписка %s: %v", s.Name, err)
		if cache != "" {
			if b, err2 := os.ReadFile(cache); err2 == nil {
				return string(b)
			}
		}
		return ""
	}
	p.mu.Lock()
	s.Err, s.Fetched = "", time.Now()
	p.mu.Unlock()
	if cache != "" {
		_ = os.MkdirAll(p.opt.StateDir, 0o700)
		_ = os.WriteFile(cache, []byte(body), 0o600)
	}
	return body
}

func (p *Pool) download(ctx context.Context, u string) (string, time.Duration, error) {
	var every time.Duration
	get := func(cl *http.Client) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", "v2rayNG/1.9.0")
		resp, err := cl.Do(req)
		if err != nil {
			return "", errors.New(Mask(err.Error()))
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		every = parseUpdateInterval(resp.Header.Get("Profile-Update-Interval"))
		b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		return string(b), err
	}
	body, err := get(p.opt.Fetch)
	if err == nil {
		return body, every, nil
	}
	// приёмы против DPI ломают рукопожатие с некоторыми серверами (сертификат
	// «без имён») — пробуем обычное соединение
	if p.opt.Fetch != nil && p.opt.Fetch.Transport != nil {
		tr := &http.Transport{TLSHandshakeTimeout: 15 * time.Second, ForceAttemptHTTP2: true}
		defer tr.CloseIdleConnections()
		if b, err2 := get(&http.Client{Transport: tr, Timeout: 45 * time.Second}); err2 == nil {
			p.opt.Logf("подписка %s скачана без приёмов против DPI", Mask(u))
			return b, every, nil
		}
	}
	// напрямую не вышло — через уже живой сервер из пула
	if e, id := p.engine(""); e != nil {
		tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return e.Dial(ctx, addr) }}
		defer tr.CloseIdleConnections()
		if b, err2 := get(&http.Client{Transport: tr}); err2 == nil {
			p.opt.Logf("подписка скачана через %s", id)
			return b, every, nil
		}
	}
	return "", 0, err
}

// rebuild — собрать узлы из подписок (дубликаты убираются).
func (p *Pool) rebuild(ctx context.Context, force bool) {
	p.mu.Lock()
	srcs := append([]*sourceState{}, p.srcs...)
	links := p.opt.Links
	p.mu.Unlock()
	nodes := map[string]*Node{}
	var order []string
	add := func(list []Node, src string) {
		for i := range list {
			n := list[i]
			if _, dup := nodes[n.ID]; dup {
				continue
			}
			n.Source = src
			nodes[n.ID] = &n
			order = append(order, n.ID)
		}
	}
	if strings.TrimSpace(links) != "" {
		l, _ := ParseText(links)
		add(l, "свои")
	}
	var wg sync.WaitGroup
	bodies := make([]string, len(srcs))
	for i, s := range srcs {
		if !s.Enabled {
			continue
		}
		wg.Add(1)
		go func(i int, s *sourceState) { defer wg.Done(); bodies[i] = p.fetchOne(ctx, s, force) }(i, s)
	}
	wg.Wait()
	for i, s := range srcs {
		if !s.Enabled {
			continue
		}
		l, bad := ParseText(bodies[i])
		mix := map[string]int{}
		for _, n := range l {
			mix[n.Proto]++
		}
		p.mu.Lock()
		s.Count, s.Bad, s.Mix = len(l), bad, mix
		p.mu.Unlock()
		add(l, s.ID)
	}
	p.mu.Lock()
	old := p.nodes
	p.nodes, p.order = nodes, order
	p.remapLocked(old)
	p.mu.Unlock()
}

// candidates — что проверять: закреплённые, недавно живые, затем случайная
// выборка поровну из каждой подписки — чтобы огромный список не вытеснил малые.
func (p *Pool) candidates(max int) []*Node {
	p.mu.Lock()
	defer p.mu.Unlock()
	seen := map[string]bool{}
	var out []*Node
	push := func(id string) {
		if n := p.nodes[id]; n != nil && !seen[id] && len(out) < max {
			seen[id] = true
			out = append(out, n)
		}
	}
	for id := range p.pinned {
		push(id)
	}
	if p.selected != "" {
		push(p.selected)
	}
	for _, id := range p.alive {
		push(id)
	}
	for id, r := range p.res {
		if r.OK {
			push(id)
		}
	}
	bySrc := map[string][]string{}
	var srcOrder []string
	for _, id := range p.order {
		n := p.nodes[id]
		if seen[id] {
			continue
		}
		// недавно мёртвые не трогаем 2 часа
		if r := p.res[id]; r != nil && !r.OK && time.Since(r.Checked) < 2*time.Hour {
			continue
		}
		if _, ok := bySrc[n.Source]; !ok {
			srcOrder = append(srcOrder, n.Source)
		}
		bySrc[n.Source] = append(bySrc[n.Source], id)
	}
	for _, s := range srcOrder {
		l := bySrc[s]
		rand.Shuffle(len(l), func(i, j int) { l[i], l[j] = l[j], l[i] })
	}
	for len(out) < max {
		progress := false
		for _, s := range srcOrder {
			if l := bySrc[s]; len(l) > 0 {
				push(l[0])
				bySrc[s] = l[1:]
				progress = true
			}
		}
		if !progress {
			break
		}
	}
	return out
}

func (p *Pool) resolve(ctx context.Context, host string) string {
	if net.ParseIP(host) != nil || p.opt.Lookup == nil {
		return host
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := p.opt.Lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String()
		}
	}
	return ips[0].String()
}

func (p *Pool) newEngine(ctx context.Context, n *Node) (*Engine, error) {
	ip := p.resolve(ctx, n.Host)
	if ip == "" {
		return nil, errors.New("DNS: адрес не найден")
	}
	ob := withIP(n.ob, n.Host, ip)
	if n.insecure && !n.UDPOnly() {
		// Xray больше не умеет allowInsecure: закрепляем сертификат сервера при
		// первом подключении (для бесплатного сервера это равноценно).
		if err := pinCert(ctx, ob, net.JoinHostPort(ip, fmt.Sprint(n.Port))); err != nil {
			return nil, err
		}
	}
	return NewEngine(ob)
}

func pinCert(ctx context.Context, ob map[string]any, addr string) error {
	ss, _ := ob["streamSettings"].(map[string]any)
	t, _ := ss["tlsSettings"].(map[string]any)
	if t == nil || t["pinnedPeerCertSha256"] != nil {
		return nil
	}
	sni, _ := t["serverName"].(string)
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true}}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("TLS: %w", err)
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return errors.New("TLS: нет сертификата")
	}
	h := sha256.Sum256(certs[0].Raw)
	t["pinnedPeerCertSha256"] = hex.EncodeToString(h[:])
	return nil
}

// probeNode — задержка + проверка «открывает ли заблокированное».
// extra — сколько раз переспросить сервер, если первый запрос не прошёл
// (для тех, кто был живым: правило «сбой → ещё 2 проверки вне очереди»).
func (p *Pool) probeNode(ctx context.Context, n *Node, r *Result, extra int) {
	cfg := p.Config()
	if p.probeFn != nil {
		var err error
		for i := 0; i <= extra; i++ {
			var d time.Duration
			if d, err = p.probeFn(ctx, n, cfg.TestURL, p.opt.ProbeTimeout); err == nil {
				r.OK, r.Delay, r.Err = true, max(1, ms(d)), ""
				return
			}
		}
		r.Err = shortErr(err)
		return
	}
	e, err := p.newEngine(ctx, n)
	if err == nil {
		var d time.Duration
		for i := 0; i <= extra; i++ {
			if d, err = probe(ctx, e, cfg.TestURL, p.opt.ProbeTimeout); err == nil {
				break
			}
		}
		if err == nil {
			r.OK, r.Delay = true, max(1, ms(d))
			if p.opt.OpenURL != "-" {
				_, e2 := probe(ctx, e, p.opt.OpenURL, p.opt.ProbeTimeout)
				r.Limited = e2 != nil
			}
		}
		_ = e.Close()
	}
	if err != nil {
		r.Err = shortErr(err)
	}
}

// Check — полный прогон: TCP-пинг выборки, затем реальная задержка через ядро.
func (p *Pool) Check(ctx context.Context, refetch bool) error {
	if !p.checking.CompareAndSwap(false, true) {
		return errors.New("проверка уже идёт")
	}
	defer p.checking.Store(false)
	t0 := time.Now()
	p.progress.Store("скачиваю подписки")
	p.rebuild(ctx, refetch)
	cands := p.candidates(p.opt.MaxCandidates)
	p.progress.Store(fmt.Sprintf("TCP-проба %d серверов", len(cands)))
	type tr struct {
		n   *Node
		tcp time.Duration
	}
	tcpRes := make([]tr, len(cands))
	parallel(ctx, len(cands), p.opt.Concurrency, func(i int) {
		n := cands[i]
		tcpRes[i].n = n
		if n.UDPOnly() {
			tcpRes[i].tcp = time.Second // UDP: TCP-пинг не применим, проверим ядром
			return
		}
		ip := p.resolve(ctx, n.Host)
		if ip == "" {
			tcpRes[i].tcp = -1
			return
		}
		d, err := tcpPing(ctx, net.JoinHostPort(ip, fmt.Sprint(n.Port)), p.opt.TCPTimeout)
		if err != nil {
			d = -1
		}
		tcpRes[i].tcp = d
	})
	var ok []tr
	now := time.Now()
	tcpN := 0
	p.mu.Lock()
	for _, r := range tcpRes {
		if r.n == nil {
			continue
		}
		if r.tcp < 0 {
			p.res[r.n.ID] = &Result{ID: r.n.ID, Err: "TCP: нет ответа", Checked: now}
			continue
		}
		ok = append(ok, r)
		tcpN++
	}
	p.mu.Unlock()
	sort.Slice(ok, func(i, j int) bool {
		pi, pj := p.isPinned(ok[i].n.ID), p.isPinned(ok[j].n.ID)
		if pi != pj {
			return pi
		}
		return ok[i].tcp < ok[j].tcp
	})
	if len(ok) > p.opt.ProbeMax {
		for _, r := range ok[p.opt.ProbeMax:] {
			p.mu.Lock()
			p.res[r.n.ID] = &Result{ID: r.n.ID, TCP: ms(r.tcp), Err: "не дошла очередь", Checked: now}
			p.mu.Unlock()
		}
		ok = ok[:p.opt.ProbeMax]
	}
	p.progress.Store(fmt.Sprintf("проверка через ядро %d серверов", len(ok)))
	parallel(ctx, len(ok), p.opt.ProbeWorkers, func(i int) {
		n := ok[i].n
		r := &Result{ID: n.ID, TCP: ms(ok[i].tcp), Checked: time.Now()}
		if n.UDPOnly() {
			r.TCP = 0
		}
		p.probeNode(ctx, n, r, p.retries(n.ID))
		p.mu.Lock()
		if old := p.res[n.ID]; old != nil {
			r.Speed = old.Speed
		}
		p.res[n.ID] = r
		p.mu.Unlock()
	})
	p.mu.Lock()
	p.rankLocked()
	p.lastRun, p.lastFull = time.Now(), time.Now()
	n, full, total := len(p.alive), 0, len(p.nodes)
	for _, id := range p.alive {
		if !p.res[id].Limited {
			full++
		}
	}
	p.saveLocked()
	p.mu.Unlock()
	p.progress.Store("")
	p.opt.Logf("подписки: проверено %d из %d, TCP отвечают %d, через ядро %d, живых %d (без ограничений %d) за %s",
		len(cands), total, tcpN, len(ok), n, full, time.Since(t0).Round(time.Second))
	return nil
}

// Recheck — дешёвая перепроверка только живых и закреплённых.
func (p *Pool) Recheck(ctx context.Context) {
	if !p.checking.CompareAndSwap(false, true) {
		return
	}
	defer p.checking.Store(false)
	p.mu.Lock()
	var ids []string
	seen := map[string]bool{}
	for _, id := range append(append([]string{}, p.alive...), keys(p.pinned)...) {
		if !seen[id] && p.nodes[id] != nil {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	p.mu.Unlock()
	parallel(ctx, len(ids), p.opt.ProbeWorkers, func(i int) {
		p.mu.Lock()
		n := p.nodes[ids[i]]
		p.mu.Unlock()
		r := &Result{ID: n.ID, Checked: time.Now()}
		p.probeNode(ctx, n, r, p.retries(n.ID))
		p.mu.Lock()
		if old := p.res[n.ID]; old != nil {
			r.TCP, r.Speed = old.TCP, old.Speed
			if !r.OK {
				r.Fails = old.Fails + 1
				if old.OK {
					p.opt.Logf("подписки: сервер %s выпал при перепроверке (и 2 повторные проверки без ответа: %s)", p.label(n.ID), r.Err)
				}
			}
		}
		p.res[n.ID] = r
		p.mu.Unlock()
	})
	p.mu.Lock()
	p.rankLocked()
	p.lastRun = time.Now()
	p.saveLocked()
	p.mu.Unlock()
}

func keys(m map[string]bool) (o []string) {
	for k := range m {
		o = append(o, k)
	}
	return
}

func (p *Pool) isPinned(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pinned[id]
}

// rankLocked — живые по задержке, закреплённые вперёд; лишние движки закрыть.
func (p *Pool) rankLocked() {
	var alive []string
	for id, r := range p.res {
		if r.OK && p.nodes[id] != nil {
			alive = append(alive, id)
		}
	}
	sort.Slice(alive, func(i, j int) bool {
		a, b := alive[i], alive[j]
		if p.pinned[a] != p.pinned[b] {
			return p.pinned[a]
		}
		if p.res[a].Limited != p.res[b].Limited {
			return !p.res[a].Limited
		}
		return p.res[a].Delay < p.res[b].Delay
	})
	if len(alive) > p.opt.Keep*3 {
		alive = alive[:p.opt.Keep*3]
	}
	p.alive = alive
	if id := p.selected; id != "" {
		if r := p.res[id]; p.nodes[id] != nil && r != nil && !r.OK && !r.Checked.IsZero() {
			p.dropSelectedLocked(fmt.Sprintf("выбранный вручную сервер %s не отвечает (%s)", p.label(id), r.Err))
		}
	}
	keep := map[string]bool{}
	for i, id := range alive {
		if i < 3 || p.pinned[id] || id == p.selected {
			keep[id] = true
		}
	}
	for id, e := range p.engines {
		if !keep[id] && id != p.active {
			_ = e.Close()
			delete(p.engines, id)
		}
	}
}

func ms(d time.Duration) int { return int(d / time.Millisecond) }

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 80 {
		s = s[i+2:]
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}
