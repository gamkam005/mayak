package sub

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// engine — движок для узла id ("" = текущий: ручной выбор или лучший живой).
func (p *Pool) engine(id string) (*Engine, string) {
	p.mu.Lock()
	if id == "" {
		id = p.selected
		if id == "" || p.nodes[id] == nil {
			id = ""
			if p.active != "" && p.res[p.active] != nil && p.res[p.active].OK {
				id = p.active
			} else if len(p.alive) > 0 {
				id = p.alive[0]
			}
		}
	}
	if id == "" {
		p.mu.Unlock()
		return nil, ""
	}
	if e := p.engines[id]; e != nil {
		p.active = id
		p.mu.Unlock()
		return e, id
	}
	n := p.nodes[id]
	p.mu.Unlock()
	if n == nil {
		return nil, ""
	}
	e, err := p.newEngine(context.Background(), n)
	if err != nil {
		p.fail(id, err)
		return nil, ""
	}
	p.mu.Lock()
	if old := p.engines[id]; old != nil {
		_ = e.Close()
		e = old
	} else {
		p.engines[id] = e
	}
	if p.active != id {
		p.opt.Logf("подписки: активный сервер %s (%s %s:%d)", n.Name, n.Proto, n.Host, n.Port)
	}
	p.active = id
	p.mu.Unlock()
	return e, id
}

// fail — неудача через сервер: после 3 подряд он выпадает из живых.
func (p *Pool) fail(id string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.res[id]
	if r == nil {
		r = &Result{ID: id}
		p.res[id] = r
	}
	r.Fails++
	if r.Fails >= 3 && r.OK {
		r.OK, r.Err, r.Checked = false, shortErr(err), time.Now()
		p.opt.Logf("подписки: сервер %s выпал (%v)", id, err)
		if p.active == id {
			p.active = ""
		}
		p.rankLocked()
		if len(p.alive) < 3 {
			select {
			case p.kick <- struct{}{}:
			default:
			}
		}
	}
}

func (p *Pool) good(id string) {
	p.mu.Lock()
	if r := p.res[id]; r != nil {
		r.Fails = 0
	}
	p.mu.Unlock()
}

// Ready — есть ли живой сервер.
func (p *Pool) Ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.alive) > 0 || (p.selected != "" && p.nodes[p.selected] != nil)
}

// Dial — TCP до target через лучший сервер.
func (p *Pool) Dial(ctx context.Context, target string) (net.Conn, error) {
	p.lastUse.Store(time.Now().Unix())
	e, _ := p.engine("")
	if e == nil {
		p.Kick()
		return nil, errors.New("подписки: нет живых серверов")
	}
	return e.Dial(ctx, target)
}

// Handle — для маршрутизатора: трафик приложения через сервер из подписки.
// Если сервер не вернул ни байта — считаем неудачей, после трёх подряд
// переключаемся на следующий.
func (p *Pool) Handle(conn net.Conn, target string) {
	defer conn.Close()
	p.lastUse.Store(time.Now().Unix())
	e, id := p.engine("")
	if e == nil {
		p.Kick()
		return
	}
	// контекст живёт всё соединение: отмена в Xray рвёт поток
	up, err := e.Dial(context.Background(), target)
	if err != nil {
		p.fail(id, err)
		return
	}
	defer up.Close()
	var got int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, conn)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	got, err = io.Copy(conn, up)
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = conn.Close()
	}
	wg.Wait()
	if got > 0 {
		p.good(id)
	} else {
		if err == nil {
			err = io.EOF
		}
		p.fail(id, err)
	}
}

// Kick — попросить фоновую проверку.
func (p *Pool) Kick() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// Run — фоновый цикл: первая проверка, затем лёгкие перепроверки живых и
// редкие полные прогоны. В режиме Lazy (резерв) спит, если пулом не пользуются.
func (p *Pool) Run(ctx context.Context, firstDelay time.Duration) {
	p.rebuild(ctx, false)
	p.mu.Lock()
	p.rankLocked()
	fresh := len(p.alive) > 0 && time.Since(p.lastFull) < p.opt.Recheck
	p.mu.Unlock()
	if !fresh {
		select {
		case <-ctx.Done():
			return
		case <-time.After(firstDelay):
		case <-p.kick:
		}
		_ = p.Check(ctx, false)
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			p.closeAll()
			return
		case <-p.kick:
			if time.Since(p.lastRun) > 20*time.Second {
				_ = p.Check(ctx, false)
			}
		case <-t.C:
			used := time.Since(time.Unix(p.lastUse.Load(), 0)) < time.Hour
			if p.opt.Lazy && !used {
				continue
			}
			p.mu.Lock()
			n, lastRun, lastFull := len(p.alive), p.lastRun, p.lastFull
			p.mu.Unlock()
			switch {
			case n < 3 && time.Since(lastRun) > 5*time.Minute, time.Since(lastFull) > p.opt.Refresh:
				_ = p.Check(ctx, time.Since(lastFull) > p.opt.Refresh)
			case time.Since(lastRun) > p.opt.Recheck:
				p.Recheck(ctx)
			}
		}
	}
}

func (p *Pool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, e := range p.engines {
		_ = e.Close()
		delete(p.engines, id)
	}
}

// Select — ручной выбор сервера ("" = автоматически лучший).
func (p *Pool) Select(id string) {
	p.mu.Lock()
	p.selected = id
	if id != "" {
		p.active = ""
	}
	p.saveLocked()
	p.mu.Unlock()
}

// Pin — закрепить сервер: проверяется всегда и стоит первым среди живых.
func (p *Pool) Pin(id string, on bool) {
	p.mu.Lock()
	if on {
		p.pinned[id] = true
	} else {
		delete(p.pinned, id)
	}
	p.rankLocked()
	p.saveLocked()
	p.mu.Unlock()
}

// Speed — быстрый замер скорости через сервер id (по кнопке).
func (p *Pool) Speed(ctx context.Context, id, url string) (float64, error) {
	p.mu.Lock()
	n := p.nodes[id]
	p.mu.Unlock()
	if n == nil {
		return 0, errors.New("нет такого сервера")
	}
	e, err := p.newEngine(ctx, n)
	if err != nil {
		return 0, err
	}
	defer e.Close()
	mbps, _, err := SpeedTest(ctx, e, url, 3<<20, 20*time.Second)
	if err == nil {
		p.mu.Lock()
		if r := p.res[id]; r != nil {
			r.Speed = mbps
		}
		p.mu.Unlock()
	}
	return mbps, err
}

// NodeView — для панели.
type NodeView struct {
	Node
	Result
	Pinned   bool `json:"pinned"`
	Active   bool `json:"active"`
	Selected bool `json:"selected"`
}

// Snapshot — состояние для панели и приложения.
type Snapshot struct {
	Total    int           `json:"total"`
	Alive    int           `json:"alive"`
	Active   *NodeView     `json:"active,omitempty"`
	Selected string        `json:"selected"`
	Checking bool          `json:"checking"`
	Progress string        `json:"progress,omitempty"`
	LastRun  time.Time     `json:"last_run"`
	Sources  []sourceState `json:"sources"`
	Nodes    []NodeView    `json:"nodes"`
}

func (p *Pool) view(id string) NodeView {
	v := NodeView{Node: *p.nodes[id], Pinned: p.pinned[id], Active: id == p.active, Selected: id == p.selected}
	if r := p.res[id]; r != nil {
		v.Result = *r
	}
	v.Result.ID = id
	return v
}

func (p *Pool) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Snapshot{Total: len(p.nodes), Alive: len(p.alive), Selected: p.selected, Checking: p.checking.Load(),
		Progress: p.progress.Load().(string), LastRun: p.lastRun}
	for _, src := range p.srcs {
		c := *src
		c.URL = Mask(c.URL)
		s.Sources = append(s.Sources, c)
	}
	seen := map[string]bool{}
	add := func(id string) {
		if !seen[id] && p.nodes[id] != nil {
			seen[id] = true
			s.Nodes = append(s.Nodes, p.view(id))
		}
	}
	for _, id := range p.alive {
		add(id)
	}
	for id := range p.pinned {
		add(id)
	}
	if p.selected != "" {
		add(p.selected)
	}
	if p.active != "" && p.nodes[p.active] != nil {
		v := p.view(p.active)
		s.Active = &v
	}
	return s
}

// Links — живые серверы в виде подписки (для «mayak picker»).
func (p *Pool) Links() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, id := range p.alive {
		if l := p.nodes[id].Link; l != "" { // узлы из Xray JSON ссылки не имеют
			out = append(out, l)
		}
	}
	return out
}
