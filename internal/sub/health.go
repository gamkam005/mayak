package sub

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MinRefresh — чаще подписку не качаем, даже если она сама просит.
const MinRefresh = 15 * time.Minute

// retryTried — после неудачной попытки скачать подписку ждём столько.
const retryTried = 5 * time.Minute

// Config — то, что меняется на лету (subs.json, панель).
type Config struct {
	Refresh       time.Duration // перекачивать подписки
	Recheck       time.Duration // перепроверять живых
	TestURL       string        // «реальная задержка»: запрос через сервер
	HonorInterval bool          // слушать profile-update-interval подписки
}

// ConfigView — Config для JSON.
type ConfigView struct {
	Refresh       string `json:"refresh"`
	Recheck       string `json:"recheck"`
	TestURL       string `json:"test_url"`
	HonorInterval bool   `json:"honor_update_interval"`
}

func (c Config) view() ConfigView {
	return ConfigView{Refresh: c.Refresh.String(), Recheck: c.Recheck.String(), TestURL: c.TestURL, HonorInterval: c.HonorInterval}
}

// Config — текущие настройки проверок.
func (p *Pool) Config() Config {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return Config{Refresh: p.opt.Refresh, Recheck: p.opt.Recheck, TestURL: p.opt.TestURL, HonorInterval: p.opt.HonorInterval}
}

// SetConfig — новые периоды/адрес проверки без перезапуска (нули = по умолчанию).
func (p *Pool) SetConfig(c Config) {
	if c.Refresh <= 0 {
		c.Refresh = 6 * time.Hour
	}
	if c.Refresh < MinRefresh {
		c.Refresh = MinRefresh
	}
	if c.Recheck <= 0 {
		c.Recheck = 30 * time.Minute
	}
	if c.TestURL == "" {
		c.TestURL = DefaultTestURL
	}
	p.cfgMu.Lock()
	changed := p.opt.Refresh != c.Refresh || p.opt.Recheck != c.Recheck || p.opt.TestURL != c.TestURL || p.opt.HonorInterval != c.HonorInterval
	p.opt.Refresh, p.opt.Recheck, p.opt.TestURL, p.opt.HonorInterval = c.Refresh, c.Recheck, c.TestURL, c.HonorInterval
	p.cfgMu.Unlock()
	if changed {
		p.opt.Logf("подписки: обновление раз в %s%s, перепроверка живых раз в %s, проверка через %s",
			c.Refresh, map[bool]string{true: " (или как просит подписка, не чаще 15 мин)"}[c.HonorInterval], c.Recheck, c.TestURL)
	}
}

// parseUpdateInterval — заголовок profile-update-interval: часы (бывает дробное).
func parseUpdateInterval(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	h, err := strconv.ParseFloat(v, 64)
	if err != nil || h <= 0 || h > 24*30 {
		return 0
	}
	return time.Duration(h * float64(time.Hour))
}

// EffectiveRefresh — период для подписки: настройка или (если включено) её
// просьба, что меньше, но не чаще MinRefresh.
func EffectiveRefresh(cfg Config, asked time.Duration) time.Duration {
	r := cfg.Refresh
	if cfg.HonorInterval && asked > 0 {
		if asked < MinRefresh {
			asked = MinRefresh
		}
		if asked < r {
			r = asked
		}
	}
	return r
}

func (p *Pool) srcRefresh(id string) time.Duration {
	cfg := p.Config()
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.srcRefreshLocked(id, cfg)
}

func (p *Pool) srcRefreshLocked(id string, cfg Config) time.Duration {
	return EffectiveRefresh(cfg, p.ivl[id])
}

func (p *Pool) triedRecently(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.tried[id]
	return ok && time.Since(t) < retryTried
}

// sourcesDue — есть подписка, которую пора перекачать.
func (p *Pool) sourcesDue() bool {
	cfg := p.Config()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.srcs {
		if !s.Enabled || s.Fetched.IsZero() {
			continue
		}
		if time.Since(s.Fetched) > p.srcRefreshLocked(s.ID, cfg) && time.Since(p.tried[s.ID]) > retryTried {
			return true
		}
	}
	return false
}

// retries — сколько раз переспросить сервер при сбое проверки: тех, кто был
// живым или выбран, — ещё 2 раза (правило «сбой → 2 проверки вне очереди»).
func (p *Pool) retries(id string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r := p.res[id]; (r != nil && r.OK) || id == p.active || id == p.selected || p.pinned[id] {
		return 2
	}
	return 0
}

func (p *Pool) label(id string) string {
	if n := p.nodes[id]; n != nil {
		if n.Name != "" {
			return fmt.Sprintf("%s (%s)", n.Name, n.Proto)
		}
		return fmt.Sprintf("%s:%d (%s)", n.Host, n.Port, n.Proto)
	}
	return id
}

func (p *Pool) setNoticeLocked(msg string) {
	p.notice, p.noticeAt = msg, time.Now()
	p.opt.Logf("подписки: %s", msg)
}

// dropSelectedLocked — ручной выбор умер: обратно на автовыбор.
func (p *Pool) dropSelectedLocked(why string) {
	if p.selected == "" {
		return
	}
	if p.active == p.selected {
		p.active = ""
	}
	p.selected = ""
	p.setNoticeLocked(why + " — включён автовыбор")
}

// nodeKeys — чем узнать «тот же сервер» в обновлённой подписке.
func nodeKeys(n *Node) []string {
	var k []string
	if n.Name != "" {
		k = append(k, "n|"+n.Source+"|"+n.Name)
	}
	return append(k, fmt.Sprintf("h|%s|%s|%s|%d", n.Source, n.Proto, n.Host, n.Port))
}

// remapLocked — после обновления подписки: серверы, чьи настройки поменялись
// (новый SNI, ключ…), получают новый id. Живые, активный, выбранный и
// закреплённые сразу переходят на новые настройки; пропавшие — убираются
// (активный — на следующий живой, выбранный — на автовыбор).
func (p *Pool) remapLocked(old map[string]*Node) {
	idx := map[string][]string{}
	for id, n := range p.nodes {
		if old[id] != nil {
			continue // такой сервер был и раньше
		}
		for _, k := range nodeKeys(n) {
			idx[k] = append(idx[k], id)
		}
	}
	succ := func(id string) string {
		n := old[id]
		if n == nil {
			return ""
		}
		for _, k := range nodeKeys(n) {
			if l := idx[k]; len(l) == 1 {
				return l[0]
			}
		}
		return ""
	}
	moved := map[string]string{}
	for id := range old {
		if p.nodes[id] == nil {
			if nid := succ(id); nid != "" {
				moved[id] = nid
			}
		}
	}
	// результаты переходят на новые настройки (проверка всё равно подтвердит)
	for oid, nid := range moved {
		if r := p.res[oid]; r != nil && p.res[nid] == nil {
			c := *r
			c.ID, c.Fails = nid, 0
			p.res[nid] = &c
		}
	}
	var alive []string
	for _, id := range p.alive {
		switch {
		case p.nodes[id] != nil:
			alive = append(alive, id)
		case moved[id] != "":
			alive = append(alive, moved[id])
		}
	}
	p.alive = alive
	for id := range p.pinned {
		if p.nodes[id] == nil {
			delete(p.pinned, id)
			if nid := moved[id]; nid != "" {
				p.pinned[nid] = true
			}
		}
	}
	if id := p.selected; id != "" && p.nodes[id] == nil && len(old) > 0 {
		if nid := moved[id]; nid != "" {
			p.selected = nid
			p.opt.Logf("подписки: у выбранного сервера %s изменились настройки — перехожу на новые", p.label(nid))
		} else if old[id] != nil {
			p.selected = ""
			p.setNoticeLocked(fmt.Sprintf("выбранный вручную сервер %s пропал из подписки — включён автовыбор", old[id].Name))
		}
	}
	if id := p.active; id != "" && p.nodes[id] == nil {
		if nid := moved[id]; nid != "" {
			p.active = nid
			p.opt.Logf("подписки: у активного сервера %s изменились настройки — перехожу на новые", p.label(nid))
		} else {
			p.active = ""
			p.opt.Logf("подписки: активный сервер пропал из подписки — переключаюсь на следующий живой")
		}
	}
	// движки со старыми настройками закрыть
	for id, e := range p.engines {
		if p.nodes[id] == nil {
			_ = e.Close()
			delete(p.engines, id)
		}
	}
}

// ViewOf — Config для JSON (панель).
func (c Config) ViewOf() ConfigView { return c.view() }

// MaskLink — ссылка на сервер без секретов: vless://***@host:port?…#имя,
// ss://***@…, vmess://*** (у vmess всё в base64).
func MaskLink(l string) string {
	l = strings.TrimSpace(l)
	i := strings.Index(l, "://")
	if i < 0 {
		return Mask(l)
	}
	scheme, rest := l[:i+3], l[i+3:]
	frag := ""
	if j := strings.IndexByte(rest, '#'); j >= 0 {
		rest, frag = rest[:j], rest[j:]
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		return scheme + "***@" + keyRe.ReplaceAllString(rest[at+1:], "${1}***") + frag
	}
	if strings.HasPrefix(strings.ToLower(scheme), "http") {
		return Mask(l)
	}
	return scheme + "***" + frag
}
