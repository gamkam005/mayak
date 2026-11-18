package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"mayak/internal/sub"
)

//go:embed web/panel.html
var panelHTML []byte

//go:embed web/login.html
var loginHTML []byte

// ---------- журнал для панели (секреты замазаны) ----------

var linkUserRe = regexp.MustCompile(`(?i)\b(mayak|vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s@"'<>]+@`)

func maskLine(s string) string {
	return sub.Mask(linkUserRe.ReplaceAllString(s, "${1}://***@"))
}

// logRing — последние строки журнала; всё, что пишется, сначала замазывается
// и уходит дальше (stderr → журнал RouterOS/OpenWrt).
type logRing struct {
	mu    sync.Mutex
	out   io.Writer
	lines []string
	max   int
	part  string
}

func newLogRing(out io.Writer, max int) *logRing { return &logRing{out: out, max: max} }

func (l *logRing) Write(b []byte) (int, error) {
	s := maskLine(string(b))
	if l.out != nil {
		_, _ = io.WriteString(l.out, s)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s = l.part + s
	parts := strings.Split(s, "\n")
	l.part = parts[len(parts)-1]
	for _, ln := range parts[:len(parts)-1] {
		l.lines = append(l.lines, ln)
	}
	if over := len(l.lines) - l.max; over > 0 {
		l.lines = append([]string(nil), l.lines[over:]...)
	}
	return len(b), nil
}

func (l *logRing) Lines(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.lines) {
		n = len(l.lines)
	}
	return append([]string(nil), l.lines[len(l.lines)-n:]...)
}

// ---------- пароль панели ----------

func isLoopbackBind(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		h = addr
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// generatedPassPath — куда положить сгенерированный пароль: в контейнере /data
// (на MikroTik это Files → mayak-data), на OpenWrt /etc, иначе рядом с программой.
var generatedPassPath = defaultPassPath

func defaultPassPath() string {
	if fi, err := os.Stat("/data"); err == nil && fi.IsDir() {
		return "/data/ui.pass"
	}
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return "/etc/mayak-ui.pass"
	}
	return besideExe("ui.pass")
}

func readPassFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
}

// uiPassword: -ui-pass (MAYAK_UI_PASS; «@файл» — из файла), затем -ui-pass-file,
// /etc/mayak/ui.pass, ранее созданный файл. Нет пароля и панель слушает не
// только localhost — создаём случайный и пишем в файл (в журнал — только путь).
func uiPassword(flagPass, passFile, bind string, logf func(string, ...any)) (string, error) {
	if strings.HasPrefix(flagPass, "@") {
		if p := readPassFile(flagPass[1:]); p != "" {
			return p, nil
		}
		return "", fmt.Errorf("пароль панели: файл %s пустой или не читается", flagPass[1:])
	}
	if flagPass != "" {
		return flagPass, nil
	}
	gen := generatedPassPath()
	for _, f := range []string{passFile, "/etc/mayak/ui.pass", gen} {
		if f == "" {
			continue
		}
		if p := readPassFile(f); p != "" {
			logf("панель: вход по паролю из файла %s", f)
			return p, nil
		}
	}
	if isLoopbackBind(bind) {
		return "", nil
	}
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	pass := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	if err := os.MkdirAll(filepath.Dir(gen), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(gen, []byte(pass+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("пароль панели: не удалось записать %s: %w", gen, err)
	}
	logf("панель: пароль создан и сохранён в файл %s (на MikroTik: Files → mayak-data/ui.pass)", gen)
	return pass, nil
}

// ---------- самоподписанный TLS ----------

func uiTLSConfig(dir string, logf func(string, ...any)) (*tls.Config, error) {
	certF, keyF := filepath.Join(dir, "ui-cert.pem"), filepath.Join(dir, "ui-key.pem")
	if _, err := os.Stat(certF); err != nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "mayak-panel"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames: []string{"mayak-panel", "localhost"}}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		if err != nil {
			return nil, err
		}
		kb, _ := x509.MarshalECPrivateKey(k)
		_ = os.MkdirAll(dir, 0o700)
		if err := os.WriteFile(keyF, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(certF, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			return nil, err
		}
	}
	c, err := tls.LoadX509KeyPair(certF, keyF)
	if err != nil {
		return nil, err
	}
	fp := sha256.Sum256(c.Certificate[0])
	logf("панель: HTTPS с самоподписанным сертификатом %s, SHA-256 %s", certF, hex.EncodeToString(fp[:]))
	return &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}, nil
}

// ---------- вход, сессии, CSRF ----------

const (
	sessionCookie = "mayak_session"
	sessionTTL    = 12 * time.Hour
)

type session struct {
	csrf string
	exp  time.Time
}

type failState struct {
	n     int
	until time.Time
}

type uiAuth struct {
	hash   [32]byte
	on     bool
	secure bool
	now    func() time.Time

	mu       sync.Mutex
	sessions map[string]*session
	fails    map[string]*failState
	window   time.Time // общий счётчик неудач за минуту
	windowN  int
}

func newUIAuth(pass string, secure bool) *uiAuth {
	a := &uiAuth{on: pass != "", secure: secure, now: time.Now, sessions: map[string]*session{}, fails: map[string]*failState{}}
	a.hash = sha256.Sum256([]byte(pass))
	return a
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (a *uiAuth) session(r *http.Request) (string, *session) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return "", nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[c.Value]
	if s == nil {
		return "", nil
	}
	if a.now().After(s.exp) {
		delete(a.sessions, c.Value)
		return "", nil
	}
	s.exp = a.now().Add(sessionTTL)
	return c.Value, s
}

// sameOrigin — Origin/Referer (если есть) должен совпадать с адресом панели.
func sameOrigin(r *http.Request) bool {
	for _, h := range []string{r.Header.Get("Origin"), r.Header.Get("Referer")} {
		if h == "" || h == "null" {
			continue
		}
		u, err := url.Parse(h)
		if err != nil || u.Host != r.Host {
			return false
		}
		return true
	}
	return true
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// retryAfter — можно ли сейчас пробовать войти с этого адреса.
func (a *uiAuth) retryAfter(ip string) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if now.Sub(a.window) < time.Minute && a.windowN >= 30 {
		return time.Minute - now.Sub(a.window)
	}
	if f := a.fails[ip]; f != nil && now.Before(f.until) {
		return f.until.Sub(now)
	}
	return 0
}

func (a *uiAuth) noteFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if now.Sub(a.window) >= time.Minute {
		a.window, a.windowN = now, 0
	}
	a.windowN++
	f := a.fails[ip]
	if f == nil {
		f = &failState{}
		a.fails[ip] = f
	}
	f.n++
	if f.n >= 5 {
		d := time.Minute << min(f.n-5, 4) // 1, 2, 4, 8, 16 мин
		if d > 15*time.Minute {
			d = 15 * time.Minute
		}
		f.until = now.Add(d)
	}
	if len(a.fails) > 1000 {
		for k, v := range a.fails {
			if now.After(v.until) {
				delete(a.fails, k)
			}
		}
	}
}

func (a *uiAuth) newSession() (string, *session) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.sessions) >= 100 {
		var oldK string
		var oldT time.Time
		for k, s := range a.sessions {
			if oldK == "" || s.exp.Before(oldT) {
				oldK, oldT = k, s.exp
			}
		}
		delete(a.sessions, oldK)
	}
	id, s := randHex(32), &session{csrf: randHex(24), exp: a.now().Add(sessionTTL)}
	a.sessions[id] = s
	return id, s
}

func (a *uiAuth) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(loginHTML)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST", http.StatusMethodNotAllowed)
		return
	}
	if !a.on {
		writeJS(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if !sameOrigin(r) {
		writeJS(w, http.StatusForbidden, map[string]any{"ok": false, "err": "чужой источник запроса"})
		return
	}
	ip := clientIP(r)
	if d := a.retryAfter(ip); d > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(int(d.Seconds())+1))
		writeJS(w, http.StatusTooManyRequests, map[string]any{"ok": false, "err": fmt.Sprintf("слишком много попыток, подождите %d с", int(d.Seconds())+1)})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	} else {
		_ = r.ParseForm()
		body.Password = r.PostFormValue("password")
	}
	h := sha256.Sum256([]byte(body.Password))
	if subtle.ConstantTimeCompare(h[:], a.hash[:]) != 1 {
		a.noteFail(ip)
		time.Sleep(300 * time.Millisecond)
		writeJS(w, http.StatusUnauthorized, map[string]any{"ok": false, "err": "неверный пароль"})
		return
	}
	a.mu.Lock()
	delete(a.fails, ip)
	a.mu.Unlock()
	id, _ := a.newSession()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: a.secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	writeJS(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *uiAuth) logout(w http.ResponseWriter, r *http.Request) {
	if id, _ := a.session(r); id != "" {
		a.mu.Lock()
		delete(a.sessions, id)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJS(w, http.StatusOK, map[string]any{"ok": true})
}

// Wrap — всё, кроме страницы входа, только после входа; изменяющие запросы —
// с CSRF-токеном сессии и с того же адреса.
func (a *uiAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		switch r.URL.Path {
		case "/login":
			a.login(w, r)
			return
		case "/logout":
			if r.Method != http.MethodPost {
				http.Error(w, "POST", http.StatusMethodNotAllowed)
				return
			}
			if a.on {
				if _, s := a.session(r); s == nil || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrf)) != 1 {
					writeJS(w, http.StatusForbidden, map[string]any{"ok": false, "err": "нет CSRF-токена"})
					return
				}
			}
			a.logout(w, r)
			return
		}
		if !a.on {
			if r.URL.Path == "/api/session" {
				writeJS(w, http.StatusOK, map[string]any{"auth": false, "csrf": ""})
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		_, s := a.session(r)
		if s == nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJS(w, http.StatusUnauthorized, map[string]any{"ok": false, "err": "нужен вход", "login": "/login"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.URL.Path == "/api/session" {
			writeJS(w, http.StatusOK, map[string]any{"auth": true, "csrf": s.csrf})
			return
		}
		if unsafeMethod(r.Method) {
			if !sameOrigin(r) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrf)) != 1 {
				writeJS(w, http.StatusForbidden, map[string]any{"ok": false, "err": "нет CSRF-токена или чужой источник"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJS(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------- настройки подписок из панели ----------

type subsConfigView struct {
	Path     string         `json:"path"`
	Writable bool           `json:"writable"`
	URLs     []string       `json:"urls"`
	Links    string         `json:"links"`
	Disabled []string       `json:"disabled"`
	Mode     string         `json:"mode"`
	Refresh  string         `json:"refresh"`
	Recheck  string         `json:"recheck"`
	TestURL  string         `json:"test_url"`
	Honor    bool           `json:"honor_update_interval"`
	Presets  []presetView   `json:"presets"`
	Defaults sub.ConfigView `json:"defaults"`
	Extra    int            `json:"extra_env"` // подписок из -sub / MAYAK_SUB (в файле их нет)
}

type presetView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

func maskLinks(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, sub.MaskLink(l))
		}
	}
	return strings.Join(out, "\n")
}

// unmask — строки, оставленные замазанными, вернуть к исходным из файла.
func unmask(in []string, orig []string, mask func(string) string) ([]string, error) {
	used := map[int]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !strings.Contains(v, "***") {
			out = append(out, v)
			continue
		}
		found := false
		for i, o := range orig {
			if !used[i] && mask(o) == v {
				used[i], found = true, true
				out = append(out, o)
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("строка со *** не совпадает ни с одной сохранённой — вставьте адрес целиком: %s", v)
		}
	}
	return out, nil
}

func validateSubsFile(f *subsFile) error {
	switch f.Mode {
	case "", "off", "reserve", "always":
	default:
		return fmt.Errorf("режим: %q (нужно off, reserve или always)", f.Mode)
	}
	known := map[string]bool{}
	for _, p := range sub.Presets {
		known[p.ID] = true
	}
	for _, id := range f.Disabled {
		if !known[id] {
			return fmt.Errorf("нет встроенной подписки %q", id)
		}
	}
	for _, u := range f.URLs {
		if !strings.Contains(u, "://") || strings.ContainsAny(u, " \t\r\n") {
			return fmt.Errorf("не похоже на адрес подписки или ссылку: %s", sub.Mask(u))
		}
	}
	check := func(name, v string, lo, hi time.Duration) error {
		if v == "" {
			return nil
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%s: %q — нужно, например, 6h, 90m", name, v)
		}
		if d < lo || d > hi {
			return fmt.Errorf("%s: %s — допустимо от %s до %s", name, d, lo, hi)
		}
		return nil
	}
	if err := check("период обновления", f.Refresh, sub.MinRefresh, 7*24*time.Hour); err != nil {
		return err
	}
	if err := check("перепроверка живых", f.Recheck, 5*time.Minute, 24*time.Hour); err != nil {
		return err
	}
	if f.TestURL != "" {
		u, err := url.Parse(f.TestURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("адрес проверки: нужен http:// или https://")
		}
	}
	return nil
}

// writeFileAtomic — во временный файл рядом, затем rename (при сбое старый цел).
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".subs-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		if runtime.GOOS == "windows" {
			_ = os.Remove(path)
			return os.Rename(tmp, path)
		}
		return err
	}
	return nil
}

func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".w-*")
	if err != nil {
		return false
	}
	n := f.Name()
	f.Close()
	_ = os.Remove(n)
	return true
}

// panelAPI — страница панели, журнал, настройки подписок.
func panelAPI(subsPath string, extra []string, def sub.Config, ring *logRing, apply func() error) map[string]http.HandlerFunc {
	var mu sync.Mutex
	nExtra := 0
	for _, u := range extra {
		if strings.TrimSpace(u) != "" {
			nExtra++
		}
	}
	return map[string]http.HandlerFunc{
		"/panel": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(panelHTML)
		},
		"/api/log": func(w http.ResponseWriter, r *http.Request) {
			n := 500
			_, _ = fmt.Sscan(r.URL.Query().Get("n"), &n)
			writeJS(w, http.StatusOK, map[string]any{"lines": ring.Lines(n)})
		},
		"/api/subs/config": func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			var f subsFile
			if subsPath != "" {
				if b, err := os.ReadFile(subsPath); err == nil {
					_ = json.Unmarshal(b, &f)
				}
			}
			if r.Method == http.MethodGet {
				v := subsConfigView{Path: subsPath, Links: maskLinks(f.Links), Disabled: f.Disabled, Mode: f.Mode,
					Refresh: f.Refresh, Recheck: f.Recheck, TestURL: f.TestURL, Honor: f.Honor == nil || *f.Honor,
					Defaults: def.ViewOf(), Extra: nExtra}
				if v.Disabled == nil {
					v.Disabled = []string{}
				}
				v.URLs = []string{}
				if subsPath != "" {
					v.Writable = dirWritable(filepath.Dir(subsPath))
				}
				for _, u := range f.URLs {
					v.URLs = append(v.URLs, sub.Mask(u))
				}
				off := map[string]bool{}
				for _, id := range f.Disabled {
					off[id] = true
				}
				for _, p := range sub.Presets {
					v.Presets = append(v.Presets, presetView{ID: p.ID, Name: p.Name, Enabled: !off[p.ID]})
				}
				writeJS(w, http.StatusOK, v)
				return
			}
			if r.Method != http.MethodPost {
				http.Error(w, "GET или POST", http.StatusMethodNotAllowed)
				return
			}
			if subsPath == "" {
				writeJS(w, http.StatusConflict, map[string]any{"ok": false, "err": "файл настроек не задан (-sub-file / MAYAK_SUB_FILE)"})
				return
			}
			var in subsConfigView
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
				writeJS(w, http.StatusBadRequest, map[string]any{"ok": false, "err": "неверный JSON"})
				return
			}
			urls, err := unmask(in.URLs, f.URLs, sub.Mask)
			if err == nil {
				var ls []string
				ls, err = unmask(strings.Split(in.Links, "\n"), strings.Split(f.Links, "\n"), sub.MaskLink)
				f.Links = strings.Join(ls, "\n")
			}
			if err != nil {
				writeJS(w, http.StatusBadRequest, map[string]any{"ok": false, "err": err.Error()})
				return
			}
			honor := in.Honor
			nf := subsFile{Disabled: in.Disabled, URLs: urls, Links: f.Links, Mode: in.Mode,
				Refresh: strings.TrimSpace(in.Refresh), Recheck: strings.TrimSpace(in.Recheck), TestURL: strings.TrimSpace(in.TestURL), Honor: &honor}
			if nf.Disabled == nil {
				nf.Disabled = []string{}
			}
			if nf.URLs == nil {
				nf.URLs = []string{}
			}
			if err := validateSubsFile(&nf); err != nil {
				writeJS(w, http.StatusBadRequest, map[string]any{"ok": false, "err": err.Error()})
				return
			}
			b, _ := json.MarshalIndent(nf, "", " ")
			if err := writeFileAtomic(subsPath, append(b, '\n')); err != nil {
				writeJS(w, http.StatusInternalServerError, map[string]any{"ok": false, "err": "не удалось сохранить: " + err.Error()})
				return
			}
			if err := apply(); err != nil {
				writeJS(w, http.StatusInternalServerError, map[string]any{"ok": false, "err": err.Error()})
				return
			}
			writeJS(w, http.StatusOK, map[string]any{"ok": true})
		},
	}
}
