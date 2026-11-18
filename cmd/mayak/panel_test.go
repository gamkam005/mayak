package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mayak/internal/sub"
)

func TestUIPassword(t *testing.T) {
	dir := t.TempDir()
	gen := filepath.Join(dir, "ui.pass")
	old := generatedPassPath
	generatedPassPath = func() string { return gen }
	defer func() { generatedPassPath = old }()
	var logs []string
	logf := func(f string, a ...any) { logs = append(logs, f) }

	if p, err := uiPassword("", "", "127.0.0.1:9090", logf); err != nil || p != "" {
		t.Fatalf("localhost без пароля: %q %v", p, err)
	}
	p, err := uiPassword("", "", "0.0.0.0:9090", logf)
	if err != nil || len(p) < 20 {
		t.Fatalf("пароль не создан: %q %v", p, err)
	}
	fi, err := os.Stat(gen)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("файл пароля: %v %v", fi, err)
	}
	for _, l := range logs {
		if strings.Contains(l, p) {
			t.Fatal("пароль попал в журнал")
		}
	}
	if p2, _ := uiPassword("", "", "0.0.0.0:9090", logf); p2 != p {
		t.Error("после перезапуска пароль должен остаться тем же")
	}
	if p3, _ := uiPassword("secret1", "", "0.0.0.0:9090", logf); p3 != "secret1" {
		t.Error("-ui-pass важнее файла")
	}
	f := filepath.Join(dir, "own.pass")
	_ = os.WriteFile(f, []byte("\ufefffrom-file\r\n"), 0o600)
	if p4, _ := uiPassword("@"+f, "", "0.0.0.0:9090", logf); p4 != "from-file" {
		t.Errorf("@файл: %q", p4)
	}
	if p5, _ := uiPassword("", f, "0.0.0.0:9090", logf); p5 != "from-file" {
		t.Errorf("-ui-pass-file: %q", p5)
	}
}

func authServer(t *testing.T, pass string) (*httptest.Server, *uiAuth) {
	t.Helper()
	a := newUIAuth(pass, false)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/x", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("/panel", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "panel") })
	srv := httptest.NewServer(a.Wrap(mux))
	t.Cleanup(srv.Close)
	return srv, a
}

func login(t *testing.T, srv *httptest.Server, pass string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"password": pass})
	r, err := http.Post(srv.URL+"/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	return r
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestAuthFlow(t *testing.T) {
	srv, _ := authServer(t, "correct horse")
	cl := noRedirect()
	// без входа
	r, _ := cl.Get(srv.URL + "/api/x")
	if r.StatusCode != 401 {
		t.Errorf("API без входа: %d", r.StatusCode)
	}
	r, _ = cl.Get(srv.URL + "/panel")
	if r.StatusCode != 303 || r.Header.Get("Location") != "/login" {
		t.Errorf("страница без входа: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	if r := login(t, srv, "wrong"); r.StatusCode != 401 {
		t.Errorf("неверный пароль: %d", r.StatusCode)
	}
	r = login(t, srv, "correct horse")
	if r.StatusCode != 200 {
		t.Fatalf("вход: %d", r.StatusCode)
	}
	var ck *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name == sessionCookie {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", ck)
	}
	do := func(method, path, csrf, origin string) int {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		req.AddCookie(ck)
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		r, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if c := do("GET", "/api/x", "", ""); c != 200 {
		t.Errorf("GET после входа: %d", c)
	}
	// CSRF-токен сессии
	req, _ := http.NewRequest("GET", srv.URL+"/api/session", nil)
	req.AddCookie(ck)
	sr, _ := cl.Do(req)
	var sess struct {
		Auth bool   `json:"auth"`
		CSRF string `json:"csrf"`
	}
	_ = json.NewDecoder(sr.Body).Decode(&sess)
	sr.Body.Close()
	if !sess.Auth || len(sess.CSRF) < 32 {
		t.Fatalf("сессия: %+v", sess)
	}
	if c := do("POST", "/api/x", "", ""); c != 403 {
		t.Errorf("POST без CSRF: %d", c)
	}
	if c := do("POST", "/api/x", "bad", ""); c != 403 {
		t.Errorf("POST с чужим CSRF: %d", c)
	}
	if c := do("POST", "/api/x", sess.CSRF, "http://evil.example"); c != 403 {
		t.Errorf("POST с чужого сайта: %d", c)
	}
	if c := do("POST", "/api/x", sess.CSRF, srv.URL); c != 200 {
		t.Errorf("POST с токеном: %d", c)
	}
	if c := do("POST", "/logout", sess.CSRF, ""); c != 200 {
		t.Errorf("выход: %d", c)
	}
	if c := do("GET", "/api/x", "", ""); c != 401 {
		t.Errorf("после выхода: %d", c)
	}
}

func TestLoginRateLimit(t *testing.T) {
	srv, a := authServer(t, "pw")
	for i := 0; i < 5; i++ {
		if r := login(t, srv, "nope"); r.StatusCode != 401 {
			t.Fatalf("попытка %d: %d", i, r.StatusCode)
		}
	}
	if r := login(t, srv, "pw"); r.StatusCode != 429 {
		t.Errorf("после 5 неудач даже верный пароль ждёт: %d", r.StatusCode)
	}
	now := time.Now().Add(2 * time.Minute)
	a.now = func() time.Time { return now }
	if r := login(t, srv, "pw"); r.StatusCode != 200 {
		t.Errorf("после паузы: %d", r.StatusCode)
	}
}

func TestAuthOff(t *testing.T) {
	srv, _ := authServer(t, "")
	r, _ := http.Post(srv.URL+"/api/x", "text/plain", nil)
	if r.StatusCode != 200 {
		t.Errorf("без пароля (localhost) всё как раньше: %d", r.StatusCode)
	}
}

func TestLogRingMasks(t *testing.T) {
	var out bytes.Buffer
	l := newLogRing(&out, 3)
	_, _ = io.WriteString(l, "подписка https://x.example/connection/subs/1b2c3d4e-0000-4111-8222-123456789abc: ok\n")
	_, _ = io.WriteString(l, "ссылка mayak://SECRETKEY@1.2.3.4:443 и vless://11111111-2222@h:1\nb\nc\n")
	lines := l.Lines(0)
	if len(lines) != 3 {
		t.Fatalf("держим 3 строки: %v", lines)
	}
	all := out.String() + strings.Join(lines, "\n")
	for _, bad := range []string{"1b2c3d4e", "SECRETKEY", "11111111-2222"} {
		if strings.Contains(all, bad) {
			t.Errorf("секрет %q не скрыт: %s", bad, all)
		}
	}
	if !strings.Contains(lines[0], "mayak://***@1.2.3.4") {
		t.Errorf("строка: %s", lines[0])
	}
}

func TestPanelConfigSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subs.json")
	secret := "https://x.example/connection/subs/1b2c3d4e-0000-4111-8222-123456789abc"
	link := "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=tls#A"
	b, _ := json.Marshal(subsFile{URLs: []string{secret}, Links: link, Mode: "always", Disabled: []string{"v2nodes-all"}})
	_ = os.WriteFile(path, b, 0o600)
	applied := 0
	h := panelAPI(path, nil, sub.Config{Refresh: 6 * time.Hour, Recheck: 30 * time.Minute, TestURL: sub.DefaultTestURL, HonorInterval: true},
		newLogRing(nil, 10), func() error { applied++; return nil })["/api/subs/config"]

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("GET", "/api/subs/config", nil))
	var v subsConfigView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if strings.Contains(rec.Body.String(), "1b2c3d4e") || strings.Contains(rec.Body.String(), "11111111-1111") {
		t.Fatalf("секреты в ответе: %s", rec.Body)
	}
	if len(v.URLs) != 1 || !strings.Contains(v.URLs[0], "***") || !v.Honor || v.Mode != "always" || len(v.Presets) != len(sub.Presets) {
		t.Fatalf("GET: %+v", v)
	}
	// сохранить: замазанный адрес остаётся, новый добавляется, периоды задаются
	v.URLs = append(v.URLs, "https://new.example/sub")
	v.Refresh, v.Recheck, v.Honor = "2h", "10m", false
	body, _ := json.Marshal(v)
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", "/api/subs/config", bytes.NewReader(body)))
	if rec.Code != 200 || applied != 1 {
		t.Fatalf("POST: %d %s applied=%d", rec.Code, rec.Body, applied)
	}
	var f subsFile
	raw, _ := os.ReadFile(path)
	_ = json.Unmarshal(raw, &f)
	if len(f.URLs) != 2 || f.URLs[0] != secret || f.URLs[1] != "https://new.example/sub" || f.Links != link {
		t.Errorf("файл: %+v", f)
	}
	if f.Refresh != "2h" || f.Recheck != "10m" || f.Honor == nil || *f.Honor || f.Mode != "always" {
		t.Errorf("периоды: %+v", f)
	}
	c := poolConfig(f, sub.Config{Refresh: 6 * time.Hour, Recheck: 30 * time.Minute, HonorInterval: true})
	if c.Refresh != 2*time.Hour || c.Recheck != 10*time.Minute || c.HonorInterval {
		t.Errorf("poolConfig: %+v", c)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("права %v", fi.Mode())
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".subs-*"))
	if len(left) != 0 {
		t.Errorf("временные файлы: %v", left)
	}
	// ошибки проверки
	for _, bad := range []map[string]any{
		{"refresh": "1m"}, {"recheck": "abc"}, {"test_url": "ftp://x"}, {"mode": "weird"},
		{"disabled": []string{"nope"}}, {"urls": []string{"https://other.example/connection/subs/***"}},
	} {
		in := map[string]any{"urls": []string{}, "links": "", "disabled": []string{}, "mode": ""}
		for k, val := range bad {
			in[k] = val
		}
		b, _ := json.Marshal(in)
		rec = httptest.NewRecorder()
		h(rec, httptest.NewRequest("POST", "/api/subs/config", bytes.NewReader(b)))
		if rec.Code != 400 {
			t.Errorf("%v: %d %s", bad, rec.Code, rec.Body)
		}
	}
	raw2, _ := os.ReadFile(path)
	if !bytes.Equal(raw, raw2) {
		t.Error("ошибочный запрос не должен менять файл")
	}
}
