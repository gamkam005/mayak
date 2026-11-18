package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.3.2", "0.3.1", 1}, {"v0.3.1", "0.3.1", 0}, {"0.3.1", "0.3.10", -1},
		{"0.10.0", "0.9.9", 1}, {"1.0", "0.99.99", 1}, {"v1", "1.0.0", 0},
	} {
		got, err := Compare(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("Compare(%s,%s)=%d,%v want %d", c.a, c.b, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "x", "0.3.2-beta", "1.2.3.4", "1..2"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("ParseVersion(%q) ok", bad)
		}
	}
}

func TestUnstable(t *testing.T) {
	for _, tag := range []string{"v0.4.0-beta", "v0.4.0-rc1", "v0.4.0rc2", "0.4.0-alpha.1", "v0.4.0-pre", "v0.4.0-dev", "v0.4.0+build", "v0.4.0beta", "v0.4.0-preview"} {
		if !Unstable(tag) {
			t.Errorf("%s должен считаться предварительным", tag)
		}
	}
	for _, tag := range []string{"v0.3.2", "0.4.0", "v1.0"} {
		if Unstable(tag) {
			t.Errorf("%s — стабильный", tag)
		}
	}
}

func TestAcceptable(t *testing.T) {
	if err := Acceptable(&Release{Tag: "v0.3.2"}, "0.3.1"); err != nil {
		t.Fatal(err)
	}
	if err := Acceptable(&Release{Tag: "v0.3.1"}, "0.3.1"); err != ErrUpToDate {
		t.Fatal("равная версия — не обновление", err)
	}
	if err := Acceptable(&Release{Tag: "v0.3.0"}, "0.3.1"); err != ErrUpToDate {
		t.Fatal("старая версия — не обновление", err)
	}
	if Acceptable(&Release{Tag: "v0.4.0", Prerelease: true}, "0.3.1") == nil {
		t.Fatal("prerelease пропущен")
	}
	if Acceptable(&Release{Tag: "v0.4.0", Draft: true}, "0.3.1") == nil {
		t.Fatal("draft пропущен")
	}
	if Acceptable(&Release{Tag: "v0.4.0-beta"}, "0.3.1") == nil {
		t.Fatal("beta пропущена")
	}
	if Acceptable(&Release{Tag: "v0.4.0"}, "dev") == nil {
		t.Fatal("непонятная текущая версия — не обновляем")
	}
}

func TestAssetFor(t *testing.T) {
	for _, c := range []struct {
		goos, arch string
		lite       bool
		want       string
	}{
		{"windows", "amd64", false, "mayak-windows-amd64.exe"},
		{"linux", "amd64", false, "mayak-linux-amd64"},
		{"linux", "arm64", false, "mayak-linux-arm64"},
		{"linux", "arm64", true, "mayak-lite-linux-arm64"},
		{"linux", "arm", true, "mayak-lite-linux-armv7"},
		{"linux", "mipsle", true, "mayak-lite-linux-mipsle-softfloat"},
		{"linux", "mips", true, "mayak-lite-linux-mips-softfloat"},
	} {
		if got := AssetFor(c.goos, c.arch, c.lite); got != c.want {
			t.Errorf("%v: %s want %s", c, got, c.want)
		}
	}
	r := &Release{Tag: "v1", Assets: []Asset{{Name: "MAYAK-vpn-1.0.0.apk"}, {Name: "mayak_1.0.0_x86_64.ipk"}, {Name: "mayak-full_1.0.0_x86_64.ipk"}, {Name: "a.apk"}, {Name: "b.apk"}}}
	if a, err := r.Find("MAYAK-vpn-*.apk"); err != nil || a.Name != "MAYAK-vpn-1.0.0.apk" {
		t.Fatal(a, err)
	}
	if a, err := r.Find("mayak_*_x86_64.ipk"); err != nil || a.Name != "mayak_1.0.0_x86_64.ipk" {
		t.Fatal(a, err)
	}
	if _, err := r.Find("*.apk"); err == nil {
		t.Fatal("несколько совпадений должны давать ошибку")
	}
	if _, err := r.Find("nope"); err == nil {
		t.Fatal("нет файла")
	}
}

func TestSumsAndSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sums := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  a.bin\n" +
		"FEDCBA9876543210fedcba9876543210fedcba9876543210fedcba9876543210 *b.exe\nmusor\n")
	m := ParseSums(sums)
	if len(m) != 2 || m["b.exe"] != strings.ToLower("FEDCBA9876543210fedcba9876543210fedcba9876543210fedcba9876543210") {
		t.Fatal(m)
	}
	sig := Sign(priv, sums)
	if err := VerifySig(sums, sig, []ed25519.PublicKey{pub}); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if VerifySig(sums, sig, []ed25519.PublicKey{other}) == nil {
		t.Fatal("чужой ключ принят")
	}
	bad := append([]byte{}, sums...)
	bad[0] = '1'
	if VerifySig(bad, sig, []ed25519.PublicKey{pub}) == nil {
		t.Fatal("подменённые суммы приняты")
	}
	if VerifySig(sums, []byte("мусор"), []ed25519.PublicKey{pub}) == nil {
		t.Fatal("мусорная подпись принята")
	}
	if len(PublicKeys()) == 0 {
		t.Fatal("нет встроенного ключа")
	}
}

// fakeGitHub — releases/latest + файлы релиза.
type fakeGitHub struct {
	srv   *httptest.Server
	files map[string][]byte
	rel   Release
}

func newFake(t *testing.T, tag string, files map[string][]byte, priv ed25519.PrivateKey, corrupt string) *fakeGitHub {
	f := &fakeGitHub{files: map[string][]byte{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	var sums strings.Builder
	for n, b := range files {
		h := sha256.Sum256(b)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), n)
		f.files[n] = b
	}
	if corrupt != "" {
		f.files[corrupt] = append([]byte("X"), f.files[corrupt]...)
	}
	f.files[SumsName] = []byte(sums.String())
	if priv != nil {
		f.files[SigName] = Sign(priv, f.files[SumsName])
	}
	f.rel = Release{Tag: tag}
	for n, b := range f.files {
		f.rel.Assets = append(f.rel.Assets, Asset{Name: n, URL: f.srv.URL + "/dl/" + n, Size: int64(len(b))})
	}
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(f.rel) })
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		b, ok := f.files[strings.TrimPrefix(r.URL.Path, "/dl/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	return f
}

func TestFetchEndToEnd(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	bin := []byte("новая версия программы")
	ctx := context.Background()
	dir := t.TempDir()

	f := newFake(t, "v0.3.2", map[string][]byte{"mayak-linux-amd64": bin, "MAYAK-vpn-0.3.2.apk": []byte("apk")}, priv, "")
	u := New("0.3.1")
	u.API, u.Keys = f.srv.URL+"/latest", []ed25519.PublicKey{pub}
	r, err := u.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "mayak")
	_ = os.WriteFile(exe, []byte("старая"), 0o755)
	if _, err := u.Fetch(ctx, r, "mayak-linux-amd64", exe+".new"); err != nil {
		t.Fatal(err)
	}
	if err := Replace(exe, exe+".new"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != string(bin) {
		t.Fatal("не заменился")
	}
	if b, _ := os.ReadFile(exe + ".old"); string(b) != "старая" {
		t.Fatal("нет .old")
	}
	Cleanup(exe)
	if _, err := os.Stat(exe + ".old"); !os.IsNotExist(err) {
		t.Fatal(".old не убран")
	}
	if n, err := u.Fetch(ctx, r, "MAYAK-vpn-*.apk", filepath.Join(dir, "u.apk")); err != nil || n != "MAYAK-vpn-0.3.2.apk" {
		t.Fatal(n, err)
	}

	// та же версия — обновления нет
	u2 := New("0.3.2")
	u2.API = u.API
	if _, err := u2.Check(ctx); err != ErrUpToDate {
		t.Fatal(err)
	}

	// подменённый файл
	f3 := newFake(t, "v0.3.2", map[string][]byte{"mayak-linux-amd64": bin}, priv, "mayak-linux-amd64")
	u.API = f3.srv.URL + "/latest"
	r3, _ := u.Check(ctx)
	if _, err := u.Fetch(ctx, r3, "mayak-linux-amd64", filepath.Join(dir, "x")); err == nil || !strings.Contains(err.Error(), "контрольная сумма") {
		t.Fatal("подмена не замечена:", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x")); !os.IsNotExist(err) {
		t.Fatal("испорченный файл остался")
	}

	// нет подписи
	f4 := newFake(t, "v0.3.2", map[string][]byte{"mayak-linux-amd64": bin}, nil, "")
	u.API = f4.srv.URL + "/latest"
	r4, _ := u.Check(ctx)
	if _, err := u.Fetch(ctx, r4, "mayak-linux-amd64", filepath.Join(dir, "y")); err == nil {
		t.Fatal("релиз без подписи принят")
	}

	// чужая подпись
	_, priv5, _ := ed25519.GenerateKey(nil)
	f5 := newFake(t, "v0.3.2", map[string][]byte{"mayak-linux-amd64": bin}, priv5, "")
	u.API = f5.srv.URL + "/latest"
	r5, _ := u.Check(ctx)
	if _, err := u.Fetch(ctx, r5, "mayak-linux-amd64", filepath.Join(dir, "z")); err == nil {
		t.Fatal("чужая подпись принята")
	}

	// prerelease с API (если вдруг) — пропуск
	f6 := newFake(t, "v0.4.0-beta.1", map[string][]byte{"mayak-linux-amd64": bin}, priv, "")
	u.API = f6.srv.URL + "/latest"
	if _, err := u.Check(ctx); !NoUpdate(err) {
		t.Fatal("beta принята:", err)
	}
}

func TestProxyFallback(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newFake(t, "v9.0.0", map[string][]byte{"f": []byte("1")}, priv, "")
	// «прямой» путь мёртв: API указывает на имя, которое резолвит только прокси
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2, _ := http.NewRequest(r.Method, f.srv.URL+r.URL.Path, nil)
		resp, err := http.DefaultTransport.RoundTrip(r2)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		b := make([]byte, 1<<16)
		for {
			n, err := resp.Body.Read(b)
			w.Write(b[:n])
			if err != nil {
				return
			}
		}
	}))
	defer proxy.Close()
	for i := range f.rel.Assets {
		f.rel.Assets[i].URL = strings.Replace(f.rel.Assets[i].URL, f.srv.URL, "http://github.invalid", 1)
	}
	u := New("1.0.0", proxy.URL)
	u.API, u.Keys = "http://github.invalid/latest", []ed25519.PublicKey{pub}
	r, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Fetch(context.Background(), r, "f", filepath.Join(t.TempDir(), "f")); err != nil {
		t.Fatal(err)
	}
}
