// Package update — самообновление МАЯКа из релизов GitHub.
//
// Источник — https://api.github.com/repos/gamkam005/mayak/releases/latest:
// GitHub отдаёт там только последний опубликованный релиз без пометки
// prerelease/draft. Дополнительно отбрасываются теги со словами alpha, beta,
// rc, pre, dev и т.п. и всё, что не новее текущей версии.
//
// Перед установкой: SHA256SUMS релиза проверяется подписью ed25519
// (SHA256SUMS.sig, открытый ключ встроен в программу), затем скачанный файл —
// по SHA256SUMS. Без подписи или при несовпадении ничего не ставится.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultAPI — последний стабильный релиз.
const DefaultAPI = "https://api.github.com/repos/gamkam005/mayak/releases/latest"

// SumsName и SigName — файлы контрольных сумм и подписи в каждом релизе.
const (
	SumsName = "SHA256SUMS"
	SigName  = "SHA256SUMS.sig"
)

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type Release struct {
	Tag        string  `json:"tag_name"`
	Name       string  `json:"name"`
	Body       string  `json:"body"`
	HTMLURL    string  `json:"html_url"`
	Prerelease bool    `json:"prerelease"`
	Draft      bool    `json:"draft"`
	Assets     []Asset `json:"assets"`
}

// Version — тег без «v».
func (r *Release) Version() string { return strings.TrimPrefix(strings.TrimPrefix(r.Tag, "v"), "V") }

// Find — файл релиза по точному имени или шаблону (path.Match, например MAYAK-vpn-*.apk).
// Если под шаблон подходит несколько — ошибка, чтобы не поставить не то.
func (r *Release) Find(pattern string) (*Asset, error) {
	var hit []*Asset
	for i := range r.Assets {
		a := &r.Assets[i]
		if a.Name == pattern {
			return a, nil
		}
		if ok, _ := path.Match(pattern, a.Name); ok {
			hit = append(hit, a)
		}
	}
	switch len(hit) {
	case 0:
		return nil, fmt.Errorf("в релизе %s нет файла %s", r.Tag, pattern)
	case 1:
		return hit[0], nil
	}
	return nil, fmt.Errorf("в релизе %s под %s подходит %d файлов", r.Tag, pattern, len(hit))
}

var unstableRe = regexp.MustCompile(`(?i)(alpha|beta|\brc|rc\d|pre|dev|nightly|snapshot|test|preview|canary)`)

// Unstable — тег похож на предварительную версию.
func Unstable(tag string) bool {
	t := strings.TrimPrefix(strings.TrimPrefix(tag, "v"), "V")
	if strings.ContainsAny(t, "-+~") {
		return true
	}
	return unstableRe.MatchString(t)
}

// ParseVersion разбирает «v1.2.3» / «1.2» в три числа. Хвосты (-beta…) — ошибка.
func ParseVersion(s string) ([3]int, error) {
	var v [3]int
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "v"), "V"))
	p := strings.Split(s, ".")
	if len(p) < 1 || len(p) > 3 || s == "" {
		return v, fmt.Errorf("версия %q", s)
	}
	for i, x := range p {
		n, err := strconv.Atoi(x)
		if err != nil || n < 0 || x == "" {
			return v, fmt.Errorf("версия %q", s)
		}
		v[i] = n
	}
	return v, nil
}

// Compare: -1 если a<b, 0 если равны, 1 если a>b. Ошибка — если что-то не разобралось.
func Compare(a, b string) (int, error) {
	va, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			if va[i] < vb[i] {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

// Acceptable — релиз годится как обновление для current.
func Acceptable(r *Release, current string) error {
	if r == nil || r.Tag == "" {
		return errors.New("пустой ответ GitHub")
	}
	if r.Draft || r.Prerelease || Unstable(r.Tag) {
		return fmt.Errorf("%w: %s", ErrUnstable, r.Tag)
	}
	c, err := Compare(r.Tag, current)
	if err != nil {
		return err
	}
	if c <= 0 {
		return ErrUpToDate
	}
	return nil
}

// ErrUpToDate — новее нет.
var ErrUpToDate = errors.New("установлена последняя версия")

// ErrUnstable — последний релиз предварительный (alpha/beta/rc/…): не ставим.
var ErrUnstable = errors.New("предварительная версия, пропускаю")

// NoUpdate — ошибка означает «ставить нечего», а не сбой.
func NoUpdate(err error) bool { return errors.Is(err, ErrUpToDate) || errors.Is(err, ErrUnstable) }

// Updater ходит в GitHub. Clients — по порядку: сначала напрямую, потом,
// например, через свой же прокси (если GitHub недоступен напрямую).
type Updater struct {
	API     string
	Current string
	Clients []*http.Client
	Keys    []ed25519.PublicKey
	UA      string
}

// New — с ключами по умолчанию и прямым клиентом; proxies — запасные http://host:port.
func New(current string, proxies ...string) *Updater {
	u := &Updater{API: DefaultAPI, Current: current, Keys: PublicKeys(), UA: "mayak/" + current}
	u.Clients = append(u.Clients, &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{Proxy: nil, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 30 * time.Second}})
	for _, p := range proxies {
		if p == "" {
			continue
		}
		if !strings.Contains(p, "://") {
			p = "http://" + p
		}
		pu, err := urlParse(p)
		if err != nil {
			continue
		}
		u.Clients = append(u.Clients, &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSHandshakeTimeout: 20 * time.Second, ResponseHeaderTimeout: 40 * time.Second}})
	}
	return u
}

// sink — куда качать; Reset перед повтором через другой клиент.
type sink interface {
	io.Writer
	Reset() error
}

type bufSink struct{ bytes.Buffer }

func (b *bufSink) Reset() error { b.Buffer.Reset(); return nil }

type fileSink struct{ f *os.File }

func (s fileSink) Write(p []byte) (int, error) { return s.f.Write(p) }
func (s fileSink) Reset() error {
	if err := s.f.Truncate(0); err != nil {
		return err
	}
	_, err := s.f.Seek(0, io.SeekStart)
	return err
}

func (u *Updater) get(ctx context.Context, url string, max int64, w sink) error {
	var last error
	for _, c := range u.Clients {
		if err := w.Reset(); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", u.UA)
		if strings.Contains(url, "api.github.com") {
			req.Header.Set("Accept", "application/vnd.github+json")
		}
		resp, err := c.Do(req)
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			last = fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
			continue
		}
		n, err := io.Copy(w, io.LimitReader(resp.Body, max+1))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if n > max {
			return fmt.Errorf("%s: больше %d байт", url, max)
		}
		return nil
	}
	if last == nil {
		last = errors.New("нет HTTP-клиента")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return last
}

// Latest — последний стабильный релиз (без проверки «новее ли»).
func (u *Updater) Latest(ctx context.Context) (*Release, error) {
	var b bufSink
	if err := u.get(ctx, u.API, 4<<20, &b); err != nil {
		return nil, err
	}
	var r Release
	if err := json.Unmarshal(b.Bytes(), &r); err != nil {
		return nil, fmt.Errorf("ответ GitHub: %v", err)
	}
	return &r, nil
}

// Check — релиз, если он стабильный и новее текущей версии; иначе ErrUpToDate или ошибка.
func (u *Updater) Check(ctx context.Context) (*Release, error) {
	r, err := u.Latest(ctx)
	if err != nil {
		return nil, err
	}
	if err := Acceptable(r, u.Current); err != nil {
		return r, err
	}
	return r, nil
}

// Sums скачивает и проверяет подпись SHA256SUMS релиза.
func (u *Updater) Sums(ctx context.Context, r *Release) (map[string]string, error) {
	sa, err := r.Find(SumsName)
	if err != nil {
		return nil, err
	}
	ga, err := r.Find(SigName)
	if err != nil {
		return nil, fmt.Errorf("в релизе нет подписи %s — не ставлю", SigName)
	}
	var sums, sig bufSink
	if err := u.get(ctx, sa.URL, 1<<20, &sums); err != nil {
		return nil, err
	}
	if err := u.get(ctx, ga.URL, 4096, &sig); err != nil {
		return nil, err
	}
	if err := VerifySig(sums.Bytes(), sig.Bytes(), u.Keys); err != nil {
		return nil, err
	}
	return ParseSums(sums.Bytes()), nil
}

// Download скачивает файл релиза в dst (через dst.part) и сверяет SHA-256.
func (u *Updater) Download(ctx context.Context, r *Release, a *Asset, sums map[string]string, dst string) error {
	want, ok := sums[a.Name]
	if !ok {
		return fmt.Errorf("%s нет в %s", a.Name, SumsName)
	}
	tmp := dst + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o755)
	if err != nil {
		return err
	}
	err = u.get(ctx, a.URL, 200<<20, fileSink{f})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	got, err := FileSHA256(tmp)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if !strings.EqualFold(got, want) {
		os.Remove(tmp)
		return fmt.Errorf("контрольная сумма %s не совпала — файл испорчен или подменён", a.Name)
	}
	return os.Rename(tmp, dst)
}

// Fetch: проверить подпись сумм и скачать файл по шаблону в dst. Возвращает имя файла.
func (u *Updater) Fetch(ctx context.Context, r *Release, pattern, dst string) (string, error) {
	a, err := r.Find(pattern)
	if err != nil {
		return "", err
	}
	sums, err := u.Sums(ctx, r)
	if err != nil {
		return "", err
	}
	return a.Name, u.Download(ctx, r, a, sums, dst)
}

// ParseSums — формат sha256sum: «<hex>  имя» или «<hex> *имя».
func ParseSums(b []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || len(f[0]) != 64 {
			continue
		}
		if _, err := hex.DecodeString(f[0]); err != nil {
			continue
		}
		m[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
	}
	return m
}

// FileSHA256 — hex SHA-256 файла.
func FileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Sign — подпись SHA256SUMS (base64 + перевод строки) закрытым ключом.
func Sign(priv ed25519.PrivateKey, sums []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums)) + "\n")
}

// VerifySig — подпись base64 (или сырые 64 байта) хотя бы одним из ключей.
func VerifySig(sums, sig []byte, keys []ed25519.PublicKey) error {
	raw := sig
	if len(sig) != ed25519.SignatureSize {
		d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
		if err != nil {
			return errors.New("подпись SHA256SUMS не читается")
		}
		raw = d
	}
	if len(raw) != ed25519.SignatureSize {
		return errors.New("подпись SHA256SUMS неверной длины")
	}
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, sums, raw) {
			return nil
		}
	}
	return errors.New("подпись SHA256SUMS не сходится — не ставлю")
}

// AssetFor — имя бинарника в релизе для этой платформы.
func AssetFor(goos, goarch string, lite bool) string {
	a := goarch
	switch goarch {
	case "arm":
		a = "armv7"
	case "mips", "mipsle":
		a = goarch + "-softfloat"
	}
	pre := "mayak-"
	if lite {
		pre = "mayak-lite-"
	}
	if goos == "windows" {
		return pre + "windows-" + a + ".exe"
	}
	return pre + goos + "-" + a
}

// Replace ставит newFile на место exe: exe → exe.old, newFile → exe.
// Работает и для запущенного exe в Windows (переименовать можно, удалить нельзя).
func Replace(exe, newFile string) error {
	_ = os.Chmod(newFile, 0o755)
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return fmt.Errorf("не переименовать %s: %v", filepath.Base(exe), err)
	}
	if err := os.Rename(newFile, exe); err != nil {
		_ = os.Rename(old, exe)
		return fmt.Errorf("не поставить новый файл: %v", err)
	}
	return nil
}

// Cleanup убирает остатки прошлого обновления (exe.old, exe.new, *.part).
func Cleanup(exe string) {
	for _, s := range []string{".old", ".new", ".new.part"} {
		_ = os.Remove(exe + s)
	}
}

// Writable — можно ли писать рядом с exe (иначе самообновление невозможно).
func Writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".mayak-w-*")
	if err != nil {
		return false
	}
	n := f.Name()
	f.Close()
	os.Remove(n)
	return true
}
