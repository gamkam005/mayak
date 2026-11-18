package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"mayak/internal/sub"
	"mayak/internal/update"
)

// restartRequested — клиент заменил себя новой версией и должен перезапуститься.
var restartRequested atomic.Bool

// selfExe — путь к своему файлу (до замены: после неё /proc/self/exe укажет на .old).
var selfExe = func() string {
	exe, err := os.Executable()
	if err != nil { // нет /proc (chroot и т.п.) — ищем по argv[0]
		if exe, err = exec.LookPath(os.Args[0]); err != nil {
			return ""
		}
		if exe, err = filepath.Abs(exe); err != nil {
			return ""
		}
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return exe
}()

func selfAsset() string { return update.AssetFor(runtime.GOOS, runtime.GOARCH, !sub.Available) }

func isOpenWrt() bool { _, err := os.Stat("/etc/openwrt_release"); return err == nil }

// autoUpdateBlocked — почему самообновление в клиенте выключено ("" — можно).
func autoUpdateBlocked(noFlag bool) string {
	switch {
	case noFlag:
		return "выключено флагом -noupdate"
	case runtime.GOOS == "android":
		return "на Android обновляет приложение"
	case runtime.GOOS != "windows" && runtime.GOOS != "linux":
		return "для этой системы нет готовых файлов"
	case isOpenWrt():
		return "на OpenWrt обновляет mayak-update (cron)"
	case selfExe == "":
		return "не найден путь к программе"
	}
	dir := filepath.Dir(selfExe)
	for _, n := range []string{"noupdate", "noupdate.txt"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			return "выключено файлом " + n
		}
	}
	if _, err := update.ParseVersion(version); err != nil {
		return "сборка без номера версии"
	}
	if !update.Writable(dir) {
		return "нет прав на запись в " + dir + " (обновите вручную: mayak update)"
	}
	return ""
}

type autoUpdate struct {
	API   string
	Every time.Duration
	Delay time.Duration
	Proxy string
}

// startAutoUpdate: проверка через Delay после старта и затем каждые Every.
// Нашлась новая стабильная версия — скачать, проверить, заменить exe и
// остановить клиент (stop), чтобы main перезапустил его с теми же аргументами.
func startAutoUpdate(ctx context.Context, stop func(), o autoUpdate, logger *log.Logger) {
	go func() {
		t := time.NewTimer(o.Delay)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if applied := autoUpdateOnce(ctx, o, logger); applied {
				restartRequested.Store(true)
				stop()
				return
			}
			t.Reset(o.Every)
		}
	}()
}

func autoUpdateOnce(ctx context.Context, o autoUpdate, logger *log.Logger) bool {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	u := update.New(version, o.Proxy)
	if o.API != "" {
		u.API = o.API
	}
	r, err := u.Check(cctx)
	if update.NoUpdate(err) {
		logger.Printf("обновления: у вас последняя стабильная версия %s", version)
		return false
	}
	if err != nil {
		logger.Printf("обновления: не удалось проверить (%v), попробую позже", err)
		return false
	}
	logger.Printf("обновления: вышла версия %s, скачиваю %s…", r.Version(), selfAsset())
	tmp := selfExe + ".new"
	if _, err := u.Fetch(cctx, r, selfAsset(), tmp); err != nil {
		logger.Printf("обновления: %v", err)
		os.Remove(tmp)
		return false
	}
	if err := update.Replace(selfExe, tmp); err != nil {
		logger.Printf("обновления: %v", err)
		os.Remove(tmp)
		return false
	}
	logger.Printf("обновления: установлена версия %s (подпись и контрольная сумма проверены), перезапускаюсь…", r.Version())
	return true
}

// afterClient — если клиент обновился, перезапустить его; иначе вернуть код.
func afterClient(code int) int {
	if !restartRequested.Load() {
		return code
	}
	if err := relaunch(selfExe); err != nil {
		fmt.Fprintln(os.Stderr, "перезапуск после обновления не удался:", err, "— запустите программу заново")
		return 1
	}
	return 0
}

type updResult struct {
	Current string `json:"current"`
	Latest  string `json:"latest,omitempty"`
	Newer   bool   `json:"newer"`
	Asset   string `json:"asset,omitempty"`
	File    string `json:"file,omitempty"`
	Page    string `json:"page,omitempty"`
	Notes   string `json:"notes,omitempty"`
	Lite    bool   `json:"lite"`
	Error   string `json:"error,omitempty"`
}

// mayak update — проверить/скачать/поставить новую версию вручную.
// Коды выхода: 0 — есть новая (скачана/установлена), 3 — новее нет, 1 — ошибка.
func runUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	check := fs.Bool("check", false, "только проверить, есть ли новая версия")
	asJSON := fs.Bool("json", false, "ответ одной строкой JSON (для приложения и скриптов)")
	asset := fs.String("asset", "", "какой файл релиза (имя или шаблон, например 'MAYAK-vpn-*.apk'); по умолчанию — бинарник для этой системы")
	out := fs.String("out", "", "скачать файл сюда (без -out — заменить саму программу)")
	api := fs.String("url", update.DefaultAPI, "адрес releases/latest")
	cur := fs.String("current", version, "текущая версия (для приложения Android — версия APK)")
	proxy := fs.String("proxy", "", "запасной путь, если GitHub напрямую недоступен: http://127.0.0.1:1080")
	_ = fs.Parse(args)

	res := updResult{Current: *cur, Lite: !sub.Available, Asset: *asset}
	if res.Asset == "" {
		res.Asset = selfAsset()
	}
	done := func(code int, err error) int {
		if err != nil {
			res.Error = err.Error()
		}
		if *asJSON {
			b, _ := json.Marshal(res)
			fmt.Println(string(b))
		} else if err != nil {
			fmt.Fprintln(os.Stderr, "Обновление:", err)
		}
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	u := update.New(*cur, *proxy)
	u.API = *api
	r, err := u.Check(ctx)
	if r != nil {
		res.Latest, res.Page = r.Version(), r.HTMLURL
		if len(r.Body) > 3000 {
			res.Notes = r.Body[:3000]
		} else {
			res.Notes = r.Body
		}
	}
	if update.NoUpdate(err) {
		if !*asJSON {
			fmt.Printf("У вас последняя стабильная версия %s.\n", *cur)
		}
		return done(3, nil)
	}
	if err != nil {
		return done(1, err)
	}
	res.Newer = true
	if a, err := r.Find(res.Asset); err == nil {
		res.Asset = a.Name
	}
	if *check {
		if !*asJSON {
			fmt.Printf("Есть новая версия %s (у вас %s): %s\n", r.Version(), *cur, r.HTMLURL)
		}
		return done(0, nil)
	}
	if *out != "" {
		name, err := u.Fetch(ctx, r, res.Asset, *out)
		if err != nil {
			return done(1, err)
		}
		res.Asset, res.File = name, *out
		if !*asJSON {
			fmt.Printf("Скачано и проверено: %s → %s\n", name, *out)
		}
		return done(0, nil)
	}
	if selfExe == "" {
		return done(1, errors.New("не найден путь к программе"))
	}
	tmp := selfExe + ".new"
	if _, err := u.Fetch(ctx, r, res.Asset, tmp); err != nil {
		os.Remove(tmp)
		return done(1, err)
	}
	if err := update.Replace(selfExe, tmp); err != nil {
		os.Remove(tmp)
		return done(1, err)
	}
	res.File = selfExe
	if !*asJSON {
		fmt.Printf("МАЯК обновлён: %s → %s (подпись и контрольная сумма проверены). Перезапустите программу/службу.\n", *cur, r.Version())
	}
	return done(0, nil)
}

// mayak sign -key ключ SHA256SUMS — подписать суммы релиза (для автора).
// mayak sign -pub ключ.pub -verify SHA256SUMS — проверить подпись.
func runSign(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "файл с закрытым ключом ed25519 (base64)")
	verify := fs.Bool("verify", false, "проверить SHA256SUMS.sig встроенным ключом (или -pub)")
	pubFile := fs.String("pub", "", "файл с открытым ключом (base64) для -verify")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "mayak sign -key KEY SHA256SUMS | mayak sign -verify SHA256SUMS")
		return 2
	}
	sums, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *verify {
		keys := update.PublicKeys()
		if *pubFile != "" {
			b, _ := os.ReadFile(*pubFile)
			k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
			if err != nil || len(k) != ed25519.PublicKeySize {
				fmt.Fprintln(os.Stderr, "плохой открытый ключ")
				return 1
			}
			keys = []ed25519.PublicKey{k}
		}
		sig, err := os.ReadFile(fs.Arg(0) + ".sig")
		if err == nil {
			err = update.VerifySig(sums, sig, keys)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("подпись верна")
		return 0
	}
	b, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != ed25519.PrivateKeySize {
		fmt.Fprintln(os.Stderr, "плохой закрытый ключ")
		return 1
	}
	if err := os.WriteFile(fs.Arg(0)+".sig", update.Sign(ed25519.PrivateKey(k), sums), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("подписано:", fs.Arg(0)+".sig")
	return 0
}
