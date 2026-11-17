package server

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
)

// buildSite — простая правдоподобная страница-визитка. Её видит любой,
// кто зайдёт на сервер без ключа (в том числе зондирование ТСПУ).
func buildSite(name string) []byte {
	return []byte(fmt.Sprintf(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%[1]s — хранилище статики</title>
<link rel="icon" href="data:,">
<style>body{font-family:system-ui,Segoe UI,Roboto,sans-serif;max-width:760px;margin:60px auto;padding:0 20px;color:#222;line-height:1.55}
h1{font-weight:600}code{background:#f3f3f3;padding:2px 6px;border-radius:4px}footer{margin-top:60px;color:#888;font-size:13px}</style>
</head><body>
<h1>%[1]s</h1>
<p>Сервис раздачи статических файлов для наших проектов. Публичного каталога нет — файлы доступны только по прямым ссылкам.</p>
<p>Если вы видите эту страницу, сервер работает нормально. По вопросам доступа пишите администратору.</p>
<p>Пример ресурса: <code>/static/app.js</code></p>
<footer>&copy; %[1]s. Работает на nginx.</footer>
<script src="/static/app.js" defer></script>
</body></html>`, name))
}

// buildAsset — «бандл» на ~1.5 МБ. Нужен для реалистичности и как
// эталонный файл для проверки «заморозки после 16 КБ».
func buildAsset() []byte {
	r := rand.New(rand.NewSource(42))
	words := []string{"function", "return", "const", "let", "this", "props", "state", "render", "module", "exports", "require", "undefined", "null", "true", "false", "async", "await", "Promise", "Object", "Array"}
	var b strings.Builder
	b.WriteString("/*! app bundle */\n(function(){'use strict';\n")
	for b.Len() < 1_500_000 {
		fmt.Fprintf(&b, "var _%x=function(a,b){%s a&&b?%s:%d};", r.Uint32(), words[r.Intn(len(words))], words[r.Intn(len(words))], r.Intn(99999))
		if r.Intn(8) == 0 {
			b.WriteByte('\n')
		}
	}
	b.WriteString("})();\n")
	return []byte(b.String())
}

func (s *Server) handleSite(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Server", "nginx")
	switch r.URL.Path {
	case "/", "/index.html":
		h.Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(s.site)
	case "/static/app.js":
		h.Set("Content-Type", "application/javascript")
		h.Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(s.asset)
	case "/robots.txt":
		h.Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	default:
		h.Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"))
	}
}
