// МАЯК — мозаичный туннель с маскировкой под обычный HTTPS-сайт.
package main

import (
	"fmt"
	"os"
)

var version = "0.3.0"

func usage() {
	fmt.Fprintf(os.Stderr, `МАЯК %s — мозаичный туннель

  mayak server  [флаги]   сервер на VPS
  mayak client  [флаги]   клиент: локальный SOCKS5/HTTP-прокси + панель
  mayak picker  [флаги]   фильтр бесплатных подписок на сервере: отдаёт живые
  mayak keygen            новый секрет
  mayak version

Без аргументов (двойной щелчок в Windows) запускается клиент: ссылка
берётся из файла link.txt рядом с программой, открывается панель.

Подробнее: mayak server -h, mayak client -h
`, version)
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(runClient(nil, true))
	}
	switch os.Args[1] {
	case "server":
		os.Exit(runServer(os.Args[2:]))
	case "client":
		os.Exit(runClient(os.Args[2:], false))
	case "picker":
		os.Exit(runPicker(os.Args[2:]))
	case "keygen":
		os.Exit(runKeygen())
	case "version", "-v", "--version":
		fmt.Println("mayak", version)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}
