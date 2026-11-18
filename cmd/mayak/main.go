// МАЯК — мозаичный туннель с маскировкой под обычный HTTPS-сайт.
package main

import (
	"fmt"
	"os"

	"mayak/internal/update"
)

var version = "0.3.4"

func usage() {
	fmt.Fprintf(os.Stderr, `МАЯК %s — мозаичный туннель

  mayak server  [флаги]   сервер на VPS
  mayak client  [флаги]   клиент: локальный SOCKS5/HTTP-прокси + панель
  mayak picker  [флаги]   фильтр бесплатных подписок на сервере: отдаёт живые
  mayak update  [флаги]   проверить и поставить новую версию с GitHub (только стабильные)
  mayak keygen            новый секрет
  mayak version

Без аргументов (двойной щелчок в Windows) запускается клиент: ссылка
берётся из файла link.txt рядом с программой, открывается панель.

Клиент на Windows/Linux сам проверяет обновления при запуске и раз в 6 часов\n(-noupdate или файл noupdate рядом с программой — выключить).\n\nПодробнее: mayak server -h, mayak client -h, mayak update -h
`, version)
}

func main() {
	update.Cleanup(selfExe) // остатки прошлого самообновления (.old)
	if len(os.Args) < 2 {
		os.Exit(afterClient(runClient(nil, true)))
	}
	switch os.Args[1] {
	case "server":
		os.Exit(runServer(os.Args[2:]))
	case "client":
		os.Exit(afterClient(runClient(os.Args[2:], false)))
	case "picker":
		os.Exit(runPicker(os.Args[2:]))
	case "update":
		os.Exit(runUpdate(os.Args[2:]))
	case "sign":
		os.Exit(runSign(os.Args[2:]))
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
