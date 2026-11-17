# Лицензии третьих сторон

Собственный код МАЯК распространяется по лицензии MIT (см. [LICENSE](LICENSE)).
Ниже — зависимости и источники идей.

## hev-socks5-tunnel (MIT)

- Репозиторий: https://github.com/heiher/hev-socks5-tunnel
- Зачем: нативная библиотека `libhev-socks5-tunnel.so` в Android VPN-режиме
  (tun → локальный SOCKS5 ядра МАЯК).
- Как попадает в сборку: `scripts/build-hev.sh` клонирует репозиторий при сборке;
  исходники hev в этот репозиторий не входят.
- Копия лицензии кладётся в APK: `android/assets/LICENSE-hev-socks5-tunnel.txt`.
- JNI-обёртка `android/src/ru/mayak/app/TProxy.java` — собственный код,
  вызывающий API hev, собранного с `-DPKGNAME=ru/mayak/app -DCLSNAME=TProxy`.

## Xray-core (MPL-2.0)

- Репозиторий: https://github.com/XTLS/Xray-core (модуль `github.com/xtls/xray-core`)
- Зачем: запасной вход из подписок (VLESS, VMess, Trojan, Shadowsocks, Hysteria2).
- Используется как библиотека Go, линкуется в клиент. MPL-2.0 требует
  сохранения уведомления о лицензии и открытости изменений в файлах самой
  Xray-core; код МАЯК от этого не становится MPL.
- Исходники Xray в этот репозиторий не вендорятся — подтягиваются через `go.mod`.

## byedpi (MIT) — только идеи

- Репозиторий: https://github.com/hufrea/byedpi
- Приёмы обхода DPI в `internal/desync` написаны заново. Из byedpi взяты
  идеи (нарезка TLS-записей, split/disorder/fake, TCP MD5), но не исходный код.

## ByeByeDPI (GPL-3.0) — ничего не копировалось

- Репозиторий: https://github.com/dovecoteescapee/ByeByeDPI
- Проект просматривался как справочник по UX Android VPN-клиента.
  Код, ресурсы и файлы ByeByeDPI в МАЯК не переносились, чтобы не навязывать GPL.

## Прочие Go-зависимости

Полный список и версии — в `go.mod` / `go.sum`. Среди прямых зависимостей:

- [uTLS](https://github.com/refraction-networking/utls) — отпечаток TLS Chrome
  (BSD-3-Clause);
- [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) (BSD-3-Clause).

Транзитивные зависимости (quic-go, circl, protobuf и др.) подтягиваются
сборщиком и сохраняют свои лицензии.
