#!/bin/sh
# Установка клиента МАЯК на OpenWrt без opkg (копирует файлы, ничего не включает).
#   scp -O -r openwrt root@192.168.1.1:/tmp/mayak && ssh root@192.168.1.1 "sh /tmp/mayak/install-openwrt.sh"
set -e
D=$(cd "$(dirname "$0")" && pwd)
case "$(uname -m)" in
  x86_64) A=amd64 ;; aarch64) A=arm64 ;; armv7l) A=armv7 ;;
  mips) A=mips-softfloat ;; mipsel|mipsle) A=mipsle-softfloat ;;
  *) echo "Неизвестная архитектура $(uname -m)"; exit 1 ;;
esac
B=""; for c in "$D/mayak-linux-$A" "$D/../bin/mayak-linux-$A"; do [ -f "$c" ] && B=$c && break; done
[ -n "$B" ] || { echo "Нет бинарника mayak-linux-$A рядом со скриптом"; exit 1; }
FREE=$(df -k /usr | awk 'NR==2{print $4}')
[ "${FREE:-0}" -gt 12000 ] || echo "ВНИМАНИЕ: мало места в /usr (${FREE} КБ). Бинарник ~10 МБ."
cp "$B" /usr/bin/mayak && chmod 755 /usr/bin/mayak
cp "$D/files/etc/init.d/mayak" /etc/init.d/mayak && chmod 755 /etc/init.d/mayak
[ -f /etc/config/mayak ] || cp "$D/files/etc/config/mayak" /etc/config/mayak
/etc/init.d/mayak enable
echo "Установлено. Дальше:"
echo "  uci set mayak.main.link='mayak://…'; uci set mayak.main.enabled=1; uci commit mayak"
echo "  /etc/init.d/mayak start; logread -e mayak"
echo "  панель: http://<IP роутера>:9091/"
