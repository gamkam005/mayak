#!/usr/bin/env bash
# Установка сервера МАЯК на VPS (Debian/Ubuntu/любой Linux с systemd).
#
# Вариант 1 (рядом лежит бинарник из архива):
#   scp -r server root@IP:/root/mayak && ssh root@IP "bash /root/mayak/install-server.sh"
# Вариант 2 (указать файл явно):
#   bash install-server.sh /путь/к/mayak-linux-amd64
#
# Переменные (необязательно):
#   PORT=443            порт HTTPS (по умолчанию 443)
#   SNI=ya.ru           что писать в SNI у клиента (по умолчанию — имя сертификата)
#   CN=cdn.example.net  имя в самоподписанном сертификате
#   CERT=/path KEY=/path  свой сертификат (например, Let's Encrypt для своего домена)
#   PUBLIC=1.2.3.4      внешний адрес для ссылки (по умолчанию определяется сам)
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
[ "$(id -u)" = 0 ] || { echo "Запустите от root (sudo)."; exit 1; }
DIR=$(cd "$(dirname "$0")" && pwd)
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) A=amd64 ;; aarch64|arm64) A=arm64 ;; armv7l) A=armv7 ;;
  *) echo "Неизвестная архитектура $ARCH"; exit 1 ;;
esac
SRC=${1:-}
[ -n "$SRC" ] || for c in "$DIR/mayak-linux-$A" "$DIR/../bin/mayak-linux-$A" "$DIR/mayak"; do [ -f "$c" ] && SRC=$c && break; done
[ -n "$SRC" ] && [ -f "$SRC" ] || { echo "Не найден бинарник mayak-linux-$A рядом со скриптом."; exit 1; }

PORT=${PORT:-443}; CN=${CN:-cdn.statika.net}
install -m 0755 "$SRC" /usr/local/bin/mayak
mkdir -p /etc/mayak && chmod 700 /etc/mayak
if ! id mayak >/dev/null 2>&1; then
  if command -v useradd >/dev/null; then useradd --system --no-create-home --shell /usr/sbin/nologin mayak
  else adduser --system --no-create-home --disabled-login mayak 2>/dev/null || adduser -S -D -H mayak; fi
fi
chown -R mayak /etc/mayak

if [ -z "${PUBLIC:-}" ]; then
  PUBLIC=$(curl -4 -s --max-time 5 https://api.ipify.org || true)
  [ -n "$PUBLIC" ] || PUBLIC=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
fi
ARGS="-listen :$PORT -state /etc/mayak -public $PUBLIC -cn $CN"
[ -n "${SNI:-}" ] && ARGS="$ARGS -sni $SNI"
[ -n "${CERT:-}" ] && ARGS="$ARGS -cert $CERT -key $KEY"

cat > /etc/systemd/system/mayak.service <<UNIT
[Unit]
Description=MAYAK tunnel server
After=network-online.target
Wants=network-online.target

[Service]
User=mayak
ExecStart=/usr/local/bin/mayak server $ARGS
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/mayak
PrivateTmp=true
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT

# ускоряем частую смену соединений
cat > /etc/sysctl.d/90-mayak.conf <<SYS
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = 4096
net.ipv4.ip_local_port_range = 10240 65000
SYS
sysctl -q --system || true

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q active; then ufw allow "$PORT"/tcp >/dev/null; fi

systemctl daemon-reload
systemctl enable --now mayak >/dev/null
sleep 2
systemctl --no-pager --lines=0 status mayak | head -3
echo
echo "Готово. Ссылка для клиента (лежит в /etc/mayak/link.txt):"
echo
cat /etc/mayak/link.txt
echo
echo "Проверка снаружи: откройте https://$PUBLIC:$PORT/ — должен быть сайт-заглушка (браузер предупредит о сертификате, это нормально)."
