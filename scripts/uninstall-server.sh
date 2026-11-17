#!/usr/bin/env bash
set -e
systemctl disable --now mayak 2>/dev/null || true
rm -f /etc/systemd/system/mayak.service /usr/local/bin/mayak /etc/sysctl.d/90-mayak.conf
systemctl daemon-reload
echo "Сервер МАЯК удалён. Ключи остались в /etc/mayak (удалите вручную, если не нужны)."
