#!/usr/bin/env bash
# Сквозные тесты МАЯКа на одной Linux-машине: сервер + симулятор ТСПУ + клиент.
# Использование: tests/e2e.sh /путь/к/mayak /путь/к/tspusim
set -u
M=${1:-./mayak}; SIM=${2:-./tspusim}
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$W"' EXIT
mkdir -p "$W/www"; head -c 20000000 /dev/urandom > "$W/www/20m.bin"; SUM=$(sha256sum < "$W/www/20m.bin")
(cd "$W/www" && exec python3 -m http.server 18088 --bind 127.0.0.1 >/dev/null 2>&1) &
"$M" server -listen 127.0.0.1:18443 -state "$W/state" -public 127.0.0.1 -cn cdn.statika.net >/dev/null 2>&1 &
sleep 1
LINK=$(cat "$W/state/link.txt")
simlink() { echo "$LINK" | sed "s/127.0.0.1:18443/127.0.0.1:$1/"; }
"$SIM" -listen 127.0.0.1:19443 -to 127.0.0.1:18443 -rtt 60ms -freeze 16384 -mbit 100 >"$W/sim1.log" 2>&1 &   # «ТСПУ» с заморозкой
"$SIM" -listen 127.0.0.1:19444 -to 127.0.0.1:18443 -rtt 60ms -freeze 0 -mbit 100 >"$W/sim2.log" 2>&1 &       # просто задержка
sleep 0.5

run() { # name link mode
  local name=$1 link=$2 mode=$3
  "$M" client -link "$link" -listen 127.0.0.1:11080 -ui 127.0.0.1:19090 -mode "$mode" >/dev/null 2>&1 & local pid=$!
  sleep ${4:-1.5}
  rm -f "$W/got"; local r; r=$(curl -s -o "$W/got" --max-time 120 -w "%{size_download} %{time_total}" --socks5-hostname 127.0.0.1:11080 http://127.0.0.1:18088/20m.bin)
  local ok="FAIL"; [ -f "$W/got" ] && [ "$(sha256sum < "$W/got")" = "$SUM" ] && ok="OK"
  local st; st=$(curl -s 127.0.0.1:19090/api/stats | python3 -c "import json,sys;s=json.load(sys.stdin);print(f\"режим={s['profile']['name']} TLS-соединений={s['dials']} макс.байт/соед={s['conn_max_bytes']} ошибок={s['errors']} дублей={s['dups']}\")")
  echo "$r" | awk -v n="$name" -v ok="$ok" -v st="$st" '{printf "%-44s %5.1f МБ за %6.2f с = %6.1f Мбит/с  целостность:%s  %s\n", n, $1/1e6, $2, $1*8/$2/1e6, ok, st}'
  kill $pid; wait $pid 2>/dev/null; sleep 0.3
}
echo "--- контроль: обычное ОДНО TLS-соединение через «ТСПУ» ---"
curl -sk -o /dev/null --max-time 10 -w "  получено %{size_download} байт из 1.5 МБ, потом тишина (curl: таймаут)\n" --resolve cdn.statika.net:19443:127.0.0.1 https://cdn.statika.net:19443/static/app.js
echo "--- МАЯК ---"
run "loopback, mosaic (без ТСПУ, без задержки)"  "$LINK" mosaic
run "loopback, fast"                             "$LINK" fast
run "RTT 60 мс, без заморозки, auto"             "$(simlink 19444)" auto 4
run "RTT 60 мс + заморозка 16 КБ, mosaic"        "$(simlink 19443)" mosaic
run "RTT 60 мс + заморозка 16 КБ, auto"          "$(simlink 19443)" auto 7
run "RTT 60 мс + заморозка 16 КБ, fast→откат"    "$(simlink 19443)" fast
