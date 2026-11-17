#!/usr/bin/env bash
# Проверка приёмов обмана DPI на настоящем TCP через «маршрутизатор» (нужен sudo).
#   cli 10.0.1.2 ── rtr 10.0.1.1|10.0.2.1 ── srv 10.0.2.2 (openssl s_server :443)
# Снифферы: на входе rtr (это «видит DPI») и на входе srv («видит сервер»).
# Использование: tests/desync-netns.sh /путь/к/mayak [стратегии...]
set -u
M=$(readlink -f "${1:-./mayak}"); shift || true
STRATS=${*:-"none tlsrec+split tlsrec+disorder fake:ttl=1 tlsrec+fake:ttl=1 oob"}
D=$(cd "$(dirname "$0")" && pwd); W=$(mktemp -d); NAME=blocked.example
cleanup() { sudo pkill -f "sniff.py veth-" 2>/dev/null; sudo ip netns pids cli 2>/dev/null | xargs -r sudo kill 2>/dev/null; sudo ip netns pids srv 2>/dev/null | xargs -r sudo kill 2>/dev/null; for n in cli rtr srv; do sudo ip netns del $n 2>/dev/null; done; sudo rm -rf /etc/netns/cli; rm -rf "$W"; }
trap cleanup EXIT; cleanup 2>/dev/null; W=$(mktemp -d)
for n in cli rtr srv; do sudo ip netns add $n; sudo ip -n $n link set lo up; done
sudo ip link add veth-c netns rtr type veth peer name eth0 netns cli
sudo ip link add veth-s netns rtr type veth peer name eth0 netns srv
sudo ip -n cli addr add 10.0.1.2/24 dev eth0; sudo ip -n cli link set eth0 up; sudo ip -n cli route add default via 10.0.1.1
sudo ip -n srv addr add 10.0.2.2/24 dev eth0; sudo ip -n srv link set eth0 up; sudo ip -n srv route add default via 10.0.2.1
sudo ip -n rtr addr add 10.0.1.1/24 dev veth-c; sudo ip -n rtr addr add 10.0.2.1/24 dev veth-s
sudo ip -n rtr link set veth-c up; sudo ip -n rtr link set veth-s up
sudo ip netns exec rtr sysctl -qw net.ipv4.ip_forward=1
sudo mkdir -p /etc/netns/cli; echo "10.0.2.2 $NAME" | sudo tee /etc/netns/cli/hosts >/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME" -days 2 -keyout "$W/k.pem" -out "$W/c.pem" 2>/dev/null
sudo ip netns exec srv openssl s_server -quiet -accept 443 -www -cert "$W/c.pem" -key "$W/k.pem" >/dev/null 2>&1 &
sleep 0.5
printf "%-22s %-14s %-60s %s\n" "стратегия" "curl" "что видит DPI (вход rtr): сегменты вверх" "что получил сервер"
for st in $STRATS; do
  sudo ip netns exec cli "$M" client -route direct -desync "$st" -doh off -listen 127.0.0.1:1080 -ui "" >"$W/cl.log" 2>&1 &
  sleep 0.4
  sudo ip netns exec rtr python3 "$D/sniff.py" veth-c 443 "$NAME" 3 >"$W/dpi.json" & p1=$!
  sudo ip netns exec rtr python3 "$D/sniff.py" veth-s 443 "$NAME" 3 >"$W/srv.json" & p2=$!
  sleep 0.3
  code=$(sudo ip netns exec cli curl -s -o /dev/null -w "%{http_code}/%{time_total}s" --max-time 5 --cacert "$W/c.pem" --socks5-hostname 127.0.0.1:1080 "https://$NAME/")
  sleep 2.8
  sudo ip netns pids cli | xargs -r sudo kill 2>/dev/null; wait $p1 $p2 2>/dev/null
  python3 - "$st" "$code" "$W/dpi.json" "$W/srv.json" <<'PY'
import json,sys
st,code,a,b=sys.argv[1:]
def load(p): return [json.loads(l) for l in open(p) if l.strip()]
def up(rows): return [r for r in rows if r["dir"]=="up"][:4]
def fmt(r): return f'{r["len"]}B ttl{r["ttl"]}' + (' SNI' if r["has_sni"] else '') + (' FAKE' if r["fake_sni"] else '') + (' URG' if r["urg"] else '') + (f' rec{r["tls_rec"][6:]}' if r["tls_rec"] else '')
A,B=up(load(a)),up(load(b))
print(f'{st:<22} {code:<14} {" | ".join(map(fmt,A)):<60} {" | ".join(map(fmt,B))}')
PY
done
