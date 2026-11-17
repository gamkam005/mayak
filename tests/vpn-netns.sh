#!/usr/bin/env bash
# VPN-цепочка как в APK, но на Linux: приложение → tun0 → hev-socks5-tunnel
# (mapdns) → SOCKS5 МАЯКа → маршрутизатор → напрямую с обманом DPI → сервер.
# Исключение ядра из VPN (на Android — addDisallowedApplication) здесь
# эмулирует ip rule по uid: root (ядро, hev) идёт мимо tun0, uid box — через tun0.
#   tests/vpn-netns.sh /путь/к/mayak /путь/к/hev-socks5-tunnel
set -u
M=$(readlink -f "$1"); HEV=$(readlink -f "$2"); D=$(cd "$(dirname "$0")" && pwd); NAME=blocked.example
W=$(mktemp -d); chmod 755 "$W"
cleanup() { sudo pkill -f "sniff.py veth-" 2>/dev/null; for n in cli srv; do sudo ip netns pids $n 2>/dev/null | xargs -r sudo kill 2>/dev/null; done; sleep 0.3; for n in cli rtr srv; do sudo ip netns del $n 2>/dev/null; done; sudo rm -rf /etc/netns/cli; rm -rf "$W"; }
trap cleanup EXIT
for n in cli rtr srv; do sudo ip netns add $n; sudo ip -n $n link set lo up; done
sudo ip link add veth-c netns rtr type veth peer name eth0 netns cli
sudo ip link add veth-s netns rtr type veth peer name eth0 netns srv
sudo ip -n cli addr add 10.0.1.2/24 dev eth0; sudo ip -n cli link set eth0 up
sudo ip -n srv addr add 10.0.2.2/24 dev eth0; sudo ip -n srv link set eth0 up; sudo ip -n srv route add default via 10.0.2.1
sudo ip -n rtr addr add 10.0.1.1/24 dev veth-c; sudo ip -n rtr addr add 10.0.2.1/24 dev veth-s
sudo ip -n rtr link set veth-c up; sudo ip -n rtr link set veth-s up
sudo ip netns exec rtr sysctl -qw net.ipv4.ip_forward=1
sudo mkdir -p /etc/netns/cli; printf "127.0.0.1 localhost %s\n10.0.2.2 %s\n" "$(hostname)" "$NAME" | sudo tee /etc/netns/cli/hosts >/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME,IP:10.0.2.2" -days 2 -keyout "$W/k.pem" -out "$W/c.pem" 2>/dev/null; chmod 644 "$W"/*.pem
sudo ip netns exec srv openssl s_server -quiet -accept 443 -www -cert "$W/c.pem" -key "$W/k.pem" >/dev/null 2>&1 &
# ядро МАЯКа (root = «приложение МАЯК», мимо VPN)
sudo ip netns exec cli "$M" client -route direct -desync tlsrec+split -doh off -listen 127.0.0.1:1080 -ui 127.0.0.1:9090 -v >"$W/core.log" 2>&1 &
cat >"$W/hev.yml" <<Y
tunnel:
  name: tun0
  mtu: 8500
  ipv4: 198.18.0.1
socks5:
  address: 127.0.0.1
  port: 1080
  udp: 'udp'
mapdns:
  address: 198.18.0.2
  port: 53
  network: 100.64.0.0
  netmask: 255.192.0.0
  cache-size: 10000
misc:
  log-level: warn
Y
sleep 0.5
sudo ip netns exec cli "$HEV" "$W/hev.yml" >"$W/hev.log" 2>&1 &
sleep 1
sudo ip -n cli link set tun0 up 2>/dev/null
sudo ip -n cli route add default dev tun0                       # все — в VPN
sudo ip -n cli rule add uidrange 0-0 lookup 200 priority 100    # кроме root (ядро/hev)
sudo ip -n cli route add default via 10.0.1.1 table 200
sudo ip -n cli route add 10.0.1.0/24 dev eth0 table 200
sudo ip netns exec rtr python3 "$D/sniff.py" veth-c 443 "$NAME" 25 >"$W/dpi.json" & SP=$!
sleep 0.3
U="sudo ip netns exec cli sudo -u box"
echo "1) DNS через mapdns (uid box → tun0 → hev):"
FAKE=$($U python3 -c "
import socket,struct
q=b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b''.join(bytes([len(l)])+l.encode() for l in '$NAME'.split('.'))+b'\x00\x00\x01\x00\x01'
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(q,('198.18.0.2',53));r=s.recv(512)
print(socket.inet_ntoa(r[-4:]))")
echo "   $NAME -> $FAKE (фейковый адрес из 100.64/10)"
echo "2) HTTPS по имени (fake IP → hev → SOCKS по имени → ядро → напрямую):"
$U curl -s -o /dev/null -w "   код %{http_code}, %{time_total} с\n" --max-time 8 --cacert "$W/c.pem" --resolve "$NAME:443:$FAKE" "https://$NAME/"
echo "3) HTTPS по IP 10.0.2.2 (без DNS):"
$U curl -s -o /dev/null -w "   код %{http_code}, %{time_total} с\n" --max-time 8 --cacert "$W/c.pem" https://10.0.2.2/
echo "4) UDP мимо mapdns (SOCKS UDP у ядра нет — должно тихо не пройти, ядро живо):"
$U python3 -c "
import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b'x',('10.0.2.2',5353))
try: s.recv(10); print('   ответ?!')
except Exception as e: print('   нет ответа (ожидаемо):',type(e).__name__)"
$U curl -s -o /dev/null -w "   после UDP: HTTPS код %{http_code}\n" --max-time 8 --cacert "$W/c.pem" --resolve "$NAME:443:$FAKE" "https://$NAME/"
sudo kill $SP 2>/dev/null; wait $SP 2>/dev/null
echo "5) что видел «DPI» на входе маршрутизатора (сегменты вверх с ClientHello):"
python3 -c "
import json
rows=[json.loads(l) for l in open('$W/dpi.json') if l.strip()]
for r in rows:
  if r['dir']=='up' and r['tls_rec'][:2]=='16': print('   ',r['len'],'B ttl',r['ttl'],'запись',r['tls_rec'],'SNI целиком' if r['has_sni'] else 'SNI не целиком')"
echo "6) журнал маршрутизатора ядра:"; sudo ip netns exec cli curl -s 127.0.0.1:9090/api/route | python3 -c "import json,sys;s=json.load(sys.stdin);print('   ',{k:s[k] for k in ('mode','direct','failed')},[(h['host'],h['path'],h['strategy']) for h in s['hosts']])"
echo "hev log:"; cat "$W/hev.log" | tail -3
