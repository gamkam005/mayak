# МАЯК: через туннель — все веб-соединения (TCP 80/443) клиентов LAN, кроме
# локальных сетей и самого сервера МАЯК. Остальное (игры, звонки по UDP) — напрямую.
# Перед запуском впишите IP своего сервера МАЯК в $server (это адрес из ссылки).
# Запуск: /import file-name=mayak-route-all.rsc

:local server "0.0.0.0"

:foreach a in={"10.0.0.0/8";"172.16.0.0/12";"192.168.0.0/16";"100.64.0.0/10";"127.0.0.0/8";"169.254.0.0/16";"224.0.0.0/4"} do={
  /ip firewall address-list add list=no-mayak address=$a comment=mayak
}
:if ($server != "0.0.0.0") do={ /ip firewall address-list add list=no-mayak address=$server comment=mayak }

/ip firewall nat add chain=dstnat in-interface-list=LAN src-address=!172.17.0.0/24 protocol=tcp dst-port=80,443 dst-address-list=!no-mayak action=dst-nat to-addresses=172.17.0.2 to-ports=8443 comment=mayak
:if ([:len [/ip firewall filter find]] > 0) do={
  /ip firewall filter add chain=forward in-interface-list=LAN protocol=udp dst-port=443 dst-address-list=!no-mayak action=reject reject-with=icmp-port-unreachable comment=mayak place-before=([/ip firewall filter find]->0)
} else={
  /ip firewall filter add chain=forward in-interface-list=LAN protocol=udp dst-port=443 dst-address-list=!no-mayak action=reject reject-with=icmp-port-unreachable comment=mayak
}
:put "mayak: весь веб-трафик LAN идёт через МАЯК"
