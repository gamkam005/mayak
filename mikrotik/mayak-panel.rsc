# МАЯК: веб-панель контейнера на адресе самого роутера, порт 9090, только из LAN.
#   http://<адрес роутера>:9090/  ->  172.17.0.2:9090
# Пароль панели: Files -> mayak-data/ui.pass (создаётся сам при первом запуске),
# или положите свой в mayak/ui.pass (одна строка) и перезапустите контейнер.
# Ниже можно ограничить доступ одним интерфейсом и одной сетью:
#   :local inif "ether1"  и  :local lannet "192.168.88.0/24"
# Пусто = список интерфейсов LAN и любые адреса из него.
# Запуск: /import file-name=mayak-panel.rsc   Откат: mayak-remove.rsc (или
#   /ip firewall nat remove [find comment="mayak-panel"]
#   /ip firewall filter remove [find comment="mayak-panel"])

:local inif ""
:local lannet ""
:local port 9090

/ip firewall nat remove [find where comment="mayak-panel"]
/ip firewall filter remove [find where comment="mayak-panel"]

:local nat [/ip firewall nat add chain=dstnat dst-address-type=local protocol=tcp dst-port=$port action=dst-nat to-addresses=172.17.0.2 to-ports=9090 comment=mayak-panel]
:if ($inif != "") do={ /ip firewall nat set $nat in-interface=$inif } else={ /ip firewall nat set $nat in-interface-list=LAN }
:if ($lannet != "") do={ /ip firewall nat set $nat src-address=$lannet }
:if ([:len [/ip firewall nat find where comment!="mayak-panel" && !dynamic]] > 0) do={
  /ip firewall nat move $nat ([/ip firewall nat find where comment!="mayak-panel" && !dynamic]->0)
}

# Порядок в forward: сначала «пустить из LAN», затем «всем остальным нельзя».
:local acc [/ip firewall filter add chain=forward dst-address=172.17.0.2 protocol=tcp dst-port=9090 action=accept comment=mayak-panel]
:if ($inif != "") do={ /ip firewall filter set $acc in-interface=$inif } else={ /ip firewall filter set $acc in-interface-list=LAN }
:if ($lannet != "") do={ /ip firewall filter set $acc src-address=$lannet }
:local drp [/ip firewall filter add chain=forward dst-address=172.17.0.2 protocol=tcp dst-port=9090 action=drop comment=mayak-panel]
:local others [/ip firewall filter find where comment!="mayak-panel" && !dynamic]
:if ([:len $others] > 0) do={
  /ip firewall filter move $acc ($others->0)
  /ip firewall filter move $drp ($others->0)
}
:put ("mayak: панель открыта из LAN на порту " . $port . ", пароль - Files: mayak-data/ui.pass")
