# МАЯК: через туннель — только выбранные сайты (со всеми поддоменами).
# Клиенты LAN должны брать DNS у роутера (так по умолчанию). Роутер, отвечая им,
# сам добавляет адреса в список via-mayak, а dst-nat отправляет TCP 80/443 к этим
# адресам в контейнер (порт 8443: МАЯК берёт имя сайта из SNI/Host).
# Запуск: /import file-name=mayak-route-list.rsc
# Добавить сайт позже:
#   /ip dns static add name=example.com match-subdomain=yes type=FWD forward-to=mayak-doh address-list=via-mayak comment=mayak

:local sites {"youtube.com";"googlevideo.com";"ytimg.com";"ggpht.com";"youtu.be";"instagram.com";"cdninstagram.com";"facebook.com";"fbcdn.net";"x.com";"twimg.com";"discord.com";"discord.gg";"discordapp.com";"discordapp.net";"api.ipify.org"}

# свой DNS по HTTPS для этих имён (провайдер не подменит ответ)
# (повторный запуск безопасен: уже добавленное пропускается)
:if ([:len [/ip dns forwarders find where name="mayak-doh"]] = 0) do={
  /ip dns forwarders add name=mayak-doh doh-servers=https://1.1.1.1/dns-query,https://8.8.8.8/dns-query verify-doh-cert=yes comment=mayak
}
:foreach s in=$sites do={
  :if ([:len [/ip dns static find where name=$s && type="FWD"]] = 0) do={
    /ip dns static add name=$s match-subdomain=yes type=FWD forward-to=mayak-doh address-list=via-mayak comment=mayak
  }
}
/ip dns cache flush

/ip firewall nat remove [find where comment="mayak" && dst-address-list="via-mayak"]
/ip firewall filter remove [find where comment="mayak" && dst-address-list="via-mayak"]
/ip firewall nat add chain=dstnat in-interface-list=LAN src-address=!172.17.0.0/24 protocol=tcp dst-port=80,443 dst-address-list=via-mayak action=dst-nat to-addresses=172.17.0.2 to-ports=8443 comment=mayak
# QUIC (UDP 443) к этим сайтам запрещаем — браузер сразу перейдёт на TCP и попадёт в туннель
:if ([:len [/ip firewall filter find]] > 0) do={
  /ip firewall filter add chain=forward in-interface-list=LAN protocol=udp dst-port=443 dst-address-list=via-mayak action=reject reject-with=icmp-port-unreachable comment=mayak place-before=([/ip firewall filter find]->0)
} else={
  /ip firewall filter add chain=forward in-interface-list=LAN protocol=udp dst-port=443 dst-address-list=via-mayak action=reject reject-with=icmp-port-unreachable comment=mayak
}
:put "mayak: выбранные сайты идут через МАЯК (список via-mayak наполняется по мере запросов DNS)"
