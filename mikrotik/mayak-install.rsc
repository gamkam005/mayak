# МАЯК в контейнере RouterOS 7 — установка (ничего не перенаправляет, только поднимает прокси).
# До запуска: пакет container установлен, /system/device-mode включён (container=yes),
# в Files лежат образ (см. $image) и папка mayak с файлом link.txt (ссылка mayak://…).
# Запуск: /import file-name=mayak-install.rsc
# Всё созданное помечено comment=mayak — откат: /import file-name=mayak-remove.rsc

:local image "mayak-container-full-armv7.tar"
# off | reserve (запасной вход из бесплатных подписок, только full-образ) | always
:local subs "reserve"
# tunnel (всё через сервер) | auto (сначала напрямую с обманом DPI, не вышло — туннель)
:local route "tunnel"

:if ([:len [/file find where name=$image]] = 0) do={ :error ("нет файла образа " . $image . " в Files") }
:if ([:len [/file find where name="mayak/link.txt"]] = 0) do={ :log warning "mayak: нет mayak/link.txt — без ссылки работают только подписки (subs=always)" }

/interface veth add name=veth-mayak address=172.17.0.2/24 gateway=172.17.0.1 comment=mayak
/interface bridge add name=containers comment=mayak
/ip address add address=172.17.0.1/24 interface=containers comment=mayak
/interface bridge port add bridge=containers interface=veth-mayak comment=mayak
/ip firewall nat add chain=srcnat src-address=172.17.0.0/24 action=masquerade comment=mayak
# DNS роутера для контейнера (стандартный firewall режет input не из LAN)
:if ([:len [/ip firewall filter find]] > 0) do={
  /ip firewall filter add chain=input in-interface=containers protocol=udp dst-port=53 action=accept comment=mayak place-before=([/ip firewall filter find]->0)
} else={
  /ip firewall filter add chain=input in-interface=containers protocol=udp dst-port=53 action=accept comment=mayak
}

/container mounts add list=mayak src=/mayak dst=/etc/mayak comment=mayak
/container mounts add list=mayak src=/mayak-data dst=/data comment=mayak
/container envs add list=mayak key=MAYAK_SUBS value=$subs comment=mayak
/container envs add list=mayak key=MAYAK_ROUTE value=$route comment=mayak
/container add name=mayak file=$image interface=veth-mayak root-dir=/mayak-root mountlists=mayak envlists=mayak dns=172.17.0.1 logging=yes start-on-boot=yes memory-high=200M comment=mayak

:local n 0
:while ([:len [/container find where name="mayak" stopped]] = 0 && $n < 90) do={ :delay 2s; :set n ($n + 1) }
/container start [find where name="mayak"]
:delay 5s
:if ([/container get [find where name="mayak"] running]) do={
  :put "mayak: контейнер запущен, прокси 172.17.0.2:1080 (SOCKS5/HTTP), панель http://172.17.0.2:9090/"
} else={
  :put "mayak: контейнер не запустился — смотрите /log print where topics~\"container\""
}
