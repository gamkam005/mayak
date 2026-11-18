# МАЯК: полный откат — снимает перенаправление, останавливает и удаляет контейнер,
# удаляет всё с comment=mayak и mayak-panel. Файлы образа и папку mayak в Files не трогает.
# Режим device-mode и пакет container остаются (их откат — см. README_RU.md).
# Запуск: /import file-name=mayak-remove.rsc

/ip firewall nat remove [find where comment="mayak" || comment="mayak-panel"]
/ip firewall filter remove [find where comment="mayak" || comment="mayak-panel"]
/ip firewall address-list remove [find where comment="mayak" && !dynamic]
/ip dns static remove [find where comment="mayak"]
:do { /ip firewall address-list remove [find where list="via-mayak" && dynamic] } on-error={}
/ip dns forwarders remove [find where comment="mayak"]
:foreach c in=[/container find where name="mayak"] do={
  :if ([/container get $c running]) do={ /container stop $c }
}
:local n 0
:while ([:len [/container find where name="mayak"]] > [:len [/container find where name="mayak" stopped]] && $n < 60) do={ :delay 1s; :set n ($n + 1) }
/container remove [find where name="mayak"]
/container envs remove [find where comment="mayak"]
/container mounts remove [find where comment="mayak"]
/interface bridge port remove [find where comment="mayak"]
/ip address remove [find where comment="mayak"]
/interface bridge remove [find where comment="mayak"]
/interface veth remove [find where comment="mayak"]
/ip dns cache flush
:put "mayak: всё снято, роутер работает как до установки"
