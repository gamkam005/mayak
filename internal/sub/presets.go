package sub

// Source — подписка.
type Source struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Preset  bool   `json:"preset"`
	Enabled bool   `json:"enabled"`
	White   bool   `json:"white,omitempty"` // серверы в «белых» подсетях РФ (режим белых списков на мобильном)
}

// Presets — встроенные бесплатные подписки (каждую можно отключить).
var Presets = []Source{
	{ID: "igareck-white-all", Name: "igareck · белые списки (все)", URL: "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt", White: true},
	{ID: "igareck-white-mobile", Name: "igareck · белые списки Reality (мобильный)", URL: "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt", White: true},
	{ID: "igareck-black-mobile", Name: "igareck · чёрные списки (мобильный)", URL: "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt"},
	{ID: "flat447-white", Name: "FLAT447 · белые списки", URL: "https://raw.githubusercontent.com/FLAT447/v2ray-lists/refs/heads/main/WHITE_FULL.txt", White: true},
	{ID: "v2nodes-all", Name: "v2nodes · все страны", URL: "https://www.v2nodes.com/subscriptions/country/all/?key=41C2C1D4C41A223"},
	{ID: "hamedcode-ss443", Name: "hamedcode · Shadowsocks :443", URL: "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/detailed/ss/443.txt"},
	{ID: "barryfar-vless", Name: "barry-far · VLESS (большой мировой)", URL: "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt"},
}

func init() {
	for i := range Presets {
		Presets[i].Preset, Presets[i].Enabled = true, true
	}
}
