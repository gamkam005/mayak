package sub

import (
	"encoding/base64"
	"encoding/json"
)

func base64StdEncode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}

// withIP — подставить заранее найденный IP сервера (на Android у Go нет
// системного DNS), сохранив имя для TLS/SNI и заголовка Host.
func withIP(ob map[string]any, host, ip string) map[string]any {
	b, _ := json.Marshal(ob)
	var c map[string]any
	_ = json.Unmarshal(b, &c)
	if ip == "" || ip == host {
		return c
	}
	set := func(m map[string]any) { m["address"] = ip }
	st, _ := c["settings"].(map[string]any)
	for _, k := range []string{"vnext", "servers"} {
		if l, ok := st[k].([]any); ok {
			for _, s := range l {
				if m, ok := s.(map[string]any); ok {
					set(m)
				}
			}
		}
	}
	if _, ok := st["address"]; ok {
		set(st)
	}
	ss, _ := c["streamSettings"].(map[string]any)
	if ss == nil {
		return c
	}
	if t, ok := ss["tlsSettings"].(map[string]any); ok {
		if t["serverName"] == nil || t["serverName"] == "" {
			t["serverName"] = host
		}
	}
	for _, k := range []string{"wsSettings", "httpupgradeSettings", "xhttpSettings"} {
		if m, ok := ss[k].(map[string]any); ok && (m["host"] == nil || m["host"] == "") {
			m["host"] = host
		}
	}
	return c
}
