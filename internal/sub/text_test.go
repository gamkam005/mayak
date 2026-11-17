package sub

import (
	"encoding/base64"
	"strings"
	"testing"
)

func get(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		switch c := cur.(type) {
		case map[string]any:
			cur = c[p]
		case []any:
			if len(c) == 0 {
				return nil
			}
			cur = c[0].(map[string]any)[p]
		default:
			return nil
		}
	}
	return cur
}

func TestParseText(t *testing.T) {
	plain := "# profile-title: x\nvless://u@1.1.1.1:443?security=none#a\nvless://u@1.1.1.1:443?security=none#dup\nfoo://bar\nss://bad\n"
	ns, bad := ParseText(plain)
	if len(ns) != 2 || bad != 2 || ns[0].ID != ns[1].ID {
		t.Errorf("plain: %d nodes, %d bad", len(ns), bad)
	}
	ns, _ = ParseText(base64.StdEncoding.EncodeToString([]byte(plain)))
	if len(ns) != 2 {
		t.Errorf("base64: %d", len(ns))
	}
	clash := `proxies:
  - {name: a, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-128-gcm, password: p}
  - name: b
    type: vless
    server: v.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    network: ws
    tls: true
    servername: v.example.com
    ws-opts: {path: /w, headers: {Host: v.example.com}}
  - {name: c, type: hysteria2, server: h.example.com, port: 443, password: pw, sni: h.example.com}
proxy-groups:
  - name: g
`
	ns, bad = ParseText(clash)
	if len(ns) != 3 || bad != 0 {
		t.Fatalf("clash: %d nodes, %d bad", len(ns), bad)
	}
	if get(ns[1].ob, "streamSettings", "wsSettings", "path") != "/w" {
		t.Errorf("clash ws: %v", ns[1].ob)
	}
}

func TestMask(t *testing.T) {
	m := Mask("https://www.v2nodes.com/subscriptions/country/all/?key=41C2C1D4C41A223")
	if strings.Contains(m, "41C2") {
		t.Error(m)
	}
}
