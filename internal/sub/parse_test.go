package sub

import (
	"encoding/base64"
	"encoding/json"
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

func TestParseLinks(t *testing.T) {
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "vm", "add": "vm.example.com", "port": "8443", "id": "11111111-2222-3333-4444-555555555555", "aid": "0", "net": "ws", "host": "cdn.example.com", "path": "/p", "tls": "tls"})
	cases := []struct {
		link, proto, net, sec string
		check                 func(t *testing.T, ob map[string]any)
	}{
		{"vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&pbk=QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE&sid=ab&sni=www.example.com&fp=qq&type=tcp&flow=xtls-rprx-vision#%F0%9F%87%A9%F0%9F%87%AA%20DE", "vless", "tcp", "reality", func(t *testing.T, ob map[string]any) {
			if get(ob, "streamSettings", "realitySettings", "publicKey") == nil || get(ob, "settings", "vnext", "users", "flow") != "xtls-rprx-vision" {
				t.Errorf("reality/flow: %v", ob)
			}
		}},
		{"vless://u@h.example.com:443?type=ws&security=tls&path=%2Fws&host=h.example.com&alpn=http%252F1.1&fp=firefox#x", "vless", "ws", "tls", func(t *testing.T, ob map[string]any) {
			a := get(ob, "streamSettings", "tlsSettings", "alpn").([]string)
			if a[0] != "http/1.1" || get(ob, "streamSettings", "wsSettings", "path") != "/ws" || get(ob, "streamSettings", "tlsSettings", "serverName") != "h.example.com" {
				t.Errorf("ws: %v", ob)
			}
		}},
		{"vless://u@h:443?type=grpc&serviceName=svc&mode=gun&security=tls&sni=s", "vless", "grpc", "tls", func(t *testing.T, ob map[string]any) {
			if get(ob, "streamSettings", "grpcSettings", "serviceName") != "svc" {
				t.Errorf("grpc: %v", ob)
			}
		}},
		{"vless://u@h:443?type=xhttp&mode=packet-up&path=%2Fx&security=reality&pbk=QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE&sni=s&extra=%7B%22a%22%3A1%7D", "vless", "xhttp", "reality", func(t *testing.T, ob map[string]any) {
			if get(ob, "streamSettings", "xhttpSettings", "mode") != "packet-up" || get(ob, "streamSettings", "xhttpSettings", "extra") == nil {
				t.Errorf("xhttp: %v", ob)
			}
		}},
		{"trojan://pa%40ss@t.example.com:443?type=ws&path=%2Fd&host=t.example.com&security=tls&sni=t.example.com#t", "trojan", "ws", "tls", func(t *testing.T, ob map[string]any) {
			if get(ob, "settings", "servers", "password") != "pa@ss" {
				t.Errorf("trojan pass: %v", ob)
			}
		}},
		{"vmess://" + base64.StdEncoding.EncodeToString(vm), "vmess", "ws", "tls", func(t *testing.T, ob map[string]any) {
			if get(ob, "streamSettings", "tlsSettings", "serverName") != "cdn.example.com" {
				t.Errorf("vmess sni from host: %v", ob)
			}
		}},
		{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw")) + "@5.6.7.8:8388#ss", "ss", "tcp", "none", func(t *testing.T, ob map[string]any) {
			if get(ob, "settings", "servers", "method") != "chacha20-ietf-poly1305" || get(ob, "settings", "servers", "password") != "pw" {
				t.Errorf("ss: %v", ob)
			}
		}},
		{"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw@9.9.9.9:443")) + "#legacy", "ss", "tcp", "none", nil},
		{"hysteria2://secret@hy.example.com:8443/?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=ob#hy", "hy2", "udp", "tls", func(t *testing.T, ob map[string]any) {
			if get(ob, "streamSettings", "hysteriaSettings", "auth") != "secret" || get(ob, "streamSettings", "finalmask") == nil {
				t.Errorf("hy2: %v", ob)
			}
			if _, err := NewEngine(withIP(ob, "hy.example.com", "127.0.0.1")); err != nil {
				t.Errorf("hy2 engine: %v", err)
			}
		}},
	}
	for _, c := range cases {
		n, err := ParseLink(c.link)
		if err != nil {
			t.Fatalf("%s: %v", c.link[:20], err)
		}
		if n.Proto != c.proto || n.Net != c.net || n.Sec != c.sec {
			t.Errorf("%s: got %s/%s/%s", c.link[:20], n.Proto, n.Net, n.Sec)
		}
		if c.check != nil {
			c.check(t, n.ob)
		}
		// каждая ссылка должна собираться в рабочий конфиг Xray
		e, err := NewEngine(withIP(n.ob, n.Host, "127.0.0.1"))
		if err != nil {
			t.Errorf("%s: engine: %v", c.proto, err)
			continue
		}
		_ = e.Close()
	}
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
