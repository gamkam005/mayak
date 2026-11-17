//go:build !lite

package sub

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

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

