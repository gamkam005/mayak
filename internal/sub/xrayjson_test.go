package sub

import "testing"

const xrayJSONSub = `[
 {"remarks":"A","outbounds":[
  {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"a.example","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","publicKey":"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE","shortId":"ab","fingerprint":"chrome"}}},
  {"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]},
 {"remarks":"B","outbounds":[
  {"tag":"p1","protocol":"vless","settings":{"vnext":[{"address":"b.example","port":8443,"users":[{"id":"22222222-2222-2222-2222-222222222222","encryption":"none"}]}]},
   "streamSettings":{"network":"xhttp","security":"tls","xhttpSettings":{"mode":"auto","path":"/x","extra":{"xPaddingBytes":"100-1000"}},"tlsSettings":{"serverName":"b.example"}}},
  {"tag":"p2","protocol":"hysteria","settings":{"address":"c.example","port":443,"version":2},
   "streamSettings":{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"auth":"x"},"tlsSettings":{"serverName":"c.example"}}},
  {"tag":"p3","protocol":"shadowsocks","settings":{"servers":[{"address":"d.example","port":8388,"method":"chacha20-ietf-poly1305","password":"x"}]}},
  {"tag":"chain","protocol":"vless","settings":{"vnext":[{"address":"e.example","port":443,"users":[{"id":"33333333-3333-3333-3333-333333333333"}]}]},"proxySettings":{"tag":"p1"}}]},
 {"remarks":"A again","outbounds":[
  {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"a.example","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","publicKey":"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE","shortId":"ab","fingerprint":"chrome"}}}]}
]`

func TestParseXrayJSON(t *testing.T) {
	ns, bad := ParseText(xrayJSONSub)
	if len(ns) != 4 || bad != 1 {
		t.Fatalf("nodes=%d bad=%d, want 4 and 1 (chain skipped, duplicate merged)", len(ns), bad)
	}
	want := []string{"vless/tcp/reality", "vless/xhttp/tls", "hy2/udp/tls", "ss/tcp/none"}
	for i, n := range ns {
		if got := n.Proto + "/" + n.Net + "/" + n.Sec; got != want[i] {
			t.Errorf("node %d: %s, want %s", i, got, want[i])
		}
		if n.ob["tag"] != "proxy" || n.Link != "" {
			t.Errorf("node %d: tag %v link %q", i, n.ob["tag"], n.Link)
		}
	}
	if ns[0].Name != "A" || ns[1].Name != "B #1" {
		t.Errorf("names: %q %q", ns[0].Name, ns[1].Name)
	}
	if get(ns[1].ob, "streamSettings", "xhttpSettings", "extra", "xPaddingBytes") != "100-1000" {
		t.Error("xhttp extra lost")
	}
	if _, _, ok := parseXrayJSON(`{"foo":1}`); ok {
		t.Error("not an xray config")
	}
}

func TestMaskPathKey(t *testing.T) {
	for in, want := range map[string]string{
		"https://sub.example.net/connection/subs/1b2c3d4e-0000-4111-8222-123456789abc":                   "https://sub.example.net/connection/subs/***",
		"https://x.example/sub/AbCdEf0123456789xyz?fmt=1":                                                "https://x.example/sub/***?fmt=1",
		`Get "https://x.example/connection/subs/1b2c3d4e-0000-4111-8222-123456789abc": tls: bad`:         `Get "https://x.example/connection/subs/***": tls: bad`,
		"https://x.example/s?token=abc":                                                                  "https://x.example/s?token=***",
		"https://raw.githubusercontent.com/a/b/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt": "https://raw.githubusercontent.com/a/b/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
		"https://raw.githubusercontent.com/h/port-based-v2ray-configs/main/ss/443.txt":                   "https://raw.githubusercontent.com/h/port-based-v2ray-configs/main/ss/443.txt",
	} {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}
