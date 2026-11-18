package sub

import (
	"encoding/json"
	"fmt"
	"strings"
)

// parseXrayJSON разбирает подписку из готовых конфигов Xray: массив полных
// конфигов или один конфиг с "outbounds" (так многие панели отвечают клиентам
// v2rayN/v2rayNG/Happ). Outbound берётся как есть — с REALITY, xhttp extra,
// finalmask и т. п.; меняется только тег. Цепочки (dialerProxy/proxySettings)
// пропускаются. ok=false — это не Xray JSON.
func parseXrayJSON(body string) (nodes []Node, bad int, ok bool) {
	var cfgs []map[string]any
	if strings.HasPrefix(body, "[") {
		if json.Unmarshal([]byte(body), &cfgs) != nil {
			return nil, 0, false
		}
	} else {
		var one map[string]any
		if json.Unmarshal([]byte(body), &one) != nil {
			return nil, 0, false
		}
		cfgs = []map[string]any{one}
	}
	seen := map[string]bool{}
	found := false
	for _, c := range cfgs {
		obs, _ := c["outbounds"].([]any)
		if len(obs) > 0 {
			found = true
		}
		name, _ := c["remarks"].(string)
		var mine []Node
		for _, o := range obs {
			ob, _ := o.(map[string]any)
			if ob == nil {
				continue
			}
			switch ob["protocol"] {
			case "freedom", "blackhole", "dns", "loopback", nil:
				continue
			}
			n, err := xrayNode(ob)
			if err != nil {
				bad++
				continue
			}
			if seen[n.ID] {
				continue
			}
			seen[n.ID] = true
			mine = append(mine, n)
		}
		for i := range mine {
			mine[i].Name = name
			if len(mine) > 1 {
				mine[i].Name = fmt.Sprintf("%s #%d", name, i+1)
			}
		}
		nodes = append(nodes, mine...)
	}
	return nodes, bad, found
}

func xrayNode(src map[string]any) (Node, error) {
	b, _ := json.Marshal(src)
	var ob map[string]any
	_ = json.Unmarshal(b, &ob)
	if _, chained := ob["proxySettings"]; chained {
		return Node{}, fmt.Errorf("цепочка outbound: %w", ErrUnsupported)
	}
	ss, _ := ob["streamSettings"].(map[string]any)
	if so, _ := ss["sockopt"].(map[string]any); so != nil && so["dialerProxy"] != nil {
		return Node{}, fmt.Errorf("dialerProxy: %w", ErrUnsupported)
	}
	st, _ := ob["settings"].(map[string]any)
	var srv map[string]any
	for _, k := range []string{"vnext", "servers"} {
		if l, _ := st[k].([]any); len(l) > 0 {
			srv, _ = l[0].(map[string]any)
			break
		}
	}
	if srv == nil {
		srv = st
	}
	host, _ := srv["address"].(string)
	port, _ := srv["port"].(float64)
	if host == "" || port <= 0 || port > 65535 {
		return Node{}, fmt.Errorf("нет адреса")
	}
	proto, _ := ob["protocol"].(string)
	n := Node{Proto: proto, Host: host, Port: int(port)}
	switch proto {
	case "vless", "vmess", "trojan":
	case "shadowsocks":
		n.Proto = "ss"
	case "hysteria":
		n.Proto = "hy2"
	default:
		return Node{}, fmt.Errorf("%s: %w", proto, ErrUnsupported)
	}
	n.Net, _ = ss["network"].(string)
	switch n.Net {
	case "", "raw":
		n.Net = "tcp"
	case "splithttp":
		n.Net = "xhttp"
	case "hysteria":
		n.Net = "udp"
	case "h2", "http", "kcp", "mkcp", "quic":
		return Node{}, fmt.Errorf("транспорт %s: %w", n.Net, ErrUnsupported)
	}
	n.Sec, _ = ss["security"].(string)
	if n.Sec == "" {
		n.Sec = "none"
	}
	ob["tag"] = "proxy"
	delete(ob, "sendThrough")
	n.ob = ob
	n.ID = nodeID(n)
	return n, nil
}
