package sub

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// parseClash — минимальный разбор Clash/Mihomo YAML (proxies: в одну строку
// «- {name: …, type: …}» или блоками). Узлы превращаем в ссылки и разбираем
// общим кодом.
func parseClash(body string) (nodes []Node, bad int) {
	var cur map[string]string
	var items []map[string]string
	inProxies := false
	flush := func() {
		if cur != nil {
			items = append(items, cur)
			cur = nil
		}
	}
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimRight(raw, "\r ")
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "-") {
			flush()
			inProxies = strings.HasPrefix(t, "proxies:")
			continue
		}
		if !inProxies {
			continue
		}
		if strings.HasPrefix(t, "- ") {
			flush()
			cur = map[string]string{}
			t = strings.TrimSpace(t[2:])
			if strings.HasPrefix(t, "{") {
				for k, v := range flowMap(t) {
					cur[k] = v
				}
				flush()
				continue
			}
		}
		if cur == nil {
			continue
		}
		if k, v, ok := strings.Cut(t, ":"); ok {
			v = strings.TrimSpace(v)
			if strings.HasPrefix(v, "{") {
				for kk, vv := range flowMap(v) {
					cur[strings.TrimSpace(k)+"."+kk] = vv
				}
			} else {
				cur[strings.TrimSpace(k)] = unq(v)
			}
		}
	}
	flush()
	for _, m := range items {
		link, err := clashLink(m)
		if err != nil {
			bad++
			continue
		}
		n, err := ParseLink(link)
		if err != nil {
			bad++
			continue
		}
		nodes = append(nodes, n)
	}
	return
}

func unq(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// flowMap — «{a: 1, b: {c: 2}}» → a=1, b.c=2 (без списков внутри).
func flowMap(s string) map[string]string {
	out := map[string]string{}
	var walk func(s, prefix string)
	walk = func(s, prefix string) {
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
		depth, start := 0, 0
		var parts []string
		inq := byte(0)
		for i := 0; i < len(s); i++ {
			c := s[i]
			switch {
			case inq != 0:
				if c == inq {
					inq = 0
				}
			case c == '"' || c == '\'':
				inq = c
			case c == '{' || c == '[':
				depth++
			case c == '}' || c == ']':
				depth--
			case c == ',' && depth == 0:
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
		parts = append(parts, s[start:])
		for _, p := range parts {
			k, v, ok := strings.Cut(p, ":")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if strings.HasPrefix(v, "{") {
				walk(v, prefix+k+".")
			} else {
				out[prefix+k] = unq(strings.Trim(v, "[]"))
			}
		}
	}
	walk(s, "")
	return out
}

func clashLink(m map[string]string) (string, error) {
	host, port := m["server"], m["port"]
	if host == "" || port == "" {
		return "", fmt.Errorf("нет server/port")
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", err
	}
	hp := host + ":" + port
	if strings.Contains(host, ":") {
		hp = "[" + host + "]:" + port
	}
	name := url.PathEscape(m["name"])
	q := url.Values{}
	netw := m["network"]
	if netw != "" {
		q.Set("type", netw)
	}
	if m["ws-opts.path"] != "" {
		q.Set("path", m["ws-opts.path"])
	}
	if m["ws-opts.headers.Host"] != "" {
		q.Set("host", m["ws-opts.headers.Host"])
	}
	if m["grpc-opts.grpc-service-name"] != "" {
		q.Set("serviceName", m["grpc-opts.grpc-service-name"])
	}
	sni := m["servername"]
	if sni == "" {
		sni = m["sni"]
	}
	if sni != "" {
		q.Set("sni", sni)
	}
	if m["client-fingerprint"] != "" {
		q.Set("fp", m["client-fingerprint"])
	}
	if m["skip-cert-verify"] == "true" {
		q.Set("allowInsecure", "1")
	}
	switch m["type"] {
	case "vless", "trojan":
		user := m["uuid"]
		if m["type"] == "trojan" {
			user = m["password"]
			q.Set("security", "tls")
		}
		if m["tls"] == "true" {
			q.Set("security", "tls")
		}
		if m["reality-opts.public-key"] != "" {
			q.Set("security", "reality")
			q.Set("pbk", m["reality-opts.public-key"])
			q.Set("sid", m["reality-opts.short-id"])
		}
		if m["flow"] != "" {
			q.Set("flow", m["flow"])
		}
		return m["type"] + "://" + url.PathEscape(user) + "@" + hp + "?" + q.Encode() + "#" + name, nil
	case "ss":
		return "ss://" + url.PathEscape(m["cipher"]+":"+m["password"]) + "@" + hp + "#" + name, nil
	case "hysteria2":
		h := url.Values{}
		if sni != "" {
			h.Set("sni", sni)
		}
		if m["skip-cert-verify"] == "true" {
			h.Set("insecure", "1")
		}
		if m["obfs"] != "" {
			h.Set("obfs", m["obfs"])
			h.Set("obfs-password", m["obfs-password"])
		}
		return "hysteria2://" + url.PathEscape(m["password"]) + "@" + hp + "/?" + h.Encode() + "#" + name, nil
	case "vmess":
		// упрощённо: через JSON v2rayN
		j := fmt.Sprintf(`{"v":"2","ps":%q,"add":%q,"port":%q,"id":%q,"aid":%q,"scy":%q,"net":%q,"type":"none","host":%q,"path":%q,"tls":%q,"sni":%q}`,
			m["name"], host, port, m["uuid"], orDef(m["alterId"], "0"), orDef(m["cipher"], "auto"), orDef(netw, "tcp"),
			m["ws-opts.headers.Host"], orDef(m["ws-opts.path"], m["grpc-opts.grpc-service-name"]), map[bool]string{true: "tls"}[m["tls"] == "true"], sni)
		return "vmess://" + b64enc(j), nil
	}
	return "", fmt.Errorf("clash %s: %w", m["type"], ErrUnsupported)
}

func b64enc(s string) string { return base64StdEncode([]byte(s)) }
