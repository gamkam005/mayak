// Package sub — «запасной вход из подписки»: разбор бесплатных подписок
// (VLESS, VMess, Trojan, Shadowsocks, Hysteria2), проверка серверов и выдача
// исходящих соединений через встроенное ядро Xray.
package sub

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Node — один сервер из подписки.
type Node struct {
	ID     string `json:"id"`
	Proto  string `json:"proto"` // vless|vmess|trojan|ss|hy2
	Name   string `json:"name"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Net    string `json:"net"` // tcp|ws|grpc|xhttp|httpupgrade|udp
	Sec    string `json:"sec"` // none|tls|reality
	Link   string `json:"-"`
	Source string `json:"source"`

	ob       map[string]any // готовый outbound для Xray
	insecure bool           // allowInsecure в ссылке: сертификат закрепим при первом подключении

}

// Outbound — JSON-outbound Xray (тег "proxy").
func (n *Node) Outbound() map[string]any { return n.ob }

// UDPOnly — сервер работает поверх UDP (TCP-пинг не годится).
func (n *Node) UDPOnly() bool { return n.Proto == "hy2" }

func (n *Node) Addr() string { return net.JoinHostPort(n.Host, strconv.Itoa(n.Port)) }

var ErrUnsupported = errors.New("не поддерживается")

// ParseText разбирает тело подписки: plain-ссылки по строкам, base64 целиком
// или Clash YAML (proxies:). Возвращает узлы и число нераспознанных строк.
func ParseText(body string) (nodes []Node, bad int) {
	body = strings.TrimPrefix(strings.TrimSpace(body), "\ufeff")
	if !strings.Contains(body, "://") {
		if dec, ok := b64(strings.Join(strings.Fields(body), "")); ok && strings.Contains(dec, "://") {
			body = dec
		}
	}
	if strings.Contains(body, "proxies:") && !strings.Contains(body, "vless://") && !strings.Contains(body, "vmess://") {
		return parseClash(body)
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '/' {
			continue
		}
		if !strings.Contains(line, "://") {
			continue
		}
		n, err := ParseLink(line)
		if err != nil {
			bad++
			continue
		}
		nodes = append(nodes, n)
	}
	return
}

// ParseLink разбирает одну ссылку.
func ParseLink(s string) (Node, error) {
	s = strings.TrimSpace(s)
	i := strings.Index(s, "://")
	if i < 0 {
		return Node{}, errors.New("нет схемы")
	}
	var n Node
	var err error
	switch strings.ToLower(s[:i]) {
	case "vless":
		n, err = parseStd("vless", s)
	case "trojan":
		n, err = parseStd("trojan", s)
	case "vmess":
		n, err = parseVMess(s)
	case "ss":
		n, err = parseSS(s)
	case "hysteria2", "hy2":
		n, err = parseHy2(s)
	default:
		return Node{}, fmt.Errorf("%s: %w", s[:i], ErrUnsupported)
	}
	if err != nil {
		return Node{}, err
	}
	if n.Host == "" || n.Port <= 0 || n.Port > 65535 {
		return Node{}, errors.New("нет адреса")
	}
	n.Link = s
	n.ID = nodeID(n)
	return n, nil
}

// nodeID — по сути сервера (без имени), чтобы дубли из разных подписок совпали.
func nodeID(n Node) string {
	b, _ := json.Marshal(n.ob)
	h := sha1.Sum(b)
	return hex.EncodeToString(h[:6])
}

func b64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), true
		}
	}
	return "", false
}

// unesc — ссылки в подписках бывают закодированы дважды-трижды (http%252F1.1).
func unesc(s string) string {
	for i := 0; i < 3 && strings.Contains(s, "%"); i++ {
		d, err := url.QueryUnescape(s)
		if err != nil || d == s {
			break
		}
		s = d
	}
	return s
}

func fragName(s string) (string, string) {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return s[:i], strings.TrimSpace(unesc(s[i+1:]))
	}
	return s, ""
}

func splitHostPort(hp string) (string, int, error) {
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return strings.Trim(h, "[]"), port, nil
}

func csv(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

var fps = map[string]bool{"chrome": true, "firefox": true, "safari": true, "ios": true, "android": true, "edge": true, "360": true, "qq": true, "random": true, "randomized": true}

func fpOf(s string) string {
	s = strings.ToLower(s)
	if fps[s] {
		return s
	}
	return "chrome"
}

// stream строит streamSettings из типовых параметров (vless/trojan/vmess).
func stream(p map[string]string, defSec string) (map[string]any, string, string, error) {
	netw := strings.ToLower(p["type"])
	switch netw {
	case "", "raw":
		netw = "tcp"
	case "splithttp":
		netw = "xhttp"
	case "h2", "http", "kcp", "mkcp", "quic":
		return nil, "", "", fmt.Errorf("транспорт %s: %w", netw, ErrUnsupported)
	}
	sec := strings.ToLower(p["security"])
	if sec == "" {
		sec = defSec
	}
	ss := map[string]any{"network": netw}
	host, path := p["host"], p["path"]
	switch netw {
	case "tcp":
		if strings.EqualFold(p["headerType"], "http") {
			req := map[string]any{"path": []string{orDef(path, "/")}}
			if host != "" {
				req["headers"] = map[string]any{"Host": csv(host)}
			}
			ss["tcpSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		}
	case "ws":
		w := map[string]any{"path": orDef(path, "/")}
		if host != "" {
			w["host"] = host
		}
		ss["wsSettings"] = w
	case "httpupgrade":
		w := map[string]any{"path": orDef(path, "/")}
		if host != "" {
			w["host"] = host
		}
		ss["httpupgradeSettings"] = w
	case "grpc":
		g := map[string]any{"serviceName": p["serviceName"]}
		if p["mode"] == "multi" {
			g["multiMode"] = true
		}
		if p["authority"] != "" {
			g["authority"] = p["authority"]
		}
		ss["grpcSettings"] = g
	case "xhttp":
		x := map[string]any{"path": orDef(path, "/"), "mode": orDef(p["mode"], "auto")}
		if host != "" {
			x["host"] = host
		}
		if e := p["extra"]; e != "" && e != "null" && json.Valid([]byte(e)) {
			x["extra"] = json.RawMessage(e)
		}
		ss["xhttpSettings"] = x
	default:
		return nil, "", "", fmt.Errorf("транспорт %s: %w", netw, ErrUnsupported)
	}
	sni := p["sni"]
	if sni == "" {
		sni = p["peer"]
	}
	switch sec {
	case "", "none":
		sec = "none"
	case "tls", "xtls":
		sec = "tls"
		t := map[string]any{"fingerprint": fpOf(p["fp"])}
		if sni == "" && host != "" && netw != "grpc" {
			sni = csv(host)[0]
		}
		if sni != "" {
			t["serverName"] = sni
		}
		if a := csv(p["alpn"]); len(a) > 0 {
			t["alpn"] = a
		}
		if p["pcs"] != "" {
			t["pinnedPeerCertSha256"] = p["pcs"]
		}
		if p["vcn"] != "" {
			t["verifyPeerCertByName"] = p["vcn"]
		}
		ss["tlsSettings"] = t
	case "reality":
		if p["pbk"] == "" {
			return nil, "", "", errors.New("reality без pbk")
		}
		r := map[string]any{"fingerprint": fpOf(p["fp"]), "publicKey": p["pbk"], "serverName": sni}
		if p["sid"] != "" {
			r["shortId"] = p["sid"]
		}
		if p["spx"] != "" {
			r["spiderX"] = p["spx"]
		}
		if p["pqv"] != "" {
			r["mldsa65Verify"] = p["pqv"]
		}
		ss["realitySettings"] = r
	default:
		return nil, "", "", fmt.Errorf("security %s: %w", sec, ErrUnsupported)
	}
	ss["security"] = sec
	return ss, netw, sec, nil
}

func insecureQ(p map[string]string) bool {
	for _, k := range []string{"allowInsecure", "insecure", "allow_insecure"} {
		if v := strings.ToLower(p[k]); v == "1" || v == "true" {
			return true
		}
	}
	return false
}

func orDef(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func query(raw string) map[string]string {
	p := map[string]string{}
	for _, kv := range strings.Split(raw, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if k = strings.TrimSpace(k); k != "" {
			p[k] = strings.TrimSpace(unesc(strings.ReplaceAll(v, "+", "%2B")))
		}
	}
	return p
}

// parseStd — vless://uuid@host:port?params#name и trojan://pass@host:port?params#name
func parseStd(proto, s string) (Node, error) {
	s, name := fragName(s)
	rest := s[strings.Index(s, "://")+3:]
	rest, q, _ := strings.Cut(rest, "?")
	at := strings.LastIndexByte(rest, '@')
	if at < 0 {
		return Node{}, errors.New("нет @")
	}
	user := unesc(rest[:at])
	host, port, err := splitHostPort(strings.TrimRight(rest[at+1:], "/"))
	if err != nil {
		return Node{}, err
	}
	p := query(q)
	defSec := "none"
	if proto == "trojan" {
		defSec = "tls"
	}
	ss, netw, sec, err := stream(p, defSec)
	if err != nil {
		return Node{}, err
	}
	var settings map[string]any
	if proto == "vless" {
		u := map[string]any{"id": user, "encryption": orDef(p["encryption"], "none")}
		if f := p["flow"]; f != "" && netw == "tcp" && sec != "none" {
			u["flow"] = f
		}
		settings = map[string]any{"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{u}}}}
	} else {
		settings = map[string]any{"servers": []any{map[string]any{"address": host, "port": port, "password": user}}}
	}
	return Node{Proto: proto, Name: name, Host: host, Port: port, Net: netw, Sec: sec, insecure: sec == "tls" && insecureQ(p),
		ob: map[string]any{"tag": "proxy", "protocol": proto, "settings": settings, "streamSettings": ss}}, nil
}

// parseVMess — vmess://base64(json v2rayN)
func parseVMess(s string) (Node, error) {
	body := s[len("vmess://"):]
	body, _ = fragName(body)
	dec, ok := b64(body)
	if !ok {
		return Node{}, errors.New("vmess: не base64")
	}
	var j map[string]any
	if err := json.Unmarshal([]byte(dec), &j); err != nil {
		return Node{}, err
	}
	str := func(k string) string {
		switch v := j[k].(type) {
		case string:
			return v
		case float64:
			return strconv.Itoa(int(v))
		}
		return ""
	}
	port, _ := strconv.Atoi(str("port"))
	p := map[string]string{"type": str("net"), "security": str("tls"), "host": str("host"), "path": str("path"),
		"sni": str("sni"), "alpn": str("alpn"), "fp": str("fp"), "headerType": str("type")}
	if p["type"] == "grpc" {
		p["serviceName"], p["path"] = p["path"], ""
		if str("type") == "multi" {
			p["mode"] = "multi"
		}
	}
	if p["type"] == "tcp" && p["headerType"] != "http" {
		p["headerType"] = ""
	}
	ss, netw, sec, err := stream(p, "none")
	if err != nil {
		return Node{}, err
	}
	aid, _ := strconv.Atoi(str("aid"))
	if aid != 0 {
		return Node{}, fmt.Errorf("vmess alterId=%d: %w", aid, ErrUnsupported)
	}
	host := str("add")
	u := map[string]any{"id": str("id"), "security": orDef(str("scy"), "auto")}
	return Node{Proto: "vmess", Name: str("ps"), Host: host, Port: port, Net: netw, Sec: sec, insecure: sec == "tls" && (str("allowInsecure") == "1" || str("allowInsecure") == "true"),
		ob: map[string]any{"tag": "proxy", "protocol": "vmess", "streamSettings": ss,
			"settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{u}}}}}}, nil
}

var ssMethods = map[string]bool{
	"aes-128-gcm": true, "aes-256-gcm": true, "chacha20-poly1305": true, "chacha20-ietf-poly1305": true,
	"xchacha20-poly1305": true, "xchacha20-ietf-poly1305": true, "none": true, "plain": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
}

// parseSS — ss://base64(method:pass)@host:port#name (SIP002) и ss://base64(method:pass@host:port)#name
func parseSS(s string) (Node, error) {
	body, name := fragName(s[len("ss://"):])
	body, q, _ := strings.Cut(body, "?")
	if q != "" {
		if p := query(q); p["plugin"] != "" {
			return Node{}, fmt.Errorf("ss plugin: %w", ErrUnsupported)
		}
	}
	var userinfo, hostport string
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		userinfo, hostport = body[:at], body[at+1:]
		if dec, ok := b64(unesc(userinfo)); ok && strings.Contains(dec, ":") {
			userinfo = dec
		} else {
			userinfo = unesc(userinfo)
		}
	} else {
		dec, ok := b64(body)
		if !ok {
			return Node{}, errors.New("ss: не base64")
		}
		at := strings.LastIndexByte(dec, '@')
		if at < 0 {
			return Node{}, errors.New("ss: нет @")
		}
		userinfo, hostport = dec[:at], dec[at+1:]
	}
	method, pass, ok := strings.Cut(userinfo, ":")
	method = strings.ToLower(method)
	if !ok || !ssMethods[method] {
		return Node{}, fmt.Errorf("ss %s: %w", method, ErrUnsupported)
	}
	host, port, err := splitHostPort(strings.TrimRight(hostport, "/"))
	if err != nil {
		return Node{}, err
	}
	return Node{Proto: "ss", Name: name, Host: host, Port: port, Net: "tcp", Sec: "none",
		ob: map[string]any{"tag": "proxy", "protocol": "shadowsocks",
			"settings": map[string]any{"servers": []any{map[string]any{"address": host, "port": port, "method": method, "password": pass}}}}}, nil
}

// parseHy2 — hysteria2://auth@host:port/?sni=&insecure=1&obfs=salamander&obfs-password=#name
func parseHy2(s string) (Node, error) {
	s, name := fragName(s)
	rest := s[strings.Index(s, "://")+3:]
	rest, q, _ := strings.Cut(rest, "?")
	rest = strings.TrimRight(rest, "/")
	auth := ""
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		auth, rest = unesc(rest[:at]), rest[at+1:]
	}
	if pp := rest[strings.LastIndexByte(rest, ':')+1:]; strings.ContainsAny(pp, ",-") {
		return Node{}, fmt.Errorf("hy2 port hopping: %w", ErrUnsupported)
	}
	host, port, err := splitHostPort(rest)
	if err != nil {
		return Node{}, err
	}
	p := query(q)
	t := map[string]any{"serverName": orDef(p["sni"], host), "alpn": []string{"h3"}}
	if p["pinSHA256"] != "" {
		t["pinnedPeerCertSha256"] = p["pinSHA256"]
	}
	ss := map[string]any{"network": "hysteria", "security": "tls", "tlsSettings": t,
		"hysteriaSettings": map[string]any{"version": 2, "auth": auth}}
	switch strings.ToLower(p["obfs"]) {
	case "":
	case "salamander":
		ss["finalmask"] = map[string]any{"udp": []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": p["obfs-password"]}}}}
	default:
		return Node{}, fmt.Errorf("hy2 obfs %s: %w", p["obfs"], ErrUnsupported)
	}
	return Node{Proto: "hy2", Name: name, Host: host, Port: port, Net: "udp", Sec: "tls", insecure: insecureQ(p),
		ob: map[string]any{"tag": "proxy", "protocol": "hysteria", "streamSettings": ss,
			"settings": map[string]any{"version": 2, "address": host, "port": port}}}, nil
}
