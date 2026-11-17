package desync

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Strategy — как отправлять первый пакет.
//
//	tlsrec[:at=mid|sni|sniext] — разрезать TLS-запись с ClientHello на две
//	multirec — разрезать на 4 записи: в начале, середине и конце имени
//	split[:at=sni|mid|end|sniext|N] — разрезать TCP-поток (по умолчанию после 1-го байта имени)
//	disorder — первый сегмент уходит с TTL=1 и теряется; ядро перешлёт его позже
//	fake[:ttl=N/md5] — перед настоящим сегментом уходит фейк (чужой SNI) с малым TTL;
//	           md5 — фейк ещё и с TCP MD5-подписью: сервер его отбросит даже если дойдёт
//	oob      — после первого сегмента 1 байт «срочных» (OOB) данных
//	hmod     — для обычного HTTP: «hOsT:», без пробела, смешанный регистр домена
//	none     — без хитростей
type Strategy struct {
	TLSRec   bool
	RecAt    string // mid|sni|sniext|multi
	Method   string // none|split|disorder|fake|oob
	At       string // где режется TCP: sni|mid|end|sniext|число
	TTL      int    // TTL фейка
	MD5      bool   // фейк с TCP MD5-подписью
	HTTPMod  bool
	FakeBase string // домен для фейкового SNI
}

var Methods = []string{"none", "split", "disorder", "fake", "oob"}

// ParseStrategy: "tlsrec+split", "fake:ttl=6/md5", "split:at=mid", "multirec+disorder", "hmod+split".
func ParseStrategy(s string) (Strategy, error) {
	st := Strategy{Method: "none", TTL: 8}
	for _, part := range strings.Split(strings.ToLower(strings.TrimSpace(s)), "+") {
		name, args, _ := strings.Cut(part, ":")
		isRec := false
		switch name {
		case "":
		case "tlsrec":
			st.TLSRec, isRec = true, true
			if st.RecAt == "" {
				st.RecAt = "mid"
			}
		case "multirec":
			st.TLSRec, st.RecAt = true, "multi"
		case "hmod":
			st.HTTPMod = true
		case "none", "split", "disorder", "fake", "oob":
			st.Method = name
		default:
			return st, fmt.Errorf("неизвестный приём %q (есть: tlsrec, multirec, hmod, %s)", name, strings.Join(Methods, ", "))
		}
		if args == "" {
			continue
		}
		for _, kv := range strings.Split(args, "/") {
			k, v, _ := strings.Cut(kv, "=")
			switch k {
			case "ttl":
				n, err := strconv.Atoi(v)
				if err != nil || n < 1 || n > 255 {
					return st, fmt.Errorf("ttl: %q", v)
				}
				st.TTL = n
			case "md5":
				st.MD5 = true
			case "sni":
				st.FakeBase = v
			case "at":
				switch v {
				case "sni", "mid", "end", "sniext":
				default:
					if n, err := strconv.Atoi(v); err != nil || n < 1 {
						return st, fmt.Errorf("at: %q (sni, mid, end, sniext или число)", v)
					}
				}
				if isRec {
					if v == "end" || (v[0] >= '0' && v[0] <= '9') {
						return st, fmt.Errorf("tlsrec:at=%s не поддерживается", v)
					}
					st.RecAt = v
				} else {
					st.At = v
				}
			default:
				return st, fmt.Errorf("неизвестный параметр %q", k)
			}
		}
	}
	return st, nil
}

func (s Strategy) String() string {
	var p []string
	if s.HTTPMod {
		p = append(p, "hmod")
	}
	if s.TLSRec {
		switch s.RecAt {
		case "multi":
			p = append(p, "multirec")
		case "", "mid":
			p = append(p, "tlsrec")
		default:
			p = append(p, "tlsrec:at="+s.RecAt)
		}
	}
	m := s.Method
	var args []string
	if s.At != "" {
		args = append(args, "at="+s.At)
	}
	if m == "fake" && s.TTL != 8 {
		args = append(args, "ttl="+strconv.Itoa(s.TTL))
	}
	if m == "fake" && s.MD5 {
		args = append(args, "md5")
	}
	if len(args) > 0 {
		m += ":" + strings.Join(args, "/")
	}
	if m != "none" || len(p) == 0 {
		p = append(p, m)
	}
	return strings.Join(p, "+")
}

// ParseList — список стратегий через запятую или пробел.
func ParseList(s string) ([]Strategy, error) {
	var out []Strategy
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		st, err := ParseStrategy(f)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

// Plan — что именно будет отправлено.
type Plan struct {
	Data   []byte // байты после перекройки TLS-записей / HTTP
	Pos    int    // где режется TCP (0 = не режется)
	Host   string // имя сайта из первого пакета
	Proto  string // tls|http|other
	Fake   []byte // фейк той же длины, что Data[:Pos] (для fake)
	Method string
	Cuts   []int // где резались TLS-записи (смещения в исходном буфере)
}

// position — смещение в исходном буфере для at.
func position(at string, name, ext, nameLen, total int) int {
	switch at {
	case "mid":
		return name + nameLen/2
	case "end":
		return name + nameLen
	case "sniext":
		return ext
	case "sni", "":
		return name + 1
	}
	n, _ := strconv.Atoi(at)
	if n >= total {
		n = total - 1
	}
	return n
}

func (s Strategy) recCuts(h HelloInfo) []int {
	n := len(h.SNI)
	switch s.RecAt {
	case "multi":
		return []int{h.SNIPos, h.SNIPos + n/2, h.SNIPos + n - 1}
	case "sni":
		return []int{h.SNIPos + 1}
	case "sniext":
		return []int{h.ExtPos}
	default:
		return []int{h.SNIPos + n/2}
	}
}

// shifted — позиция TCP-разреза в перекроенном буфере: каждая TLS-вырезка
// раньше неё добавляет 5 байт заголовка.
func shifted(pos int, cuts []int) int {
	out := pos
	for _, c := range cuts {
		if c < pos {
			out += 5
		}
	}
	return out
}

// MakePlan готовит первый пакет к отправке.
func (s Strategy) MakePlan(first []byte) Plan {
	p := Plan{Data: first, Proto: "other", Method: s.Method}
	at := s.At
	if at == "" && s.Method == "fake" {
		at = "end" // фейк должен нести имя целиком
	}
	switch {
	case IsTLSHello(first):
		p.Proto = "tls"
		h, err := ParseHello(first)
		if err != nil || h.SNIPos == 0 || h.RecLen > len(first) {
			p.Method = "none"
			return p
		}
		p.Host = h.SNI
		pos := position(at, h.SNIPos, h.ExtPos, len(h.SNI), h.RecLen)
		if s.TLSRec {
			p.Cuts = s.recCuts(h)
			p.Data = SplitRecords(first, p.Cuts)
		}
		p.Pos = shifted(pos, p.Cuts)
		if s.Method == "fake" {
			f := FakeHello(first, h, s.FakeBase)
			if s.TLSRec {
				f = SplitRecords(f, p.Cuts)
			}
			p.Fake = f[:p.Pos]
		}
	case IsHTTP(first):
		p.Proto = "http"
		if s.HTTPMod {
			first = HTTPMod(first)
			p.Data = first
		}
		hp, hl := HTTPHostPos(first)
		if hp == 0 {
			p.Method = "none"
			return p
		}
		p.Host = string(first[hp : hp+hl])
		ext := hp
		if i := lastCRLF(first[:hp]); i >= 0 {
			ext = i + 2
		}
		p.Pos = position(at, hp, ext, hl, len(first))
		if s.Method == "fake" {
			f := append([]byte(nil), first...)
			copy(f[hp:], FakeHost(hl, s.FakeBase))
			p.Fake = f[:p.Pos]
		}
	default:
		p.Method = "none"
	}
	if p.Method == "none" {
		p.Pos = 0
	}
	if p.Pos >= len(p.Data) {
		p.Pos = 0
		if p.Method != "none" {
			p.Method = "split"
		}
	}
	return p
}

func lastCRLF(b []byte) int {
	for i := len(b) - 2; i >= 0; i-- {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}

// Report — что реально ушло в сеть (для журнала и тестов).
type Report struct {
	Plan     Plan
	Segments []int // размеры отдельных send()
	Note     string
}

// Send отправляет первый пакет по стратегии и возвращает отчёт.
func (s Strategy) Send(c *net.TCPConn, first []byte) (Report, error) {
	pl := s.MakePlan(first)
	r := Report{Plan: pl}
	_ = c.SetNoDelay(true)
	if pl.Pos <= 0 || pl.Pos >= len(pl.Data) {
		_, err := c.Write(pl.Data)
		r.Segments = []int{len(pl.Data)}
		return r, err
	}
	rest := pl.Data[pl.Pos:]
	var err error
	switch pl.Method {
	case "disorder":
		err = sendDisorder(c, pl.Data[:pl.Pos], &r)
	case "fake":
		err = sendFake(c, pl.Data[:pl.Pos], pl.Fake, s.TTL, s.MD5, &r)
	case "oob":
		err = sendOOB(c, pl.Data[:pl.Pos], &r)
	default:
		_, err = c.Write(pl.Data[:pl.Pos])
		r.Segments = append(r.Segments, pl.Pos)
		waitSent(c, 50*time.Millisecond)
	}
	if err != nil {
		return r, err
	}
	_, err = c.Write(rest)
	r.Segments = append(r.Segments, len(rest))
	return r, err
}
