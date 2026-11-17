// Package desync — «прямой» путь мимо DPI без своего сервера: первый пакет
// соединения (TLS ClientHello или HTTP-запрос) отправляется так, чтобы DPI
// не смог собрать имя сайта (SNI/Host), а настоящий сервер принял всё как
// обычно. Идеи взяты из byedpi (MIT, github.com/hufrea/byedpi); код свой.
package desync

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"strings"
)

// HelloInfo — где в TLS-записи с ClientHello лежит имя сайта.
type HelloInfo struct {
	SNI    string
	SNIPos int // смещение первого байта имени от начала буфера (0 = нет SNI)
	ExtPos int // начало расширения server_name (его тип)
	RecLen int // длина первой TLS-записи вместе с 5-байтовым заголовком
}

// IsTLSHello — похоже ли начало буфера на TLS-запись с ClientHello.
func IsTLSHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04 && b[5] == 0x01
}

// TLSRecordLen — полная длина первой TLS-записи (с заголовком) или 0.
func TLSRecordLen(b []byte) int {
	if len(b) < 5 || b[0] != 0x16 {
		return 0
	}
	return 5 + int(binary.BigEndian.Uint16(b[3:5]))
}

var errShort = errors.New("short client hello")

// ParseHello разбирает ClientHello в первой TLS-записи и находит SNI.
func ParseHello(b []byte) (HelloInfo, error) {
	var h HelloInfo
	if !IsTLSHello(b) {
		return h, errors.New("not a TLS ClientHello")
	}
	h.RecLen = TLSRecordLen(b)
	end := h.RecLen
	if end > len(b) {
		end = len(b)
	}
	p := 5 + 4  // заголовок записи + заголовок handshake
	p += 2 + 32 // версия + random
	if p+1 > end {
		return h, errShort
	}
	p += 1 + int(b[p]) // session id
	if p+2 > end {
		return h, errShort
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:])) // cipher suites
	if p+1 > end {
		return h, errShort
	}
	p += 1 + int(b[p]) // compression
	if p+2 > end {
		return h, errShort
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if extEnd > end {
		extEnd = end
	}
	for p+4 <= extEnd {
		typ := binary.BigEndian.Uint16(b[p:])
		l := int(binary.BigEndian.Uint16(b[p+2:]))
		if typ == 0 && p+4+5 <= extEnd { // server_name
			h.ExtPos = p
			q := p + 4 + 2 // список
			if b[q] == 0 {
				nl := int(binary.BigEndian.Uint16(b[q+1:]))
				if q+3+nl <= end {
					h.SNIPos = q + 3
					h.SNI = string(b[q+3 : q+3+nl])
				}
			}
			return h, nil
		}
		p += 4 + l
	}
	return h, nil
}

// SplitRecord режет первую TLS-запись на две в точке at (смещение от начала
// буфера, внутри тела записи). Сервер обязан склеить фрагменты handshake —
// так требует RFC 8446, а DPI, разбирающий одну запись, имени не видит.
func SplitRecord(b []byte, at int) []byte {
	rl := TLSRecordLen(b)
	if rl == 0 || rl > len(b) || at <= 5 || at >= rl {
		return b
	}
	out := make([]byte, 0, len(b)+5)
	out = append(out, b[:3]...)
	out = binary.BigEndian.AppendUint16(out, uint16(at-5))
	out = append(out, b[5:at]...)
	out = append(out, b[:3]...)
	out = binary.BigEndian.AppendUint16(out, uint16(rl-at))
	out = append(out, b[at:]...)
	return out
}

// SplitRecords режет первую TLS-запись на несколько в точках cuts
// (смещения от начала буфера, по возрастанию). Остаток буфера — как есть.
func SplitRecords(b []byte, cuts []int) []byte {
	rl := TLSRecordLen(b)
	if rl == 0 || rl > len(b) {
		return b
	}
	var cs []int
	last := 5
	for _, c := range cuts {
		if c > last && c < rl {
			cs = append(cs, c)
			last = c
		}
	}
	if len(cs) == 0 {
		return b
	}
	out := make([]byte, 0, len(b)+5*len(cs))
	from := 5
	for _, c := range append(cs, rl) {
		out = append(out, b[:3]...)
		out = binary.BigEndian.AppendUint16(out, uint16(c-from))
		out = append(out, b[from:c]...)
		from = c
	}
	return append(out, b[rl:]...)
}

// FakeHost — имя той же длины, что и настоящее: так фейковый ClientHello
// совпадает по длинам с настоящим, и пересчитывать поля не нужно.
func FakeHost(n int, base string) string {
	if base == "" {
		base = "vk.com"
	}
	const abc = "abcdefghijklmnopqrstuvwxyz"
	if n <= len(base)+1 {
		var s strings.Builder
		for i := 0; i < n; i++ {
			s.WriteByte(abc[rand.Intn(len(abc))])
		}
		return s.String()
	}
	var s strings.Builder
	for i := 0; i < n-len(base)-1; i++ {
		s.WriteByte(abc[rand.Intn(len(abc))])
	}
	return s.String() + "." + base
}

// FakeHello — копия ClientHello с подменённым SNI (той же длины).
func FakeHello(b []byte, h HelloInfo, base string) []byte {
	f := append([]byte(nil), b...)
	if h.SNIPos > 0 {
		copy(f[h.SNIPos:], FakeHost(len(h.SNI), base))
	}
	return f
}

// HTTPHostPos — смещение значения заголовка Host в HTTP-запросе (0 = нет).
func HTTPHostPos(b []byte) (int, int) {
	if !IsHTTP(b) {
		return 0, 0
	}
	i := bytes.Index(bytes.ToLower(b), []byte("\r\nhost:"))
	if i < 0 {
		return 0, 0
	}
	p := i + 7
	for p < len(b) && b[p] == ' ' {
		p++
	}
	e := bytes.Index(b[p:], []byte("\r\n"))
	if e < 0 {
		return 0, 0
	}
	return p, e
}

// HTTPMod — приёмы для обычного HTTP: «hOsT:» вместо «Host:», без пробела
// после двоеточия, смешанный регистр домена. Серверы это принимают (имена
// заголовков и домены регистронезависимы), а простой DPI ищет «Host: домен».
func HTTPMod(b []byte) []byte {
	hp, hl := HTTPHostPos(b)
	if hp == 0 {
		return b
	}
	i := bytes.LastIndex(b[:hp], []byte("\r\n"))
	if i < 0 {
		return b
	}
	out := append([]byte(nil), b[:i+2]...)
	out = append(out, "hOsT:"...)
	dom := []byte(strings.ToLower(string(b[hp : hp+hl])))
	for k := range dom {
		if k%2 == 1 && dom[k] >= 'a' && dom[k] <= 'z' {
			dom[k] -= 32
		}
	}
	out = append(out, dom...)
	return append(out, b[hp+hl:]...)
}

func IsHTTP(b []byte) bool {
	for _, m := range []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH "} {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}
