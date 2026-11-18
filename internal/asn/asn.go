// Package asn — по IP узнать автономную систему (AS) и есть ли она в списке
// сетей, которые ТСПУ «замораживает» (поток встаёт после ~16 КБ / ~25 пакетов).
//
// База IP→AS — IPtoASN (https://iptoasn.com, PDDL v1.0), встроена только в
// полные сборки (в lite её нет: там нет и подписок). Список «замороженных»
// сетей — из замеров github.com/MarkSinD/freeze-check (MIT, ноябрь 2026,
// сети, где заморожены все проверенные точки) плюс несколько соседних AS тех
// же компаний. Это подсказка, а не приговор: решает настоящий тест загрузки.
package asn

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
)

// Info — что известно об адресе.
type Info struct {
	ASN     uint32 `json:"asn,omitempty"`
	Name    string `json:"as_name,omitempty"`
	Country string `json:"as_cc,omitempty"`
	// Frozen — AS в списке сетей, замороженных ТСПУ (по внешним замерам).
	Frozen     bool   `json:"as_frozen,omitempty"`
	FrozenNote string `json:"as_frozen_note,omitempty"`
}

// FrozenAS — сети, замороженные ТСПУ целиком.
var FrozenAS = map[uint32]string{
	16276:  "OVH",
	63023:  "GTHost",
	36352:  "HostPapa (RackNerd, DediRock…)",
	14061:  "DigitalOcean",
	9009:   "M247",
	62240:  "Clouvider",
	42708:  "Glesys",
	20860:  "iomart",
	20473:  "Vultr (The Constant Company)",
	53667:  "BuyVM (FranTech)",
	62563:  "GTHost (GlobalTeleHost)",
	24940:  "Hetzner",
	213230: "Hetzner Cloud",
	212317: "Hetzner (US/SG)",
	12876:  "Scaleway",
	199741: "TransitX",
	42831:  "UK Dedicated Servers",
}

type db struct {
	starts []uint32
	asns   []uint32
	names  map[uint32]string // "CC|имя"
}

var (
	once   sync.Once
	loaded *db
)

func get() *db {
	once.Do(func() {
		if len(blob) == 0 {
			return
		}
		d, err := parse(blob)
		if err == nil {
			loaded = d
		}
	})
	return loaded
}

// Available — встроена ли база.
func Available() bool { return len(blob) > 0 }

func parse(gz []byte) (*db, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	if len(raw) < 13 || string(raw[:5]) != "MASN1" {
		return nil, errors.New("asn: неизвестный формат")
	}
	nr := binary.LittleEndian.Uint32(raw[5:])
	na := binary.LittleEndian.Uint32(raw[9:])
	r := bytes.NewReader(raw[13:])
	d := &db{starts: make([]uint32, 0, nr), asns: make([]uint32, 0, nr), names: make(map[uint32]string, na)}
	var prev uint64
	for i := uint32(0); i < nr; i++ {
		ds, err1 := binary.ReadUvarint(r)
		a, err2 := binary.ReadUvarint(r)
		if err1 != nil || err2 != nil {
			return nil, errors.New("asn: обрыв диапазонов")
		}
		prev += ds
		d.starts = append(d.starts, uint32(prev))
		d.asns = append(d.asns, uint32(a))
	}
	for i := uint32(0); i < na; i++ {
		a, err1 := binary.ReadUvarint(r)
		l, err2 := binary.ReadUvarint(r)
		if err1 != nil || err2 != nil || l > 256 {
			return nil, errors.New("asn: обрыв имён")
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		d.names[uint32(a)] = string(b)
	}
	return d, nil
}

// Lookup — AS для IPv4/IPv6-адреса (для IPv6 — только список по ASN недоступен,
// вернётся пусто).
func Lookup(ip net.IP) Info {
	v4 := ip.To4()
	if v4 == nil {
		return Info{}
	}
	d := get()
	if d == nil {
		return Info{}
	}
	x := binary.BigEndian.Uint32(v4)
	i := sort.Search(len(d.starts), func(i int) bool { return d.starts[i] > x }) - 1
	if i < 0 || d.asns[i] == 0 {
		return Info{}
	}
	return ByASN(d.asns[i])
}

// LookupString — то же по строке ("" если не IP).
func LookupString(s string) Info {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return Info{}
	}
	return Lookup(ip)
}

// ByASN — имя и страна AS (если база есть) и отметка «заморожена».
func ByASN(a uint32) Info {
	in := Info{ASN: a}
	if d := get(); d != nil {
		if s, ok := d.names[a]; ok {
			if cc, n, ok := strings.Cut(s, "|"); ok {
				in.Country, in.Name = cc, n
			}
		}
	}
	if note, ok := FrozenAS[a]; ok {
		in.Frozen, in.FrozenNote = true, note
	}
	return in
}
