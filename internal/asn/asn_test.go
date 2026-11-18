//go:build !lite

package asn

import (
	"net"
	"testing"
)

func TestLookup(t *testing.T) {
	cases := []struct {
		ip     string
		asn    uint32
		frozen bool
	}{
		{"1.0.0.1", 13335, false},  // Cloudflare
		{"5.9.0.1", 24940, true},   // Hetzner
		{"51.68.0.1", 16276, true}, // OVH
		{"8.8.8.8", 15169, false},  // Google
		{"10.0.0.1", 0, false},     // частная сеть
	}
	for _, c := range cases {
		in := Lookup(net.ParseIP(c.ip))
		if in.ASN != c.asn || in.Frozen != c.frozen {
			t.Errorf("%s: %+v, want AS%d frozen=%v", c.ip, in, c.asn, c.frozen)
		}
	}
	if in := Lookup(net.ParseIP("1.0.0.1")); in.Name == "" || in.Country == "" {
		t.Errorf("no name: %+v", in)
	}
}
