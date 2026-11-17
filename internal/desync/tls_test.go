package desync

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
)

func clientHello(t *testing.T, sni string) []byte {
	a, b := net.Pipe()
	go func() { tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake() }()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, _ := b.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rl := TLSRecordLen(buf); rl > 0 && len(buf) >= rl {
			break
		}
	}
	a.Close()
	b.Close()
	return buf
}

func TestParseAndSplit(t *testing.T) {
	ch := clientHello(t, "rutracker.org")
	h, err := ParseHello(ch)
	if err != nil || h.SNI != "rutracker.org" || string(ch[h.SNIPos:h.SNIPos+len(h.SNI)]) != "rutracker.org" {
		t.Fatalf("%+v %v", h, err)
	}
	s := SplitRecord(ch, h.SNIPos+len(h.SNI)/2)
	if len(s) != len(ch)+5 {
		t.Fatal("len")
	}
	l1 := TLSRecordLen(s)
	if bytes.Contains(s[:l1], []byte("rutracker.org")) || bytes.Contains(s[l1:], []byte("rutracker.org")) {
		t.Fatal("full SNI still visible in one record")
	}
	joined := append(append([]byte(nil), s[5:l1]...), s[l1+5:]...)
	if !bytes.Equal(joined, ch[5:]) {
		t.Fatal("payload differs")
	}
	f := FakeHello(ch, h, "")
	if len(f) != len(ch) || bytes.Contains(f, []byte("rutracker")) {
		t.Fatal("fake")
	}
	fh, _ := ParseHello(f)
	t.Logf("SNI at %d, record %d bytes; fake SNI %q", h.SNIPos, h.RecLen, fh.SNI)
}

func TestParseStrategy(t *testing.T) {
	for _, s := range []string{"tlsrec+split", "fake:ttl=5", "tlsrec+disorder", "oob", "none", "multirec+split", "split:at=mid", "tlsrec:at=sniext+split", "fake:ttl=64/md5", "hmod+split", "tlsrec+fake:md5", "split:at=sniext"} {
		st, err := ParseStrategy(s)
		if err != nil || st.String() != s {
			t.Fatalf("%s -> %v %v", s, st, err)
		}
	}
	if _, err := ParseStrategy("bogus"); err == nil {
		t.Fatal("want error")
	}
}

func TestMultirecAndPositions(t *testing.T) {
	ch := clientHello(t, "rutracker.org")
	h, _ := ParseHello(ch)
	for _, name := range []string{"multirec+split", "tlsrec:at=sniext+split:at=mid", "split:at=sniext", "split:at=end", "multirec+fake"} {
		st, err := ParseStrategy(name)
		if err != nil {
			t.Fatal(err)
		}
		p := st.MakePlan(ch)
		// склейка записей даёт исходный ClientHello
		var joined []byte
		b := p.Data
		for len(b) >= 5 && b[0] == 0x16 {
			rl := TLSRecordLen(b)
			if bytes.Contains(b[:rl], []byte("rutracker.org")) && st.TLSRec && st.RecAt != "sniext" { // sniext: имя целиком во 2-й записи — так и задумано
				t.Fatalf("%s: SNI whole in one record", name)
			}
			joined = append(joined, b[5:rl]...)
			b = b[rl:]
		}
		if !bytes.Equal(joined, ch[5:]) {
			t.Fatalf("%s: payload differs", name)
		}
		if p.Pos <= 0 || p.Pos >= len(p.Data) {
			t.Fatalf("%s: pos %d", name, p.Pos)
		}
		if p.Fake != nil && len(p.Fake) != p.Pos {
			t.Fatalf("%s: fake len", name)
		}
		t.Logf("%-32s records=%d tcp-cut=%d (SNI at %d, ext at %d)", name, len(p.Cuts)+1, p.Pos, h.SNIPos, h.ExtPos)
	}
}

func TestHTTPMod(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n")
	m := HTTPMod(req)
	if !bytes.Contains(m, []byte("\r\nhOsT:eXaMpLe.cOm\r\n")) {
		t.Fatalf("%q", m)
	}
	st, _ := ParseStrategy("hmod+split")
	p := st.MakePlan(req)
	if p.Host != "eXaMpLe.cOm" || p.Pos == 0 {
		t.Fatalf("%+v", p)
	}
}
